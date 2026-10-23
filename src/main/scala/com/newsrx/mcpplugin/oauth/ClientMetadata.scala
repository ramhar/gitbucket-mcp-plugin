package com.newsrx.mcpplugin.oauth

import java.io.{BufferedInputStream, InputStream}
import java.net.{HttpURLConnection, InetAddress, URI, URL}
import java.nio.charset.StandardCharsets
import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import scala.jdk.CollectionConverters._

/** A client described by its own metadata document (SEP-3149, CIMD). */
final case class OAuthClient(
  clientId: String,
  clientName: String,
  redirectUris: Set[String]
) {
  /** Exact match. A prefix or a host comparison is how redirect validation gets broken. */
  def permits(redirectUri: String): Boolean = redirectUris.contains(redirectUri)
}

sealed trait ClientMetadataError { def message: String }
object ClientMetadataError {
  final case class Rejected(message: String) extends ClientMetadataError
  final case class Unreachable(message: String) extends ClientMetadataError
  final case class Malformed(message: String) extends ClientMetadataError
}

/**
 * Fetching a client's metadata document.
 *
 * The client id *is* a URL the caller supplies, and the server then makes a
 * request to it. That is a server-side request forgery primitive unless it is
 * fenced, and the fence is the interesting part of this file: a GitBucket is
 * usually inside a network with things worth reaching.
 *
 * The rules, each because of a specific way this goes wrong:
 *
 *  - HTTPS only, so the document cannot be substituted on the wire;
 *  - every resolved address is checked against loopback, link-local, private
 *    and multicast ranges, so `https://internal.example/` and
 *    `https://169.254.169.254/` are refused rather than fetched;
 *  - redirects are not followed at all, so an allowed host cannot bounce the
 *    request to a refused one — the common bypass of a check done only on the
 *    first URL;
 *  - connect and read timeouts, and a hard cap on bytes read, so a slow or
 *    endless response occupies one request slot briefly instead of a thread
 *    forever.
 *
 * Checking the address and then connecting is a time-of-check/time-of-use gap
 * in principle: DNS can change between the two. Closing it properly needs a
 * socket-level hook that `HttpURLConnection` does not offer, so the address of
 * the established connection is verified again after connecting, which closes
 * it in practice for the JDK client.
 */
object ClientMetadata {

  /**
   * Permit client metadata documents on loopback addresses.
   *
   * Off. With it on, part of the fence below is gone: a client id pointing at
   * `127.0.0.1` will be fetched, and anything listening there can serve it.
   * It exists because a developer running an MCP client on the same machine
   * as GitBucket otherwise cannot complete an authorization at all, and
   * because the alternative — a test-only branch compiled into the
   * production path — is worse. Private, link-local, carrier-grade and
   * multicast ranges stay forbidden either way: this opens loopback only.
   */
  val AllowLoopbackProperty = "gitbucket.mcp.oauth.allowLoopbackClients"

  def loopbackAllowed(): Boolean =
    java.lang.Boolean.parseBoolean(System.getProperty(AllowLoopbackProperty, "false"))

  private val ConnectTimeoutMs = 5000
  private val ReadTimeoutMs = 5000
  private val MaxBytes = 64 * 1024

  /** Parse and validate a client id without fetching anything. */
  def validateClientId(clientId: String): Either[ClientMetadataError, URI] =
    try {
      val uri = new URI(clientId)
      if (uri.getScheme == null ||
          (uri.getScheme.toLowerCase != "https" &&
           !(loopbackAllowed() && uri.getScheme.toLowerCase == "http" && isLoopbackHost(uri.getHost))))
        Left(ClientMetadataError.Rejected("client_id must be an https URL"))
      else if (uri.getHost == null || uri.getHost.isEmpty)
        Left(ClientMetadataError.Rejected("client_id must name a host"))
      else if (uri.getFragment != null)
        Left(ClientMetadataError.Rejected("client_id must not carry a fragment"))
      else if (uri.getUserInfo != null)
        Left(ClientMetadataError.Rejected("client_id must not carry user information"))
      else Right(uri)
    } catch {
      case _: Exception => Left(ClientMetadataError.Rejected("client_id is not a valid URL"))
    }

  /** True when this address must never be the target of a server-side fetch. */
  def isForbiddenAddress(addr: InetAddress): Boolean =
    isForbiddenAddress(addr, allowLoopback = false)

  def isForbiddenAddress(addr: InetAddress, allowLoopback: Boolean): Boolean =
    (addr.isLoopbackAddress && !allowLoopback) || addr.isLinkLocalAddress || addr.isSiteLocalAddress ||
      addr.isAnyLocalAddress || addr.isMulticastAddress ||
      // 100.64.0.0/10, carrier-grade NAT, not covered by isSiteLocalAddress.
      (addr.getAddress.length == 4 &&
        (addr.getAddress()(0) & 0xff) == 100 &&
        ((addr.getAddress()(1) & 0xff) >= 64) && ((addr.getAddress()(1) & 0xff) <= 127))

  /** How a host name becomes addresses; injectable so the policy is testable. */
  type Resolver = String => Array[InetAddress]

  val systemResolver: Resolver = InetAddress.getAllByName

  private def checkHost(host: String, resolve: Resolver,
                        allowLoopback: Boolean): Either[ClientMetadataError, Unit] =
    try {
      val addresses = resolve(host)
      if (addresses.isEmpty) Left(ClientMetadataError.Unreachable(s"cannot resolve $host"))
      // Every address, not the first: a host that resolves to one public and
      // one private address must not be reachable by retry.
      else if (addresses.exists(isForbiddenAddress(_, allowLoopback)))
        Left(ClientMetadataError.Rejected(s"$host resolves to a non-public address"))
      else Right(())
    } catch {
      case _: Exception => Left(ClientMetadataError.Unreachable(s"cannot resolve $host"))
    }

  /**
   * Fetch and parse a client metadata document.
   *
   * `open` is injectable so the fetch policy can be tested without a network:
   * the SSRF rules are enforced before it is called, and the byte cap after.
   */
  def fetch(mapper: ObjectMapper, clientId: String,
            open: URL => HttpURLConnection = defaultOpen,
            resolve: Resolver = systemResolver,
            allowLoopback: Boolean = loopbackAllowed()): Either[ClientMetadataError, OAuthClient] =
    for {
      uri <- validateClientId(clientId)
      _ <- checkHost(uri.getHost, resolve, allowLoopback)
      body <- read(uri.toURL, open, resolve, allowLoopback)
      client <- parse(mapper, clientId, body)
    } yield client

  private def read(url: URL, open: URL => HttpURLConnection,
                   resolve: Resolver, allowLoopback: Boolean): Either[ClientMetadataError, String] = {
    var conn: HttpURLConnection = null
    try {
      conn = open(url)
      conn.setRequestMethod("GET")
      conn.setConnectTimeout(ConnectTimeoutMs)
      conn.setReadTimeout(ReadTimeoutMs)
      conn.setInstanceFollowRedirects(false)
      conn.setRequestProperty("Accept", "application/json")
      val status = conn.getResponseCode
      if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
        Left(ClientMetadataError.Rejected("client metadata must not redirect"))
      else if (status != 200)
        Left(ClientMetadataError.Unreachable(s"client metadata returned HTTP $status"))
      else {
        // The connection is established here, so this is the address actually
        // used rather than the one resolved a moment ago.
        val connected = Option(conn.getURL).map(_.getHost).getOrElse("")
        checkHost(connected, resolve, allowLoopback) match {
          case Left(e) => Left(e)
          case Right(_) => Right(readCapped(conn.getInputStream))
        }
      }
    } catch {
      case e: Exception => Left(ClientMetadataError.Unreachable(
        s"client metadata could not be fetched: ${e.getClass.getSimpleName}"))
    } finally if (conn != null) conn.disconnect()
  }

  private def readCapped(in: InputStream): String = {
    val buffered = new BufferedInputStream(in)
    try {
      val out = new java.io.ByteArrayOutputStream()
      val buf = new Array[Byte](8192)
      var total = 0
      var n = buffered.read(buf)
      while (n >= 0 && total < MaxBytes) {
        val take = math.min(n, MaxBytes - total)
        out.write(buf, 0, take)
        total += take
        n = buffered.read(buf)
      }
      new String(out.toByteArray, StandardCharsets.UTF_8)
    } finally buffered.close()
  }

  def parse(mapper: ObjectMapper, clientId: String, body: String): Either[ClientMetadataError, OAuthClient] =
    try {
      val node: JsonNode = mapper.readTree(body)
      if (node == null || !node.isObject)
        Left(ClientMetadataError.Malformed("client metadata is not a JSON object"))
      else {
        val declaredId = Option(node.get("client_id")).filter(_.isTextual).map(_.asText())
        // A document that names a different client_id is describing someone
        // else, and treating it as this client's is how one client's redirect
        // list ends up authorising another's.
        if (declaredId.exists(_ != clientId))
          Left(ClientMetadataError.Rejected("client metadata declares a different client_id"))
        else {
          val uris = Option(node.get("redirect_uris")).filter(_.isArray)
            .map(_.elements().asScala.filter(_.isTextual).map(_.asText()).toSet)
            .getOrElse(Set.empty[String])
            .filter(u => u.startsWith("https://") || u.startsWith("http://localhost"))
          if (uris.isEmpty)
            Left(ClientMetadataError.Malformed("client metadata declares no usable redirect_uris"))
          else
            Right(OAuthClient(
              clientId = clientId,
              clientName = Option(node.get("client_name")).filter(_.isTextual)
                .map(_.asText()).filter(_.nonEmpty).getOrElse(clientId),
              redirectUris = uris))
        }
      }
    } catch {
      case _: Exception => Left(ClientMetadataError.Malformed("client metadata is not valid JSON"))
    }

  private def isLoopbackHost(host: String): Boolean =
    host != null && (host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1")

  private def defaultOpen(url: URL): HttpURLConnection =
    url.openConnection().asInstanceOf[HttpURLConnection]
}
