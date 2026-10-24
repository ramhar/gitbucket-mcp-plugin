package com.newsrx.mcpplugin.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.{HttpExchange, HttpHandler, HttpsConfigurator, HttpsServer}
import java.io.IOException
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, URL}
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.{HttpsURLConnection, KeyManagerFactory, SSLContext, SSLSocketFactory, TrustManagerFactory}
import org.junit.runner.RunWith
import org.scalatestplus.junit.JUnitRunner
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/**
 * The client metadata fetch, over a real connection.
 *
 * `ClientMetadataSpec` establishes the policy: which addresses are forbidden,
 * which client ids are malformed, what a redirect does. It cannot establish
 * where the request actually went, because it never makes one.
 *
 * That gap was not academic. The fence used to check an address and then hand
 * a *host name* to the URL connection, which resolved it again independently;
 * a name answering with a public address for the check and a loopback address
 * for the connection was fetched from loopback with the loopback escape off.
 * The second check that was supposed to catch this read the URL's host rather
 * than the peer, and ran after the response had arrived — after the request
 * had been sent, which is the entire injury.
 *
 * So these cases run the production `fetch` against sockets, and the witness
 * is what the listeners saw rather than what the fetch returned.
 *
 * The TLS material is a throwaway self-signed key pair in `src/test/resources`,
 * trusted only by the socket factory this suite installs. Nothing outside this
 * suite trusts it and it is never packaged with the plugin.
 */
@RunWith(classOf[JUnitRunner])
class PinnedFetchSpec extends AnyFunSuite with Matchers with BeforeAndAfterAll {

  private val mapper = new ObjectMapper()
  private val Host = "client.example.test"
  private val loopback = InetAddress.getByName("127.0.0.1")
  // Documentation range, no listener anywhere: if a request is attempted here
  // it fails, and if one is attempted elsewhere a recorder sees it.
  private val elsewhere = InetAddress.getByName("203.0.113.10")

  private var server: HttpsServer = _
  private var port: Int = 0
  private val served = new AtomicInteger(0)
  private var previousFactory: SSLSocketFactory = _

  private def keystore(): KeyStore = {
    val ks = KeyStore.getInstance("PKCS12")
    val in = getClass.getResourceAsStream("/cimd-test-server.p12")
    require(in != null, "the test keystore is missing from the test classpath")
    try ks.load(in, "changeit".toCharArray) finally in.close()
    ks
  }

  private def serverContext(): SSLContext = {
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    kmf.init(keystore(), "changeit".toCharArray)
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(kmf.getKeyManagers, null, null)
    ctx
  }

  private def trustingContext(): SSLContext = {
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(keystore())
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(null, tmf.getTrustManagers, null)
    ctx
  }

  private def body(clientId: String) =
    s"""{"client_id":"$clientId","client_name":"Pinned","redirect_uris":["https://app.example.com/cb"]}"""

  override def beforeAll(): Unit = {
    // A proxy would send the request wherever it liked, so destination control
    // could not be observed at all. Production refuses proxies for the same
    // reason; here it also keeps the sandbox's proxy out of the measurement.
    System.clearProperty("https.proxyHost")
    System.clearProperty("http.proxyHost")

    server = HttpsServer.create(new InetSocketAddress(loopback, 0), 0)
    server.setHttpsConfigurator(new HttpsConfigurator(serverContext()))
    server.createContext("/client.json", new HttpHandler {
      def handle(ex: HttpExchange): Unit = {
        served.incrementAndGet()
        val bytes = body(clientId).getBytes("UTF-8")
        ex.getResponseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(200, bytes.length)
        ex.getResponseBody.write(bytes)
        ex.close()
      }
    })
    server.createContext("/redirect.json", new HttpHandler {
      def handle(ex: HttpExchange): Unit = {
        served.incrementAndGet()
        ex.getResponseHeaders.add("Location", "https://somewhere.example.com/other.json")
        ex.sendResponseHeaders(302, -1)
        ex.close()
      }
    })
    server.createContext("/endless.json", new HttpHandler {
      def handle(ex: HttpExchange): Unit = {
        served.incrementAndGet()
        val pad = "x" * (300 * 1024)
        val bytes = s"""{"client_id":"$clientId","redirect_uris":[],"pad":"$pad"}""".getBytes("UTF-8")
        ex.getResponseHeaders.add("Content-Type", "application/json")
        ex.sendResponseHeaders(200, bytes.length)
        ex.getResponseBody.write(bytes)
        ex.close()
      }
    })
    server.start()
    port = server.getAddress.getPort

    previousFactory = HttpsURLConnection.getDefaultSSLSocketFactory
    HttpsURLConnection.setDefaultSSLSocketFactory(trustingContext().getSocketFactory)
  }

  override def afterAll(): Unit = {
    if (server != null) server.stop(0)
    if (previousFactory != null) HttpsURLConnection.setDefaultSSLSocketFactory(previousFactory)
  }

  private def clientId = s"https://$Host:$port/client.json"
  private def resolvesTo(addr: InetAddress): ClientMetadata.Resolver = _ => Array(addr)

  // ── the lawful case, end to end over TLS ──────────────────────────────────

  test("a permitted destination is fetched, with TLS verified against the host name") {
    // The socket goes to an address; the certificate is still checked against
    // the name. If pinning had replaced the name with the address, this would
    // fail certificate verification instead of succeeding.
    served.set(0)
    val result = ClientMetadata.fetch(mapper, clientId,
      resolve = resolvesTo(loopback), allowLoopback = true)
    result.map(_.clientName) shouldBe Right("Pinned")
    withClue("the server should have been asked exactly once: ")(served.get() shouldBe 1)
  }

  test("the fetch presents the host name to TLS, not the pinned address") {
    // Proved by elimination: the fixture's certificate is issued for the name,
    // and the default factory installed here trusts only that certificate.
    // A handshake carrying the literal address would not match it.
    val cert = keystore().getCertificate("cimd").asInstanceOf[java.security.cert.X509Certificate]
    cert.getSubjectX500Principal.getName should include(Host)
    ClientMetadata.fetch(mapper, clientId,
      resolve = resolvesTo(loopback), allowLoopback = true).isRight shouldBe true
  }

  // ── the divergence that used to get through ───────────────────────────────

  test("a request goes to the checked address, not to one DNS supplies later") {
    // The policy resolver answers with a public address. The server is on
    // loopback. Before the connection was pinned, the fetch succeeded and the
    // loopback server served the document with the escape switched off.
    served.set(0)
    val result = ClientMetadata.fetch(mapper, clientId,
      resolve = resolvesTo(elsewhere), allowLoopback = false)
    result.isLeft shouldBe true
    withClue("the loopback server must not have been contacted: ")(served.get() shouldBe 0)
  }

  test("the forbidden listener receives nothing even when it is the real host") {
    // The same shape, with a recorder that accepts raw TCP, so the witness is
    // a connection rather than a completed HTTP exchange: a pin that leaked
    // would show up here even if TLS then failed.
    val recorder = new ServerSocket(0, 50, loopback)
    val accepted = new AtomicInteger(0)
    val t = new Thread(() => {
      try while (!recorder.isClosed) {
        val s: Socket = recorder.accept()
        accepted.incrementAndGet()
        s.close()
      } catch { case _: Exception => () }
    })
    t.setDaemon(true)
    t.start()
    try {
      val target = s"https://$Host:${recorder.getLocalPort}/client.json"
      val result = ClientMetadata.fetch(mapper, target,
        resolve = resolvesTo(elsewhere), allowLoopback = false)
      result.isLeft shouldBe true
      Thread.sleep(200)
      withClue("no TCP connection may reach the loopback recorder: ")(accepted.get() shouldBe 0)
    } finally recorder.close()
  }

  test("a loopback destination is still refused when the escape is off") {
    served.set(0)
    val result = ClientMetadata.fetch(mapper, clientId,
      resolve = resolvesTo(loopback), allowLoopback = false)
    result shouldBe Left(ClientMetadataError.Rejected(
      s"$Host resolves to a non-public address"))
    withClue("refused before any request: ")(served.get() shouldBe 0)
  }

  // ── the pin refuses to be redirected by the JDK ───────────────────────────

  test("plain http is refused unless the address is loopback") {
    // The escape exists for a developer's own machine. Carrying it to any
    // other address would be an unauthenticated fetch to an arbitrary host.
    val thrown = the[IOException] thrownBy PinnedConnection.fetch(
      new URL(s"http://$Host:$port/client.json"), elsewhere, 2000, 2000, 1024)
    thrown.getMessage should include("loopback")
  }

  test("a scheme other than http or https is refused") {
    an[IOException] should be thrownBy PinnedConnection.fetch(
      new URL(s"ftp://$Host:$port/client.json"), loopback, 2000, 2000, 1024)
  }

  test("the transport sends no request when the connection cannot be made") {
    // 203.0.113.0/24 is documentation space with nothing listening; the point
    // is that the attempt goes there and not to the server on loopback.
    served.set(0)
    an[Exception] should be thrownBy PinnedConnection.fetch(
      new URL(s"https://$Host:$port/client.json"), elsewhere, 1500, 1500, 1024)
    served.get() shouldBe 0
  }

  // ── the other guarantees still hold on the real path ──────────────────────

  test("a redirect is refused over a real connection, not followed") {
    served.set(0)
    val result = ClientMetadata.fetch(mapper, s"https://$Host:$port/redirect.json",
      resolve = resolvesTo(loopback), allowLoopback = true)
    result shouldBe Left(ClientMetadataError.Rejected("client metadata must not redirect"))
    withClue("the redirecting document was fetched exactly once: ")(served.get() shouldBe 1)
  }

  test("an oversized document is capped over a real connection") {
    val result = ClientMetadata.fetch(mapper, s"https://$Host:$port/endless.json",
      resolve = resolvesTo(loopback), allowLoopback = true)
    // Truncated at the cap, so it no longer parses.
    result.isLeft shouldBe true
  }

  test("a destination with nothing listening is unreachable, not a client") {
    val result = ClientMetadata.fetch(mapper, s"https://$Host:$port/missing.json",
      resolve = resolvesTo(loopback), allowLoopback = true)
    result.isLeft shouldBe true
  }

  // ── the address classification the divergence also exposed ────────────────

  test("IPv6 unique-local addresses are forbidden targets") {
    // fc00::/7. `isSiteLocalAddress` covers only the deprecated fec0::/10, so
    // every one of these used to read as an ordinary public address.
    Seq("fd00::1", "fc00::1", "fd12:3456:789a:1::1", "fdff:ffff::1").foreach { ip =>
      withClue(s"$ip: ")(
        ClientMetadata.isForbiddenAddress(InetAddress.getByName(ip)) shouldBe true)
    }
  }

  test("an IPv4 address wrapped in IPv6 notation is still that address") {
    Seq("::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1")
      .foreach { ip =>
        withClue(s"$ip: ")(
          ClientMetadata.isForbiddenAddress(InetAddress.getByName(ip)) shouldBe true)
      }
  }

  test("public IPv6 addresses are still permitted") {
    Seq("2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888").foreach { ip =>
      withClue(s"$ip: ")(
        ClientMetadata.isForbiddenAddress(InetAddress.getByName(ip)) shouldBe false)
    }
  }
}
