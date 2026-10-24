package com.newsrx.mcpplugin.oauth

import java.io.{BufferedInputStream, ByteArrayOutputStream, IOException, InputStream, OutputStreamWriter}
import java.net.{InetAddress, InetSocketAddress, Socket, URL}
import java.nio.charset.StandardCharsets
import javax.net.ssl.{HttpsURLConnection, SNIHostName, SNIServerName, SSLSocket}
import scala.jdk.CollectionConverters._

/** What a pinned request came back with. */
final case class PinnedResponse(status: Int, body: String)

/**
 * One HTTP request to an address that was decided in advance.
 *
 * Why this is not `HttpURLConnection`. Checking an address and then handing a
 * *name* to a URL connection checks nothing: the connection resolves the name
 * again, independently, and that second answer is the one that decides where
 * the request goes. Verifying afterwards is later still, because a response
 * only exists once the request has been sent — and for a server-side request
 * forgery, sending it is the whole of the damage.
 *
 * Neither `HttpURLConnection` nor `java.net.http.HttpClient` can be told which
 * address to use; both resolve the URL's host themselves. `HttpURLConnection`
 * looks as though its `SSLSocketFactory` is a hook for this, and it is not:
 * the JDK asks the factory for an *unconnected* socket and then connects it
 * itself, by name. So the socket is opened here instead.
 *
 * What is deliberately not hand-written: certificate verification. The socket
 * is layered with the original host name and
 * `setEndpointIdentificationAlgorithm("HTTPS")`, so the JDK performs the same
 * name check it performs for any HTTPS client, against the name rather than
 * against the pinned address. Pinning decides where the bytes go; it gives up
 * nothing about who must be at the other end.
 *
 * No proxy is consulted. A proxied request goes wherever the proxy decides,
 * which would make destination control an illusion.
 */
object PinnedConnection {

  private val MaxHeaderBytes = 32 * 1024
  private val MaxHeaderLines = 100

  def fetch(url: URL, address: InetAddress, connectTimeoutMs: Int,
            readTimeoutMs: Int, maxBytes: Int): PinnedResponse = {
    val scheme = url.getProtocol.toLowerCase
    val port = if (url.getPort != -1) url.getPort else if (scheme == "https") 443 else 80
    val host = url.getHost

    if (scheme == "http" && !address.isLoopbackAddress)
      throw new IOException("plain http is only reachable on a loopback address")
    if (scheme != "http" && scheme != "https")
      throw new IOException(s"unsupported scheme: $scheme")

    val raw = new Socket()
    var socket: Socket = raw
    try {
      raw.connect(new InetSocketAddress(address, port), connectTimeoutMs)
      raw.setSoTimeout(readTimeoutMs)

      if (scheme == "https") {
        val ssl = HttpsURLConnection.getDefaultSSLSocketFactory
          .createSocket(raw, host, port, true).asInstanceOf[SSLSocket]
        val params = ssl.getSSLParameters
        // The JDK checks the certificate against this name, exactly as it
        // would for any HTTPS client. Nothing about identity is re-implemented.
        params.setEndpointIdentificationAlgorithm("HTTPS")
        if (!isLiteralAddress(host))
          params.setServerNames(List[SNIServerName](new SNIHostName(host)).asJava)
        ssl.setSSLParameters(params)
        ssl.setSoTimeout(readTimeoutMs)
        ssl.startHandshake()
        socket = ssl
      }

      val authority = if (url.getPort != -1) s"$host:${url.getPort}" else host
      val path = {
        val p = Option(url.getPath).filter(_.nonEmpty).getOrElse("/")
        Option(url.getQuery).map(q => s"$p?$q").getOrElse(p)
      }
      val writer = new OutputStreamWriter(socket.getOutputStream, StandardCharsets.US_ASCII)
      writer.write(
        s"GET $path HTTP/1.1\r\n" +
          s"Host: $authority\r\n" +
          "Accept: application/json\r\n" +
          "User-Agent: gitbucket-mcp-plugin\r\n" +
          "Connection: close\r\n\r\n")
      writer.flush()

      val in = new BufferedInputStream(socket.getInputStream)
      val status = readStatus(in)
      val headers = readHeaders(in)
      // Redirects are refused rather than followed, so the body of a redirect
      // is never read and the hop is never made.
      if (status >= 300 && status < 400) PinnedResponse(status, "")
      else PinnedResponse(status, readBody(in, headers, maxBytes))
    } finally {
      try socket.close() catch { case _: Exception => () }
      try raw.close() catch { case _: Exception => () }
    }
  }

  private[oauth] def isLiteralAddress(host: String): Boolean =
    host != null && (host.contains(":") || host.matches("""\d{1,3}(\.\d{1,3}){3}"""))

  /** One line, CRLF-terminated, bounded so a server cannot stream forever. */
  private def readLine(in: InputStream, limit: Int): String = {
    val out = new ByteArrayOutputStream()
    var c = in.read()
    while (c >= 0 && c != '\n') {
      if (out.size() >= limit) throw new IOException("response header line is too long")
      if (c != '\r') out.write(c)
      c = in.read()
    }
    if (c < 0 && out.size() == 0) throw new IOException("the connection closed before a response")
    new String(out.toByteArray, StandardCharsets.ISO_8859_1)
  }

  private def readStatus(in: InputStream): Int = {
    val line = readLine(in, 8 * 1024)
    val parts = line.split(" ", 3)
    if (parts.length < 2 || !parts(0).toUpperCase.startsWith("HTTP/"))
      throw new IOException("the response is not HTTP")
    try parts(1).toInt catch {
      case _: NumberFormatException => throw new IOException("the response has no status code")
    }
  }

  private def readHeaders(in: InputStream): Map[String, String] = {
    var headers = Map.empty[String, String]
    var total = 0
    var lines = 0
    var line = readLine(in, 8 * 1024)
    while (line.nonEmpty) {
      total += line.length
      lines += 1
      if (total > MaxHeaderBytes || lines > MaxHeaderLines)
        throw new IOException("the response headers are too large")
      val i = line.indexOf(':')
      if (i > 0) headers += line.substring(0, i).trim.toLowerCase -> line.substring(i + 1).trim
      line = readLine(in, 8 * 1024)
    }
    headers
  }

  private def readBody(in: InputStream, headers: Map[String, String], maxBytes: Int): String = {
    val chunked = headers.get("transfer-encoding").exists(_.toLowerCase.contains("chunked"))
    val out = new ByteArrayOutputStream()
    if (chunked) {
      var size = parseChunkSize(readLine(in, 1024))
      while (size > 0 && out.size() < maxBytes) {
        copy(in, out, size, maxBytes)
        readLine(in, 1024) // the CRLF after the chunk
        size = parseChunkSize(readLine(in, 1024))
      }
    } else {
      val declared = headers.get("content-length").flatMap(v => scala.util.Try(v.toLong).toOption)
      val want = declared.map(d => math.min(d, maxBytes.toLong)).getOrElse(maxBytes.toLong)
      copy(in, out, want, maxBytes)
    }
    new String(out.toByteArray, StandardCharsets.UTF_8)
  }

  private def parseChunkSize(line: String): Long =
    try java.lang.Long.parseLong(line.trim.takeWhile(_ != ';').trim, 16)
    catch { case _: Exception => 0L }

  private def copy(in: InputStream, out: ByteArrayOutputStream, want: Long, maxBytes: Int): Unit = {
    val buf = new Array[Byte](8192)
    var remaining = want
    var n = 0
    while (remaining > 0 && out.size() < maxBytes && { n = in.read(buf, 0, math.min(buf.length.toLong, remaining).toInt); n } >= 0) {
      val take = math.min(n, maxBytes - out.size())
      out.write(buf, 0, take)
      remaining -= n
    }
  }
}
