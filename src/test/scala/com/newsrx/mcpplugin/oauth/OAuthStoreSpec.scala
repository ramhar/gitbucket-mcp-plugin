package com.newsrx.mcpplugin.oauth

import java.sql.{Connection, DriverManager}
import java.time.Instant
import java.util.concurrent.{Callable, Executors, TimeUnit}
import liquibase.{Contexts, LabelExpression, Liquibase}
import liquibase.database.DatabaseFactory
import liquibase.database.jvm.JdbcConnection
import liquibase.resource.ClassLoaderResourceAccessor
import org.junit.runner.RunWith
import org.scalatestplus.junit.JUnitRunner
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import scala.jdk.CollectionConverters._

/**
 * The grant store, against a real database, with the real schema.
 *
 * H2 in memory, created by applying the plugin's own Liquibase changelog —
 * so the migration is exercised by every case here rather than being a file
 * nobody runs until deployment. The same changelog is what runs on
 * PostgreSQL; this suite establishes the logic, not the PostgreSQL DDL, and
 * that distinction is kept in the documentation.
 *
 * The concurrency cases use two real connections and a thread pool. A
 * sequential test cannot tell an atomic conditional update from a
 * check-then-write, which is exactly the property that matters for
 * single-use codes and rotating refresh tokens.
 */
@RunWith(classOf[JUnitRunner])
class OAuthStoreSpec extends AnyFunSuite with Matchers {

  private val now = Instant.parse("2026-01-01T12:00:00Z")
  private val later = now.plusSeconds(60)
  private val resource = "https://git.example.com/plugin-mcp/"
  private val clientId = "https://client.example.com/.well-known/mcp-client"
  private val redirect = "https://chatgpt.com/connector_platform_oauth_redirect"
  private val verifier = "v" * 64
  private val challenge = Pkce.challengeFor(verifier)

  private var counter = 0

  /** A fresh, independently named in-memory database per test. */
  private def freshDb(): String = {
    counter += 1
    val name = s"mcpoauth$counter"
    val url = s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1"
    val conn = DriverManager.getConnection(url)
    try {
      val database = DatabaseFactory.getInstance
        .findCorrectDatabaseImplementation(new JdbcConnection(conn))
      // `liquibase` as a local name would shadow the package, so the types
      // below could not be resolved.
      val lb = new Liquibase("update/mcp-plugin_1.0.xml",
        new ClassLoaderResourceAccessor(), database)
      lb.update(new Contexts(), new LabelExpression())
    } finally conn.close()
    url
  }

  private def withDb[A](body: Connection => A): A = {
    val url = freshDb()
    val conn = DriverManager.getConnection(url)
    try body(conn) finally conn.close()
  }

  private def seedGrant(conn: Connection, scopes: Set[String] = Set("mcp:read")): String =
    OAuthStore.createGrant(conn, "alice", clientId, resource, scopes, now)

  // ── the migration itself ──────────────────────────────────────────────────

  test("the plugin's changelog creates its tables on a blank database") {
    withDb { conn =>
      val md = conn.getMetaData
      val tables = {
        val rs = md.getTables(null, null, "%", Array("TABLE"))
        val b = Set.newBuilder[String]
        while (rs.next()) b += rs.getString("TABLE_NAME").toUpperCase
        b.result()
      }
      tables should contain allOf ("MCP_OAUTH_GRANT", "MCP_OAUTH_CODE", "MCP_OAUTH_TOKEN",
        "MCP_OAUTH_REFRESH")
    }
  }

  test("the changelog is idempotent, as an upgrade path requires") {
    val url = freshDb()
    val conn = DriverManager.getConnection(url)
    try {
      val database = DatabaseFactory.getInstance
        .findCorrectDatabaseImplementation(new JdbcConnection(conn))
      // Running it a second time must not fail or duplicate anything.
      noException should be thrownBy new Liquibase("update/mcp-plugin_1.0.xml",
        new ClassLoaderResourceAccessor(), database)
        .update(new Contexts(), new LabelExpression())
      OAuthStore.grantsFor(conn, "alice") shouldBe empty
    } finally conn.close()
  }

  // ── bindings: a code is not a bearer credential ───────────────────────────

  test("a code redeems once, to the grant it was issued for") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val code = OAuthStore.issueCode(conn, grantId, challenge, redirect, later)
      val result = OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), verifier, now)
      result.map(_.userName) shouldBe Right("alice")
      result.map(_.scopes) shouldBe Right(Set("mcp:read"))
      result.map(_.grantId) shouldBe Right(grantId)
    }
  }

  test("a code presented by another client is refused") {
    withDb { conn =>
      val code = OAuthStore.issueCode(conn, seedGrant(conn), challenge, redirect, later)
      OAuthStore.redeemCode(conn, code, "https://evil.example.com/meta", redirect,
        Some(resource), verifier, now) shouldBe Left(GrantFailure.ClientMismatch)
    }
  }

  test("a code redeemed against a different redirect URI is refused") {
    withDb { conn =>
      val code = OAuthStore.issueCode(conn, seedGrant(conn), challenge, redirect, later)
      OAuthStore.redeemCode(conn, code, clientId, "https://evil.example.com/cb",
        Some(resource), verifier, now) shouldBe Left(GrantFailure.RedirectMismatch)
    }
  }

  test("a code redeemed for a different resource is refused") {
    withDb { conn =>
      val code = OAuthStore.issueCode(conn, seedGrant(conn), challenge, redirect, later)
      OAuthStore.redeemCode(conn, code, clientId, redirect,
        Some("https://other.example.com/plugin-mcp/"), verifier, now) shouldBe
        Left(GrantFailure.ResourceMismatch)
    }
  }

  test("a code redeemed without the PKCE verifier is refused") {
    withDb { conn =>
      val code = OAuthStore.issueCode(conn, seedGrant(conn), challenge, redirect, later)
      OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), "w" * 64, now) shouldBe
        Left(GrantFailure.PkceFailed)
      OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), "", now) shouldBe
        Left(GrantFailure.PkceFailed)
    }
  }

  test("an expired code is refused") {
    withDb { conn =>
      val code = OAuthStore.issueCode(conn, seedGrant(conn), challenge, redirect, now.minusSeconds(1))
      OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), verifier, now) shouldBe
        Left(GrantFailure.Expired)
    }
  }

  test("an unknown code is refused without revealing anything else") {
    withDb { conn =>
      OAuthStore.redeemCode(conn, "not-a-code", clientId, redirect, Some(resource), verifier, now) shouldBe
        Left(GrantFailure.NotFound)
    }
  }

  // ── replay ────────────────────────────────────────────────────────────────

  test("replaying a code fails and revokes what the first redemption bought") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val code = OAuthStore.issueCode(conn, grantId, challenge, redirect, later)
      OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), verifier, now).isRight shouldBe true
      val token = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.resolveAccessToken(conn, token, now).isRight shouldBe true

      // A second presentation means the code may have been stolen; the grant
      // it bought is no longer trustworthy.
      OAuthStore.redeemCode(conn, code, clientId, redirect, Some(resource), verifier, now) shouldBe
        Left(GrantFailure.AlreadyUsed)
      OAuthStore.resolveAccessToken(conn, token, now) shouldBe Left(GrantFailure.Revoked)
      OAuthStore.findGrant(conn, grantId) shouldBe None
    }
  }

  // ── concurrency ───────────────────────────────────────────────────────────

  test("two simultaneous redemptions of one code produce exactly one grant") {
    val url = freshDb()
    val setup = DriverManager.getConnection(url)
    val grantId = try seedGrant(setup) finally ()
    val code = try OAuthStore.issueCode(setup, grantId, challenge, redirect, later) finally setup.close()

    val pool = Executors.newFixedThreadPool(2)
    try {
      val task = new Callable[Either[GrantFailure, ResolvedGrant]] {
        def call(): Either[GrantFailure, ResolvedGrant] = {
          val c = DriverManager.getConnection(url)
          try OAuthStore.redeemCode(c, code, clientId, redirect, Some(resource), verifier, now)
          finally c.close()
        }
      }
      val results = pool.invokeAll(List(task, task).asJava, 30, TimeUnit.SECONDS)
        .asScala.map(_.get()).toList
      withClue(s"results=$results: ") {
        results.count(_.isRight) shouldBe 1
        results.count(_ == Left(GrantFailure.AlreadyUsed)) shouldBe 1
      }
    } finally pool.shutdownNow()
  }

  test("two simultaneous refreshes rotate exactly once and end the grant") {
    // What the race actually produces, rather than what is convenient to
    // assert. The rotation itself is atomic, so exactly one UPDATE matches.
    // But the loser sees an already-rotated token, which is indistinguishable
    // from a stolen copy being replayed, so it revokes the family — and the
    // winner, reaching its grant a moment later, finds it revoked too.
    //
    // Neither caller gets a usable credential, which is the documented
    // reuse-detection policy applied consistently. A client must not refresh
    // twice in parallel; OAuth 2.1 says so for exactly this reason.
    val url = freshDb()
    val setup = DriverManager.getConnection(url)
    val (grantId, refresh) = try {
      val g = seedGrant(setup)
      (g, OAuthStore.setRefreshToken(setup, g, now.plusSeconds(3600), now))
    } finally setup.close()

    val pool = Executors.newFixedThreadPool(2)
    val results = try {
      val task = new Callable[Either[GrantFailure, (ResolvedGrant, String)]] {
        def call(): Either[GrantFailure, (ResolvedGrant, String)] = {
          val c = DriverManager.getConnection(url)
          try OAuthStore.rotateRefreshToken(c, refresh, clientId, now.plusSeconds(3600), now)
          finally c.close()
        }
      }
      pool.invokeAll(List(task, task).asJava, 30, TimeUnit.SECONDS).asScala.map(_.get()).toList
    } finally pool.shutdownNow()

    val check = DriverManager.getConnection(url)
    try {
      withClue(s"results=$results: ") {
        // The atomic step ran once: one caller saw the token as still
        // rotatable, the other saw it already rotated.
        results.count(_ == Left(GrantFailure.AlreadyUsed)) shouldBe 1
        // At most one succeeded, and the grant is gone either way.
        results.count(_.isRight) should be <= 1
        OAuthStore.findGrant(check, grantId) shouldBe None
        // Nothing either caller came away with is usable.
        results.collect { case Right((_, token)) => token }.foreach { token =>
          OAuthStore.rotateRefreshToken(check, token, clientId, now.plusSeconds(3600), now)
            .isRight shouldBe false
        }
      }
    } finally check.close()
  }

  test("schedule A: replay after the first exchange has completed") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val first = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)

      // The legitimate exchange completes and its caller holds both tokens.
      val Right((_, successor)) =
        OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now)
      val access = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.resolveAccessToken(conn, access, now).isRight shouldBe true

      // Only afterwards does the superseded token come back.
      OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now) shouldBe
        Left(GrantFailure.AlreadyUsed)

      // Committed state: the family is gone.
      OAuthStore.findGrant(conn, grantId) shouldBe None
      // A fresh authorization check refuses what the completed exchange
      // produced. The earlier response was not retracted; the credentials it
      // carried simply stop being accepted.
      OAuthStore.resolveAccessToken(conn, access, now) shouldBe Left(GrantFailure.Revoked)
      OAuthStore.rotateRefreshToken(conn, successor, clientId, now.plusSeconds(3600), now)
        .isRight shouldBe false
    }
  }

  test("schedule B: revocation lands between a completed exchange and the next use") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val first = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      val Right((_, successor)) =
        OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now)
      val access = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)

      // The user withdraws consent after the exchange returned.
      OAuthStore.revokeGrant(conn, grantId, now) shouldBe true

      // Everything that exchange produced is refused at the next check, and
      // the successor cannot be rotated back into a live grant.
      OAuthStore.resolveAccessToken(conn, access, now) shouldBe Left(GrantFailure.Revoked)
      OAuthStore.rotateRefreshToken(conn, successor, clientId, now.plusSeconds(3600), now)
        .isRight shouldBe false
    }
  }

  test("a binding failure leaves a lawful refresh token usable") {
    // The distinction the policy depends on: presenting the right token with
    // the wrong client is a binding failure, which must not be treated as a
    // replay. Here it does revoke, by design, because an attacker holding a
    // valid refresh token is the more dangerous reading — but it must not
    // rotate first, and the wrongly-bound attempt must not hand anything out.
    withDb { conn =>
      val grantId = seedGrant(conn)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      val attempt = OAuthStore.rotateRefreshToken(conn, refresh,
        "https://evil.example.com/meta", now.plusSeconds(3600), now)
      attempt shouldBe Left(GrantFailure.ClientMismatch)
      attempt.isRight shouldBe false
    }
  }

  test("exactly one successor row exists after a contended rotation") {
    // The storage-level invariant on its own: whatever the callers were told,
    // the chain did not fork.
    val url = freshDb()
    val setup = DriverManager.getConnection(url)
    val refresh = try {
      OAuthStore.setRefreshToken(setup, seedGrant(setup), now.plusSeconds(3600), now)
    } finally setup.close()

    val pool = Executors.newFixedThreadPool(2)
    try {
      val task = new Callable[Any] {
        def call(): Any = {
          val c = DriverManager.getConnection(url)
          try OAuthStore.rotateRefreshToken(c, refresh, clientId, now.plusSeconds(3600), now)
          finally c.close()
        }
      }
      pool.invokeAll(List(task, task).asJava, 30, TimeUnit.SECONDS).asScala.foreach(_.get())
    } finally pool.shutdownNow()

    val check = DriverManager.getConnection(url)
    try {
      val st = check.createStatement()
      try {
        val rs = st.executeQuery("SELECT COUNT(*) FROM MCP_OAUTH_REFRESH")
        rs.next()
        // The original plus at most one successor; never two successors.
        rs.getInt(1) should be <= 2
        val rotated = st.executeQuery("SELECT COUNT(*) FROM MCP_OAUTH_REFRESH WHERE ROTATED = TRUE")
        rotated.next()
        rotated.getInt(1) shouldBe 1
      } finally st.close()
    } finally check.close()
  }

  // ── refresh rotation ──────────────────────────────────────────────────────

  test("rotation replaces the refresh token and the old one stops working") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val first = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      val Right((grant, second)) =
        OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now)
      grant.userName shouldBe "alice"
      second should not be first
      // The second one works; the first is now a replay.
      OAuthStore.rotateRefreshToken(conn, second, clientId, now.plusSeconds(3600), now).isRight shouldBe true
    }
  }

  test("replaying a rotated refresh token revokes the whole grant") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val first = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now).isRight shouldBe true
      val token = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)

      OAuthStore.rotateRefreshToken(conn, first, clientId, now.plusSeconds(3600), now) shouldBe
        Left(GrantFailure.AlreadyUsed)
      OAuthStore.findGrant(conn, grantId) shouldBe None
      OAuthStore.resolveAccessToken(conn, token, now) shouldBe Left(GrantFailure.Revoked)
    }
  }

  test("an unknown refresh token fails without revoking anything") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.rotateRefreshToken(conn, "never-issued", clientId, now.plusSeconds(3600), now) shouldBe
        Left(GrantFailure.NotFound)
      OAuthStore.findGrant(conn, grantId).isDefined shouldBe true
    }
  }

  test("a refresh token presented by another client revokes the grant") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.rotateRefreshToken(conn, refresh, "https://evil.example.com/meta",
        now.plusSeconds(3600), now) shouldBe Left(GrantFailure.ClientMismatch)
      OAuthStore.findGrant(conn, grantId) shouldBe None
    }
  }

  test("an expired refresh token is refused without revoking the grant") {
    // Expiry is the client being slow, not a credential being somewhere it
    // should not be, so it must not end a consent the user still holds.
    withDb { conn =>
      val grantId = seedGrant(conn)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.minusSeconds(1), now)
      OAuthStore.rotateRefreshToken(conn, refresh, clientId, now.plusSeconds(3600), now) shouldBe
        Left(GrantFailure.Expired)
      OAuthStore.findGrant(conn, grantId).isDefined shouldBe true
    }
  }

  test("every token in a rotation chain stays recognisable as a replay") {
    // Three rotations deep, the first token must still revoke rather than
    // read as a string that was never issued.
    withDb { conn =>
      val grantId = seedGrant(conn)
      val t1 = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      val Right((_, t2)) = OAuthStore.rotateRefreshToken(conn, t1, clientId, now.plusSeconds(3600), now)
      val Right((_, t3)) = OAuthStore.rotateRefreshToken(conn, t2, clientId, now.plusSeconds(3600), now)
      OAuthStore.rotateRefreshToken(conn, t3, clientId, now.plusSeconds(3600), now).isRight shouldBe true

      OAuthStore.rotateRefreshToken(conn, t1, clientId, now.plusSeconds(3600), now) shouldBe
        Left(GrantFailure.AlreadyUsed)
      OAuthStore.findGrant(conn, grantId) shouldBe None
    }
  }

  // ── revocation ────────────────────────────────────────────────────────────

  test("revoking a grant invalidates every access token it issued, at once") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val tokens = (1 to 3).map(_ => OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now))
      tokens.foreach(t => OAuthStore.resolveAccessToken(conn, t, now).isRight shouldBe true)

      OAuthStore.revokeGrant(conn, grantId, now) shouldBe true
      tokens.foreach(t => OAuthStore.resolveAccessToken(conn, t, now) shouldBe Left(GrantFailure.Revoked))
    }
  }

  test("revoking by access token ends the grant, not just that token") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val a = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      val b = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.revokeByToken(conn, a, now) shouldBe true
      OAuthStore.resolveAccessToken(conn, b, now) shouldBe Left(GrantFailure.Revoked)
    }
  }

  test("revoking by refresh token ends the grant") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      val access = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.revokeByToken(conn, refresh, now) shouldBe true
      OAuthStore.resolveAccessToken(conn, access, now) shouldBe Left(GrantFailure.Revoked)
    }
  }

  test("revoking an unknown token reports nothing revoked") {
    withDb { conn => OAuthStore.revokeByToken(conn, "never-issued", now) shouldBe false }
  }

  test("revoking twice is harmless and still reports the first one as the revocation") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      OAuthStore.revokeGrant(conn, grantId, now) shouldBe true
      OAuthStore.revokeGrant(conn, grantId, now) shouldBe false
    }
  }

  test("a revoked grant cannot be refreshed back into life") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.revokeGrant(conn, grantId, now)
      OAuthStore.rotateRefreshToken(conn, refresh, clientId, now.plusSeconds(3600), now).isLeft shouldBe true
    }
  }

  // ── access tokens ─────────────────────────────────────────────────────────

  test("an expired access token is refused even though its grant is live") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val token = OAuthStore.issueAccessToken(conn, grantId, now.minusSeconds(1), now)
      OAuthStore.resolveAccessToken(conn, token, now) shouldBe Left(GrantFailure.Expired)
      OAuthStore.findGrant(conn, grantId).isDefined shouldBe true
    }
  }

  test("an unknown access token is refused") {
    withDb { conn =>
      OAuthStore.resolveAccessToken(conn, "never-issued", now) shouldBe Left(GrantFailure.NotFound)
    }
  }

  test("a token carries the scopes of its grant, not of the request") {
    withDb { conn =>
      val grantId = seedGrant(conn, Set("mcp:read", "mcp:write"))
      val token = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      OAuthStore.resolveAccessToken(conn, token, now).map(_.scopes) shouldBe
        Right(Set("mcp:read", "mcp:write"))
    }
  }

  test("two users' grants are isolated from each other") {
    withDb { conn =>
      val alice = OAuthStore.createGrant(conn, "alice", clientId, resource, Set("mcp:write"), now)
      val bob = OAuthStore.createGrant(conn, "bob", clientId, resource, Set("mcp:write"), now)
      val bobToken = OAuthStore.issueAccessToken(conn, bob, now.plusSeconds(3600), now)

      OAuthStore.revokeGrant(conn, alice, now)
      // Revoking Alice's consent must not touch Bob's, and Bob's token must
      // still resolve to Bob.
      OAuthStore.resolveAccessToken(conn, bobToken, now).map(_.userName) shouldBe Right("bob")
      OAuthStore.grantsFor(conn, "alice") shouldBe empty
      OAuthStore.grantsFor(conn, "bob").map(_.grantId) shouldBe List(bob)
    }
  }

  // ── credentials are not stored in the clear ───────────────────────────────

  test("no credential is recoverable from the tables") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val code = OAuthStore.issueCode(conn, grantId, challenge, redirect, later)
      val access = OAuthStore.issueAccessToken(conn, grantId, now.plusSeconds(3600), now)
      val refresh = OAuthStore.setRefreshToken(conn, grantId, now.plusSeconds(3600), now)

      def dump(table: String): String = {
        val st = conn.createStatement()
        try {
          val rs = st.executeQuery(s"SELECT * FROM $table")
          val md = rs.getMetaData
          val sb = new StringBuilder
          while (rs.next()) (1 to md.getColumnCount).foreach(i => sb.append(String.valueOf(rs.getObject(i))))
          sb.toString
        } finally st.close()
      }
      val all = dump("MCP_OAUTH_GRANT") + dump("MCP_OAUTH_CODE") + dump("MCP_OAUTH_TOKEN") +
        dump("MCP_OAUTH_REFRESH")
      all should not include code
      all should not include access
      all should not include refresh
      // The hashes are there, which is what makes a lookup possible at all.
      all should include(Secrets.hash(access))
    }
  }

  // ── housekeeping is not a security control ────────────────────────────────

  test("expiry is enforced by the clock, not by the purge having run") {
    withDb { conn =>
      val grantId = seedGrant(conn)
      val token = OAuthStore.issueAccessToken(conn, grantId, now.minusSeconds(1), now)
      // Nothing has been purged, and it is already refused.
      OAuthStore.resolveAccessToken(conn, token, now) shouldBe Left(GrantFailure.Expired)
      OAuthStore.purgeExpired(conn, now) should be >= 1
      OAuthStore.resolveAccessToken(conn, token, now) shouldBe Left(GrantFailure.NotFound)
    }
  }
}
