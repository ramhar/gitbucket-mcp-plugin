package com.newsrx.mcpplugin.oauth

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/**
 * Proof Key for Code Exchange, S256 only (RFC 7636).
 *
 * The `plain` method is not accepted and is not advertised. It protects
 * against nothing an attacker who can read the authorization response cannot
 * also do, and offering it invites a downgrade: a client that can be talked
 * into sending `code_challenge_method=plain` has no protection at all.
 */
object Pkce {

  /** RFC 7636 §4.1: 43–128 characters from the unreserved set. */
  private val VerifierPattern = "^[A-Za-z0-9\\-._~]{43,128}$".r

  /** A challenge is the base64url-no-padding SHA-256 of the verifier. */
  def challengeFor(verifier: String): String = {
    val digest = MessageDigest.getInstance("SHA-256")
      .digest(verifier.getBytes(StandardCharsets.US_ASCII))
    Base64.getUrlEncoder.withoutPadding.encodeToString(digest)
  }

  def isWellFormedVerifier(verifier: String): Boolean =
    verifier != null && VerifierPattern.pattern.matcher(verifier).matches()

  /**
   * Whether `verifier` proves possession of the key behind `challenge`.
   *
   * The comparison is constant-time. A challenge is not a secret, so this is
   * belt-and-braces rather than load-bearing, but the same helper is used for
   * values that are secret and a single comparison routine is easier to keep
   * right than two.
   */
  def verify(verifier: String, challenge: String): Boolean = {
    if (!isWellFormedVerifier(verifier) || challenge == null || challenge.isEmpty) false
    else constantTimeEquals(challengeFor(verifier), challenge)
  }

  def constantTimeEquals(a: String, b: String): Boolean = {
    val x = a.getBytes(StandardCharsets.UTF_8)
    val y = b.getBytes(StandardCharsets.UTF_8)
    // MessageDigest.isEqual is constant-time for equal-length inputs and
    // short-circuits only on length, which is not secret here.
    MessageDigest.isEqual(x, y)
  }
}
