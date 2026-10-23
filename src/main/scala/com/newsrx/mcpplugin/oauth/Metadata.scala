package com.newsrx.mcpplugin.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode

/**
 * The discovery documents, and the challenge that points at them.
 *
 * These describe only what is implemented. A metadata document is a promise a
 * client acts on without asking again: advertising `plain` PKCE, a
 * registration endpoint or an OIDC scope that does not work produces a client
 * that fails later, further from the cause, with a worse error.
 */
object Metadata {

  /**
   * RFC 9728 protected resource metadata, served at
   * `/.well-known/oauth-protected-resource`.
   */
  def protectedResource(mapper: ObjectMapper, config: OAuthConfig): ObjectNode = {
    val n = mapper.createObjectNode()
    n.put("resource", config.resource)
    val servers = mapper.createArrayNode()
    servers.add(config.issuer)
    n.set[ObjectNode]("authorization_servers", servers)
    val scopes = mapper.createArrayNode()
    McpScope.all.foreach(s => scopes.add(s.name))
    n.set[ObjectNode]("scopes_supported", scopes)
    val methods = mapper.createArrayNode()
    methods.add("header")
    n.set[ObjectNode]("bearer_methods_supported", methods)
    n
  }

  /**
   * RFC 8414 authorization server metadata, served at
   * `/.well-known/oauth-authorization-server`.
   */
  def authorizationServer(mapper: ObjectMapper, config: OAuthConfig): ObjectNode = {
    val n = mapper.createObjectNode()
    n.put("issuer", config.issuer)
    n.put("authorization_endpoint", config.authorizationEndpoint)
    n.put("token_endpoint", config.tokenEndpoint)
    n.put("revocation_endpoint", config.revocationEndpoint)

    array(mapper, n, "response_types_supported", Seq("code"))
    array(mapper, n, "response_modes_supported", Seq("query"))
    array(mapper, n, "grant_types_supported", Seq("authorization_code", "refresh_token"))
    // S256 only. The absence of "plain" is the point, not an omission.
    array(mapper, n, "code_challenge_methods_supported", Seq("S256"))
    array(mapper, n, "scopes_supported", McpScope.all.map(_.name))
    // Public clients proving possession with PKCE; no client secret exists to
    // present, so "none" is the honest value rather than a weaker default.
    array(mapper, n, "token_endpoint_auth_methods_supported", Seq("none"))
    array(mapper, n, "revocation_endpoint_auth_methods_supported", Seq("none"))

    // RFC 9207: the authorization response carries `iss`, so a client can tell
    // which server answered and cannot be fed a response from another one.
    n.put("authorization_response_iss_parameter_supported", true)
    // The client_id is an HTTPS URL serving the client's own metadata; there
    // is no registration step and therefore no registration_endpoint.
    n.put("client_id_metadata_document_supported", true)
    n
  }

  /**
   * The `WWW-Authenticate` value for a 401 from the resource server
   * (RFC 9728 §5.1), which is how a client discovers where to authenticate
   * when it did not look first.
   *
   * The reason is a [[ChallengeError]] rather than a string, so nothing a
   * caller sent can reach a response header. Sanitising caller text would
   * also work and is worse: it is a blacklist, it has to stay correct as the
   * header grammar grows, and it still copies an attacker's words into a
   * response other software may log or parse.
   */
  def challenge(config: OAuthConfig, error: Option[ChallengeError] = None): String = {
    val metadataUrl = s"${config.baseUrl}/.well-known/oauth-protected-resource"
    val parts = Seq(
      Some(s"""resource_metadata="$metadataUrl""""),
      error.map(e => s"""error="${e.code}""""),
      error.map(e => s"""error_description="${e.description}"""")
    ).flatten
    s"Bearer ${parts.mkString(", ")}"
  }

  private def array(mapper: ObjectMapper, parent: ObjectNode, field: String, values: Seq[String]): Unit = {
    val arr = mapper.createArrayNode()
    values.foreach(arr.add)
    parent.set[ObjectNode](field, arr)
  }
}
