# Authentication

The MCP endpoint accepts two authentication methods. Both resolve to a real
GitBucket account, and neither grants anything that account does not already
have.

| Method | For | State |
| --- | --- | --- |
| HTTP Basic | clients that can send a username and password or personal access token, such as Claude Desktop | supported |
| OAuth 2.1 Bearer | clients that require a browser authorization flow, such as ChatGPT | this document |

## Why the plugin is also the authorization server

GitBucket is **not** an OAuth authorization server. It ships
`AccessToken`/`AccessTokenService` — personal access tokens, stored as a hash —
and session authenticators, but no authorization endpoint, no token endpoint,
no client registry and no key set. Its OAuth support is as a *client*, for
signing users in from an external provider. Verified against the published
artifacts rather than assumed.

So an authorization server has to come from somewhere, and there are two
honest options.

**An external authorization server** (Keycloak, Authentik, a hosted IdP). This
can be done safely: the mapping from the external subject to a GitBucket
account is an explicit, administrator-established binding on
`(issuer, subject)`, stored and verified, and an identity provider that
GitBucket already trusts for sign-in is a reasonable thing to trust for
authorization too. Matching on email is not the only option and is not what
makes this approach hard.

What makes it hard is operational. It is a second service to deploy, operate,
upgrade and back up; it needs its own availability story, because the MCP
endpoint stops authenticating when it is down; and the binding table has to be
populated and maintained by hand for every user, which is work an
administrator does before anyone can connect. For a plugin whose premise is
"no separate service or proxy required", that cost falls on every deployment
to serve a case most of them do not have. Rejected on those grounds, and
recorded here so the choice is visible rather than implied. A deployment that
already runs an IdP and wants it to own MCP authorization is a reasonable
future option, not a contradiction of this one.

**The plugin acts as the authorization server**, authenticating the resource
owner with the GitBucket session the user already has. No new identity store,
no account linking, no second service. The resource owner is a GitBucket
account by construction, because the only way to reach the consent screen is
to be signed in to GitBucket. Chosen.

The cost of that choice is honest too: this plugin then owns authorization
codes, tokens and consent records, and owns their security properties. The
rest of this document is about those properties.

## What is a dependency and what is ours

The protocol types come from **`com.nimbusds:oauth2-oidc-sdk`**, Apache-2.0,
which GitBucket already carries on its runtime classpath for its own OpenID
Connect sign-in. It is therefore a `compileOnly` dependency and is **not**
bundled into the plugin JAR: no duplicate classes, no version skew with the
host, no growth in the artifact. Pinned at 11.33, the version shipped by the
oldest supported GitBucket, so only API present across the whole tested range
is used.

| Supplied by the library | Implemented here |
| --- | --- |
| PKCE: verifier syntax, S256 computation (`CodeVerifier`, `CodeChallenge`) | the policy that S256 is the only accepted method |
| RFC 8414 authorization server metadata: field names, JSON shape | the values in it, and the claim that each one is true |
| Authorization and token request parsing, error objects, token responses, revocation requests | which requests are honoured, and every decision about whether to honour one |
| `ClientID`, `Scope`, `State`, `AuthorizationCode`, `BearerAccessToken` types | the storage, lifetime, binding and rotation of everything they name |
| — | RFC 9728 protected resource metadata, which has no type in the shipped SDK version |
| — | the `WWW-Authenticate` challenge |
| — | consent, CSRF, GitBucket account resolution, scope enforcement, the CIMD fetcher and its SSRF controls, and the schema |

Randomness and hashing are the JDK's `SecureRandom` and `MessageDigest`. No
cryptography is implemented here, and nothing in the table's right-hand column
is described anywhere in this repository as coming from the library.

## Boundaries

| Role | Where it lives |
| --- | --- |
| MCP resource server | the existing `/plugin-mcp/` endpoint, now also accepting `Authorization: Bearer` |
| Authorization server | this plugin, at its own endpoints |
| Resource owner authentication | GitBucket's own session — the plugin never sees a password |
| Account resolution | the signed-in GitBucket account, carried on the grant |
| Repository authorization | unchanged: GitBucket's `hasGuestRole` / `hasDeveloperRole`, per request |
| Persistent state | plugin-owned tables, created by a Solidbase migration |

Effective access is the **intersection** of the granted scope and the account's
current GitBucket permissions. A token is never sufficient on its own: every
tool still runs the same repository guard it runs under Basic authentication,
so a grant issued yesterday cannot outlive a role removed today.

## Registration: client ID metadata documents

ChatGPT supports three registration mechanisms. This plugin implements one.

- **CIMD** — the client's `client_id` is an HTTPS URL serving its own metadata.
  Nothing is registered and nothing is stored. Implemented.
- **Dynamic client registration** (RFC 7591) — requires an open registration
  endpoint and a client table. Not implemented: it is a larger attack surface
  for a self-hosted server, and CIMD covers the client this work targets.
- **Pre-registration** — an administrator pastes a client ID and secret.
  Not implemented.

Fetching a metadata document means the server makes an outbound request to a
URL a caller supplied, which is a server-side request forgery primitive if it
is done carelessly. The fetcher is therefore bounded: HTTPS only, a response
size and time limit, no redirects followed to a different host, and private,
loopback and link-local address ranges refused after DNS resolution.

## Tokens

Access tokens are opaque, generated from a cryptographic random source and
stored as a SHA-256 hash, in the same spirit as GitBucket's own personal
access tokens. They are not self-contained.

That is a deliberate trade. A signed self-contained token needs no storage and
no lookup, but it also cannot be revoked before it expires — revocation
latency becomes the token lifetime. An opaque token costs one indexed lookup
per request and gives **immediate** revocation, which is the property that
matters when a grant is withdrawn or an account is disabled.

| Credential | Lifetime | Revocation |
| --- | --- | --- |
| authorization code | 60 seconds, single use | consumed atomically |
| access token | 1 hour | immediate |
| refresh token | 30 days, rotated on use | immediate; reuse of a rotated token revokes the whole grant |

Reuse detection applies to races as well as to theft, because the server
cannot tell them apart. If a client presents the same refresh token twice at
once, one request rotates it and the other sees a token that has already been
rotated — which is exactly what a stolen copy looks like — so the grant is
revoked and **neither** request comes away with a usable credential. A client
must therefore serialise its refreshes. This is what OAuth 2.1 asks for, and
it is tested against two real connections rather than assumed.

Expiry is treated differently on purpose. An expired refresh token is refused
but does **not** revoke the grant: that is the client being slow, not a
credential being somewhere it should not be.

## Scopes

| Scope | Grants |
| --- | --- |
| `mcp:read` | the read-only tools |
| `mcp:write` | the mutating tools, in addition to `mcp:read` |

Every tool declares which one it needs, as an abstract member, so a tool that
forgets to declare does not compile rather than defaulting to the weaker
requirement. A read grant cannot mutate: the scope check happens before the
tool runs, and the repository guard still happens inside it.

OIDC scopes (`openid`, `email`, `profile`) and a UserInfo endpoint are **not**
implemented, and the metadata does not advertise them. They are only needed
for workspace domain restrictions, and advertising a capability that is not
implemented is worse than not having it.

## What the metadata says is what exists

The discovery documents describe only implemented behaviour. In particular
`code_challenge_methods_supported` lists `S256` and nothing else, because the
plain method is not accepted; `grant_types_supported` lists only
`authorization_code` and `refresh_token`; and no `registration_endpoint` is
published, because dynamic registration is not implemented.

## Tested versions

Compiled, and the unit suite executed, against the runtime classpaths of
GitBucket **4.46.0**, **4.47.0** and **4.48.0**, each with the
`oauth2-oidc-sdk` version that release ships (11.33 for 4.46.0, 11.38.2 for
the other two). Those three are what has been run; versions between or beyond
them are untested rather than known-good.

## Configuration

The canonical resource URL is configured explicitly. It is **not** derived
from the `Host` header or from `X-Forwarded-*`, because those are attacker-
controlled on a reverse-proxied deployment and a resource identifier that
moves with the request is not an audience binding. A deployment behind a proxy
or in a servlet context path sets the external URL once; everything else —
issuer, endpoints, the `resource` value in tokens — is derived from it.
