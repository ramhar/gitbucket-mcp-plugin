# Authentication

The MCP endpoint accepts two authentication methods. Both resolve to a real
GitBucket account, and neither grants anything that account does not already
have.

| Method | For | State |
| --- | --- | --- |
| HTTP Basic | clients that can send a username and password or personal access token, such as Claude Desktop | supported |
| OAuth 2.1 Bearer | clients that require a browser authorization flow, such as ChatGPT | this document |

## Why the plugin is also the authorization server

GitBucket 4.46–4.48 is **not** an OAuth authorization server. It ships
`AccessToken`/`AccessTokenService` — personal access tokens, stored as a hash —
and session authenticators, but no authorization endpoint, no token endpoint,
no client registry and no key set. Its OAuth support is as a *client*, for
signing users in from an external provider. Verified against the published
4.48.0 artifact rather than assumed.

So an authorization server has to come from somewhere, and there are two
honest options.

**An external authorization server** (Keycloak, Authentik, a hosted IdP). This
is a second service to deploy, operate and back up, with its own user store.
Worse, it reintroduces the problem this plugin exists to avoid: the external
server's subject is not a GitBucket account, so something has to map one to
the other, and the only cheap mapping — matching an email address — is exactly
the unverified link that turns an identity provider into a privilege
escalation. Rejected, but recorded here so the choice is visible rather than
implied.

**The plugin acts as the authorization server**, authenticating the resource
owner with the GitBucket session the user already has. No new identity store,
no account linking, no second service. The resource owner is a GitBucket
account by construction, because the only way to reach the consent screen is
to be signed in to GitBucket. Chosen.

The cost of that choice is honest too: this plugin then owns authorization
codes, tokens and consent records, and owns their security properties. The
rest of this document is about those properties.

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

## Configuration

The canonical resource URL is configured explicitly. It is **not** derived
from the `Host` header or from `X-Forwarded-*`, because those are attacker-
controlled on a reverse-proxied deployment and a resource identifier that
moves with the request is not an audience binding. A deployment behind a proxy
or in a servlet context path sets the external URL once; everything else —
issuer, endpoints, the `resource` value in tokens — is derived from it.
