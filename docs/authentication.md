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
size and time limit, redirects refused outright rather than followed, and
private, loopback, link-local, carrier-grade and multicast address ranges
refused after DNS resolution — every resolved address, not the first, and the
address of the established connection re-checked after connecting.

Redirects are refused rather than re-validated because an allowed host
bouncing to a forbidden one is the usual way such a fence is bypassed, and
there is no legitimate reason for a client's own metadata document to move.

One escape exists, off by default. `gitbucket.mcp.oauth.allowLoopbackClients`
permits a `client_id` on a loopback address, and opens **loopback only**: the
private, link-local, carrier-grade and multicast ranges stay forbidden with it
on. It exists because a developer running an MCP client on the same machine as
GitBucket otherwise cannot complete an authorization at all. A deployment that
never sets it behaves exactly as if it did not exist.

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
cannot tell them apart. A correctly bound refresh token presented a second
time is treated as reuse and the whole grant is revoked. Nothing about that
decision identifies the legitimate caller — the server has no way to do so,
which is precisely why reuse ends the family rather than being arbitrated.

The consequence is an interoperability requirement of this policy, and worth
stating plainly: **a client must serialise its refreshes.** If it presents the
same refresh token twice at once, one request rotates it and the other finds a
token that has already been rotated, the grant is revoked, and neither request
leaves the client with a credential it can keep using. That is what OAuth 2.1
asks for; it is a constraint on the client, not a claim about the server's
ability to tell two callers apart.

Three things are kept distinct, because they are often conflated:

- **The database transition.** One refresh credential cannot produce two
  independently valid successors, and the chain cannot fork. This holds under
  any scheduling and is asserted on stored state.
- **Replay handling.** A correctly bound second presentation revokes the
  grant, and that revocation is committed whatever the HTTP endpoint answers.
- **The HTTP result.** A response may already have completed before the
  revocation landed. It is not undone. The guarantee is stated where it holds:
  every *subsequent* authorization check refuses credentials from the revoked
  grant.

A **binding failure is not a replay.** Presenting a refresh token with the
wrong `client_id` is refused and changes nothing: it does not rotate the
token, does not revoke the grant, and the legitimate client's next refresh
still works. The client id is not a secret — anyone who learned a refresh
token could send it with any client id they liked, and treating that as
evidence of theft would hand an unauthenticated caller a way to destroy a
credential that is in legitimate use. The same holds for the authorization
code: a wrong client, redirect URI, resource or PKCE verifier is refused
without consuming the code.

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

## Storage

The four tables — grant, authorization code, refresh token, access token —
are created by the plugin's own schema migration, which GitBucket runs at
startup through Solidbase. Nothing needs to be created by hand, and an
existing installation of an earlier version of this plugin picks the migration
up on the next restart.

Two notes for anyone changing that migration. Its root element is a bare
`<changeSet>`, not a Liquibase `<databaseChangeLog>`: Solidbase supplies the
wrapper, the change set id and the author, and a file carrying its own root
parses as a nested changelog and is **skipped silently** — the plugin still
loads and the first request that needs a table fails. And the version list
has to be declared on the root-package class named `Plugin`, which is the one
GitBucket loads by name; it extends `MCPPlugin` so there is a single
declaration. Both failures happened here, and both are now covered by tests
that run the real mechanism rather than a convenient substitute.

## What has been tested

Compiled, and the unit suite executed, against the runtime classpaths of
GitBucket **4.46.0**, **4.47.0** and **4.48.0**, each with the
`oauth2-oidc-sdk` version that release ships (11.33 for 4.46.0, 11.38.2 for
the other two). Those three are what has been run; versions between or beyond
them are untested rather than known-good.

The flow itself is exercised over real HTTP against a disposable GitBucket
with the plugin installed: discovery, consent, approval, denial and CSRF
rejection, code exchange and every binding failure, refresh rotation and
replay, revocation, Bearer authentication, and tool calls through the
production dispatcher — with the effects read back from GitBucket's own REST
API rather than from the plugin's replies. Those controls are
`itest/oauth_controls.py`.

Installation, upgrade and restart are a separate gate again, because a
migration can be written, committed, tested against a database directly and
still never run: what executes is what the loaded `Plugin` class declares and
what Solidbase finds packaged in the JAR. `itest/upgrade_gate.py` starts real
GitBucket processes and checks the operator's questions — the previous
plugin runs, the candidate replaces it, the migration executes, data created
under the previous plugin survives, a grant issued after the upgrade survives
a restart, and a revocation performed before a restart is still in force
after it. That last one is what distinguishes persistence from a cache.

That gate has been run on **both** supported backends: the bundled H2, and
PostgreSQL 16, from a blank database through the pre-OAuth plugin to this
one. On PostgreSQL the four tables and the recorded module version were read
back from the database afterwards. The processes run with a non-UTC default
time zone on purpose — a UTC host is the configuration that once hid a
timestamp defect here.

One thing is still **not** established. Connecting a particular commercial
MCP client is its own gate: a client's behaviour is not the protocol, and raw
HTTP passing says nothing about whether, say, ChatGPT's connector accepts
this server.

### The guards have been shown to fail

A suite that passes says nothing until a broken implementation makes it fail.
Five single-line mutations of production source — the scope gate permitting
everything, a code's `redirect_uri` binding unchecked, a refresh token's
client binding unchecked, the SSRF fence opened, and PKCE accepted without
verification — each turn the suite red on the controls written for that
guard, and the source is restored byte-for-byte afterwards. The first of
those mutations originally left the suite green, which is how the scope gate
turned out to have no offline control at all; it has one now.

## Configuration

The canonical resource URL is configured explicitly. It is **not** derived
from the `Host` header or from `X-Forwarded-*`, because those are attacker-
controlled on a reverse-proxied deployment and a resource identifier that
moves with the request is not an audience binding. A deployment behind a proxy
or in a servlet context path sets the external URL once; everything else —
issuer, endpoints, the `resource` value in tokens — is derived from it.

| Property | Default | Effect |
| --- | --- | --- |
| `gitbucket.mcp.oauth.baseUrl` | unset | The external base URL. Unset, OAuth is off: discovery answers 404 and Bearer tokens are refused. Basic auth is unaffected. |
| `gitbucket.mcp.oauth.allowLoopbackClients` | `false` | Permits a `client_id` on a loopback address, and nothing else. |

`GITBUCKET_MCP_OAUTH_BASE_URL` is read if the system property is unset. The
URL must be `https://`, except on `localhost` or `127.0.0.1` where plain HTTP
is allowed so the suites can run, and it must carry no trailing slash, query
or fragment. A value that fails any of these is rejected with a reason rather
than normalised, and OAuth stays off — a bearer token on a cleartext
connection is a bearer token for whoever is on the path, and a base URL that
quietly becomes something else is not an audience binding.
