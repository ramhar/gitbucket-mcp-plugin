# Installing on a GitBucket instance

Generic runbook. It names no particular instance: substitute your own host,
account and `GITBUCKET_HOME`. For what the plugin requires, which GitBucket
versions have been tested and what has not been tried, see
[README.md](README.md) and [docs/authentication.md](docs/authentication.md);
this page is only the mechanics of getting the JAR in place.

## 1. Build

```bash
./gradlew shadowJar
```

Produces `build/libs/gitbucket-mcp-plugin-<version>.jar`.

## 2. Install

Copy the JAR into the target GitBucket's plugin directory:

```bash
cp build/libs/gitbucket-mcp-plugin-<version>.jar "$GITBUCKET_HOME/plugins/"
```

GitBucket runs a `PluginWatchThread` over that directory and reloads on file
creation, so a restart is not always required:

```
INFO  g.core.plugin.PluginWatchThread - ENTRY_CREATE: gitbucket-mcp-plugin-<version>.jar
INFO  g.core.plugin.PluginWatchThread - Reloading plugins...
INFO  g.core.plugin.PluginRegistry - Initialize gitbucket-mcp-plugin-<version>.jar
INFO  g.core.plugin.PluginWatchThread - Reloading finished.
```

Prefer a restart when **replacing** an installed version: the plugin's
database migration runs from the loaded `Plugin` class's declared versions,
and `itest/upgrade_gate.py` is what exercises install, replacement, migration
and restart as a sequence.

## 3. Verify

```bash
curl http://<host>/plugin-mcp/health
# {"status":"ok","protocol":"MCP","transport":"Streamable HTTP"}
```

Then the MCP handshake. HTTP Basic takes a GitBucket account's own
credentials and needs no configuration:

```bash
curl -u <user>:<password> \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}' \
  http://<host>/plugin-mcp/
```

The `serverInfo.version` in the reply comes from the descriptor packaged in
the installed JAR, so it is the way to confirm *which* artifact is running.
`tools/list` then enumerates the tools, each with the scope it requires.

For the browser authorization flow, set the external base URL — OAuth stays
off until you do, and nothing else changes:

```bash
-Dgitbucket.mcp.oauth.baseUrl=https://<your-gitbucket>
```

[docs/authentication.md](docs/authentication.md) covers what that value
governs and why it is not taken from a request header.

## Before deploying anywhere shared

- Identify the exact artifact. Verify the JAR's checksum against the build it
  came from, after copying it onto the target.
- Run the gates against a **disposable** instance, never a shared one: they
  create accounts and repositories and deliberately attempt refused writes.
  See [itest/README.md](itest/README.md).
- Untested configurations are listed in [README.md](README.md) — among them
  TLS termination by a reverse proxy, GitBucket's LDAP authentication, and
  interaction with plugins beyond the bundled ones. Untested is not the same
  as known-broken, but it is not evidence either.
