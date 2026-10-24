# Live-instance integration gate

The offline suites under `src/test` replace GitBucket's storage and role
predicates, so they establish tool wiring and policy branching but not
GitBucket's own role computation, its SQL or the HTTP transport. This harness
closes that gap: it drives the deployed plugin over `/plugin-mcp/` with real
credentials, on a disposable GitBucket, and cross-checks every answer against
GitBucket's own REST API, its web routes and Git.

**It must never be pointed at a GitBucket that holds anything real.** It
creates accounts, repositories, issues, comments and merges, and it deliberately
attempts refused writes. `fixtures.py` assumes a blank instance.

## Running it

A disposable GitBucket 4.48.0 on `127.0.0.1:8099`, with this plugin installed
and an empty `GITBUCKET_HOME`:

```sh
java -jar gitbucket.war --port=8099 --host=127.0.0.1 --gitbucket.home=/tmp/gb-itest
# drop the plugin JAR into /tmp/gb-itest/plugins/ and restart
MCP_PLUGIN_JAR=/tmp/gb-itest/plugins/gitbucket-mcp-plugin-*.jar python3 itest/integration.py
```

`MCP_PLUGIN_JAR` is required, not optional. The gate compares the version the
plugin reports with the descriptor packaged in that JAR; checking it against a
literal written here would re-introduce exactly the defect the descriptor
lookup exists to prevent, and would quietly encode one fork's version number.
An unset or unreadable path is exit 2, like every other precondition.

`oauth_controls.py` is a second gate over the same instance, covering the
OAuth flow. It needs two more system properties on the GitBucket command
line, because the plugin publishes its identifiers from a configured base URL
and because a client metadata document served from this machine is on a
loopback address the fetcher refuses by default:

```sh
java -Dgitbucket.mcp.oauth.baseUrl=http://localhost:8099 \
     -Dgitbucket.mcp.oauth.allowLoopbackClients=true \
     -jar gitbucket.war --port=8099 --host=127.0.0.1 --gitbucket.home=/tmp/gb-itest
python3 itest/oauth_controls.py
```

Use `localhost` for the browser part and `127.0.0.1` for the REST control
calls, as the files do: the consent form's action is built from the
configured base URL, so the session cookie has to live on that host name.

## Installation and upgrade

`upgrade_gate.py` is different from the two above: it starts and stops its own
GitBucket processes rather than talking to one you started, because what it
checks is startup, migration and restart.

```sh
python3 itest/upgrade_gate.py \
  --war gitbucket.war \
  --previous <the plugin being replaced>.jar \
  --candidate build/libs/gitbucket-mcp-plugin-*.jar \
  --home /tmp/gb-upgrade
```

Add `--db-url jdbc:postgresql://host:port/db --db-user … --db-password …` to
run the whole sequence against PostgreSQL. Without it the bundled H2 is used,
and the PostgreSQL path remains generated DDL rather than an executed
migration.

It refuses to start if something else is already serving the port: a leftover
server answers health checks and would otherwise be mistaken for the artifact
under test. It stops every process it started, including when it aborts.

## The repository listing

`repo_list_gate.py` checks the listing's counters against GitBucket's own REST
API rather than against the plugin's other answers, because the original
defect made two plugin answers disagree and comparing them to each other would
have been the only way to see it. Its fixture holds a repository with real
issues and a pull request, one that is legitimately empty, a private one, and
a real fork, so a correct zero is distinguishable from an unpopulated field.

```sh
python3 itest/repo_list_gate.py
```

`oauth_gate.py` holds the flow helpers — a local HTTP server that publishes
client metadata documents, PKCE, a non-following HTTP client so redirects are
inspected rather than followed, and the walk through the real consent screen.
`oauth_controls.py` holds the controls themselves.

Committed effects are observed by asking again rather than by reading the
tables. After a refusal that must change nothing, the lawful operation is
performed next and has to succeed; after a replay that must revoke, a fresh
authorization check has to refuse. That is the property the server actually
has to provide, and it is taken on a connection the first request did not
use.

It needs only the standard library and `git`. It writes nothing outside a
directory from `tempfile.mkdtemp()`, which it removes on exit. Exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | every check ran and passed |
| 1 | a check failed |
| 2 | **the gate could not be run** — a precondition failed, a comparison lost its input, or fewer than 200 checks executed. No result may be read from the run. |

`BASE` and the account passwords are at the top of `mcp.py`. They are
throwaway credentials for a throwaway instance; do not reuse them anywhere.

## Nothing here may be skipped

The two defects this harness was corrected for were both *skips*, not wrong
answers: a precondition that failed quietly, and a comparison whose input went
missing. A green run proved nothing about either, because a skipped check
reports nothing at all. So:

- every setup step goes through `checks.require_ok`, which raises. `fixtures.py`
  verifies that collaborators were actually added, that `issuesOption` and
  `isPrivate` read *back* from storage, that the fork's inherited roles were
  actually removed, and that every Git command exited zero;
- the web merge route is a fixture, not an inline step, so a creation failure
  stops the run instead of skipping the only check of the commit-id recording
  path;
- pull request comparisons go through `checks.require_same_set`, which fails on
  a partial or empty set rather than comparing the intersection;
- GitBucket's own verdict goes through `checks.native_decision`, which accepts
  200/401/403 and raises on anything else. A 5xx is not a refusal: reading it as
  one lets a broken control agree with any answer;
- the stored-state witness for a write goes through `observe.stored_issue_count`
  and `observe.observe_issue_write`, which require 200 **and** a JSON list.
  There is no sentinel for an unavailable read: it used to answer `-1`, so two
  failed reads cancelled into a delta of zero and a refused write was reported
  as having stored nothing. A successful empty list stays a lawful zero;
- timestamps go through `checks.require_iso_utc` and `checks.same_instant`,
  which compare the moment against GitBucket's own value instead of checking
  that a string is non-empty;
- the run aborts if fewer than 200 checks executed.

### Proving the guards fire

`python3 itest/selftest.py` runs 63 negative controls against those guards,
with no server and no network. Each asserts that a guard **raises** on the
input that used to be tolerated — an empty gateway list, a 500 from
GitBucket's own route, a failed collaborator addition, a `Date.toString`
timestamp, an unreadable stored-issue count — and that it does not raise on a
legitimate one.

Two of the bypasses were at the *call site* rather than in the helper, so these
controls drive the real code path with API doubles instead of testing a helper
alone. The stored-count section reproduces a worked counterexample: the
read answers 500 with an error object while the doubled tool refuses to its
caller and writes anyway, in three variants — read failing on the way in, read
failing only on the way out, and both reads working so the unintended insert
shows as a delta of 1.

End to end, `ITEST_BREAK` injects one of the same faults into a real run:

| `ITEST_BREAK` | Fault | Required outcome |
| --- | --- | --- |
| `native500` | GitBucket's own issue route answers 500 | abort, exit 2 |
| `webmerge` | the web merge route fails | abort, exit 2 |
| `prlist` | the gateway's pull request list comes back empty | abort, exit 2 |
| `storage` | the stored-issue count cannot be read | abort, exit 2 |

It is off unless the variable names a fault, and a run with it set announces
itself.

## What it covers

| Section | Checks |
| --- | --- |
| transport and identity | `whoami` per account, admin flag, wrong password and unknown account rejected at the transport, registry size over HTTP, descriptor version in `initialize` |
| read authorization | every read tool refused on a private repository without a role, hidden and absent indistinguishable, guest and site-admin access, public readable by any authenticated account, `list_repositories` filtered for the caller |
| issue-creation policy | the `issuesOption` × role × privacy matrix, each case witnessed by the stored issue count **and** compared with GitBucket's own `POST /api/v3/.../issues` verdict |
| issue round-trip | title and body stored byte for byte including Unicode and CRLF, attribution, close/reopen reaching GitBucket's store, a guest refused |
| commit identities | `head_sha` against `git rev-parse`, `merge_base_sha` against `git merge-base`, fork head repository, and the inherited coercion still live on read-only tools |
| `update_pull_request` | omitted-field preservation both ways, explicit clearing, empty title refused, guest and outsider refused, every refusal witnessed as unchanged storage |
| argument strictness | all eight malformed identifier forms against both mutating identifier sites, malformed and null bodies, each with a before/after snapshot of every pull request |
| comments | byte-exact storage, attribution, `total_count` against GitBucket's own count, bounded paging, non-overlap, full coverage, read and write authorization |
| `update_own_comment` | author edits byte-exactly; repository owner, site admin and unrelated account all refused; empty replacement refused; every malformed id refused; a state-change record refused |
| `mark_ready_for_review` | developer role required on the **head** repository of a fork and not the base, stale and malformed preconditions, idempotence, closed and merged refused, nothing but the draft flag changed |
| merged semantics | both of GitBucket's merge routes, `merged` / `merged_at` / `merged_by` / `merged_commit_ids` compared with GitBucket's own fields on every pull request |

## A note on the fork fixture

GitBucket copies a repository's collaborators when it is forked. A developer of
the base is therefore usually also a developer of the fork, which makes the
head-repository role check look like a no-op. `fixtures.py` removes the
inherited collaborators from the fork on purpose, so the distinction is
observable. Without that step the check passes for the wrong reason.
