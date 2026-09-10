# Athena forwarding proxy

Status: proposed; not implemented.

## Decision

Forward Athena operations to AWS, adding proxy-monster authentication,
authorization, and response masking. Athena owns query execution, IDs, status,
cancellation, pagination, idempotency, and result storage. Do not implement a
second query service.

The control plane owns identity, Cedar decisions, SQL analysis, catalog policy,
and audit. The Go data plane forwards requests and applies those decisions. It
keeps only the enforcement context that Athena does not know.

Java JDBC, Node.js, Python, and other Athena clients use the same endpoint. This
is neither a JDBC adapter nor a MySQL/PostgreSQL facade.

## Forwarding

```text
Athena client -> pmon -> Go forwarding proxy -> AWS Athena / result storage
                              |
                              +-> control plane: authentication and decisions
                              +-> cache: enforcement context only
```

Use the AWS SDK for Go v2 for credentials and signing. Forward HTTP payloads
without rebuilding every operation through a local SDK request/response model,
which could discard fields. Preserve Athena's JSON protocol, operation names,
response fields, IDs, status codes, and errors except where enforcement requires
a change. Requests remain subject to the configured datasource's AWS scope.

Athena's JSON API uses `POST /`, `application/x-amz-json-1.1`, and
`X-Amz-Target: AmazonAthena.<Operation>`. Authenticate at the proxy and sign the
AWS hop independently; do not forward client AWS signatures after changing the
host or body.

<!-- prettier-ignore -->
| Operation | Proxy responsibility | Athena responsibility |
| --- | --- | --- |
| Submit SQL | Obtain the Cedar decision for the actual SQL/parameters; apply any required faithful rewrite and associate the original enforcement context. | Execute or deduplicate the submission; return its `QueryExecutionId`. |
| Fetch results | Check access and context; mask the response using the admitted instructions. | Store results, return rows, and interpret `NextToken`. |
| Get status / cancel | Authorize the referenced execution against its owner and forward the call. | Report actual status and perform cancellation. |
| List executions | Forward the call; keep only the caller's own executions in the response. | Return the workgroup's history and page tokens. |
| Metadata, history, configuration, prepared statements, and other APIs | Apply the appropriate resource/operation authorization; preserve permitted requests and responses. | Implement the operation and maintain its state. |

Return AWS execution IDs and continuation tokens unchanged. No proxy execution
IDs, execution-status table, independent polling scheduler, cancellation-intent
queue, or query-history cache. HTTP disconnects and local cache expiry do not
cancel or resubmit an AWS query. AWS remains the source of truth.

Do not create a closed operation/field allowlist merely because the first test
client does not use an API. Forwarding coverage includes the whole Athena
surface; enforcement coverage is a separate requirement, not permission to
silently pass through an unhandled data or execution path.

### Authentication

`pmon` supplies a loopback Athena endpoint and installation-local SigV4
credentials usable by ordinary client libraries. It validates signed requests,
then forwards over verified TLS with the user's proxy-monster token. Local
credentials stay bound to the chosen principal; logging in as another principal
must not silently change a saved connection's identity.

The data plane keeps the real AWS credentials. The control plane derives roles,
channel, and requester IP from trusted ingress, never client claims. Every call
checks current authentication and the applicable datasource/resource access;
connection reuse and polling do not extend login.

### Idempotency belongs to Athena

Preserve `ClientRequestToken` across retries. If isolation under a shared AWS
role requires namespacing, use a stable mapping of datasource, authenticated
principal, and client token. Do not generate a fresh upstream token because a
local entry expired or the process restarted.

Athena returns the same execution ID for an identical repeated token and rejects
changed request parameters. Forward that behavior rather than maintaining local
request reservations, duplicate-submission tombstones, or a retry state machine.
SQL rewrites must preserve the admitted upstream request on retries; changing
that request under the same token is not transparent forwarding.

## Minimal enforcement context

Athena does not know proxy-monster principals or mask instructions. Retain the
original context needed to authorize and enforce later responses:

<!-- prettier-ignore -->
| Key / field | Purpose |
| --- | --- |
| `(datasource, QueryExecutionId)` | Bind every result, status, cancel, and history read to the execution the caller submitted. |
| Owner principal and target binding | Prevent another user or a changed datasource target from reusing the context. |
| Admitted masks, unmaskable/diagnostic instructions | Enforce result and error responses without reanalyzing SQL on every fetch. |
| Expected projection width where known; optional metadata digest | Bind masks and check page consistency. A metadata digest is not historical lineage. |
| Trusted output-object binding, when required | Associate an S3 object with its execution using AWS metadata, not a caller's claimed query ID or a guessed filename. |
| Decision/audit reference and necessary enforcement commands | Link access to the existing audit and apply required catalog/diagnostic handling without retaining request objects or closures. |
| Absolute expiry | Bound local memory. It grants no AWS execution or result lifetime. |

Keep the context immutable except for narrowly defined shape/expiry updates.
Concurrent association must not replace an existing execution's owner or
instructions. The current `Verdict.result_fingerprint` is a grant list, not a
small shape hash; do not retain full grants or catalog snapshots solely for
backlogged reanalysis.

Do not retain result rows, SQL history, AWS status copies, SDK clients, request
contexts, credentials, or queues. Keep request bytes only as needed for the
forwarded call and faithful retries. A narrow original-admission association may
be needed for retry binding; it is not an execution manager.

### Context loss and retries

Missing context never means unmasked access. Result reanalysis and recovery
remain [backlog work](./backlog.md#athena). Known native executions use the
original admitted instructions; column-policy changes do not silently replace
that plan. Current authentication, datasource, and ownership gates still apply.
The existing editor/approval stored-result view rules remain unchanged.

Resolve retry binding before implementation: `StartQueryExecution` does not say
whether it created a query or replayed a token. An unknown returned ID is not
proof of a new execution. After context loss, today's decision may describe
different data from the returned execution; equal SQL, output width, or
timestamps do not prove historical lineage. Protected responses remain
unavailable until the original context can be established. Never install a new
plan on a possibly old result or rotate the upstream token to force reexecution.

### Cache, expiry, and memory

Keep this behind a small `EnforcementContextCache`, not an execution-store API.
It needs lookup, atomic association, and bounded expiry. Use BuntDB in
`:memory:` mode by default; an optional file path enables its append-only file
(AOF). Redis or control-plane DB adapters can later store the same versioned
protobuf context. Storage changes neither AWS execution ownership nor the
authorization path.

With AOF enabled, sync every committed write (`Always`) before acknowledging a
context association. A weaker sync policy must be an explicit opt-in with its
possible loss window documented. Reopen the file on restart and preserve
absolute expiry, owner/target bindings, and original instructions. Restored
context is not a restored login: each request still checks current access. Use
an exclusive owner, private file/directory permissions, and a persistent volume
where restart survival is required. An unreadable, corrupt, or incompatible file
must not silently become an empty cache. AOF does not recover context lost
before its write was committed or settle the retry-binding issue above; it
stores enforcement context, not query results or AWS lifecycle state.

Use ordinary TTL/capacity management for this cache. Athena managed results last
24 hours, which is a reasonable initial retention target. When completion time
is observed in a forwarded response, it can supply an absolute expiry; do not
add polling solely to maintain the cache. Reads do not indefinitely renew it.
Local expiry or restart can make context unavailable before AWS deletes its
result. That is a context-availability limit, not permission to resubmit.

No per-page token map or status/due indexes are needed. Add only the aliases
needed to find enforcement context, such as a trusted S3-object binding. Bound
entry count, serialized context size, and in-flight response buffering. Memory
is determined by retained contexts, not the number of polls or returned rows:

```text
retained context bytes ≈ contexts retained within TTL × bytes per context
```

Measure this smaller cache and its implementation before publishing capacity
numbers. Separately account for process baseline, GC headroom, and concurrent
row/JSON buffers; a 1,000-row page is not a byte limit.

## Enforcement across the whole surface

Forwarding is not blanket authorization through `datasource.connect`:

- SQL submission authorizes the actual SQL and ordered parameter expressions.
  `EXECUTE` resolves its Athena-owned prepared statement; storing a definition
  does not authorize executing it. The analyzer/control plane owns SQL meaning.
- Result reads cover paginated rows, Athena streaming, and S3 downloads. Each
  data path must apply the required masking or obtain explicit authorization for
  raw disclosure. The client must route streaming and S3 requests through the
  proxy too; an Athena JSON endpoint override alone does not guarantee this.
  Respect range/length/encoding semantics when rewriting data. The compatibility
  target includes normal client retrieval modes, not just a forced JSON
  fallback.
- Manifests and exports are not SELECT rows. CTAS, `UNLOAD`, `INSERT`, and DDL
  remain Cedar-controlled; a permitted export can intentionally write raw data.
- Catalog, history, configuration, and batch calls authorize every exposed or
  modified resource. The proxy's AWS role is not the caller's permission.
- Spark sessions, calculations, and notebooks execute code and return data
  outside the SQL path, so they are refused. Supporting them needs owner binding
  for session ids first.

An enforcement gap must remain closed through the appropriate Cedar gate, with
operator-controlled exceptions where applicable. It is not a reason to emulate
an Athena response or silently let data bypass masking. Streaming/S3 coverage is
part of the forwarding design; actual support must be verified before it is
claimed. Preserve raw AWS errors when permitted and redact diagnostics when
required; proxy-generated failures use stable codes in a compatible envelope.

AWS IAM, Lake Formation, and source/result-bucket permissions must prevent
independent access around the proxy. An endpoint override does not enforce that
boundary. Client-selectable workgroups, catalogs, and write destinations remain
within the datasource's configured scope rather than becoming arbitrary AWS
access through the proxy's role.

## Integration and verification

Reuse the existing listener lifecycle, `QueryEngine.Authorize`, and row masker.
Separate SDK/API metadata access from the SQL-only `Provider`/refetch
interfaces; do not create a fake `database/sql` driver. Admission uses the
existing catalog freshness contract. DDL invalidation must not depend solely on
clients polling for completion. Status/page authentication must not allocate
full SQL sessions.

Add the Athena analyzer engine and system classification. The existing resource
format supports catalog/schema/table/column, but proxy protocol, storage, and
classification keys still need catalog propagation. Athena DML is Trino-based
and much of its DDL is Hive-based; parsing support is not lineage coverage.
Athena offers no atomic catalog-and-execution snapshot; test concurrent Glue
changes rather than treating fresh metadata or equal output width as proof of
lineage.

Verify with real JDBC, Node AWS SDK, and boto3 clients, including their normal
retrieval paths. Tests cover native IDs/status/cancel/pagination, stable-token
retries and changed parameters, concurrent submission, cache loss, masked rows
across pages, metadata/diagnostic disclosure, prepared statements, and permitted
versus denied exports and non-SQL execution. Confirm that requests and response
fields survive forwarding and that no default retrieval path reaches raw data
without authorization. Keep the existing MySQL/PostgreSQL gate intact.

## References

- [StartQueryExecution and idempotency](https://docs.aws.amazon.com/athena/latest/APIReference/API_StartQueryExecution.html).
- [Result APIs and S3 access](https://docs.aws.amazon.com/athena/latest/APIReference/API_GetQueryResults.html).
- [JDBC endpoints and retrieval modes](https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver-advanced-connection-parameters.html).
- [Managed results](https://docs.aws.amazon.com/athena/latest/ug/managed-results.html).
- [Athena SQL dialects](https://docs.aws.amazon.com/athena/latest/ug/ddl-sql-reference.html).
- [BuntDB](https://github.com/tidwall/buntdb).
- [Datasource registration](./datasource-registration.md),
  [catalog identity](./mapping-schema-construction.md), and
  [task execution](./task-execution.md).
