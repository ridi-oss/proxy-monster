# Stored-result classification — snapshot the tags at execution

Proposed, not built. The view path currently reads classification live, which is
the defect [The failure it closes](#the-failure-it-closes) describes.

This is also the record that lets classification stop being a control-plane
store: under [classification-as-code.md](./classification-as-code.md) the proxy
declares classification live and the control plane keeps no durable copy, so the
per-result snapshot below is the only classification it retains — and the only
one a saved result may be judged by.

## Decision

A saved result records the classification of every column it touched, at the
moment it executed. Viewing it re-decides against that snapshot, not against
today's classification.

Tags are a fact about the bytes captured in the result. Context is a fact about
the request doing the viewing. Only the first is knowable at execution, so only
the first is snapshotted: `context`, the resolved roles, and the policy set all
stay live, which is what keeps a view able to mask _further_ than the run did
([task-execution.md](./task-execution.md)).

Snapshotted per stored result, over the touched columns only:

- each column's `tags` and `mask_fn`
- the datasource's `system:*` posture tags

Not snapshotted:

- **System-classification tags.** They resolve from an immutable, version-pinned
  JSON manifest bundled with the binary
  ([system-classification.md](./system-classification.md)), so no operator
  action can edit them out from under a stored result. Freezing them would add
  churn and close nothing.
- **Context, roles, policy, the mask decision.** Freezing any of these would
  break the tightening property below.

## The failure it closes

`decideResultView` (`control-plane/.../Approvals.kt`) re-decides an
already-extracted result. It reads classification live, through
`datasourceStore.catalog(ds.id)`. Two routes reach it: the approval result view
and the editor saved-result view (`Query.kt`).

The stored ciphertext is fixed at execution. Only the mask _decision_ is
recomputed. So a classification change after execution is applied to bytes that
predate it, and in one direction that reveals data:

1. `users.ssn` carries `pii`. An approved run executes as
   `system:production-pii-accessor` on the `workflow-executor` channel, so the
   preset `system:production-pii-unmasked-workflow-executor` permit fires and
   the column is stored **unmasked** — the maximal result `{R}` is entitled to.
   The ciphertext holds real values.
2. A data cleanup nulls the live column, and the `pii` tag is removed. That is
   correct about the table as it now stands.
3. A viewer assumes `{R}` and reads the saved result. The broad production read
   (`system:production-non-pii-read`) permits every `production-*` role unmasked
   `unless resource in Tag::"pii"`. With the tag gone that exclusion no longer
   matches, so the permit applies and the stored values are returned in
   cleartext.

Step 3 is worth being precise about: at view time the leak does not come from a
channel-conditioned permit. The executor-channel permit is what put unmasked
bytes into the result at step 1; what returns them at step 3 is the broad
production read, whose only protection for this column was the tag that has
since been removed. Both preset policies are seeded in `V8__seed.sql`
([policy-store.md](./policy-store.md)).

The untag was right about the live column and wrong about the stored bytes;
nothing distinguished them. This is the fail-open shape
[authz-model.md](./authz-model.md) names — a column that is not `in Tag::"pii"`
falls out of the exclusion and is returned cleartext — reached by a correct
administrative action rather than a mistake.

Deny-by-default does not cover it. That protects a column a principal must be
granted to read; here the grant exists and the tag is what decides masked versus
cleartext.

## Strict snapshot, not a union with current tags

The rule is the snapshot alone. Not the snapshot unioned with present-day tags,
which is unsound: a union sees two endpoints and misses everything between them.

- Result stored while the column is untagged → snapshot `{}`.
- Later the column is tagged `pii` — someone establishes it is sensitive.
- Later still the cleanup lands and it is untagged again → current `{}`.

`{} ∪ {} = {}`, so the column reads cleartext even though it was classified
`pii` inside the result's lifetime. Catching that needs the full history of
every tag change, and then whether a result leaks depends on a window nothing
tracks.

Strict snapshot needs no history. Tags at execution are correct for the bytes
captured at execution, which is the whole premise; a later change describes the
live column, and a stored result is not the live column.

### What strict snapshot gives up, and the remedy

A tag added _after_ a result is stored does not retroactively mask it. That is
bounded: `QueryResultStore.RESULT_RETENTION_SEC` is 24 hours, so the exposure is
one retention window of results, not the archive.

The remedy for "we have found PII in extracted results" is to **purge** them,
not to silently re-mask. `purgeExpired` already drops the payload (`ciphertext`,
`row_count`, `columns`) while keeping the row for audit, and
`deleteResultsForTask` removes a task's children outright. Purge is explicit,
auditable, and complete; re-masking a result somebody may already have read is
none of those.

The snapshot makes purge-by-column answerable for the first time — which stored
results touched `users.ssn` — since the classification of each result's columns
is now recorded rather than inferred. That is additive and not required by this
change.

## Worked example — the tightening property still holds

From [task-execution.md](./task-execution.md): `R` =
`system:production-pii-accessor`, which the production preset lets read `pii`
unmasked `when context.channel == "workflow-executor"`.

- **Execute.** Channel `workflow-executor`, so the permit fires and `users.ssn`
  is stored unmasked. Snapshot records `users.ssn → [pii]`.
- **View, off-network.** Channel is `workflow-viewer`, which that permit does
  not match. Evaluation falls through to the masked grant → masked. The snapshot
  supplied `pii`; the _context_ did the narrowing, exactly as before.
- **View, after the tag is removed.** The snapshot still carries `pii`, so the
  verdict is unchanged. Under live classification this is the case that returned
  cleartext.
- **View, after a policy change.** The policy set is live, so a newly added
  `forbid` applies immediately. Only classification is frozen.

## Shape

The snapshot belongs on the `query_result` row, beside the payload it describes,
and is written by the same statement that stores the ciphertext — a result whose
snapshot could be missing is a result that cannot be safely viewed.

`purgeExpired` must clear it with the rest of the payload. It is classification
metadata about extracted data and must not outlive the extract.

A stored result written before this change has no snapshot. Absence must deny
the view rather than fall back to live classification: the fallback is the
behavior being removed, and a silent fallback would keep the leak for exactly
the rows most likely to hit it. The deny carries its own `ApiError` code, so "no
classification snapshot" is distinguishable from "no tags configured" — those
justify different operator responses.

## Consequence for the docs

[task-execution.md](./task-execution.md) states that masking always reflects the
current schema, and that there is no stored plan to go stale. That stays true of
the run, which is decided against the live per-connection catalog. It is no
longer true of the view: the view is decided against the snapshot for
classification, and live for everything else. That section needs to say so.
