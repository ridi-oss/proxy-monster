# BigQuery forwarding proxy

The BigQuery engine (`PM_ENGINE=bigquery`) is an HTTPS proxy for the BigQuery
REST API (`/bigquery/v2/`). Clients keep their own tools — the bq CLI, the
Python and Go client libraries — and point them at the proxy instead of
`bigquery.googleapis.com`. It shares the forwarder, the enforcement-context
cache, and the editor session with Athena (`goproxy/httpdb`); see
[athena.md](./athena.md) for that common design.

## Target

One datasource is one project and one location, with a default dataset:

| Setting                    | Meaning                                                                             |
| -------------------------- | ----------------------------------------------------------------------------------- |
| `PM_BIGQUERY_PROJECT`      | The project every job runs and bills in.                                            |
| `PM_BIGQUERY_LOCATION`     | The job location (`US`, `asia-northeast3`, …).                                      |
| `PM_TARGET_DB`             | The default dataset: unqualified tables resolve in it and the editor runs in it.    |
| `PM_BIGQUERY_CONTEXT_PATH` | The enforcement-context store, as `PM_ATHENA_CONTEXT_PATH`.                         |
| `PM_BIGQUERY_ENDPOINT`     | The API root (default `https://bigquery.googleapis.com`).                           |
| `PM_BIGQUERY_CA_FILE`      | A PEM bundle trusted for the endpoint instead of the system roots, for an emulator. |

The proxy calls Google with Application Default Credentials: a service-account
key, the GCE/GKE metadata server, or workload identity federation through
service-account impersonation. It pins the principal those credentials act as at
startup and refuses to start when it cannot name it.

## What a client may call

| Calls                                                                        | Decided as                                                                             |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `jobs.query`, `jobs.insert`                                                  | SQL: the statement is analyzed and decided like any other, and masked on the way back. |
| `jobs.get`, `jobs.getQueryResults`, `jobs.cancel`                            | The caller's own job only (enforcement context). Result pages are masked.              |
| `jobs.list`                                                                  | Filtered to the caller's own jobs.                                                     |
| `projects.list`, `datasets.get/list`, `tables.get/list`, `routines.get/list` | Metadata: `native.invoke` on the named resource.                                       |
| `datasets`/`tables` insert, patch, update, delete; `routines.delete`         | `native.invoke` on the named resource.                                                 |

Everything else is refused: `tabledata.*`, load, extract and copy jobs,
`models.*`, routine writes, views and external tables in table bodies.

A query job must be GoogleSQL (`useLegacySql: false`), in the target project and
location, not a dry run or a continuous query, and may not name a destination
table, session, script options, or UDF resources. Query parameters are inlined
as typed literals before analysis.

## Clients through pmon

pmon serves a local BigQuery endpoint per datasource. A client presents a local
bearer token bound to the principal and datasource; pmon swaps it for the
current proxy-monster token and relays over verified HTTPS.

```sh
pmon show warehouse                  # a ready bq command
pmon show warehouse --format python  # google-cloud-bigquery client setup
```

The bq command is
`bq --api=<local endpoint> --oauth_access_token=<local token> --project_id=<project> --location=<location> …`.
bq reads the API's discovery document from its endpoint first; pmon serves
Google's public copy.

## Editor and workflows

The console editor runs each statement as a `jobs.query` in the configured
project, location, and default dataset, polls it, and reads masked pages under
the result caps. A statement whose session names another dataset is refused.
