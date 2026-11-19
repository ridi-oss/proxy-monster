# BigQuery forwarding proxy

The BigQuery engine (`PM_ENGINE=bigquery`) is an HTTPS proxy for the BigQuery
REST API (`/bigquery/v2/`). Clients keep their own tools — the bq CLI, the
Python and Go client libraries — and point them at the proxy instead of
`bigquery.googleapis.com`. It shares the forwarder, the enforcement-context
cache, and the editor session with Athena (`goproxy/httpdb`); see
[athena.md](./athena.md) for that common design.

## Target

One datasource is one project and one location, with a default dataset:

| Setting                        | Meaning                                                                                 |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `PM_BIGQUERY_PROJECT`          | The project every job runs and bills in.                                                |
| `PM_BIGQUERY_LOCATION`         | The job location (`US`, `asia-northeast3`, …).                                          |
| `PM_TARGET_DB`                 | The default dataset: unqualified tables resolve in it and the editor runs in it.        |
| `PM_BIGQUERY_CONTEXT_PATH`     | The enforcement-context store, as `PM_ATHENA_CONTEXT_PATH`.                             |
| `PM_BIGQUERY_ENDPOINT`         | The API root (default `https://bigquery.googleapis.com`).                               |
| `PM_BIGQUERY_STORAGE_ENDPOINT` | The Storage Read API's gRPC `host:port` (default `bigquerystorage.googleapis.com:443`). |
| `PM_BIGQUERY_CA_FILE`          | A PEM bundle trusted for both endpoints instead of the system roots, for an emulator.   |

The proxy calls Google with Application Default Credentials: a service-account
key, the GCE/GKE metadata server, or workload identity federation through
service-account impersonation. It pins the principal those credentials act as at
startup and refuses to start when it cannot name it.

On AWS (ECS, EC2, EKS) use federation with no key: the file from
`gcloud iam workload-identity-pools create-cred-config <provider> --service-account=<sa> --aws --output-file=wif.json`,
mounted and named by `GOOGLE_APPLICATION_CREDENTIALS`. The proxy signs its
subject token with the AWS SDK's default credentials (the ECS task role
included) in `AWS_REGION`; map that role to the service account through the
provider's `attribute.aws_role`.

## What a client may call

| Calls                                                                        | Decided as                                                                             |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `jobs.query`, `jobs.insert`                                                  | SQL: the statement is analyzed and decided like any other, and masked on the way back. |
| `jobs.get`, `jobs.getQueryResults`, `jobs.cancel`                            | The caller's own job only (enforcement context). Result pages are masked.              |
| `jobs.list`                                                                  | Filtered to the caller's own jobs.                                                     |
| Storage Read API: `CreateReadSession`, `ReadRows`, `SplitReadStream`         | The result table of the caller's own query job only. Record batches are masked.        |
| `projects.list`, `datasets.get/list`, `tables.get/list`, `routines.get/list` | Metadata: `native.invoke` on the named resource.                                       |
| `datasets`/`tables` insert, patch, update, delete; `routines.delete`         | `native.invoke` on the named resource.                                                 |

Everything else is refused: `tabledata.*`, the Storage Write API, load, extract
and copy jobs, `models.*`, routine writes, views and external tables in table
bodies.

A query job must be GoogleSQL (`useLegacySql: false`), in the target project and
location, not a dry run or a continuous query, and may not name a destination
table, session, script options, or UDF resources. Query parameters are inlined
as typed literals before analysis.

## Storage Read API

The proxy serves `google.cloud.bigquery.storage.v1.BigQueryRead` over gRPC on
its HTTPS port, so a client's `to_dataframe()` reads query results through it. A
read session is allowed only on the result table of the caller's own query job:
the proxy finds the job among those it relayed, confirms upstream that the job
wrote that table, and asks the control plane as for `jobs.getQueryResults` on
that job. The session must be Arrow, billed to the target project, with no row
restriction, sampling, snapshot, or response compression; `selected_fields` may
name only result columns, which come back in result order. A direct table read
is refused — rows of a table come only through SQL.

`ReadRows` and `SplitReadStream` are allowed only on streams of a session the
same caller created, authorized again on every call. Each record batch is
decoded, masked under the job's context (masks map to the session's fields by
name), and encoded again. A masked column becomes a nullable string, as on the
REST side; a NULL mask keeps the type. A masked nested column fails the read.

## Clients through pmon

pmon serves a local BigQuery endpoint per datasource. A client presents a local
bearer token bound to the principal and datasource; pmon swaps it for the
current proxy-monster token and relays over verified HTTPS. The same local port
takes the Storage Read API over cleartext HTTP/2, which pmon relays to the proxy
over HTTPS.

```sh
pmon show warehouse                  # a ready bq command
pmon show warehouse --format python  # google-cloud-bigquery client with a Storage Read client
```

The bq command is
`bq --api=<local endpoint> --oauth_access_token=<local token> --project_id=<project> --location=<location> …`.
bq reads the API's discovery document from its endpoint first; pmon serves
Google's public copy.

## Editor and workflows

The console editor runs each statement as a `jobs.query` in the configured
project, location, and default dataset, polls it, and reads masked pages under
the result caps. A statement whose session names another dataset is refused.
