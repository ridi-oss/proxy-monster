# deploy/

Supporting artifacts for running proxy-monster. The deployment guide itself —
the per-service env-var contract, the image `docker build` commands, and the
local, ECS Fargate, and EKS run steps — lives in [INSTALL.md](../INSTALL.md).

## Contents

- `seed/target-seed-mysql.sql`, `seed/target-seed.sql` — sample target-DB schema
  and seed data: a small OLTP schema (`users`, `orders`, `payments`,
  `addresses`, ...) with realistic PII columns (`email`, `phone`, `name`, `ssn`,
  `card_number`, ...) to classify and mask against. The local compose stack
  bind-mounts them into the MySQL and Postgres sample targets; see
  [Datastores](../INSTALL.md#datastores).

## Deploying

For the env-var contract and image builds, see
[Configuration](../INSTALL.md#configuration); for the ECS and EKS run steps, see
[Deploying on AWS](../INSTALL.md#deploying-on-aws-ecs-fargate--s3--aurora).
