# Seeds the Athena emulator the way deploy/seed seeds the SQL targets: an acme database whose users table
# holds the same three rows. Runs inside the container once the gateway is ready.
import os

import boto3
from botocore.config import Config

users = (
    "id,email,phone,name,ssn,region,created_at\n"
    "1,jiwon@example.com,010-1111-2222,Kim Jiwon,987-65-4320,KR-11,2025-01-02 09:00:00\n"
    "2,minseo@example.com,010-3333-4444,Lee Minseo,987-65-4322,KR-26,2025-02-14 13:30:00\n"
    "3,haeun@example.com,010-5555-6666,Park Haeun,987-65-4323,KR-41,2025-03-21 18:45:00\n"
)
columns = [("id", "bigint"), ("email", "string"), ("phone", "string"), ("name", "string"),
           ("ssn", "string"), ("region", "string"), ("created_at", "string")]

# The gateway serves HTTPS with a self-signed cert; the script env still names the plain HTTP endpoint.
endpoint = "https://localhost:4566" if os.environ.get("USE_SSL") == "1" else os.environ.get("AWS_ENDPOINT_URL")
client = dict(endpoint_url=endpoint, verify=False, config=Config(retries={"max_attempts": 2}))
s3 = boto3.client("s3", **client)
glue = boto3.client("glue", **client)
s3.create_bucket(Bucket="acme-data")
s3.create_bucket(Bucket="athena-results")
s3.put_object(Bucket="acme-data", Key="users/users.csv", Body=users.encode())
glue.create_database(DatabaseInput={"Name": "acme"})
glue.create_table(
    DatabaseName="acme",
    TableInput={
        "Name": "users",
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": {
            "Columns": [{"Name": name, "Type": kind} for name, kind in columns],
            "Location": "s3://acme-data/users/",
        },
        "Parameters": {"classification": "csv"},
    },
)
print("athena seed: acme.users ready")
