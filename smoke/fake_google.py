"""Google in front of the BigQuery emulator for the smoke test's bigquery row.

The proxy only forwards to HTTPS and needs Google credentials, while goccy/bigquery-emulator serves plain HTTP
and checks none. This serves the emulator's REST API over HTTPS and an OAuth token endpoint over plain HTTP
(the service-account key's token_uri). It also fills two emulator gaps: INFORMATION_SCHEMA.ROUTINES is answered
here with no routines, a reply naming a job or listing datasets gets the location BigQuery always returns (US
when none was asked for), job times the emulator gives in seconds are given in milliseconds, a missing dataset's
view is a 404 rather than a 400, and the dataset the emulator makes for each job's result is not listed, as
BigQuery hides those.

    python3 fake_google.py <https port> <token port> <cert> <key> <emulator port>
"""
import json
import ssl
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TLS_PORT, TOKEN_PORT, CERT, KEY, EMULATOR = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
JOBS = set()
ROUTINE_FIELDS = [{"name": "routine_schema", "type": "STRING", "mode": "NULLABLE"}, {"name": "routine_name", "type": "STRING", "mode": "NULLABLE"}]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("fake-google: " + (fmt % args) + "\n")

    def reply(self, status, body, headers=()):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_POST(self):
        body = self.body()
        if self.server.server_port == TOKEN_PORT:
            return self.reply(200, {"access_token": "emulator-token", "token_type": "Bearer", "expires_in": 3600})
        if self.path.split("?")[0].endswith("/queries") and b"INFORMATION_SCHEMA.ROUTINES" in body:
            project = self.path.split("/projects/")[1].split("/")[0]
            location = json.loads(body).get("location")
            return self.reply(200, {"kind": "bigquery#queryResponse", "jobComplete": True, "totalRows": "0", "rows": [],
                                    "jobReference": {"projectId": project, "jobId": "routines", "location": location},
                                    "schema": {"fields": ROUTINE_FIELDS}})
        self.forward(body)

    def do_GET(self):
        self.forward(None)

    def do_PATCH(self):
        self.forward(self.body())

    do_PUT = do_PATCH

    def do_DELETE(self):
        self.forward(None)

    def as_bigquery(self, body, raw):
        sent = json.loads(body) if body else {}
        location = (parse_qs(urlparse(self.path).query).get("location", [None])[0] or sent.get("location")
                    or (sent.get("jobReference") or {}).get("location"))
        reply = json.loads(raw) if raw else {}
        if location and isinstance(reply.get("jobReference"), dict) and not reply["jobReference"].get("location"):
            reply["jobReference"]["location"] = location
        if isinstance(reply.get("jobReference"), dict):
            JOBS.add(reply["jobReference"].get("jobId"))
        if "datasets" in reply:
            reply["datasets"] = [d for d in reply["datasets"] or [] if d.get("datasetReference", {}).get("datasetId") not in JOBS]
            for dataset in reply["datasets"]:
                dataset.setdefault("location", "US")
        statistics = reply.get("statistics") if isinstance(reply.get("statistics"), dict) else {}
        for name in ("creationTime", "startTime", "endTime"):
            if str(statistics.get(name, "")).isdigit() and int(statistics[name]) < 10**11:
                statistics[name] = str(int(statistics[name]) * 1000)
        return json.dumps(reply).encode() if reply else raw

    def forward(self, body):
        if self.server.server_port == TOKEN_PORT or self.headers.get("Authorization") != "Bearer emulator-token":
            return self.reply(401, {"error": {"code": 401, "message": "fake-google: no emulator token", "status": "UNAUTHENTICATED",
                                              "errors": [{"reason": "authError", "message": "no emulator token"}]}})
        request = urllib.request.Request(f"http://127.0.0.1:{EMULATOR}{self.path}", data=body, method=self.command)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
            self.reply(response.status, self.as_bigquery(body, raw))
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code == 400 and b"Table not found" in raw and b"INFORMATION_SCHEMA" in raw:
                return self.reply(404, {"error": {"code": 404, "message": "Not found: Dataset", "status": "NOT_FOUND",
                                                  "errors": [{"reason": "notFound", "message": "Not found: Dataset"}]}})
            self.reply(e.code, raw)


ThreadingHTTPServer.request_queue_size = 64
api = ThreadingHTTPServer(("127.0.0.1", TLS_PORT), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT, KEY)
api.socket = context.wrap_socket(api.socket, server_side=True)
token = ThreadingHTTPServer(("127.0.0.1", TOKEN_PORT), Handler)
threading.Thread(target=token.serve_forever, daemon=True).start()
api.serve_forever()
