#!/usr/bin/env python3
"""End-to-end smoke legs against a running proxy-monster stack (started by smoke/run.sh)."""
import argparse
import datetime as dt
import hashlib
import http.cookiejar
import json
import os
import re
import shlex
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

LEGS = ["editor", "browser", "wire", "pmon", "workflow", "rate", "audit", "github", "names", "native"]
MASK = "####"
TRUSTED_IP = "100.100.1.8"
PRODUCTION_PRESETS = [-200, -201, -202, *range(-238, -229), -250, -251, -252, -253, -255, *range(-262, -255), -280, -300, -305, -306, -307]


class Fail(Exception):
    pass


class Skip(Exception):
    pass


GITHUB_REPO = "acme/db"
GITHUB_DEV = ("dev", 201)
GITHUB_DEV_EMAIL = "dev@smoke.example"


CATALOGS = {"mysql": ("def", "acme"), "postgres": ("acme", "public"), "athena": ("awsdatacatalog", "acme")}

# Names leg per matrix row; one classified column per spelling. Read: (mask|deny|clear:<value prefix>, sql[, pending]).
# A pending check runs and reports SKIP while it fails, UNEXPECTED PASS once it passes.
GLUE_CASE = "pending-name-fix: a mixed-case Glue table is allowed, but its read fails on the target"
NAMES = {
    "mysql": {
        "classify": [("Customers", "Email"), ("Customers", "phone"), ("Customers", "SSN")],
        "refuse": [("CUSTOMERS", "EMAIL", ["Customers", "customers"])],
        "forbid": ("Customers", "secret"),
        "detail": [("Customers", "email"), ("Customers", "phone"), ("Customers", "ssn")],
        "reads": [
            ("mask", "SELECT id, Email FROM Customers ORDER BY id"),
            ("mask", "SELECT id, email FROM Customers ORDER BY id"),
            ("mask", "SELECT id, EMAIL FROM acme.Customers ORDER BY id"),
            ("mask", "SELECT c.id, c.eMaIl FROM `Customers` c ORDER BY c.id"),
            ("mask", "SELECT id, Phone FROM Customers ORDER BY id"),
            ("mask", "SELECT id, PHONE FROM Customers ORDER BY id"),
            ("mask", "SELECT id, Ssn FROM Customers ORDER BY id"),
            ("mask", "SELECT id, ssn FROM Customers ORDER BY id"),
            ("clear:lower-email", "SELECT id, email FROM customers ORDER BY id"),
            ("deny", "SELECT id, Secret FROM Customers ORDER BY id"),
            ("deny", "SELECT id, SECRET FROM Customers ORDER BY id"),
            ("clear:lower-secret", "SELECT id, secret FROM customers ORDER BY id"),
        ],
    },
    "mysql-lctn1": {
        "classify": [("Customers", "Email"), ("CUSTOMERS", "PHONE"), ("customers", "ssn")],
        "refuse": [],
        "forbid": ("customers", "secret"),
        "detail": [("customers", "email"), ("customers", "phone"), ("customers", "ssn")],
        "reads": [
            ("mask", "SELECT id, email FROM customers ORDER BY id"),
            ("mask", "SELECT id, Email FROM Customers ORDER BY id"),
            ("mask", "SELECT id, EMAIL FROM CUSTOMERS ORDER BY id"),
            ("mask", "SELECT id, email FROM ACME.Customers ORDER BY id"),
            ("mask", "SELECT c.id, c.Email FROM `CUSTOMERS` c ORDER BY c.id"),
            ("mask", "SELECT id, phone FROM customers ORDER BY id"),
            ("mask", "SELECT id, Phone FROM Customers ORDER BY id"),
            ("mask", "SELECT id, ssn FROM customers ORDER BY id"),
            ("mask", "SELECT id, SSN FROM CUSTOMERS ORDER BY id"),
            ("deny", "SELECT id, secret FROM customers ORDER BY id"),
            ("deny", "SELECT id, Secret FROM CUSTOMERS ORDER BY id"),
        ],
    },
    "postgres": {
        "classify": [("customers", "email"), ('"Customers"', '"Phone"'), ("Customers", "Ssn")],
        "refuse": [],
        "forbid": ("Customers", "Secret"),
        "detail": [("customers", "email"), ("Customers", "Phone"), ("customers", "ssn")],
        "reads": [
            ("mask", "SELECT id, email FROM customers ORDER BY id"),
            ("mask", "SELECT id, EMAIL FROM CUSTOMERS ORDER BY id"),
            ("mask", 'SELECT id, "email" FROM "customers" ORDER BY id'),
            ("mask", "SELECT id, Email FROM public.Customers ORDER BY id"),
            ("clear:upper-email", 'SELECT id, "Email" FROM "Customers" ORDER BY id'),
            ("mask", 'SELECT id, "Phone" FROM "Customers" ORDER BY id'),
            ("mask", 'SELECT c.id, c."Phone" FROM public."Customers" c ORDER BY c.id'),
            ("clear:lower-phone", "SELECT id, phone FROM customers ORDER BY id"),
            ("mask", "SELECT id, ssn FROM customers ORDER BY id"),
            ("mask", "SELECT id, SSN FROM Customers ORDER BY id"),
            ("clear:upper-ssn", 'SELECT id, "Ssn" FROM "Customers" ORDER BY id'),
            ("deny", 'SELECT id, "Secret" FROM "Customers" ORDER BY id'),
            ("deny", 'SELECT id, "Secret" FROM public."Customers" ORDER BY id'),
            ("clear:lower-secret", "SELECT id, SECRET FROM CUSTOMERS ORDER BY id"),
        ],
    },
    "athena": {
        "classify": [("Accounts", "Email"), ("ACCOUNTS", "PHONE"), ("accounts", "ssn"), ("customers", "email")],
        "refuse": [],
        "forbid": ("accounts", "secret"),
        "detail": [("accounts", "email"), ("accounts", "phone"), ("accounts", "ssn")],
        "reads": [
            ("mask", "SELECT id, email FROM accounts ORDER BY id"),
            ("mask", "SELECT id, EMAIL FROM ACCOUNTS ORDER BY id"),
            ("mask", "SELECT a.id, a.Email FROM Accounts a ORDER BY a.id"),
            ("mask", "SELECT id, email FROM ACME.Accounts ORDER BY id"),
            ("mask", "SELECT id, phone FROM accounts ORDER BY id"),
            ("mask", "SELECT id, Phone FROM awsdatacatalog.acme.ACCOUNTS ORDER BY id"),
            ("mask", "SELECT id, ssn FROM accounts ORDER BY id"),
            ("mask", "SELECT id, SSN FROM Accounts ORDER BY id"),
            ("deny", "SELECT id, secret FROM accounts ORDER BY id"),
            ("deny", "SELECT id, SECRET FROM Accounts ORDER BY id"),
            ("mask", "SELECT id, email FROM customers ORDER BY id", GLUE_CASE),
            ("mask", "SELECT id, Email FROM Customers ORDER BY id", GLUE_CASE),
        ],
    },
}


class Session:
    def __init__(self, base, log):
        self.base = base
        self.log = log
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def call(self, method, path, body=None, ok=(200, 201, 202)):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req, timeout=120) as resp:
                status, raw, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        text = raw.decode(errors="replace")
        self.log.write(f"{method} {path} {'' if body is None else json.dumps(body)} -> {status} {text[:2000]}\n")
        parsed = None
        if text.startswith(("{", "[")):
            parsed = json.loads(text)
        if ok is not None and status not in ok:
            raise Fail(f"{method} {path} -> {status} {text[:300]}")
        return status, parsed, headers

    def login(self, principal, roles, requester_ip=None):
        body = {"principal": principal, "roles": roles}
        if requester_ip:
            body["requesterIp"] = requester_ip
        self.call("POST", "/auth/debug", body)
        return self

    def query(self, ds_id, sql):
        return self.call("POST", f"/api/datasources/{ds_id}/query", {"sql": sql, "maxRows": 500})[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def expect(cond, msg):
    if not cond:
        raise Fail(msg)


def run(cmd, env=None, timeout=60, stdin=None, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, input=stdin, cwd=cwd)
    return p.returncode, p.stdout, p.stderr


class Stack:
    def __init__(self, args):
        self.args = args
        self.logs = args.logs
        self.setup_log = open(os.path.join(self.logs, "setup.log"), "w")
        self.admin = Session(args.cp, self.setup_log).login("smoke-admin", ["system:admin"])
        self.datasources = {}
        self.produced = {}
        self.unexpected = []
        self.github = None
        if args.github:
            from fake_github import FakeGitHub
            tls_port, http_port, cert, key, signing_key, app_id = args.github.split(",")
            self.github = FakeGitHub(int(tls_port), int(http_port), cert, key, signing_key, app_id)

    def session(self, name):
        return Session(self.args.cp, open(os.path.join(self.logs, name + ".log"), "a"))

    def seed(self):
        a = self.admin
        _, fns, _ = a.call("GET", "/api/mask-fns")
        fixed = next((f for f in fns if f["name"] == "smoke-fixed"), None) or a.call("POST", "/api/mask-fns", {"name": "smoke-fixed", "kind": "FIXED"})[1]
        self.fixed_mask_fn = fixed["id"]
        for pid in PRODUCTION_PRESETS:
            a.call("POST", f"/api/policies/{pid}/enable")
        _, roles, _ = a.call("GET", "/api/roles")
        self.roles = {r["name"]: r["id"] for r in roles}
        for name in ("smoke-rate-mysql", "smoke-rate-postgres", "smoke-rate-athena"):
            if name not in self.roles:
                self.roles[name] = a.call("POST", "/api/roles", {"name": name})[1]["id"]
        _, policies, _ = a.call("GET", "/api/policies")
        have = {p["name"] for p in policies}
        wanted = {
            "smoke:rate-mysql": '@cap("2, 2/1h") permit(principal in Role::"smoke-rate-mysql", action == Action::"result.cap", resource);',
            "smoke:rate-postgres": '@cap("2, 2/1h") permit(principal in Role::"smoke-rate-postgres", action == Action::"result.cap", resource);',
            "smoke:rate-athena": '@cap("2, 2/1h") permit(principal in Role::"smoke-rate-athena", action == Action::"result.cap", resource);',
        }
        for name, src in wanted.items():
            if name not in have:
                a.call("POST", "/api/policies", {"name": name, "cedarSrc": src})
        _, listed, _ = a.call("GET", "/api/datasources")
        by_name = {d["name"]: d for d in listed}
        for engine, name, port, row in self.args.datasource:
            expect(name in by_name, f"datasource {name} is not registered (proxies: {sorted(by_name)})")
            d = by_name[name]
            expect("system:production" in d["tags"], f"{name} is not tagged system:production: {d['tags']}")
            catalog, schema = CATALOGS[engine]
            a.call("PUT", f"/api/datasources/{d['id']}/classification",
                   {"catalog": catalog, "schema": schema, "table": "users", "column": "email",
                    "tags": ["pii"], "maskFnId": fixed["id"]})
            self.datasources[row] = {"id": d["id"], "name": name, "port": int(port), "engine": engine, "row": row}
        if self.github:
            _, users, _ = a.call("GET", "/api/users")
            if GITHUB_DEV_EMAIL not in {u.get("email") for u in users}:
                a.call("POST", "/api/users", {"principal": "smoke-github-dev", "email": GITHUB_DEV_EMAIL})
        # The wire cert is connect-gated, so a viewer fetches it the way a client would.
        viewer = self.session("setup").login("smoke-viewer", ["system:production-viewer"])
        for ds in self.datasources.values():
            if ds["engine"] == "athena":
                status, _, _ = viewer.call("GET", f"/api/datasources/{ds['id']}/wire-cert", ok=None)
                expect(status == 200, f"wire-cert for {ds['name']}: {status}")
                ds["certChain"] = self.raw_get(viewer, f"/api/datasources/{ds['id']}/wire-cert")

    def raw_get(self, session, path):
        with session.opener.open(urllib.request.Request(session.base + path), timeout=30) as resp:
            return resp.read().decode()

    # ---- wire clients -------------------------------------------------------------------------------
    def athena_call(self, ds, token, operation, body):
        """One Athena JSON API call at the proxy, the wire token as bearer; returns (status, parsed body)."""
        ctx = ssl.create_default_context(cadata=ds["certChain"])
        req = urllib.request.Request(f"https://127.0.0.1:{ds['port']}/", data=json.dumps(body).encode(), method="POST", headers={
            "Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "AmazonAthena." + operation, "Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def athena_sql(self, ds, token, sql):
        """StartQueryExecution, poll to a terminal state, page the results; returns (ok, rows, error text)."""
        status, r = self.athena_call(ds, token, "StartQueryExecution", {
            "QueryString": sql, "WorkGroup": "primary", "QueryExecutionContext": {"Catalog": "AwsDataCatalog", "Database": "acme"}})
        if status != 200:
            return False, [], r.get("Message", str(r))
        qid = r["QueryExecutionId"]
        deadline = time.time() + 60
        while True:
            status, r = self.athena_call(ds, token, "GetQueryExecution", {"QueryExecutionId": qid})
            expect(status == 200, f"GetQueryExecution {qid}: {status} {r}")
            state = r["QueryExecution"]["Status"]
            if state["State"] in ("SUCCEEDED", "FAILED", "CANCELLED") or time.time() > deadline:
                break
            time.sleep(0.2)
        if state["State"] != "SUCCEEDED":
            return False, [], f"{state['State']}: {state.get('StateChangeReason')}"
        rows, token_next, first = [], None, True
        while True:
            body = {"QueryExecutionId": qid, "MaxResults": 2}
            if token_next:
                body["NextToken"] = token_next
            status, r = self.athena_call(ds, token, "GetQueryResults", body)
            expect(status == 200, f"GetQueryResults {qid}: {status} {r}")
            page = [[d.get("VarCharValue") for d in row["Data"]] for row in r["ResultSet"]["Rows"]]
            if first and page and page[0] == [c["Name"] for c in r["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]:
                page = page[1:]
            rows += page
            first = False
            token_next = r.get("NextToken")
            if not token_next:
                break
        return True, rows, ""

    def wire_sql(self, ds, principal, token, sql, verbose=False):
        """Run one statement through the proxy as a native client; returns (ok, rows, stderr)."""
        if ds["engine"] == "athena":
            return self.athena_sql(ds, token, sql)
        if ds["engine"] == "mysql":
            cmd = ["mysql", "--protocol=tcp", "-h", "127.0.0.1", "-P", str(ds["port"]), "-u", principal,
                   "--enable-cleartext-plugin", "--ssl-mode=DISABLED", "-N", "-B", *(["-vvv"] if verbose else []),
                   "-e", sql, "acme"]
            env = dict(os.environ, MYSQL_PWD=token)
        else:
            cmd = ["psql", f"host=127.0.0.1 port={ds['port']} dbname=acme user={principal} sslmode=disable",
                   "-v", "ON_ERROR_STOP=1", "-At", "-F", "\t", "-c", sql]
            env = dict(os.environ, PGPASSWORD=token)
        code, out, err = run(cmd, env=env)
        rows = [line.split("\t") for line in out.splitlines() if line]
        return code == 0, rows, err

    def wire_token(self, session):
        return session.call("POST", "/api/wire-tokens", {"ttlSeconds": 600})[1]["token"]

    # ---- legs ----------------------------------------------------------------------------------------
    def leg_editor(self, ds):
        viewer = self.session("editor").login("smoke-viewer", ["system:production-viewer"])
        r = viewer.query(ds["id"], "SELECT id, email FROM users")
        expect(r["decision"] == "MASK", f"viewer SELECT id, email: expected MASK, got {r['decision']} {r.get('denyReason')}")
        expect(len(r["rows"]) == 3, f"expected 3 rows, got {len(r['rows'])}")
        expect(all(row[1] == MASK for row in r["rows"]), f"email not masked: {r['rows']}")
        r = viewer.query(ds["id"], "SELECT * FROM users")
        expect(r["decision"] == "MASK", f"viewer SELECT *: expected MASK, got {r['decision']} {r.get('denyReason')}")
        cols = [c.lower() for c in r["columns"]]
        email, name = cols.index("email"), cols.index("name")
        expect(all(row[email] == MASK for row in r["rows"]), f"SELECT * left email unmasked at ordinal {email}: {r['rows']}")
        expect(all(row[name] != MASK for row in r["rows"]), f"SELECT * masked the wrong ordinal ({name}): {r['rows']}")
        r = viewer.query(ds["id"], "SELECT id FROM users WHERE email = 'a@example.com'")
        expect(r["decision"] == "DENY", f"predicate on masked column: expected DENY, got {r['decision']}")
        expect("cannot be masked" in (r.get("denyReason") or ""), f"deny reason does not name the unmaskable predicate: {r.get('denyReason')}")
        pii = self.session("editor").login("smoke-pii", ["system:production-pii-accessor"], TRUSTED_IP)
        r = pii.query(ds["id"], "SELECT id, email FROM users")
        expect(r["decision"] == "ALLOW", f"pii-accessor from {TRUSTED_IP}: expected ALLOW, got {r['decision']} {r.get('denyReason')}")
        expect(all("@" in row[1] for row in r["rows"]), f"pii-accessor should read cleartext: {r['rows']}")
        # mcp: the console tools take the same decision path; an MCP leg plugs in here.
        self.produced.setdefault(ds["engine"], set()).add("editor")

    def leg_browser(self, ds):
        """The console in a real browser (smoke/browser.spec.ts): editor mask, table detail by catalog, Data tab."""
        catalog, schema = CATALOGS[ds["engine"]]
        env = dict(os.environ, SMOKE_WEB_URL=self.args.web, SMOKE_DATASOURCES=f"{ds['engine']}:{ds['name']}:{catalog}:{schema}")
        code, out, err = run(["node_modules/.bin/playwright", "test", "-c", os.path.join(self.args.root, "smoke", "playwright.config.ts")],
                             env=env, timeout=300, cwd=os.path.join(self.args.root, "web"))
        with open(os.path.join(self.logs, "browser.log"), "a") as f:
            f.write(out + err)
        expect(code == 0, f"playwright exited {code}; see logs/browser.log")

    def leg_wire(self, ds):
        viewer = self.session("wire").login("smoke-viewer", ["system:production-viewer"])
        token = self.wire_token(viewer)
        ok, rows, err = self.wire_sql(ds, "smoke-viewer", token, "SELECT id, email FROM users ORDER BY id")
        expect(ok, f"viewer wire SELECT failed: {err.strip()}")
        expect(len(rows) == 3 and all(r[1] == MASK for r in rows), f"wire result not masked: {rows}")
        ok, rows, err = self.wire_sql(ds, "smoke-viewer", token, "SELECT id FROM users WHERE email = 'a@example.com'")
        expect(not ok and "proxy-monster denied" in err, f"wire predicate on masked column should be denied: ok={ok} rows={rows} err={err.strip()}")
        arch = self.session("wire").login("smoke-architect", ["system:production-viewer", "system:production-architect"])
        atoken = self.wire_token(arch)
        ddl = ("CREATE EXTERNAL TABLE smoke_ddl (id INT, note STRING) LOCATION 's3://acme-data/smoke_ddl/'"
               if ds["engine"] == "athena" else "CREATE TABLE smoke_ddl (id INT, note VARCHAR(20))")
        ok, _, err = self.wire_sql(ds, "smoke-architect", atoken, ddl)
        expect(ok, f"DDL as architect failed: {err.strip()}")
        try:
            deadline = time.time() + 30
            while True:
                ok, rows, err = self.wire_sql(ds, "smoke-architect", atoken, "SELECT id, note FROM smoke_ddl")
                if ok or time.time() > deadline:
                    break
                time.sleep(1)
            expect(ok, f"read of a table created by DDL is still refused after the refetch window: {err.strip()}")
            if ds["engine"] == "mysql":
                self.wire_ok_info(ds)
        finally:
            self.wire_sql(ds, "smoke-architect", atoken, "DROP TABLE smoke_ddl")
        self.produced.setdefault(ds["engine"], set()).add("wire")

    def wire_ok_info(self, ds):
        """A write whose OK packet carries an info message reaches the client with that message intact."""
        updater = self.session("wire").login("smoke-updater", ["system:production-viewer", "system:production-updater"])
        utoken = self.wire_token(updater)
        for sql, info in (("INSERT INTO smoke_ddl VALUES (1, 'a'), (2, 'b')", "Records: 2"),
                          ("UPDATE smoke_ddl SET note = 'c' WHERE id = 1", "Rows matched: 1")):
            ok, rows, err = self.wire_sql(ds, "smoke-updater", utoken, sql, verbose=True)
            expect(ok, f"wire {sql.split()[0]} as updater failed: {err.strip()}")
            expect(any(r[0].startswith(info) for r in rows), f"wire {sql.split()[0]} OK info not relayed intact: {rows}")

    def leg_pmon(self, ds):
        a = self.args
        env = self.pmon_env()
        log = open(os.path.join(self.logs, f"pmon-{ds['engine']}.log"), "a")
        try:
            cli = self.pmon_login(ds, env, log)
            ok, rows, err = self.pmon_sql(ds, cli, "SELECT id, email FROM users ORDER BY id", log)
            expect(ok, f"client via pmon failed: {err.strip()}")
            expect(len(rows) == 3 and all(r[1] == MASK for r in rows), f"result via pmon not masked: {rows}")
        finally:
            run([a.pmon, "logout"], env=env)
        self.produced.setdefault(ds["engine"], set()).add("pmon")

    def pmon_env(self):
        a = self.args
        return dict(os.environ, PMON_CONFIG_DIR=a.pmon_dir, PMON_PORT_BASE=str(a.pmon_port_base), PMON_NO_BROWSER="1")

    def pmon_login(self, ds, env, log, principal="smoke-pmon", roles=("system:production-viewer",)):
        """Log pmon in through the device flow; returns `pmon show <ds> --cli`."""
        a = self.args
        user = self.session("pmon").login(principal, list(roles))
        proc = subprocess.Popen([a.pmon, "login", "--url", a.cp, "--ttl", "600"], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        try:
            code = None
            deadline = time.time() + 60
            while code is None and time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                log.write(line)
                m = re.search(r"enter this code when asked: (\S+)", line)
                if m:
                    code = m.group(1)
            expect(code, "pmon login printed no device code")
            user.call("POST", "/auth/device/confirm", {"userCode": code})
            status, _, headers = user.call("GET", f"/auth/device/authorize?user_code={code}", ok=(302, 303))
            expect("/device/success" in headers.get("Location", ""), f"device authorize redirected to {headers.get('Location')}")
            out, _ = proc.communicate(timeout=60)
            log.write(out)
            expect(proc.returncode == 0 and f"logged in as {principal}" in out, f"pmon login did not finish: {out.strip()}")
            deadline = time.time() + 30
            while time.time() < deadline:
                rc, cli, err = run([a.pmon, "show", ds["name"], "--cli"], env=env)
                if rc == 0:
                    break
                time.sleep(1)
            expect(rc == 0, f"pmon show {ds['name']} --cli failed: {err.strip()}")
            return cli.strip()
        finally:
            if proc.poll() is None:
                proc.kill()

    def pmon_sql(self, ds, cli, sql, log):
        """Run one statement with the client command pmon printed; returns (ok, rows, stderr)."""
        if ds["engine"] == "athena":
            try:
                return True, self.athena_via_pmon(cli, log, sql), ""
            except Fail as e:
                return False, [], str(e)
        argv = shlex.split(cli)
        if ds["engine"] == "mysql":
            argv += ["--protocol=tcp", "--ssl-mode=DISABLED", "-N", "-B", "-e", sql]
        else:
            argv += ["-At", "-F", "\t", "-c", sql]
        rc, out, err = run(argv)
        log.write(f"$ {argv[0]} ... {sql} -> {rc}\n{out}{err}")
        return rc == 0, [l.split("\t") for l in out.splitlines() if l], err

    def pmon_aws_env(self, cli):
        """The env of the `VAR=… aws athena start-query-execution …` command `pmon show --cli` prints."""
        words = shlex.split(cli)
        env = dict(os.environ)
        while words and "=" in words[0] and not words[0].startswith("aws"):
            key, value = words.pop(0).split("=", 1)
            env[key] = value
        expect(words[:2] == ["aws", "athena"], f"pmon show --cli did not print an aws athena command: {cli}")
        return env

    def athena_via_pmon(self, cli, log, sql):
        """Run a masked read as the AWS CLI would: SigV4 with the local credentials from `pmon show --cli`, at pmon's
        local Athena endpoint."""
        env = self.pmon_aws_env(cli)
        endpoint = env["AWS_ENDPOINT_URL_ATHENA"]
        context = json.dumps({"Catalog": "AwsDataCatalog", "Database": "acme"})

        def aws(*args):
            rc, out, err = run(["aws", "athena", *args, "--endpoint-url", endpoint, "--output", "json"], env=env, timeout=120)
            log.write(f"$ aws athena {args[0]} -> {rc}\n{out}{err}")
            expect(rc == 0, f"aws athena {args[0]} via pmon failed: {err.strip()}")
            return json.loads(out) if out.strip() else {}
        qid = aws("start-query-execution", "--query-string", sql, "--work-group", "primary",
                  "--query-execution-context", context)["QueryExecutionId"]
        deadline = time.time() + 60
        while True:
            state = aws("get-query-execution", "--query-execution-id", qid)["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED") or time.time() > deadline:
                break
            time.sleep(0.2)
        expect(state == "SUCCEEDED", f"execution via pmon ended {state}")
        result = aws("get-query-results", "--query-execution-id", qid)
        rows = [[d.get("VarCharValue") for d in row["Data"]] for row in result["ResultSet"]["Rows"]]
        return rows[1:]

    def leg_workflow(self, ds):
        requester = self.session("workflow").login("smoke-requester", ["system:production-viewer"])
        role_id = self.roles["system:production-pii-accessor"]
        _, created, _ = requester.call("POST", "/api/approvals", {
            "datasourceId": ds["id"], "sql": "SELECT id, email FROM users ORDER BY id",
            "title": "smoke", "reason": "smoke test", "roleId": role_id})
        rid = created["request"]["id"]
        self.admin.call("POST", f"/api/approvals/{rid}/approve", {"revision": created["request"]["revision"]})
        self.admin.call("POST", f"/api/approvals/{rid}/execute")
        deadline = time.time() + 90
        while True:
            _, detail, _ = self.admin.call("GET", f"/api/approvals/{rid}")
            status = (detail.get("result") or {}).get("status")
            if status in ("DONE", "FAILED") or time.time() > deadline:
                break
            time.sleep(0.5)
        expect(status == "DONE", f"approval {rid} did not finish: status={status} request={detail['request'].get('status')} denyReason={detail['request'].get('denyReason')}")
        expect(detail["request"]["executeAs"] == ["system:production-pii-accessor"], f"executeAs: {detail['request']['executeAs']}")
        # A debug login ends the principal's earlier web session, so each view logs in afresh.
        trusted = self.session("workflow").login("smoke-requester", ["system:production-viewer"], TRUSTED_IP)
        _, view, _ = trusted.call("GET", f"/api/approvals/{rid}/result")
        expect(view["decision"] == "ALLOW" and all("@" in r[1] for r in view["rows"]),
               f"stored result should be cleartext for the requester on the trusted network: {view['decision']} {view['rows']}")
        requester = self.session("workflow").login("smoke-requester", ["system:production-viewer"])
        _, view, _ = requester.call("GET", f"/api/approvals/{rid}/result")
        expect(view["decision"] == "MASK" and all(r[1] == MASK for r in view["rows"]),
               f"stored result should re-mask for the requester off the trusted network: {view['decision']} {view['rows']}")
        other = self.session("workflow").login("smoke-other", ["system:production-viewer"], TRUSTED_IP)
        status, _, _ = other.call("GET", f"/api/approvals/{rid}/result", ok=None)
        expect(status in (403, 404), f"a non-party viewer got {status} on the stored result")
        self.produced.setdefault(ds["engine"], set()).add("workflow")
        self.produced.setdefault("approval_ids", set()).add(rid)

    def leg_github(self, ds):
        # One engine is enough to prove the flow; MySQL is the primary target.
        if not self.github or not self.args.pm_ci or ds["engine"] != "mysql":
            raise Skip()
        gh, repo, a = self.github, GITHUB_REPO, self.args
        work = tempfile.mkdtemp(prefix="pm-smoke-github-")
        gh.repo_dir = work

        def git(*args):
            rc, out, err = run(["git", "-c", "user.name=dev", "-c", f"user.email={GITHUB_DEV_EMAIL}", *args], cwd=work)
            expect(rc == 0, f"git {args[0]}: {err.strip()}")
            return out.strip()

        def commit(path, content, msg):
            os.makedirs(os.path.join(work, os.path.dirname(path)), exist_ok=True)
            with open(os.path.join(work, path), "w") as f:
                f.write(content)
            git("add", "-A")
            git("commit", "-q", "-m", msg)
            return git("rev-parse", "HEAD")

        def file(head):
            env = dict(os.environ, ACTIONS_ID_TOKEN_REQUEST_URL=gh.token_url, ACTIONS_ID_TOKEN_REQUEST_TOKEN="smoke",
                       PM_CI_SERVER_URL=a.cp, PM_CI_AUDIENCE="smoke-github")
            rc, out, err = run([a.pm_ci, "file", "--repository", repo, "--pr", "1", "--base", base, "--head", head,
                                "--dir", "db", "--datasource", ds["name"], "--schema", "acme",
                                "--role", "system:production-architect"], env=env, cwd=work)
            expect(rc == 0, f"pm-ci file -> {rc}: {(out + err).strip()[-400:]}")

        def detail(rid):
            return self.admin.call("GET", f"/api/approvals/{rid}")[1]["request"]

        def wait(desc, fn, timeout=90):
            deadline = time.time() + timeout
            while time.time() < deadline:
                v = fn()
                if v:
                    return v
                time.sleep(1)
            raise Fail(f"timed out waiting for {desc}")

        table = f"gh_smoke_{int(time.time())}"
        path = "db/0001_create.sql"
        git("init", "-q", "-b", "main")
        commit("README.md", "smoke\n", "base")
        base = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "change")
        head = commit(path, f"CREATE TABLE {table} (id INT PRIMARY KEY);\n", "add a table")
        gh.claims = {"sub": f"repo:{repo}:pull_request", "repository": repo, "repository_id": "1",
                     "ref": "refs/pull/1/merge", "base_ref": "main", "event_name": "pull_request", "actor": GITHUB_DEV[0],
                     "workflow_ref": f"{repo}/.github/workflows/sql.yml@refs/pull/1/merge"}
        gh.open_pr(repo, 1, head, GITHUB_DEV, GITHUB_DEV_EMAIL, [path])
        file(head)
        req = wait("the filed request", lambda: next((r for r in self.admin.call("GET", "/api/approvals/inbox")[1]
                                                      if (r.get("pullRequest") or {}).get("repository") == repo), None))
        expect(req["revision"] == 1, f"a new request is revision 1: {req['revision']}")
        expect((gh.check(repo, head) or {}).get("status") == "in_progress", f"query executed is pending: {gh.check(repo, head)}")

        # An edit before approval changes the same request.
        head = commit(path, f"CREATE TABLE {table} (id BIGINT PRIMARY KEY);\n", "widen the key")
        gh.update_pr(repo, 1, head=head)
        file(head)
        edited = detail(req["id"])
        expect((edited["status"], edited["revision"]) == ("PENDING", 2), f"the edit is revision 2: {edited['status']} {edited['revision']}")
        status, body, _ = self.admin.call("POST", f"/api/approvals/{req['id']}/approve", {"revision": 1}, ok=None)
        expect(status == 409 and body.get("code") == "approval.request_changed", f"approving revision 1 is refused: {status} {body}")
        self.admin.call("POST", f"/api/approvals/{req['id']}/approve", {"revision": 2})

        gh.update_pr(repo, 1, autoMerge=(*GITHUB_DEV, dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))
        wait("the run on auto-merge", lambda: detail(req["id"])["status"] in ("EXECUTED", "FAILED"))
        expect(detail(req["id"])["status"] == "EXECUTED", f"the run failed: {detail(req['id'])}")
        wait("query executed green", lambda: (gh.check(repo, head) or {}).get("conclusion") == "success")
        wait("the PR comment reports the run", lambda: any("Statements run" in c for c in gh.comments_on(repo, 1)))

        gh.update_pr(repo, 1, state="MERGED", merged=True, mergeCommit=head,
                     mergedAt=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        wait("the merge recorded", lambda: detail(req["id"]).get("mergedAt"))

    def leg_rate(self, ds):
        principal = f"smoke-rated-{ds['engine']}"
        rated = self.session("rate").login(principal, ["system:production-viewer", f"smoke-rate-{ds['engine']}"])
        r = rated.query(ds["id"], "SELECT id FROM users ORDER BY id")
        expect(r["decision"] == "ALLOW", f"first capped query: expected ALLOW, got {r['decision']} {r.get('denyReason')}")
        expect(len(r["rows"]) == 2 and r.get("truncatedByCap"), f"row cap 2 not applied: rows={len(r['rows'])} truncatedByCap={r.get('truncatedByCap')}")
        r = rated.query(ds["id"], "SELECT id FROM users")
        expect(r["decision"] == "DENY" and "rate 2/1h spent" in (r.get("denyReason") or ""),
               f"editor query past the rate: expected DENY naming 'rate 2/1h spent', got {r['decision']} {r.get('denyReason')}")
        token = self.wire_token(rated)
        ok, rows, err = self.wire_sql(ds, principal, token, "SELECT id FROM users")
        expect(not ok and "rate 2/1h spent" in err, f"wire query past the rate: expected a deny naming the rate, got ok={ok} rows={rows} err={err.strip()}")
        self.produced.setdefault(ds["engine"], set()).add("rate")

    def leg_native(self, ds):
        """Every Athena API call the proxy reads, sent by the AWS CLI through pmon: what smoke-native's scoped
        native.invoke policy names reaches the target, the rest is refused at the proxy, a principal holding no
        native.invoke is refused everything but SQL, and executions stay with the principal who started them."""
        if ds["engine"] != "athena":
            raise Skip()
        wg, cat, db, table, other = os.environ.get("SMOKE_ATHENA_TARGET", "primary,AwsDataCatalog,acme,users,accounts").split(",")
        self.native_policy(wg, cat, db, table)
        log = open(os.path.join(self.logs, "native.log"), "a")
        env = self.pmon_env()
        native = self.session("native").login("smoke-native", ["system:production-viewer", "smoke-native"])
        viewer = self.session("native").login("smoke-viewer", ["system:production-viewer"])
        ntoken, vtoken = self.wire_token(native), self.wire_token(viewer)
        try:
            aws_env = self.pmon_aws_env(self.pmon_login(ds, env, log, "smoke-native", ["system:production-viewer", "smoke-native"]))
            self.native_calls(ds, log, aws_env, ntoken, vtoken, wg, cat, db, table, other)
        finally:
            run([self.args.pmon, "logout"], env=env)
        self.produced.setdefault(ds["engine"], set()).add("native")

    def native_policy(self, wg, cat, db, table):
        a = self.admin
        _, roles, _ = a.call("GET", "/api/roles")
        if "smoke-native" not in {r["name"] for r in roles}:
            a.call("POST", "/api/roles", {"name": "smoke-native"})
        read = 'context.native_operation like "athena:Get*" || context.native_operation like "athena:List*" || context.native_operation like "athena:BatchGet*"'
        cat, db, table = cat.lower(), db.lower(), table.lower()
        src = f'''permit(principal in Role::"smoke-native", action == Action::"native.invoke", resource)
when {{ context has native_operation && (
  ({read}) && (resource.kind == "datasource" || resource.kind == "tagged-resource" || resource.kind == "named-query"
    || resource.kind == "prepared-statement" || resource.kind == "workgroup" && resource.id == "{wg}"
    || resource.kind == "data-catalog" && resource.id == "{cat}" || resource.kind == "database" && resource.id == "{cat}/{db}"
    || resource.kind == "table" && resource.id == "{cat}/{db}/{table}")
  || resource.kind == "prepared-statement" && resource.id like "{wg}/smoke_*"
  || resource.kind == "named-query"
  || resource.kind == "workgroup" && resource.id == "{wg}" && context.native_operation == "athena:CreateNamedQuery") }};'''
        _, policies, _ = a.call("GET", "/api/policies")
        if "smoke:native" not in {p["name"] for p in policies}:
            a.call("POST", "/api/policies", {"name": "smoke:native", "cedarSrc": src})

    def native_calls(self, ds, log, aws_env, ntoken, vtoken, wg, cat, db, table, other):
        def outcome(status, body):
            if status == 200:
                return "ok"
            if body.get("__type") == "AccessDeniedException" and str(body.get("Message", "")).startswith("athena."):
                return "refused"
            return "target"

        def direct(token, op, body):
            status, r = self.athena_call(ds, token, op, body)
            log.write(f"direct {op} {json.dumps(body)} -> {status} {json.dumps(r)[:300]}\n")
            return outcome(status, r), r

        def cli(op, body):
            """One call as smoke-native, by the AWS CLI at pmon's local endpoint; ops the CLI lacks go direct."""
            name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "-", op).lower()
            if op in ("GetQueryResultsStream",):
                return direct(ntoken, op, body)
            rc, out, err = run(["aws", "athena", name, "--cli-input-json", json.dumps(body), "--endpoint-url",
                                aws_env["AWS_ENDPOINT_URL_ATHENA"], "--output", "json"], env=aws_env, timeout=120)
            log.write(f"cli {op} {json.dumps(body)} -> {rc} {out[:300]}{err[:300]}\n")
            if rc == 0:
                return "ok", json.loads(out) if out.strip() else {}
            if "AccessDeniedException" in err and re.search(r": athena\.[a-z_]+", err):
                return "refused", {}
            return "target", {"error": err.strip()}

        def check(who, op, body, want, call):
            got, r = call(op, body)
            if want == "fwd":
                expect(got != "refused", f"{who} {op}: refused at the proxy, expected it to reach the target")
            else:
                expect(got == want, f"{who} {op}: {got}, expected {want} {r.get('error', '')}")
            return r

        arn = f"arn:aws:athena:us-east-1:000000000000:workgroup/{wg}"
        spark = {"WorkGroup": wg, "SessionId": "smoke-session"}
        calls = [
            ("ListWorkGroups", {}, "ok"), ("GetWorkGroup", {"WorkGroup": wg}, "ok"),
            ("GetWorkGroup", {"WorkGroup": "smoke-other"}, "refused"),
            ("ListDataCatalogs", {}, "ok"), ("GetDataCatalog", {"Name": cat}, "fwd"), ("GetDataCatalog", {"Name": "smoke-other"}, "refused"),
            ("ListDatabases", {"CatalogName": cat}, "ok"), ("GetDatabase", {"CatalogName": cat, "DatabaseName": db}, "ok"),
            ("GetDatabase", {"CatalogName": cat, "DatabaseName": "smoke_other"}, "refused"),
            ("ListTableMetadata", {"CatalogName": cat, "DatabaseName": db}, "ok"),
            ("GetTableMetadata", {"CatalogName": cat, "DatabaseName": db, "TableName": table}, "ok"),
            ("GetTableMetadata", {"CatalogName": cat.upper(), "DatabaseName": db.upper(), "TableName": table.upper()}, "ok"),
            ("GetTableMetadata", {"CatalogName": cat, "DatabaseName": db, "TableName": other}, "refused"),
            ("ListPreparedStatements", {"WorkGroup": wg}, "ok"), ("ListNamedQueries", {"WorkGroup": wg}, "ok"),
            ("ListEngineVersions", {}, "fwd"), ("ListApplicationDPUSizes", {}, "fwd"), ("ListCapacityReservations", {}, "fwd"),
            ("GetCapacityReservation", {"Name": "smoke-cr"}, "refused"),
            ("GetCapacityAssignmentConfiguration", {"CapacityReservationName": "smoke-cr"}, "refused"),
            ("ListTagsForResource", {"ResourceARN": arn}, "fwd"), ("GetResourceDashboard", {"ResourceARN": arn}, "fwd"),
            ("CreateWorkGroup", {"Name": "smoke-other"}, "refused"), ("UpdateWorkGroup", {"WorkGroup": "smoke-other", "Description": "smoke"}, "refused"),
            ("DeleteWorkGroup", {"WorkGroup": "smoke-other"}, "refused"),
            ("CreateDataCatalog", {"Name": "smoke-other", "Type": "HIVE"}, "refused"),
            ("UpdateDataCatalog", {"Name": "smoke-other", "Type": "GLUE"}, "refused"), ("DeleteDataCatalog", {"Name": "smoke-other"}, "refused"),
            ("CreateCapacityReservation", {"Name": "smoke-cr", "TargetDpus": 24}, "refused"),
            ("UpdateCapacityReservation", {"Name": "smoke-cr", "TargetDpus": 24}, "refused"),
            ("CancelCapacityReservation", {"Name": "smoke-cr"}, "refused"), ("DeleteCapacityReservation", {"Name": "smoke-cr"}, "refused"),
            ("PutCapacityAssignmentConfiguration", {"CapacityReservationName": "smoke-cr", "CapacityAssignments": []}, "refused"),
            ("TagResource", {"ResourceARN": arn, "Tags": [{"Key": "smoke", "Value": "1"}]}, "refused"),
            ("UntagResource", {"ResourceARN": arn, "TagKeys": ["smoke"]}, "refused"),
            ("CreatePreparedStatement", {"WorkGroup": wg, "StatementName": "other_ps", "QueryStatement": "SELECT 1"}, "refused"),
            ("StartSession", {"WorkGroup": wg, "EngineConfiguration": {"MaxConcurrentDpus": 2}}, "refused"),
            ("StartCalculationExecution", {"SessionId": "smoke-session", "CodeBlock": "1"}, "refused"),
            ("CreateNotebook", {"WorkGroup": wg, "Name": "smoke"}, "refused"),
            ("GetSessionEndpoint", {"SessionId": "smoke-session"}, "refused"), ("ListSessions", {"WorkGroup": wg}, "refused"),
        ]
        for op, body, want in calls:
            check("smoke-native", op, body, want, cli)
        # Bodies the CLI would refuse to send still reach the proxy from other clients.
        check("smoke-native", "NotAnOperation", {}, "refused", lambda op, body: direct(ntoken, op, body))
        check("smoke-native", "StartCalculationExecution", spark, "refused", lambda op, body: direct(ntoken, op, body))
        for op, body, _ in calls:
            check("smoke-viewer", op, body, "refused", lambda op, body: direct(vtoken, op, body))

        ps = {"WorkGroup": wg, "StatementName": "smoke_ps"}
        check("smoke-native", "CreatePreparedStatement", {**ps, "QueryStatement": "SELECT 1"}, "ok", cli)
        try:
            check("smoke-native", "GetPreparedStatement", ps, "ok", cli)
            check("smoke-native", "BatchGetPreparedStatement", {"WorkGroup": wg, "PreparedStatementNames": ["smoke_ps"]}, "fwd", cli)
            check("smoke-native", "UpdatePreparedStatement", {**ps, "QueryStatement": "SELECT 2"}, "fwd", cli)
            check("smoke-viewer", "GetPreparedStatement", ps, "refused", lambda op, body: direct(vtoken, op, body))
        finally:
            check("smoke-native", "DeletePreparedStatement", ps, "ok", cli)
        nq = check("smoke-native", "CreateNamedQuery", {"Name": "smoke", "Database": db, "QueryString": "SELECT 1", "WorkGroup": wg}, "ok", cli)
        nid = nq["NamedQueryId"]
        try:
            check("smoke-native", "GetNamedQuery", {"NamedQueryId": nid}, "ok", cli)
            check("smoke-native", "BatchGetNamedQuery", {"NamedQueryIds": [nid]}, "ok", cli)
            check("smoke-native", "UpdateNamedQuery", {"NamedQueryId": nid, "Name": "smoke", "QueryString": "SELECT 2"}, "fwd", cli)
            check("smoke-viewer", "GetNamedQuery", {"NamedQueryId": nid}, "refused", lambda op, body: direct(vtoken, op, body))
        finally:
            check("smoke-native", "DeleteNamedQuery", {"NamedQueryId": nid}, "ok", cli)

        def start(call):
            r = check("smoke", "StartQueryExecution", {"QueryString": "SELECT 1", "WorkGroup": wg, "ClientRequestToken": str(uuid.uuid4()),
                                                       "QueryExecutionContext": {"Catalog": cat, "Database": db}}, "ok", call)
            qid, deadline = r["QueryExecutionId"], time.time() + 120
            while time.time() < deadline:
                state = call("GetQueryExecution", {"QueryExecutionId": qid})[1]["QueryExecution"]["Status"]["State"]
                if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                    break
                time.sleep(1)
            expect(state == "SUCCEEDED", f"SELECT 1 ended {state}")
            return qid
        mine, theirs = start(cli), start(lambda op, body: direct(vtoken, op, body))
        for op, body, want in [
            ("GetQueryExecution", {"QueryExecutionId": mine}, "ok"), ("GetQueryResults", {"QueryExecutionId": mine}, "ok"),
            ("GetQueryRuntimeStatistics", {"QueryExecutionId": mine}, "fwd"), ("GetQueryResultsStream", {"QueryExecutionId": mine}, "refused"),
            ("BatchGetQueryExecution", {"QueryExecutionIds": [mine]}, "ok"),
            ("BatchGetQueryExecution", {"QueryExecutionIds": [mine, theirs]}, "refused"),
            ("GetQueryExecution", {"QueryExecutionId": theirs}, "refused"), ("GetQueryResults", {"QueryExecutionId": theirs}, "refused"),
            ("GetQueryRuntimeStatistics", {"QueryExecutionId": theirs}, "refused"),
            ("StopQueryExecution", {"QueryExecutionId": theirs}, "refused"),
        ]:
            check("smoke-native", op, body, want, cli)
        for who, call, own, other_id in (("smoke-native", cli, mine, theirs),
                                         ("smoke-viewer", lambda op, body: direct(vtoken, op, body), theirs, mine)):
            ids = check(who, "ListQueryExecutions", {"WorkGroup": wg}, "ok", call).get("QueryExecutionIds", [])
            expect(own in ids and other_id not in ids, f"{who} ListQueryExecutions: own {own in ids}, other's {other_id in ids}, {len(ids)} ids")
        log.write(f"native: {len(calls)} calls for each principal, plus prepared statements, named queries and executions\n")

    def leg_audit(self, ds):
        _, events, _ = self.admin.call("GET", "/api/audit?limit=500")
        mine = [e for e in events if e["datasource"] == ds["name"]]
        ran = self.produced.get(ds["engine"], set())

        def has(kind, principal, channel, decision=None):
            return any(e["kind"] == kind and e["principal"] == principal and e.get("channel") == channel
                       and (decision is None or e["decision"] == decision) for e in mine)
        if "wire" in ran:
            expect(has("decision", "smoke-viewer", "wire", "MASK"), "no wire MASK decision for smoke-viewer in the audit log")
            expect(has("decision", "smoke-viewer", "wire", "DENY"), "no wire DENY decision for smoke-viewer in the audit log")
            expect(has("completion", "smoke-viewer", "wire"), "no wire completion event for smoke-viewer")
        if "editor" in ran:
            expect(has("decision", "smoke-viewer", "editor", "MASK"), "no editor MASK decision for smoke-viewer in the audit log")
            expect(has("decision", "smoke-pii", "editor", "ALLOW"), "no editor ALLOW decision for smoke-pii in the audit log")
        if "workflow" in ran:
            expect(any(e["kind"] == "admin" and e["principal"] == "smoke-admin" and e.get("authzAction") == "task.approve" for e in events),
                   "no task.approve admin event by smoke-admin in the audit log")
            expect(has("decision", "smoke-admin", "workflow-executor", "ALLOW"), "no workflow-executor decision by the approver for the approved run")
            expect(has("approval_lifecycle", "smoke-admin", "workflow-executor"), "no approval_lifecycle event for the approver's execution")
            expect(has("approval_lifecycle", "smoke-requester", "workflow-viewer"), "no approval_lifecycle event for the requester's result view")
        if ds["row"] == self.args.datasource[-1][3]:
            self.verify_chain()

    def leg_names(self, ds):
        """Identifier spellings: classify and forbid in one spelling, read in others, on every channel."""
        spec, row = NAMES[ds["row"]], ds["row"]
        catalog, schema = CATALOGS[ds["engine"]]
        a, fixed = self.admin, self.fixed_mask_fn
        checks = []

        def check(channel, what, fn, pending=None):
            try:
                fn()
                checks.append((channel, what, None, pending))
            except Fail as e:
                checks.append((channel, what, str(e), pending))

        viewer = self.session("names").login("smoke-viewer", ["system:production-viewer"])

        def editor(sql):
            status, r, _ = viewer.call("POST", f"/api/datasources/{ds['id']}/query", {"sql": sql, "maxRows": 500}, ok=None)
            if status != 200 or r.get("decision") == "DENY":
                return False, [], f"{status} {r.get('decision') if r else ''} {(r or {}).get('denyReason') or (r or {}).get('code')}"
            return True, r["rows"], ""

        for table, column, real_tables, *pending in spec["refuse"]:
            def refused():
                body = {"catalog": catalog, "schema": schema, "table": table, "column": column}
                status, _, _ = a.call("PUT", f"/api/datasources/{ds['id']}/classification",
                                         {**body, "tags": ["pii"], "maskFnId": fixed}, ok=None)
                if status >= 400:
                    return
                try:
                    for real in real_tables:
                        cols = viewer.call("GET", f"/api/datasources/{ds['id']}/table-detail?catalog={catalog}&schema={schema}&table={real}")[1]["columns"]
                        tagged = [c["name"] for c in cols if (c.get("classification") or {}).get("tags")]
                        expect(not tagged, f"classifying {table}.{column} returned {status} and {real} shows {tagged} classified")
                        ok, rows, err = editor(f"SELECT id, {column} FROM {real} ORDER BY id")
                        expect(ok and len(rows) == 3 and all(r[1] != MASK for r in rows), f"classifying {table}.{column} returned {status} and {real} reads ok={ok} {rows} {err}")
                finally:
                    a.call("DELETE", f"/api/datasources/{ds['id']}/classification", body, ok=None)
            check("api", f"classify {table}.{column} is refused or attaches to nothing", refused, *pending)
        for table, column in spec["classify"]:
            a.call("PUT", f"/api/datasources/{ds['id']}/classification", {
                "catalog": catalog, "schema": schema, "table": table, "column": column, "tags": ["pii"], "maskFnId": fixed})
        table, column = spec["forbid"]
        name = f"smoke:names-{row}"
        _, policies, _ = a.call("GET", "/api/policies")
        if name not in {p["name"] for p in policies}:
            a.call("POST", "/api/policies", {"name": name, "cedarSrc":
                   f'forbid(principal, action in [Action::"result.read.unmasked", Action::"result.read.masked"], '
                   f'resource == Column::"{ds["name"]}/{catalog}/{schema}/{table}/{column}");'})

        details = {}
        for table, column, *pending in spec["detail"]:
            def classified():
                if table not in details:
                    details[table] = viewer.call("GET", f"/api/datasources/{ds['id']}/table-detail?catalog={catalog}&schema={schema}&table={table}")[1]
                col = next((c for c in details[table]["columns"] if c["name"] == column), None)
                expect(col is not None, f"table detail of {table} has no column {column}")
                expect("pii" in (col.get("classification") or {}).get("tags", []), f"table detail shows {table}.{column} unclassified: {col}")
            check("detail", f"{table}.{column} shows its classification", classified, *pending)
        token = self.wire_token(viewer)
        env = self.pmon_env()
        log = open(os.path.join(self.logs, f"names-{row}.log"), "a")
        channels = [("editor", editor), ("wire", lambda sql: self.wire_sql(ds, "smoke-viewer", token, sql))]
        try:
            cli = self.pmon_login(ds, env, log)
            channels.append(("pmon", lambda sql: self.pmon_sql(ds, cli, sql, log)))
        except Fail as e:
            checks.append(("pmon", "login", str(e), None))
        try:
            for channel, sql_fn in channels:
                for want, sql, *pending in spec["reads"]:
                    check(channel, sql, lambda: names_expect(want, *sql_fn(sql)), *pending)
        finally:
            run([self.args.pmon, "logout"], env=env)

        failed, counts = [], {}
        for channel, what, err, reason in checks:
            if err and reason:
                status, note = "SKIP", f"({reason}) observed: {err}"
            elif err:
                status, note = "FAIL", err
                failed.append(f"{channel}: {what}: {err}")
            elif reason:
                status, note = "UNEXPECTED PASS", f"drop its pending flag: ({reason})"
                self.unexpected.append(f"{row} {channel} {what}")
            else:
                status, note = "PASS", ""
            counts[status] = counts.get(status, 0) + 1
            print(f"  {row:11} names  {status:4} {channel:6} {what}  {note}", flush=True)
            log.write(f"{status} {channel} {what} {note}\n")
        print(f"  {row:11} names  " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())), flush=True)
        expect(not failed, f"{len(failed)} name check(s) failed; first: {failed[0] if failed else ''}")

    def verify_chain(self):
        env = dict(os.environ, PGTZ="UTC")
        rc, out, err = run(["psql", self.args.cp_db, "-At", "-c",
                            "SELECT row_to_json(a) FROM audit_event a ORDER BY id"], env=env, timeout=120)
        expect(rc == 0, f"reading audit_event: {err.strip()}")
        rows = [json.loads(l) for l in out.splitlines() if l]
        expect(len(rows) > 0, "audit_event is empty")
        prev = hashlib.sha256(b"pm-audit-genesis").digest()
        for i, row in enumerate(rows):
            expect(row["id"] == i + 1, f"audit id gap at {row['id']}")
            expect(bytes.fromhex(row["prev_hash"][2:]) == prev, f"audit event {row['id']}: prev_hash does not chain")
            got = bytes.fromhex(row["row_hash"][2:])
            expect(row_hash(row, prev) == got, f"audit event {row['id']}: row_hash does not match its fields")
            prev = got
        rc, out, _ = run(["psql", self.args.cp_db, "-At", "-c", "SELECT last_id, encode(head_hash, 'hex') FROM audit_chain_head WHERE id = 1"])
        last_id, head = out.strip().split("|")
        expect(int(last_id) == rows[-1]["id"] and bytes.fromhex(head) == prev, "audit_chain_head does not point at the last event")


def names_expect(want, ok, rows, err):
    if want == "deny":
        expect(not ok and "policy denies column" in err, f"expected a policy deny, got ok={ok} rows={rows} err={err.strip()}")
        return
    expect(ok, f"failed: {err.strip()}")
    if want == "mask":
        expect(len(rows) == 3 and all(r[1] == MASK for r in rows), f"not masked: {rows}")
    else:
        prefix = want.split(":", 1)[1]
        expect(len(rows) == 3 and all(r[1].startswith(prefix) for r in rows), f"expected cleartext {prefix}-*: {rows}")


def row_hash(row, prev):
    def s(v):
        b = v.encode()
        return struct.pack(">I", len(b)) + b

    def ns(v):
        return struct.pack(">I", 0xFFFFFFFF) if v is None else s(v)

    def i64(v):
        return struct.pack(">I", 8) + struct.pack(">q", int(v))

    def ni64(v):
        return struct.pack(">I", 0xFFFFFFFF) if v is None else i64(v)

    def arr(vals, sort):
        enc = [v.encode() for v in (vals or [])]
        if sort:
            enc.sort()
        return struct.pack(">I", len(enc)) + b"".join(struct.pack(">I", len(e)) + e for e in enc)

    ts = dt.datetime.fromisoformat(row["ts"])
    micros = (ts - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)) // dt.timedelta(microseconds=1)
    fields = (s(row["kind"]) + i64(micros) + s(row["principal"]) + arr(row["roles"], True) + s(row["datasource"])
              + ns(row["client_addr"]) + s(row["statement"]) + s(row["decision"]) + ns(row["failed_stage"])
              + arr(row["effective_namespace"], False) + arr(row["masked_columns"], True) + arr(row["pii_touched"], True)
              + i64(row["latency_ms"]) + ns(row["detail"]) + ns(row["channel"]) + arr(row["context_tags"], True)
              + ns(row["action"]) + ns(row["resource"]) + ns(row["outcome"]) + ni64(row["rows_returned"])
              + ni64(row["bytes_returned"]) + ni64(row["decision_id"]))
    return hashlib.sha256(b"pm-audit-event" + struct.pack(">I", 1) + struct.pack(">Q", row["id"]) + fields + prev).digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp", required=True)
    ap.add_argument("--web", required=True, help="the console started against --cp")
    ap.add_argument("--root", required=True, help="repository root (web/ holds the Playwright install)")
    ap.add_argument("--cp-db", required=True, help="psql conninfo for the control-plane store")
    ap.add_argument("--datasource", action="append", required=True, help="engine:name:proxyPort[:row]; row names the matrix row, the engine by default")
    ap.add_argument("--pmon", required=True)
    ap.add_argument("--pmon-dir", required=True)
    ap.add_argument("--pmon-port-base", type=int, required=True)
    ap.add_argument("--logs", required=True)
    ap.add_argument("--only", choices=LEGS)
    ap.add_argument("--pm-ci", help="the pm-ci binary the github leg files with")
    ap.add_argument("--github", help="tlsPort,httpPort,cert,key,signingKey,appId for the fake GitHub; the github leg skips without it")
    ap.add_argument("--engine", choices=list(NAMES), help="one matrix row")
    args = ap.parse_args()
    args.datasource = [(*f, f[0]) if len(f) == 3 else tuple(f) for f in (d.split(":") for d in args.datasource)]
    if args.engine:
        args.datasource = [d for d in args.datasource if d[3] == args.engine]

    stack = Stack(args)
    try:
        stack.seed()
    except Fail as e:
        print(f"SETUP FAILED: {e}")
        return 1
    results = []
    legs = [args.only] if args.only else LEGS
    for engine, _, _, row in args.datasource:
        ds = stack.datasources[row]
        for leg in legs:
            # A row beside its engine's own (mysql-lctn1) runs only the names leg.
            if row != engine and leg != "names":
                continue
            t0 = time.time()
            try:
                getattr(stack, f"leg_{leg}")(ds)
                results.append((row, leg, "PASS", ""))
            except Skip:
                results.append((row, leg, "-", ""))
                continue
            except Fail as e:
                results.append((row, leg, "FAIL", str(e)))
            except Exception as e:  # a crashed leg is a failed leg, with the crash as its message
                results.append((row, leg, "FAIL", f"{type(e).__name__}: {e}"))
            print(f"{row:11} {leg:9} {results[-1][2]:4} {time.time() - t0:5.1f}s  {results[-1][3]}", flush=True)
    print()
    print(f"{'engine':11} " + " ".join(f"{l:9}" for l in legs))
    for _, _, _, row in args.datasource:
        cells = {leg: status for r, leg, status, _ in results if r == row}
        print(f"{row:11} " + " ".join(f"{cells.get(l, '-'):9}" for l in legs))
    failed = [r for r in results if r[2] == "FAIL"]
    if stack.unexpected:
        print(f"\nUNEXPECTED PASS: {len(stack.unexpected)} pending-name-fix check(s) now pass; drop their pending flag in NAMES:")
        for u in stack.unexpected:
            print(f"  {u}")
    print(f"\nlogs: {args.logs}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
