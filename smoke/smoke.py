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
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

LEGS = ["editor", "browser", "wire", "pmon", "workflow", "rate", "audit"]
MASK = "####"
TRUSTED_IP = "100.100.1.8"
PRODUCTION_PRESETS = [-200, -201, -202, *range(-238, -229), -250, -251, -255, *range(-262, -255), -280, -300, -305, -306, -307]


class Fail(Exception):
    pass


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

    def session(self, name):
        return Session(self.args.cp, open(os.path.join(self.logs, name + ".log"), "a"))

    def seed(self):
        a = self.admin
        _, fns, _ = a.call("GET", "/api/mask-fns")
        fixed = next((f for f in fns if f["name"] == "smoke-fixed"), None) or a.call("POST", "/api/mask-fns", {"name": "smoke-fixed", "kind": "FIXED"})[1]
        for pid in PRODUCTION_PRESETS:
            a.call("POST", f"/api/policies/{pid}/enable")
        _, roles, _ = a.call("GET", "/api/roles")
        self.roles = {r["name"]: r["id"] for r in roles}
        for name in ("smoke-rate-mysql", "smoke-rate-postgres"):
            if name not in self.roles:
                self.roles[name] = a.call("POST", "/api/roles", {"name": name})[1]["id"]
        _, policies, _ = a.call("GET", "/api/policies")
        have = {p["name"] for p in policies}
        wanted = {
            "smoke:rate-mysql": '@cap("2, 2/1h") permit(principal in Role::"smoke-rate-mysql", action == Action::"result.cap", resource);',
            "smoke:rate-postgres": '@cap("2, 2/1h") permit(principal in Role::"smoke-rate-postgres", action == Action::"result.cap", resource);',
        }
        for name, src in wanted.items():
            if name not in have:
                a.call("POST", "/api/policies", {"name": name, "cedarSrc": src})
        _, listed, _ = a.call("GET", "/api/datasources")
        by_name = {d["name"]: d for d in listed}
        for engine, name, port in self.args.datasource:
            expect(name in by_name, f"datasource {name} is not registered (proxies: {sorted(by_name)})")
            d = by_name[name]
            expect("system:production" in d["tags"], f"{name} is not tagged system:production: {d['tags']}")
            catalog, schema = ("def", "acme") if engine == "mysql" else ("acme", "public")
            a.call("PUT", f"/api/datasources/{d['id']}/classification",
                   {"catalog": catalog, "schema": schema, "table": "users", "column": "email",
                    "tags": ["pii"], "maskFnId": fixed["id"]})
            self.datasources[engine] = {"id": d["id"], "name": name, "port": int(port), "engine": engine}

    # ---- wire clients -------------------------------------------------------------------------------
    def wire_sql(self, ds, principal, token, sql):
        """Run one statement through the proxy as a native client; returns (ok, rows, stderr)."""
        if ds["engine"] == "mysql":
            cmd = ["mysql", "--protocol=tcp", "-h", "127.0.0.1", "-P", str(ds["port"]), "-u", principal,
                   "--enable-cleartext-plugin", "--ssl-mode=DISABLED", "-N", "-B", "-e", sql, "acme"]
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
        catalog, schema = ("def", "acme") if ds["engine"] == "mysql" else ("acme", "public")
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
        ok, _, err = self.wire_sql(ds, "smoke-architect", atoken, "CREATE TABLE smoke_ddl (id INT, note VARCHAR(20))")
        expect(ok, f"DDL as architect failed: {err.strip()}")
        try:
            deadline = time.time() + 30
            while True:
                ok, rows, err = self.wire_sql(ds, "smoke-architect", atoken, "SELECT id, note FROM smoke_ddl")
                if ok or time.time() > deadline:
                    break
                time.sleep(1)
            expect(ok, f"read of a table created by DDL is still refused after the refetch window: {err.strip()}")
        finally:
            self.wire_sql(ds, "smoke-architect", atoken, "DROP TABLE smoke_ddl")
        self.produced.setdefault(ds["engine"], set()).add("wire")

    def leg_pmon(self, ds):
        a = self.args
        env = dict(os.environ, PMON_CONFIG_DIR=a.pmon_dir, PMON_PORT_BASE=str(a.pmon_port_base), PMON_NO_BROWSER="1")
        log = open(os.path.join(self.logs, f"pmon-{ds['engine']}.log"), "a")
        user = self.session("pmon").login("smoke-pmon", ["system:production-viewer"])
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
            expect(proc.returncode == 0 and "logged in as smoke-pmon" in out, f"pmon login did not finish: {out.strip()}")
            deadline = time.time() + 30
            while time.time() < deadline:
                rc, cli, err = run([a.pmon, "show", ds["name"], "--cli"], env=env)
                if rc == 0:
                    break
                time.sleep(1)
            expect(rc == 0, f"pmon show {ds['name']} --cli failed: {err.strip()}")
            argv = shlex.split(cli.strip())
            if ds["engine"] == "mysql":
                argv += ["--protocol=tcp", "--ssl-mode=DISABLED", "-N", "-B", "-e", "SELECT id, email FROM users ORDER BY id"]
            else:
                argv += ["-At", "-F", "\t", "-c", "SELECT id, email FROM users ORDER BY id"]
            rc, out, err = run(argv)
            log.write(f"$ {argv[0]} ... -> {rc}\n{out}{err}")
            expect(rc == 0, f"client via pmon failed: {err.strip()}")
            rows = [l.split("\t") for l in out.splitlines() if l]
            expect(len(rows) == 3 and all(r[1] == MASK for r in rows), f"result via pmon not masked: {rows}")
        finally:
            if proc.poll() is None:
                proc.kill()
            run([a.pmon, "logout"], env=env)
        self.produced.setdefault(ds["engine"], set()).add("pmon")

    def leg_workflow(self, ds):
        requester = self.session("workflow").login("smoke-requester", ["system:production-viewer"])
        role_id = self.roles["system:production-pii-accessor"]
        _, created, _ = requester.call("POST", "/api/approvals", {
            "datasourceId": ds["id"], "sql": "SELECT id, email FROM users ORDER BY id",
            "title": "smoke", "reason": "smoke test", "roleId": role_id})
        rid = created["request"]["id"]
        self.admin.call("POST", f"/api/approvals/{rid}/approve")
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
        if ds["engine"] == self.args.datasource[-1][0]:
            self.verify_chain()

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
    ap.add_argument("--datasource", action="append", required=True, help="engine:name:proxyPort")
    ap.add_argument("--pmon", required=True)
    ap.add_argument("--pmon-dir", required=True)
    ap.add_argument("--pmon-port-base", type=int, required=True)
    ap.add_argument("--logs", required=True)
    ap.add_argument("--only", choices=LEGS)
    ap.add_argument("--engine", choices=["mysql", "postgres"])
    args = ap.parse_args()
    args.datasource = [tuple(d.split(":")) for d in args.datasource]
    if args.engine:
        args.datasource = [d for d in args.datasource if d[0] == args.engine]

    stack = Stack(args)
    try:
        stack.seed()
    except Fail as e:
        print(f"SETUP FAILED: {e}")
        return 1
    results = []
    legs = [args.only] if args.only else LEGS
    for engine, _, _ in args.datasource:
        ds = stack.datasources[engine]
        for leg in legs:
            t0 = time.time()
            try:
                getattr(stack, f"leg_{leg}")(ds)
                results.append((engine, leg, "PASS", ""))
            except Fail as e:
                results.append((engine, leg, "FAIL", str(e)))
            except Exception as e:  # a crashed leg is a failed leg, with the crash as its message
                results.append((engine, leg, "FAIL", f"{type(e).__name__}: {e}"))
            print(f"{engine:9} {leg:9} {results[-1][2]:4} {time.time() - t0:5.1f}s  {results[-1][3]}", flush=True)
    athena = "SKIP (PM_SMOKE_ATHENA unset)" if not os.environ.get("PM_SMOKE_ATHENA") else "FAIL athena: no provider in this checkout"
    print()
    print(f"{'engine':9} " + " ".join(f"{l:9}" for l in legs))
    for engine, _, _ in args.datasource:
        cells = {leg: status for e, leg, status, _ in results if e == engine}
        print(f"{engine:9} " + " ".join(f"{cells.get(l, '-'):9}" for l in legs))
    print(f"{'athena':9} {athena}")
    failed = [r for r in results if r[2] == "FAIL"] + ([athena] if athena.startswith("FAIL") else [])
    print(f"\nlogs: {args.logs}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
