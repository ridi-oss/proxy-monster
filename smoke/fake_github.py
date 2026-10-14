"""A fake GitHub for the smoke test's github leg.

It answers the REST and GraphQL calls the control plane's GitHub adapter makes, serves an OIDC issuer (discovery
and JWKS) for CI tokens, and the Actions token endpoint pm-ci asks for one. The API and the issuer are HTTPS,
since the control plane only trusts an HTTPS issuer; the token endpoint is plain HTTP, as pm-ci calls it.
"""
import base64
import datetime as dt
import json
import re
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGitHub:
    def __init__(self, tls_port, http_port, cert, key, signing_key, app_id, repo_dir=None):
        self.issuer = f"https://127.0.0.1:{tls_port}"
        self.token_url = f"http://127.0.0.1:{http_port}/token"
        self.signing_key = signing_key
        self.app_id = app_id
        self.repo_dir = repo_dir
        self.lock = threading.Lock()
        self.prs = {}
        self.required = {}
        self.check_runs = []
        self.comments = []
        self.claims = {}
        modulus = subprocess.run(["openssl", "rsa", "-in", signing_key, "-noout", "-modulus"],
                                 capture_output=True, text=True, check=True).stdout.strip().split("=", 1)[1]
        self.jwk = {"kty": "RSA", "kid": "smoke", "use": "sig", "alg": "RS256", "n": b64url(bytes.fromhex(modulus)), "e": "AQAB"}
        tls = ThreadingHTTPServer(("127.0.0.1", tls_port), self._handler())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        plain = ThreadingHTTPServer(("127.0.0.1", http_port), self._handler())
        for server in (tls, plain):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    # ---- what the smoke leg drives -------------------------------------------------------------------
    def open_pr(self, repo, number, head, author, email, files, required=("build",)):
        with self.lock:
            self.prs[(repo, number)] = {
                "number": number, "state": "OPEN", "merged": False, "mergedAt": None, "mergeCommit": None,
                "head": head, "base": "main", "author": author, "email": email, "autoMerge": None,
                "reviews": [], "files": files, "checks": list(required),
            }
            self.required[(repo, "main")] = list(required) + ["query executed"]

    def update_pr(self, repo, number, **fields):
        with self.lock:
            self.prs[(repo, number)].update(fields)

    def check(self, repo, sha, name="query executed"):
        with self.lock:
            runs = [r for r in self.check_runs if r["repo"] == repo and r["head_sha"] == sha and r["name"] == name]
            return dict(runs[-1]) if runs else None

    def comments_on(self, repo, number):
        with self.lock:
            return [c["body"] for c in self.comments if c["repo"] == repo and c["pr"] == number]

    def ci_token(self, audience):
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": audience, "iat": now, "nbf": now, "exp": now + 300, **self.claims}
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "smoke"}).encode())
        payload = b64url(json.dumps(claims).encode())
        signing_input = f"{header}.{payload}".encode()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.signing_key],
                             input=signing_input, capture_output=True, check=True).stdout
        return f"{header}.{payload}.{b64url(sig)}"

    # ---- GitHub's answers ----------------------------------------------------------------------------
    # Only the fields the control plane asks for: its GraphQL client rejects any other.
    def _pr_node(self, pr):
        user = lambda u: {"login": u[0], "databaseId": u[1]} if u else None
        rollup = {"contexts": {"pageInfo": {"hasNextPage": False}, "nodes": [
            {"__typename": "CheckRun", "name": c, "status": "COMPLETED", "conclusion": "SUCCESS", "isRequired": True}
            for c in pr["checks"]]}}
        return {
            "state": pr["state"], "merged": pr["merged"], "mergedAt": pr["mergedAt"],
            "mergeCommit": {"oid": pr["mergeCommit"]} if pr["mergeCommit"] else None,
            "headRefOid": pr["head"], "baseRefName": pr["base"],
            "author": user(pr["author"]),
            "autoMergeRequest": {"enabledAt": pr["autoMerge"][2], "enabledBy": user(pr["autoMerge"][:2])} if pr["autoMerge"] else None,
            "reviews": {"pageInfo": {"hasNextPage": False}, "nodes": pr["reviews"]},
            "files": {"pageInfo": {"hasNextPage": False}, "nodes": [{"path": p, "changeType": "ADDED"} for p in pr["files"]]},
            "commits": {"nodes": [{"commit": {"oid": pr["head"], "statusCheckRollup": rollup}}]},
            "authors": {"nodes": [{"commit": {"parents": {"totalCount": 1},
                                              "author": {"email": pr["email"], "user": {"databaseId": pr["author"][1]}}}}]},
        }

    def _graphql(self, body):
        v = body.get("variables") or {}
        repo = f"{v.get('owner')}/{v.get('name')}"
        repository, errors = {}, []
        with self.lock:
            for alias in re.findall(r"(pr\d+): pullRequest", body.get("query", "")):
                pr = self.prs.get((repo, v.get("n" + alias[2:])))
                repository[alias] = self._pr_node(pr) if pr else None
                if not pr:
                    errors.append({"type": "NOT_FOUND", "path": ["repository", alias], "message": "not found"})
        out = {"data": {"rateLimit": {"remaining": 5000, "resetAt": iso(time.time() + 3600)}, "repository": repository}}
        if errors:
            out["errors"] = errors
        return out

    def _compare(self, base, head):
        if base == head:
            return "identical"
        ancestor = self.repo_dir and subprocess.run(["git", "merge-base", "--is-ancestor", base, head],
                                                    cwd=self.repo_dir, capture_output=True).returncode == 0
        return "ahead" if ancestor else "diverged"

    def _route(self, method, path, query, body):
        if path == "/.well-known/openid-configuration":
            return 200, {"issuer": self.issuer, "jwks_uri": self.issuer + "/jwks"}
        if path == "/jwks":
            return 200, {"keys": [self.jwk]}
        if path == "/token":
            return 200, {"value": self.ci_token(query.get("audience", [""])[0])}
        if path == "/graphql":
            return 200, self._graphql(body)
        if re.fullmatch(r"/app/installations/\d+/access_tokens", path):
            return 201, {"token": "smoke-installation-token", "expires_at": iso(time.time() + 3600)}
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)(/.*)", path)
        if not m:
            return 404, {"message": "Not Found"}
        repo, rest = m.groups()
        with self.lock:
            if rest == "/installation":
                return 200, {"id": 1}
            if c := re.fullmatch(r"/compare/(\w+)\.\.\.(\w+)", rest):
                return 200, {"status": self._compare(*c.groups())}
            if b := re.fullmatch(r"/rules/branches/(.+)", rest):
                contexts = self.required.get((repo, b.group(1)), [])
                return 200, [{"type": "required_status_checks",
                              "parameters": {"required_status_checks": [{"context": c} for c in contexts]}}] if contexts else []
            if re.fullmatch(r"/branches/.+", rest):
                return 200, {"protected": False}
            if c := re.fullmatch(r"/commits/(\w+)/check-runs", rest):
                name = query.get("check_name", [None])[0]
                runs = [r for r in self.check_runs if r["repo"] == repo and r["head_sha"] == c.group(1) and r["name"] == name]
                return 200, {"check_runs": [{"id": r["id"], "app": {"id": int(self.app_id)}} for r in runs]}
            if rest == "/check-runs" and method == "POST":
                run = {"id": len(self.check_runs) + 1, "repo": repo, **body}
                self.check_runs.append(run)
                return 201, {"id": run["id"]}
            if (c := re.fullmatch(r"/check-runs/(\d+)", rest)) and method == "PATCH":
                run = next(r for r in self.check_runs if r["id"] == int(c.group(1)))
                run.update({k: v for k, v in body.items() if k != "head_sha"})
                return 200, {"id": run["id"]}
            if c := re.fullmatch(r"/issues/(\d+)/comments", rest):
                if method == "POST":
                    self.comments.append({"id": len(self.comments) + 1, "repo": repo, "pr": int(c.group(1)), "body": body["body"]})
                    return 201, {"id": len(self.comments)}
                return 200, [{"id": x["id"], "body": x["body"]} for x in self.comments if x["repo"] == repo and x["pr"] == int(c.group(1))]
            if (c := re.fullmatch(r"/issues/comments/(\d+)", rest)) and method == "PATCH":
                next(x for x in self.comments if x["id"] == int(c.group(1)))["body"] = body["body"]
                return 200, {"id": int(c.group(1))}
            if (c := re.fullmatch(r"/pulls/(\d+)/reviews/(\d+)/dismissals", rest)) and method == "PUT":
                for r in self.prs[(repo, int(c.group(1)))]["reviews"]:
                    if str(r["databaseId"]) == c.group(2):
                        r["state"] = "DISMISSED"
                return 200, {}
        return 404, {"message": "Not Found"}

    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _serve(self):
                url = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"null") if length else None
                status, out = fake._route(self.command, url.path.removeprefix("/api/v3"), parse_qs(url.query), body)
                raw = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PATCH = do_PUT = _serve

        return Handler
