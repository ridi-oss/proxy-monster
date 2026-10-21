"""Helpers the real-GitHub scripts share: the test repository, the control plane, and the target database."""
import http.cookiejar
import json
import os
import random
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request


def need(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"{name} is not set; see smoke/github/README.md")
    return value


REPO = need("PM_GITHUB_E2E_REPO")
CLONE = need("PM_GITHUB_E2E_CLONE")
APP_ID = int(need("PM_GITHUB_E2E_APP_ID"))
CP = os.environ.get("PM_GITHUB_E2E_CP", "http://127.0.0.1:8090")
APPROVER = os.environ.get("PM_GITHUB_E2E_APPROVER", "approver@example.com")
DIR = os.environ.get("PM_GITHUB_E2E_DIR", "db/orders")
MYSQL = os.environ.get("PM_GITHUB_E2E_MYSQL", "mysql -h127.0.0.1 -P3306 -uacme -pacme acme").split()
SFX = "".join(random.choices(string.ascii_lowercase, k=5))
RESULTS = []


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def sh(*cmd, cwd=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout.strip()


TRANSIENT = ("Bad Gateway", "502", "503", "Something went wrong")


# GitHub answers an occasional 502 or GraphQL "Something went wrong"; a run of 40-odd checks meets one.
def gh(*a, check=True):
    for attempt in range(3):
        try:
            return sh("gh", *a, check=check)
        except RuntimeError as e:
            if attempt == 2 or not any(t in str(e) for t in TRANSIENT):
                raise
            time.sleep(5 * (attempt + 1))


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    log("PASS" if ok else "FAIL", name, detail)


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(method, path, body=None):
    req = urllib.request.Request(CP + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "Origin": CP})
    try:
        with opener.open(req) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


# The approver signs in through the debug login, so the control plane runs with PM_AUTH_DEBUG=true.
def login():
    call("POST", "/auth/debug", {"principal": APPROVER, "roles": ["system:admin"]})


# A run outlasts the console session's idle limit, so a 401 signs in again.
def api(method, path, body=None):
    status, out = call(method, path, body)
    if status == 401:
        login()
        status, out = call(method, path, body)
    return status, out


def mysql(q):
    return sh(*MYSQL, "-N", "-e", q, check=False)


def table_exists(t):
    return mysql(f"SHOW TABLES LIKE '{t}'") == t


def column_exists(t, c):
    return c in mysql(f"SHOW COLUMNS FROM {t}")


def git(*a):
    return sh("git", *a, cwd=CLONE)


def open_pr(branch, files, title, base="main", draft=False):
    git("fetch", "-q", "origin")
    git("checkout", "-q", "-B", branch, f"origin/{base}")
    for p, c in files.items():
        os.makedirs(os.path.dirname(os.path.join(CLONE, p)), exist_ok=True)
        with open(os.path.join(CLONE, p), "w") as f:
            f.write(c)
    git("add", "-A")
    git("commit", "-q", "-m", title)
    git("push", "-q", "-f", "-u", "origin", branch)
    url = gh("pr", "create", "-R", REPO, "--head", branch, "--base", base, "--title", title, "--body", "e2e " + SFX,
             *(["--draft"] if draft else []))
    return int(url.rsplit("/", 1)[1])


def push_change(branch, files, msg):
    git("checkout", "-q", branch)
    for p, c in files.items():
        with open(os.path.join(CLONE, p), "w") as f:
            f.write(c)
    git("add", "-A")
    git("commit", "-q", "-m", msg)
    git("push", "-q", "origin", branch)


def head(pr):
    return json.loads(gh("pr", "view", str(pr), "-R", REPO, "--json", "headRefOid"))["headRefOid"]


def pr_state(pr):
    return json.loads(gh("pr", "view", str(pr), "-R", REPO, "--json", "state"))["state"]


def approval_check(pr, sha=None):
    sha = sha or head(pr)
    for r in json.loads(gh("api", f"repos/{REPO}/commits/{sha}/check-runs"))["check_runs"]:
        if r["name"] == "query executed" and r["app"]["id"] == APP_ID:
            return r["status"], r["conclusion"], (r.get("output") or {}).get("title") or ""
    return None, None, ""


def wait(desc, fn, timeout=420):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v
        time.sleep(5)
    log("timeout:", desc)
    return None


def wait_title(pr, needle, timeout=420):
    return wait(f"#{pr} title~{needle}", lambda: (lambda c: c if needle.lower() in c[2].lower() else None)(approval_check(pr)), timeout)


def requests_for(pr):
    _, inbox = api("GET", "/api/approvals/inbox")
    return [r for r in (inbox or []) if ((r.get("pullRequest") or {}).get("prUrl") or "").endswith(f"/pull/{pr}")]


def approve_pending(pr):
    rs = wait(f"#{pr} pending request", lambda: requests_for(pr) or None, 300) or []
    for r in rs:
        st, _ = api("POST", f"/api/approvals/{r['id']}/approve", {"revision": r["revision"]})
        log(f"approved request {r['id']} rev {r['revision']} ({r['pullRequest']['path']}) -> {st}")
    return rs


def automerge(pr, method="squash"):
    gh("pr", "merge", str(pr), "-R", REPO, "--auto", "--" + method)


def update_branch(pr):
    gh("api", "-X", "PUT", f"repos/{REPO}/pulls/{pr}/update-branch", "--silent")


def wait_merged(pr, timeout=420):
    return wait(f"#{pr} merged", lambda: pr_state(pr) == "MERGED", timeout)


def comments(pr):
    return " ".join(json.loads(gh("api", f"repos/{REPO}/issues/{pr}/comments", "--jq", "[.[].body]")))


def request(rid):
    body = api("GET", f"/api/approvals/{rid}")[1] or {}
    return body.get("request", body)


def sql_path(name):
    return f"{DIR}/{name}"




def finish():
    passed = sum(ok for _, ok in RESULTS)
    log(f"RESULT {passed}/{len(RESULTS)} passed")
    for name, ok in RESULTS:
        if not ok:
            log("FAILED:", name)
    sys.exit(0 if passed == len(RESULTS) else 1)


login()
