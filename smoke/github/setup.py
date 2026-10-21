#!/usr/bin/env python3
"""Set up what run.py needs on real GitHub: a GitHub App, a private test repository with its workflow and
ruleset, a self-hosted runner, and the control-plane user. Re-running it skips the steps already done.

GitHub asks a person to confirm two of the steps in a browser: creating the App and installing it.
"""
import argparse
import base64
import html
import http.server
import json
import os
import platform
import secrets
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LABEL = "pm-github-e2e"
RULESET = "main: SQL from proxy-monster"


def log(*a):
    print("setup:", *a, flush=True)


def sh(*cmd, cwd=None, check=True, env=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        sys.exit(f"setup: {' '.join(cmd[:3])}… failed: {r.stderr.strip()}")
    return r.stdout.strip()


def gh_api(*args, check=True):
    out = sh("gh", "api", *args, check=check)
    return json.loads(out) if out else None


class State:
    def __init__(self, path):
        self.path = path
        self.data = json.load(open(path)) if os.path.exists(path) else {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def app_jwt(app_id, key_file):
    now = int(time.time())
    head = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_file], input=f"{head}.{body}".encode(),
                         capture_output=True, check=True).stdout
    return f"{head}.{body}.{b64url(sig)}"


def create_app(args, st, state_dir):
    if st.get("app"):
        log("App exists:", st.get("app")["slug"])
        return
    owner_type = gh_api(f"users/{args.owner}")["type"]
    action = (f"https://github.com/organizations/{args.owner}/settings/apps/new" if owner_type == "Organization"
              else "https://github.com/settings/apps/new")
    nonce = secrets.token_hex(12)
    callback = f"http://{args.callback_host}:{args.callback_port}"
    manifest = {
        "name": args.app_name,
        "url": "https://github.com/ridi-oss/proxy-monster",
        "hook_attributes": {"url": "https://example.invalid/hook", "active": False},
        "redirect_url": f"{callback}/callback",
        "public": False,
        "default_permissions": {"checks": "write", "pull_requests": "write", "contents": "read", "metadata": "read",
                                "members": "read"},
        "default_events": [],
    }
    done = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if url.path == "/":
                body = (f'<form id=f method=post action="{action}?state={nonce}">'
                        f'<input type=hidden name=manifest value="{html.escape(json.dumps(manifest))}">'
                        "<button>Create the GitHub App</button></form><script>document.getElementById('f').submit()</script>")
            elif url.path == "/callback" and q.get("state", [""])[0] == nonce and "code" in q:
                r = gh_api("-X", "POST", f"/app-manifests/{q['code'][0]}/conversions")
                key_file = os.path.join(state_dir, "app-key.pem")
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.write(fd, r["pem"].encode())
                os.close(fd)
                done.update(id=r["id"], slug=r["slug"], key_file=key_file)
                body = f"<p>Created {html.escape(r['slug'])}. You can close this tab.</p>"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

    server = http.server.HTTPServer((args.callback_bind, args.callback_port), Handler)
    log(f"open {callback}/ and click Create (GitHub asks a person to confirm a new App)")
    webbrowser.open(f"{callback}/")
    while not done:
        server.handle_request()
    server.server_close()
    st.set("app", done)
    log("App created:", done["slug"], "id", done["id"])


def create_repo(args, st):
    full = f"{args.owner}/{args.repo}"
    if not st.get("repo"):
        if sh("gh", "repo", "view", full, check=False):
            sys.exit(f"setup: {full} already exists and this setup did not create it; pick another --repo")
        sh("gh", "repo", "create", full, "--private", "--add-readme")
        st.set("repo", full)
        log("repository created:", full)
    gh_api("-X", "PATCH", f"repos/{full}", "-F", "allow_auto_merge=true", "-F", "allow_squash_merge=true")


def push_workflow(args, st, state_dir):
    clone = os.path.join(state_dir, "clone")
    if not os.path.isdir(clone):
        sh("gh", "repo", "clone", st.get("repo"), clone)
    workflow = open(os.path.join(HERE, "sql.yml")).read()
    for old, new in {
        "http://127.0.0.1:8090": args.cp, "pm-github-e2e\n": args.audience + "\n", "db/orders": args.dir,
        "e2e-mysql": args.datasource, "--schema acme": f"--schema {args.schema}",
        "system:development-architect": args.role,
    }.items():
        workflow = workflow.replace(old, new)
    path = os.path.join(clone, ".github", "workflows", "sql.yml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and open(path).read() == workflow:
        log("workflow up to date")
        return clone
    with open(path, "w") as f:
        f.write(workflow)
    sh("git", "add", "-A", cwd=clone)
    sh("git", "commit", "-q", "-m", "ci: file SQL with proxy-monster", cwd=clone)
    sh("git", "push", "-q", "origin", "HEAD:main", cwd=clone)
    log("workflow pushed")
    return clone


def install_app(args, st):
    app = st.get("app")
    full = st.get("repo")
    jwt = lambda: app_jwt(app["id"], app["key_file"])

    def installed():
        req = urllib.request.Request(f"https://api.github.com/repos/{full}/installation",
                                     headers={"Authorization": f"Bearer {jwt()}", "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req) as r:
                return json.load(r)["id"]
        except urllib.error.HTTPError:
            return None

    if installed():
        log("App installed on", full)
        return
    url = f"https://github.com/apps/{app['slug']}/installations/new"
    log(f"open {url} and install the App on {full} only")
    webbrowser.open(url)
    while not installed():
        time.sleep(3)
    log("App installed on", full)


def add_ruleset(st):
    full = st.get("repo")
    if any(r["name"] == RULESET for r in gh_api(f"repos/{full}/rulesets") or []):
        log("ruleset exists")
        return
    ruleset = json.load(open(os.path.join(HERE, "ruleset.json")))
    ruleset["name"] = RULESET
    r = subprocess.run(["gh", "api", "-X", "POST", f"repos/{full}/rulesets", "--input", "-"],
                       input=json.dumps(ruleset), text=True, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"setup: adding the ruleset failed: {r.stderr.strip()}")
    log("ruleset added")


def build_pm_ci(state_dir):
    out = os.path.join(state_dir, "bin", "pm-ci")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    env = dict(os.environ, GOWORK="off", CGO_ENABLED="0")
    subprocess.run(["go", "build", "-o", out, "."], cwd=os.path.join(ROOT, "sql-action"), env=env, check=True)
    log("pm-ci built:", out)
    return out


def start_runner(st, state_dir, pm_ci):
    full = st.get("repo")
    runner = os.path.join(state_dir, "runner")
    if not os.path.exists(os.path.join(runner, ".runner")):
        os_name = {"Darwin": "osx", "Linux": "linux"}[platform.system()]
        arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}[platform.machine()]
        release = gh_api("repos/actions/runner/releases/latest")
        version = release["tag_name"].lstrip("v")
        asset = f"actions-runner-{os_name}-{arch}-{version}.tar.gz"
        os.makedirs(runner, exist_ok=True)
        tarball = os.path.join(state_dir, asset)
        urllib.request.urlretrieve(f"https://github.com/actions/runner/releases/download/v{version}/{asset}", tarball)
        with tarfile.open(tarball) as t:
            t.extractall(runner)
        os.remove(tarball)
        token = gh_api("-X", "POST", f"repos/{full}/actions/runners/registration-token")["token"]
        sh("./config.sh", "--unattended", "--url", f"https://github.com/{full}", "--token", token,
           "--labels", LABEL, "--name", f"{LABEL}-{platform.node().split('.')[0]}", "--replace", cwd=runner)
        log("runner registered")
    # The runner runs as you, so your global git config (an insteadOf rewriting to SSH, say) would change
    # how jobs fetch; actions/checkout must use the job's token over HTTPS.
    with open(os.path.join(runner, ".env"), "w") as f:
        f.write(f"PM_CI_BIN={pm_ci}\nGIT_CONFIG_GLOBAL=/dev/null\n")
    pid = st.get("runner_pid")
    if pid and subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode == 0:
        log("runner running, pid", pid)
        return
    out = open(os.path.join(state_dir, "runner.log"), "a")
    proc = subprocess.Popen(["./run.sh"], cwd=runner, stdout=out, stderr=out, start_new_session=True)
    st.set("runner_pid", proc.pid)
    log("runner started, pid", proc.pid)


def create_user(args, clone):
    email = sh("git", "config", "user.email", cwd=clone)
    try:
        jar = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(jar)

        def call(method, path, body):
            req = urllib.request.Request(args.cp + path, method=method, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", "Origin": args.cp})
            try:
                with opener.open(req) as r:
                    return r.status, None
            except urllib.error.HTTPError as e:
                return e.code, (json.loads(e.read() or b"{}") or {}).get("code")

        call("POST", "/auth/debug", {"principal": "github-e2e-setup", "roles": ["system:admin"]})
        status, code = call("POST", "/api/users", {"principal": email, "email": email})
        result = {201: "created"}.get(status) or ("exists" if code == "common.already_exists" else f"HTTP {status} {code}")
        log(f"control-plane user {email}:", result)
    except OSError as e:
        log(f"could not reach {args.cp} ({e}); create a user with email {email} once it is up")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--owner", required=True, help="the GitHub organization or user that owns the test repository")
    ap.add_argument("--repo", default="pm-github-e2e", help="test repository name (created; must not exist)")
    ap.add_argument("--app-name", default="proxy-monster-github-e2e", help="GitHub App name (unique across GitHub)")
    ap.add_argument("--cp", default="http://127.0.0.1:8090", help="control-plane URL, as the runner reaches it")
    ap.add_argument("--audience", default="pm-github-e2e", help="CI OIDC audience (PM_CI_OIDC_AUDIENCE)")
    ap.add_argument("--datasource", required=True)
    ap.add_argument("--schema", default="acme")
    ap.add_argument("--role", default="system:development-architect")
    ap.add_argument("--dir", default="db/orders")
    ap.add_argument("--mysql", default="mysql -h127.0.0.1 -P3306 -uacme -pacme acme", help="how run.py reads the target")
    ap.add_argument("--state-dir", default=os.path.expanduser("~/.cache/proxy-monster/github-e2e"))
    ap.add_argument("--callback-host", default="127.0.0.1", help="host the browser reaches this script on")
    ap.add_argument("--callback-bind", default="127.0.0.1")
    ap.add_argument("--callback-port", type=int, default=48090)
    args = ap.parse_args()
    args.cp = args.cp.rstrip("/")

    os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
    st = State(os.path.join(args.state_dir, "state.json"))
    st.set("owner", args.owner)
    create_app(args, st, args.state_dir)
    create_repo(args, st)
    clone = push_workflow(args, st, args.state_dir)
    install_app(args, st)
    add_ruleset(st)
    start_runner(st, args.state_dir, build_pm_ci(args.state_dir))
    create_user(args, clone)

    app = st.get("app")
    env_file = os.path.join(args.state_dir, "run.env")
    with open(env_file, "w") as f:
        f.write(f"export PM_GITHUB_E2E_REPO={st.get('repo')}\nexport PM_GITHUB_E2E_CLONE={clone}\n"
                f"export PM_GITHUB_E2E_APP_ID={app['id']}\nexport PM_GITHUB_E2E_CP={args.cp}\n"
                f"export PM_GITHUB_E2E_DIR={args.dir}\nexport PM_GITHUB_E2E_MYSQL='{args.mysql}'\n")
    print(f"""
Start the control plane with:
  PM_AUTH_DEBUG=true
  PM_INSTANCE_NAME=github-e2e
  PM_GITHUB_APP_ID={app['id']}
  PM_GITHUB_APP_PRIVATE_KEY_FILE={app['key_file']}
  PM_GITHUB_IDENTITY=commit-email
  PM_CI_OIDC_ISSUERS=github=https://token.actions.githubusercontent.com
  PM_CI_OIDC_AUDIENCE={args.audience}

Then run:
  source {env_file} && python3 smoke/github/run.py

Remove everything with: python3 smoke/github/teardown.py""")


if __name__ == "__main__":
    main()
