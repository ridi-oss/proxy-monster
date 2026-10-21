#!/usr/bin/env python3
"""The run gate against real GitHub branch configurations: each scenario's base branch has its own ruleset, so the
control plane's five-minute rules cache never carries one scenario's rules into the next. Each base branch starts from
the last one a scenario merged into, and the chain merges back into main at the end: a later PR's head must contain
the scope's last merged run."""
import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.request

from e2e import *  # noqa: F403

APP_KEY = os.environ.get("PM_GITHUB_E2E_APP_KEY", os.path.expanduser("~/.cache/proxy-monster/github-e2e/app-key.pem"))
OWNER = REPO.split("/")[0]
tip = "main"
rulesets, protected, opened = [], [], []


def own(strict=False):
    return {"type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": strict,
        "required_status_checks": [{"context": CHECK, "integration_id": APP_ID}]}}


def pull_request(**p):
    return {"type": "pull_request", "parameters": {
        "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": False, "require_code_owner_review": False,
        "require_last_push_approval": False, "required_review_thread_resolution": False, **p}}


def gh_json(method, path, body):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(body, f)
    try:
        return json.loads(gh("api", "-X", method, path, "--input", f.name) or "null")
    finally:
        os.unlink(f.name)


def branch(name):
    b = f"cfg-{SFX}-{name}"
    sha = gh("api", f"repos/{REPO}/git/ref/heads/{tip}", "--jq", ".object.sha")
    gh("api", "-X", "POST", f"repos/{REPO}/git/refs", "-f", f"ref=refs/heads/{b}", "-f", f"sha={sha}", "--silent")
    return b


def protect(b, *rules, strict=False):
    r = gh_json("POST", f"repos/{REPO}/rulesets", {
        "name": b, "target": "branch", "enforcement": "active", "bypass_actors": [],
        "conditions": {"ref_name": {"include": [f"refs/heads/{b}"], "exclude": []}}, "rules": [own(strict), *rules]})
    rulesets.append(r["id"])
    return r["id"]


def push_base(b, path, content):
    git("fetch", "-q", "origin")
    git("checkout", "-q", "-B", f"{b}-base", f"origin/{b}")
    with open(os.path.join(CLONE, path), "w") as f:
        f.write(content)
    git("add", "-A")
    git("commit", "-q", "-m", f"base change on {b}")
    git("push", "-q", "origin", f"HEAD:{b}")


def sql_pr(name, b, extra=None, draft=False):
    t = f"c_{name}_{SFX}"
    files = {sql_path(f"{next_key()}_{t}.sql"): f"CREATE TABLE {t} (id INT PRIMARY KEY);\n", **(extra or {})}
    pr = open_pr(f"{b}-pr", files, f"db: {name} {SFX}", base=b, draft=draft)
    opened.append(pr)
    log(name, "PR", pr, "onto", b)
    wait_title(pr, "Waiting for approval")
    approve_pending(pr)
    return pr, t


KEY = [200]


def next_key():
    KEY[0] += 1
    return f"{KEY[0]:04d}"


def merged_into(b, pr, table, name):
    global tip
    ok = bool(wait_merged(pr))
    check(f"{name}: runs and merges", ok and table_exists(table))
    if ok:
        tip = b


def app_token():
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    now = int(time.time())
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iat": now - 60, "exp": now + 500, "iss": str(APP_ID)}).encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", APP_KEY], input=f"{head}.{body}".encode(),
                         capture_output=True, check=True).stdout
    jwt = f"{head}.{body}.{b64(sig)}"

    def call(method, path):
        req = urllib.request.Request("https://api.github.com" + path, method=method,
                                     headers={"Authorization": f"Bearer {jwt}", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    inst = call("GET", f"/repos/{REPO}/installation")["id"]
    return call("POST", f"/app/installations/{inst}/access_tokens")["token"]


def app_api(token, method, path, body):
    req = urllib.request.Request("https://api.github.com" + path, method=method, data=json.dumps(body).encode(),
                                 headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def close(pr):
    gh("pr", "close", str(pr), "-R", REPO, check=False)


log("suffix", SFX)
try:
    # C1: a draft waits until it is marked ready, then runs.
    b = branch("draft")
    protect(b)
    pr, t = sql_pr("draft", b, draft=True)
    c = wait_title(pr, "marked ready")
    check("C1 an approved draft waits", bool(c), str(c))
    check("C1 nothing ran while a draft", not table_exists(t))
    gh("pr", "ready", str(pr), "-R", REPO)
    automerge(pr)
    merged_into(b, pr, t, "C1")

    # C2: an optional check still running holds the run; once it fails, the run goes ahead.
    b = branch("running")
    protect(b)
    pr, t = sql_pr("running", b)
    token = app_token()
    run = app_api(token, "POST", f"/repos/{REPO}/check-runs", {"name": "slow", "head_sha": head(pr), "status": "in_progress"})
    automerge(pr)
    c = wait_title(pr, "other checks")
    check("C2 a running optional check holds the run", bool(c), str(c))
    check("C2 nothing ran while it was running", not table_exists(t))
    app_api(token, "PATCH", f"/repos/{REPO}/check-runs/{run['id']}", {"status": "completed", "conclusion": "failure"})
    del token
    merged_into(b, pr, t, "C2")

    # C3: a review the base requires and the SQL approval does not give holds the run.
    b = branch("review")
    rid = protect(b, pull_request(required_approving_review_count=1))
    pr, t = sql_pr("review", b)
    automerge(pr)
    c = wait_title(pr, "reviews the base branch requires")
    check("C3 a required review holds the run", bool(c), str(c))
    check("C3 nothing ran without it", not table_exists(t))
    gh_json("PUT", f"repos/{REPO}/rulesets/{rid}", {"rules": [own(), pull_request()]})
    merged_into(b, pr, t, "C3")

    # C4: a code-owner rule with no approval count leaves GitHub without a review decision, so it is unchecked.
    b = branch("codeowner")
    protect(b, pull_request(require_code_owner_review=True))
    pr, t = sql_pr("codeowner", b)
    automerge(pr)
    c = wait_title(pr, "pull_request rule cannot be checked")
    check("C4 a code-owner rule with no approval count holds the run", bool(c), str(c))
    check("C4 nothing ran", not table_exists(t))
    close(pr)

    # C5: conflicts with the base hold the run until they are resolved.
    b = branch("conflict")
    pr, t = sql_pr("conflict", b, extra={"notes.txt": f"from the PR {SFX}\n"})
    push_base(b, "notes.txt", f"from the base {SFX}\n")
    protect(b)
    automerge(pr)
    c = wait_title(pr, "Resolve the conflicts")
    check("C5 a conflict holds the run", bool(c), str(c))
    check("C5 nothing ran with the conflict", not table_exists(t))
    git("checkout", "-q", f"{b}-pr")
    sh("git", "merge", "-q", "-X", "ours", "-m", "resolve", f"origin/{b}", cwd=CLONE)
    git("push", "-q", "origin", f"{b}-pr")
    merged_into(b, pr, t, "C5")

    # C6: a strict status-check rule holds a branch that is behind the base until it is updated.
    b = branch("strict")
    pr, t = sql_pr("strict", b)
    push_base(b, f"strict-{SFX}.txt", "base moved\n")
    protect(b, strict=True)
    automerge(pr)
    c = wait_title(pr, "Update your branch")
    check("C6 a branch behind a strict base waits", bool(c), str(c))
    check("C6 nothing ran while behind", not table_exists(t))
    update_branch(pr)
    merged_into(b, pr, t, "C6")

    # C7: an unresolved review conversation holds the run when the base requires resolution.
    b = branch("threads")
    protect(b, pull_request(required_review_thread_resolution=True))
    pr, t = sql_pr("threads", b)
    path = next(p for p in json.loads(gh("pr", "view", str(pr), "-R", REPO, "--json", "files"))["files"])["path"]
    gh("api", "-X", "POST", f"repos/{REPO}/pulls/{pr}/comments", "-f", "body=check this", "-f", f"commit_id={head(pr)}",
       "-f", f"path={path}", "-F", "line=1", "-f", "side=RIGHT", "--silent")
    automerge(pr)
    c = wait_title(pr, "Resolve the review conversations")
    check("C7 an unresolved conversation holds the run", bool(c), str(c))
    check("C7 nothing ran with it open", not table_exists(t))
    q = 'query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){reviewThreads(first:10){nodes{id}}}}}'
    ids = json.loads(gh("api", "graphql", "-f", f"query={q}", "-f", f"o={OWNER}", "-f", f"n={REPO.split('/')[1]}", "-F", f"p={pr}",
                        "--jq", "[.data.repository.pullRequest.reviewThreads.nodes[].id]"))
    for i in ids:
        gh("api", "graphql", "-f", "query=mutation($t:ID!){resolveReviewThread(input:{threadId:$t}){thread{id}}}", "-f", f"t={i}", "--silent")
    merged_into(b, pr, t, "C7")

    # C8: an auto-merge method the base does not allow holds the run.
    b = branch("method")
    protect(b, pull_request(allowed_merge_methods=["rebase"]))
    pr, t = sql_pr("method", b)
    try:
        automerge(pr, "squash")
        c = wait_title(pr, "does not allow merging by squash")
        check("C8 a disallowed auto-merge method holds the run", bool(c), str(c))
        check("C8 nothing ran", not table_exists(t))
        gh("pr", "merge", str(pr), "-R", REPO, "--disable-auto")
    except RuntimeError as e:
        check("C8 GitHub refuses to enable auto-merge with a disallowed method", "not allowed" in str(e).lower() or "merge method" in str(e).lower(), str(e)[-200:])
    automerge(pr, "rebase")
    merged_into(b, pr, t, "C8")

    # C9: a merge-time rule the gate does not evaluate holds the run.
    b = branch("signatures")
    protect(b, {"type": "required_signatures"})
    pr, t = sql_pr("signatures", b)
    automerge(pr, "merge")
    c = wait_title(pr, "required_signatures rule cannot be checked")
    check("C9 an unchecked rule holds the run", bool(c), str(c))
    check("C9 nothing ran", not table_exists(t))
    close(pr)

    # C10: classic branch protection shows the App only its required checks, so it holds the run.
    b = branch("classic")
    protect(b)
    gh_json("PUT", f"repos/{REPO}/branches/{b}/protection", {
        "required_status_checks": None, "enforce_admins": False, "required_pull_request_reviews": None, "restrictions": None,
        "required_conversation_resolution": True})
    protected.append(b)
    pr, t = sql_pr("classic", b)
    automerge(pr)
    c = wait_title(pr, "branch_protection rule cannot be checked")
    check("C10 classic branch protection holds the run", bool(c), str(c))
    check("C10 nothing ran", not table_exists(t))
    close(pr)
finally:
    for pr in opened:
        if pr_state(pr) == "OPEN":
            close(pr)
    for b in protected:
        gh("api", "-X", "DELETE", f"repos/{REPO}/branches/{b}/protection", "--silent", check=False)
    for rid in rulesets:
        gh("api", "-X", "DELETE", f"repos/{REPO}/rulesets/{rid}", "--silent", check=False)
    if tip != "main":
        url = gh("pr", "create", "-R", REPO, "--head", tip, "--base", "main", "--title", f"e2e: configs {SFX} back to main",
                 "--body", "Carries the configuration scenarios' merges, so main contains the scope's last merged run.")
        back = int(url.rsplit("/", 1)[1])
        automerge(back, "merge")
        check("the scenarios' merges reach main", bool(wait_merged(back)))
    for ref in json.loads(gh("api", f"repos/{REPO}/git/matching-refs/heads/cfg-{SFX}-", "--jq", "[.[].ref]")):
        gh("api", "-X", "DELETE", f"repos/{REPO}/git/{ref}", "--silent", check=False)

finish()
