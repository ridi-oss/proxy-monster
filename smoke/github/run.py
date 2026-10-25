#!/usr/bin/env python3
"""SQL files from GitHub against real GitHub: opens pull requests in a test repository and checks how the control
plane files, approves, runs, and merges them. Setup and settings are in README.md next to this file."""
import json
import os
import signal
import time

from e2e import *  # noqa: F403

log("suffix", SFX)

# S1: a file that fails partway
s1 = f"s1_{SFX}"
F = open_pr(f"s1-{SFX}", {sql_path(f"0010_s1_{SFX}.sql"): f"CREATE TABLE {s1} (id INT PRIMARY KEY);\nALTER TABLE s1_missing_{SFX} ADD COLUMN x INT;\n"}, f"db: s1 {SFX}")
log("S1 PR", F)
wait_title(F, "Waiting for approval")
s1reqs = approve_pending(F)
automerge(F)
c = wait(f"#{F} failure", lambda: (lambda c: c if c[1] == "failure" else None)(approval_check(F)))
check("S1 approval check red after the failing statement", bool(c), str(c))
check("S1 PR stays open", pr_state(F) == "OPEN")
check("S1 statement 1 was applied", table_exists(s1))
cm = comments(F)
check("S1 PR comment names the failure", "fail" in cm.lower(), cm[-300:])
check("S1 comment names the failed statement", "statement 2 of 2" in cm and "s1_missing_" in cm, cm[-400:])
check("S1 request is FAILED", bool(s1reqs) and request(s1reqs[0]["id"]).get("status") == "FAILED")

# S2: another PR is not blocked by the failed one
s2 = f"s2_{SFX}"
G = open_pr(f"s2-{SFX}", {sql_path(f"0011_s2_{SFX}.sql"): f"CREATE TABLE {s2} (id INT PRIMARY KEY);\n"}, f"db: s2 {SFX}")
log("S2 PR", G)
wait_title(G, "Waiting for approval")
approve_pending(G)
automerge(G)
check("S2 runs and merges while S1 is failed", bool(wait_merged(G)))
check("S2 table exists", table_exists(s2))

# S1b: the fix after the failure must first update onto S2's merge
push_change(f"s1-{SFX}", {sql_path(f"0010_s1_{SFX}.sql"): f"ALTER TABLE {s1} ADD COLUMN x INT;\n"}, "fix s1")
c = wait_title(F, "Waiting for approval")
check("S1b fix needs a new approval", bool(c), str(c))
approve_pending(F)
c = wait_title(F, "update your branch")
check("S1b fix waits: branch is behind S2's merge", bool(c), str(c))
update_branch(F)
check("S1b fix runs and merges after the update", bool(wait_merged(F)))
check("S1b column x added", column_exists(s1, "x"))
cm = comments(F)
check("S1b success comment says Statements run", "Statements run: 1" in cm, cm[-300:])

# S3: two PRs approved at once
a, b = f"s3a_{SFX}", f"s3b_{SFX}"
A = open_pr(f"s3a-{SFX}", {sql_path(f"0012_s3a_{SFX}.sql"): f"CREATE TABLE {a} (id INT PRIMARY KEY);\n"}, f"db: s3a {SFX}")
B = open_pr(f"s3b-{SFX}", {sql_path(f"0013_s3b_{SFX}.sql"): f"CREATE TABLE {b} (id INT PRIMARY KEY);\n"}, f"db: s3b {SFX}")
log("S3 PRs", A, B)
wait_title(A, "Waiting for approval")
wait_title(B, "Waiting for approval")
approve_pending(A)
approve_pending(B)
automerge(A)
automerge(B)
first = wait("one of S3 merged", lambda: next((p for p in (A, B) if pr_state(p) == "MERGED"), None))
other = B if first == A else A
check("S3 one PR merges first", bool(first), f"first=#{first}")
c = wait_title(other, "update your branch") if first else None
check("S3 the other waits for an update", bool(c), str(c))
update_branch(other)
check("S3 the other merges after the update", bool(wait_merged(other)))
check("S3 both tables exist", table_exists(a) and table_exists(b))

# S4: SQL changed after approval edits the same request
o, n = f"s4old_{SFX}", f"s4new_{SFX}"
C = open_pr(f"s4-{SFX}", {sql_path(f"0014_s4_{SFX}.sql"): f"CREATE TABLE {o} (id INT PRIMARY KEY);\n"}, f"db: s4 {SFX}")
log("S4 PR", C)
wait_title(C, "Waiting for approval")
old = approve_pending(C)
c = wait_title(C, "auto-merge")
check("S4 approved, waiting for auto-merge", bool(c), str(c))
push_change(f"s4-{SFX}", {sql_path(f"0014_s4_{SFX}.sql"): f"CREATE TABLE {n} (id INT PRIMARY KEY);\n"}, "change s4")
c = wait_title(C, "Waiting for approval")
check("S4 changed SQL needs approval again", bool(c), str(c))
od = request(old[0]["id"]) if old else {}
check("S4 the same request was edited: PENDING at revision 2", (od.get("status"), od.get("revision")) == ("PENDING", 2), f"{od.get('status')} rev {od.get('revision')}")
check("S4 it holds the new SQL", n in (od.get("sql") or ""), od.get("sql"))
st, body = api("POST", f"/api/approvals/{old[0]['id']}/approve", {"revision": 1}) if old else (0, None)
check("S4 approving the old revision is refused", st == 409 and (body or {}).get("code") == "approval.request_changed", f"{st} {body}")
new = approve_pending(C)
automerge(C)
check("S4 the re-approval is the same request", bool(new) and bool(old) and new[0]["id"] == old[0]["id"], str([r["id"] for r in new]))
check("S4 merges after re-approval", bool(wait_merged(C)))
check("S4 only the new SQL ran", table_exists(n) and not table_exists(o))

# S5: editing a merged file fails the Action
E = open_pr(f"s5-{SFX}", {sql_path(f"0011_s2_{SFX}.sql"): f"CREATE TABLE {s2} (id BIGINT PRIMARY KEY);\n"}, f"db: s5 {SFX}")
log("S5 PR", E)
run = wait("S5 file job", lambda: (lambda r: r if r and r[0]["status"] == "completed" else None)(
    json.loads(gh("run", "list", "-R", REPO, "--branch", f"s5-{SFX}", "--limit", "1", "--json", "status,conclusion,databaseId"))))
check("S5 file job fails on an edited merged file", bool(run) and run[0]["conclusion"] == "failure", str(run))
logtxt = gh("run", "view", str(run[0]["databaseId"]), "-R", REPO, "--log-failed", check=False) if run else ""
check("S5 log says the merged file must not change", "merged" in logtxt.lower(), logtxt[-300:].replace("\n", " "))
st, conc, title = approval_check(E)
check("S5 approval never turns green", conc != "success", f"{st}/{conc}/{title}")
gh("pr", "close", str(E), "-R", REPO, "--delete-branch", check=False)

# S6: numeric key order inside one PR
ot = f"s6_{SFX}"
O = open_pr(f"s6-{SFX}", {sql_path(f"10_s6b_{SFX}.sql"): f"ALTER TABLE {ot} ADD COLUMN y INT;\n",
                          sql_path(f"9_s6a_{SFX}.sql"): f"CREATE TABLE {ot} (id INT PRIMARY KEY);\n"}, f"db: s6 {SFX}")
log("S6 PR", O)
wait_title(O, "Waiting for approval")
s6 = approve_pending(O)
automerge(O)
check("S6 runs 9_ before 10_ and merges", bool(wait_merged(O)))
check("S6 column y exists", column_exists(ot, "y"))
keys = sorted(request(r["id"]).get("fileKey") or "" for r in s6)
check("S6 file keys stored as 9 and 10", keys == ["10", "9"], str(keys))

# S7: force-run a PR that is behind
fa, fb = f"s7a_{SFX}", f"s7b_{SFX}"
A7 = open_pr(f"s7a-{SFX}", {sql_path(f"0030_s7a_{SFX}.sql"): f"CREATE TABLE {fa} (id INT PRIMARY KEY);\n"}, f"db: s7a {SFX}")
B7 = open_pr(f"s7b-{SFX}", {sql_path(f"0031_s7b_{SFX}.sql"): f"CREATE TABLE {fb} (id INT PRIMARY KEY);\n"}, f"db: s7b {SFX}")
log("S7 PRs", A7, B7)
wait_title(A7, "Waiting for approval")
wait_title(B7, "Waiting for approval")
approve_pending(A7)
b7 = approve_pending(B7)
automerge(A7)
check("S7 first PR merges", bool(wait_merged(A7)))
automerge(B7)
c = wait_title(B7, "update your branch")
check("S7 second PR is held as behind", bool(c), str(c))
st, body = api("POST", f"/api/approvals/{b7[0]['id']}/force-run", {}) if b7 else (0, None)
check("S7 admin force-run accepted", st == 200, f"{st}")
check("S7 forced PR runs and merges without an update", bool(wait_merged(B7)))
check("S7 forced table exists", table_exists(fb))
cm = comments(B7)
check("S7 PR comment announces the force-run", "force" in cm.lower(), cm[-300:])

# S8: a reformat-only push keeps the approval
s8 = f"s8_{SFX}"
H = open_pr(f"s8-{SFX}", {sql_path(f"0040_s8_{SFX}.sql"): f"CREATE TABLE {s8} (id INT PRIMARY KEY);\n"}, f"db: s8 {SFX}")
log("S8 PR", H)
wait_title(H, "Waiting for approval")
h8 = approve_pending(H)
c = wait_title(H, "auto-merge")
check("S8 approved, waiting for auto-merge", bool(c), str(c))
push_change(f"s8-{SFX}", {sql_path(f"0040_s8_{SFX}.sql"): f"-- reformatted\ncreate table {s8} (\n  id INT PRIMARY KEY\n);\n"}, "reformat s8")
time.sleep(60)
c = wait_title(H, "auto-merge", 300)
check("S8 still approved after a reformat-only push", bool(c), str(c))
d8 = request(h8[0]["id"]) if h8 else {}
check("S8 revision and approval kept", (d8.get("status"), d8.get("revision")) == ("APPROVED", 1), f"{d8.get('status')} rev {d8.get('revision')}")
automerge(H)
check("S8 merges without re-approval", bool(wait_merged(H)))
check("S8 table exists", table_exists(s8))


# S9: a PR without SQL gets its check as skipped from the workflow, also while the control plane is paused
def workflow_check(pr):
    for r in json.loads(gh("api", f"repos/{REPO}/commits/{head(pr)}/check-runs"))["check_runs"]:
        if r["name"] == CHECK and r["app"]["slug"] == "github-actions":
            return r["conclusion"]
    return None


I = open_pr(f"s9-{SFX}", {f"docs/s9_{SFX}.md": "no SQL\n"}, f"docs: s9 {SFX}")
log("S9 PR", I)
check("S9 the workflow marks a PR without SQL skipped", wait("S9 skipped", lambda: workflow_check(I) == "skipped", 300))
time.sleep(30)
check("S9 the control plane posts no check of its own", approval_check(I)[0] is None, str(approval_check(I)))
automerge(I)
check("S9 merges", bool(wait_merged(I)))

port = CP.rsplit(":", 1)[1].split("/")[0]
cp_pid = int(sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN").split()[0])
os.kill(cp_pid, signal.SIGSTOP)
try:
    J = open_pr(f"s9b-{SFX}", {f"docs/s9b_{SFX}.md": "no SQL\n"}, f"docs: s9b {SFX}")
    log("S9 PR with the control plane paused", J)
    automerge(J)
    check("S9 skipped while the control plane is paused", wait("S9b skipped", lambda: workflow_check(J) == "skipped", 300))
    check("S9 merges while the control plane is paused", bool(wait_merged(J)))
finally:
    os.kill(cp_pid, signal.SIGCONT)

finish()
