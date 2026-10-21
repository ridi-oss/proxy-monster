#!/usr/bin/env python3
"""Remove what setup.py created: the runner, the test repository, the App's private key, and the state directory.

GitHub has no API to delete an App, so this opens the App's settings page for that one step.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import webbrowser


def log(*a):
    print("teardown:", *a, flush=True)


def run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def destroy(path):
    """Overwrite a secret with random bytes before unlinking it."""
    if os.path.exists(path):
        with open(path, "r+b") as f:
            f.write(os.urandom(os.path.getsize(path)))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state-dir", default=os.path.expanduser("~/.cache/proxy-monster/github-e2e"))
    ap.add_argument("--keep-repo", action="store_true", help="leave the test repository")
    args = ap.parse_args()
    path = os.path.join(args.state_dir, "state.json")
    if not os.path.exists(path):
        sys.exit(f"teardown: no setup state in {args.state_dir}")
    st = json.load(open(path))
    repo, app = st.get("repo"), st.get("app")
    failed = False

    pid = st.get("runner_pid")
    if pid:
        run("kill", "--", f"-{pid}")
        run("kill", str(pid))
        log("runner stopped")
    runner = os.path.join(args.state_dir, "runner")
    if repo and os.path.exists(os.path.join(runner, ".runner")):
        token = run("gh", "api", "-X", "POST", f"repos/{repo}/actions/runners/remove-token", "--jq", ".token").stdout.strip()
        r = run("./config.sh", "remove", "--token", token, cwd=runner)
        log("runner removed" if r.returncode == 0 else f"runner removal failed: {r.stderr.strip()[-200:]}")

    if repo and not args.keep_repo:
        r = run("gh", "repo", "delete", repo, "--yes")
        if r.returncode == 0:
            log("repository deleted:", repo)
        else:
            failed = True
            log(f"repository not deleted ({r.stderr.strip()}); `gh auth refresh -s delete_repo` grants the scope")

    if app:
        destroy(app["key_file"])
        log("App private key destroyed")
        owner = st.get("owner")
        kind = run("gh", "api", f"users/{owner}", "--jq", ".type").stdout.strip()
        base = f"https://github.com/organizations/{owner}/settings/apps" if kind == "Organization" else "https://github.com/settings/apps"
        url = f"{base}/{app['slug']}/advanced"
        log(f"delete the App at {url} (GitHub has no API for it)")
        webbrowser.open(url)

    if failed:
        sys.exit(f"teardown: kept {args.state_dir}; fix the failure above and run it again")
    shutil.rmtree(args.state_dir)
    log("state removed:", args.state_dir)


if __name__ == "__main__":
    main()
