"""
install_hooks.py — One-click Git Pre-Push Hook Installer for Project Aegis.

Installs a pre-push hook in .git/hooks/pre-push that runs:
    python aegis_ci.py --fail-on-critical
before any 'git push' command succeeds.
"""
import os
import sys
import stat

PRE_PUSH_HOOK = """#!/bin/sh
# Project Aegis Autonomous Pre-Push Security Gate
echo "============================================================"
echo "[Aegis Hook] Running Autonomous Security Gate before push..."
echo "============================================================"

# Resolve python executable
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[Aegis Hook Error] Python is not found in PATH."
    exit 1
fi

$PYTHON_CMD aegis_ci.py --repo . --fail-on-critical
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "============================================================"
    echo "[Aegis Hook] Push BLOCKED by Project Aegis Security Gate!"
    echo "Review findings in aegis_summary.md or .aegis_alerts/"
    echo "============================================================"
    exit 1
fi

echo "[Aegis Hook] Security Gate Cleared. Proceeding with push."
exit 0
"""

def install_hook():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    git_dir = os.path.join(repo_root, ".git")

    if not os.path.isdir(git_dir):
        print(f"[Aegis Hooks Error] No .git directory found at: {repo_root}")
        sys.exit(1)

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-push")

    with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(PRE_PUSH_HOOK.strip() + "\n")

    # Make executable on Unix / Linux / macOS / Git Bash
    try:
        current_stat = os.stat(hook_path)
        os.chmod(hook_path, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    print("============================================================")
    print("PROJECT AEGIS — PRE-PUSH HOOK INSTALLED SUCCESSFULLY!")
    print(f"Location: {hook_path}")
    print("Project Aegis will now automatically audit code diffs before every 'git push'.")
    print("============================================================")

if __name__ == "__main__":
    install_hook()
