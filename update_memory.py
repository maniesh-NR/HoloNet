"""PROJECT_MEMORY.md updater + verification gate (pstack protocol, D-0016/D-0021).

Default mode appends a ZERO-NOISE summary of the last NUM_COMMITS
commits (per-commit: hash, subject, author, date) —
no raw patches or diffs. Set HOLO_MEMORY_FULL_DIFF=1 to include full diffs
(large; only when a session explicitly needs byte-level history).

Run before starting a coding session, or as a pre-commit/post-commit
hook: install the hooks once with `python3 update_memory.py
--install-hooks` (pre-commit refreshes + stages the memory file so
every commit carries fresh state; post-commit is a read-only
structural check that warns, never blocks).

Modes
  (default)       refresh the git-activity section (idempotent replace;
                  the structured sections above it are never touched)
  --check         verification gate (exit 2 on failure): the memory
                  file exists, has the activity section with >=1 commit
                  entry, its newest entry is an ancestor of HEAD, and
                  it lags HEAD by at most NUM_COMMITS commits
  --install-hooks write .git/hooks/pre-commit + post-commit (local to
                  this clone only; re-run after a fresh clone/restore)

The git-activity section is REPLACED on each run (idempotent); the
structured sections above it are never touched.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MEMORY_FILE = ROOT / "PROJECT_MEMORY.md"
GIT_DIR = ROOT / ".git"
NUM_COMMITS = 3  # commits summarized / max allowed memory lag behind HEAD
FULL_DIFF = os.environ.get("HOLO_MEMORY_FULL_DIFF") == "1"
SECTION_HEADER = "## Recent Progress & Git Activity"
ENTRY_RE = re.compile(r"^### Commit: ([0-9a-f]{7,40}) - ", re.M)


def _git(*args):
    """Run a git command in the repo; return (returncode, stdout)."""
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=True, check=False, encoding="utf-8",
        )
    except FileNotFoundError:
        return 1, ""
    return r.returncode, (r.stdout or "").strip()


def get_recent_git_activity():
    """Recent commit summaries (and optionally patches) via git log."""
    if FULL_DIFF:
        args = ["log", f"-n{NUM_COMMITS}",
                "--pretty=format:### Commit: %h - %s (%an, %ad)",
                "--date=short", "-p"]
    else:
        # Zero-noise default: subjects only (--no-patch suppresses the
        # stat display; diffs only via HOLO_MEMORY_FULL_DIFF=1).
        args = ["log", f"-n{NUM_COMMITS}",
                "--pretty=format:### Commit: %h - %s (%an, %ad)",
                "--date=short", "--stat", "--no-patch"]
    rc, out = _git(*args)
    if rc != 0:
        print("[!] git log failed (not a git repository?)")
        return ""
    return out


def update_project_memory():
    """Refresh the git-activity section (idempotent)."""
    activity = get_recent_git_activity()
    if not activity:
        print("[!] No git history or changes found to update.")
        return 1

    fence = "diff" if FULL_DIFF else "text"
    new_section = f"{SECTION_HEADER}\n\n```{fence}\n{activity}\n```\n"

    if MEMORY_FILE.exists():
        content = MEMORY_FILE.read_text(encoding="utf-8")
        if SECTION_HEADER in content:
            parts = content.split(SECTION_HEADER)
            remainder = parts[1]
            next_header_idx = remainder.find("\n## ")
            remaining = remainder[next_header_idx:] if next_header_idx != -1 else ""
            updated = parts[0].rstrip() + "\n\n" + new_section + remaining.lstrip()
        else:
            updated = content + "\n\n" + new_section
    else:
        updated = f"# Project Memory & State\n\n{new_section}"
    with open(MEMORY_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(updated)
    mode = "full diffs" if FULL_DIFF else "stat summaries"
    print(f"[OK] Updated {MEMORY_FILE.name} with the last {NUM_COMMITS} commits ({mode}).")
    return 0


def check():
    """Gate: prove the memory file is present, structured, and fresh."""
    problems = []
    lag_str = "n/a"
    if not MEMORY_FILE.exists():
        problems.append(f"{MEMORY_FILE.name} missing — restore from git")
    else:
        content = MEMORY_FILE.read_text(encoding="utf-8")
        if SECTION_HEADER not in content:
            problems.append(f"section '{SECTION_HEADER}' missing")
        else:
            section = content.split(SECTION_HEADER, 1)[1]
            entries = ENTRY_RE.findall(section)
            if not entries:
                problems.append("activity section has no '### Commit:' entries")
            else:
                newest = entries[0]  # git log lists newest first
                rc, _ = _git("merge-base", "--is-ancestor", newest, "HEAD")
                if rc != 0:
                    problems.append(f"newest entry {newest} is not an ancestor of HEAD")
                rc, out = _git("rev-list", "--count", f"{newest}..HEAD")
                if rc != 0 or not out.isdigit():
                    problems.append(f"cannot compute memory lag for {newest}")
                    out = "?"
                else:
                    lag_str = f"{out} commit(s)"
                    if int(out) > NUM_COMMITS:
                        problems.append(
                            f"memory is {out} commits behind HEAD (max {NUM_COMMITS})")
    if problems:
        print("[FAIL] MEMORY CHECK FAILED:")
        for p in problems:
            print(f"    - {p}")
        print("    fix: python3 update_memory.py")
        return 2
    print(f"[OK] MEMORY CHECK PASSED (section present, lag {lag_str}).")
    return 0


PRE_COMMIT = """#!/bin/sh
# HoloNet memory hook — installed by update_memory.py --install-hooks (D-0021).
# Refresh PROJECT_MEMORY.md's zero-noise git-activity section and stage it, so
# every commit carries fresh memory. Fails loud (blocks the commit) only on a
# real script error; a missing python interpreter is a warning, not a block.
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then
  echo "memory-hook: no python interpreter — PROJECT_MEMORY.md not refreshed" >&2
  exit 0
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
"$PY" "$ROOT/update_memory.py" || exit 1
git -C "$ROOT" add PROJECT_MEMORY.md 2>/dev/null || true
exit 0
"""

POST_COMMIT = """#!/bin/sh
# HoloNet memory hook — read-only structural check after the commit; never
# blocks (the pre-commit hook is the write path). Warns if the memory file
# lost its structure and prints the fix command.
PY="$(command -v python3 || command -v python)"
[ -z "$PY" ] && exit 0
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
"$PY" "$ROOT/update_memory.py" --check >/dev/null 2>&1 \\
  || echo "memory-hook: PROJECT_MEMORY.md check failed — run: python3 update_memory.py" >&2
exit 0
"""


def install_hooks():
    """Write the local pre-/post-commit hooks (never tracked by git)."""
    if not GIT_DIR.exists():
        print("[FAIL] no .git directory — not a repository (hooks are local-only)")
        return 1
    hooks = GIT_DIR / "hooks"
    hooks.mkdir(exist_ok=True)
    for name, body in (("pre-commit", PRE_COMMIT), ("post-commit", POST_COMMIT)):
        p = hooks / name
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        p.chmod(0o755)
        print(f"[OK] installed {p}")
    print("[OK] hooks installed (local to this clone; re-run --install-hooks after a fresh restore)")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="PROJECT_MEMORY.md updater + verification gate (pstack protocol)")
    ap.add_argument("--check", action="store_true",
                    help="gate: verify memory file exists, is structured, and <= NUM_COMMITS behind HEAD")
    ap.add_argument("--install-hooks", action="store_true",
                    help="install .git/hooks/pre-commit + post-commit memory hooks (local only)")
    args = ap.parse_args()
    if args.install_hooks:
        return install_hooks()
    if args.check:
        return check()
    return update_project_memory()


if __name__ == "__main__":
    sys.exit(main() or 0)
