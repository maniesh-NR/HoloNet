"""PROJECT_MEMORY.md updater (pstack protocol, D-0016).

Default mode appends a ZERO-NOISE summary of the last NUM_COMMITS
commits (per-commit: hash, subject, author, date, per-file stat line) —
no raw patches. Set HOLO_MEMORY_FULL_DIFF=1 to include full diffs
(large; only when a session explicitly needs byte-level history).

Run before starting a coding session, or as a pre-commit/post-commit
hook. The git-activity section is REPLACED on each run (idempotent);
the structured sections above it are never touched.
"""
import os
import subprocess
from pathlib import Path

MEMORY_FILE = Path("PROJECT_MEMORY.md")
NUM_COMMITS = 3  # Number of recent commits to summarize
FULL_DIFF = os.environ.get("HOLO_MEMORY_FULL_DIFF") == "1"
SECTION_HEADER = "## Recent Progress & Git Activity"


def get_recent_git_activity():
    """Recent commit summaries (and optionally patches) via git log."""
    try:
        if FULL_DIFF:
            args = [
                "git", "log", f"-n{NUM_COMMITS}",
                "--pretty=format:### Commit: %h - %s (%an, %ad)",
                "--date=short", "-p",
            ]
        else:
            # Zero-noise default: stat lines only, no patches.
            args = [
                "git", "log", f"-n{NUM_COMMITS}",
                "--pretty=format:### Commit: %h - %s (%an, %ad)",
                "--date=short", "--stat", "--no-patch",
            ]
        result = subprocess.run(
            args, capture_output=True, text=True, check=True, encoding="utf-8"
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running git command: {e}")
        return ""
    except FileNotFoundError:
        print("[!] Git is not installed or not found in system PATH.")
        return ""


def update_project_memory():
    activity = get_recent_git_activity()
    if not activity:
        print("[!] No git history or changes found to update.")
        return

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

    MEMORY_FILE.write_text(updated, encoding="utf-8")
    mode = "full diffs" if FULL_DIFF else "stat summaries"
    print(f"[✓] Updated {MEMORY_FILE} with the last {NUM_COMMITS} commits ({mode}).")


if __name__ == "__main__":
    update_project_memory()
