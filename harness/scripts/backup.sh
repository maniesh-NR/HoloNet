#!/usr/bin/env bash
# HoloNet sandbox backup — MUST be the last step of every execution plan.
# Event-driven by design: there is deliberately NO cron/interval variant.
#
# Auth: the token arrives via the HOLO_GITHUB_TOKEN env var only; it is
# never stored in the repo and never echoed. TRADEOFF (recorded in
# THREAT-MODEL.md §A and LESSONS.md): the token is interpolated into the
# push URL, transiently visible in git's process argv during the push —
# accepted single-user-sandbox risk; a credential-helper flow is the
# documented backlog alternative.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# one line, no newlines, bounded length — the message becomes a BACKUPS.md
# log line (gate-0001 A4 recommendation)
MSG="$(printf '%s' "${1:-sandbox snapshot}" | tr -d '\n\r' | head -c 200)"

BRANCH="$(git branch --show-current)"
if [ "$BRANCH" != "main" ]; then
  echo "backup: REFUSING to push non-main branch '$BRANCH'" >&2
  exit 1
fi

LOG="harness/memory/BACKUPS.md"
PREV="$(git rev-parse --short HEAD)"

# 1) Log the attempt BEFORE committing, so the line lands in this commit.
printf '%s | prev=%s | %s\n' "$TS" "$PREV" "$MSG" >> "$LOG"

# 2) Commit everything (gitignore keeps build artifacts out of history).
git add -A
if git diff --cached --quiet; then
  echo "backup: tree clean (no new commit)"
else
  git commit -m "backup: ${MSG}" >/dev/null
  echo "backup: committed $(git rev-parse --short HEAD)"
fi

# 3) Push. Token (if provided) is used inline only and never persisted.
if [ -n "${HOLO_GITHUB_TOKEN:-}" ]; then
  URL="https://x-access-token:${HOLO_GITHUB_TOKEN}@github.com/maniesh-NR/HoloNet.git"
else
  URL="origin"
fi
if ! git push "$URL" main; then
  # durably record the failure (gate-0001 A4-C1): the next successful
  # backup's commit carries this marker, so the log never claims a
  # backup that did not land
  printf '%s | FAILED | push did not land — run incomplete\n' "$TS" >> "$LOG"
  echo "backup: PUSH FAILED — the run is NOT complete; nothing is claimed" >&2
  exit 1
fi

# 4) Rolling restore pointer (cold-sandbox restore = checkout sandbox/latest).
git tag -f sandbox/latest HEAD >/dev/null
if ! git push "$URL" --force sandbox/latest >/dev/null 2>&1; then
  # tag failure is best-effort and LOGGED, per WORKFLOW.md §1.3 — main is
  # the completion criterion, the tag is the convenience pointer
  printf '%s | WARN | sandbox/latest tag push failed (main pushed OK)\n' "$TS" >> "$LOG"
  echo "backup: WARN rolling tag push failed (branch push succeeded)"
fi
echo "backup: pushed ${TS} HEAD=$(git rev-parse --short HEAD) tag=sandbox/latest"
