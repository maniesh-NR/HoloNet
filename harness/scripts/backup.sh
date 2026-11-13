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
#
# Durability scoping (honest, gate-0001 A4-C5): FAILED/WARN marker lines
# are committed LOCALLY immediately, but they reach the remote only inside
# the NEXT successful backup's push. A pushed BACKUPS.md that ends with no
# FAILED line does not prove no failure happened — an unpushed gap is the
# out-of-band signal of a dead run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# one line, no newlines, no pipe-forged fields, bounded length — the
# message becomes a BACKUPS.md log line (gate-0001 A4)
MSG="$(printf '%s' "${1:-sandbox snapshot}" | tr -d '\n\r|' | cut -c1-200)"

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
  # durably record the failure (gate-0001 A4-C1/C2): commit the marker NOW
  # so the mandated rebase recovery path (WORKFLOW §1.4) starts from a
  # clean tree instead of unstaged changes a rebase would refuse.
  printf '%s | FAILED | push did not land — run incomplete\n' "$TS" >> "$LOG"
  git add "$LOG" && git commit -m "backup: FAILED ${TS} (push did not land)" >/dev/null 2>&1 || true
  echo "backup: PUSH FAILED — the run is NOT complete; nothing is claimed" >&2
  exit 1
fi

# 4) Rolling restore pointer (cold-sandbox restore = checkout sandbox/latest).
#    Best-effort and LOGGED per WORKFLOW §1.3 — main is the completion
#    criterion, the tag is the convenience pointer.
git tag -f sandbox/latest HEAD >/dev/null
if ! git push "$URL" --force sandbox/latest >/dev/null 2>&1; then
  printf '%s | WARN | sandbox/latest tag push failed (main pushed OK)\n' "$TS" >> "$LOG"
  echo "backup: WARN rolling tag push failed (branch push succeeded)"
fi
echo "backup: pushed ${TS} HEAD=$(git rev-parse --short HEAD) tag=sandbox/latest"
