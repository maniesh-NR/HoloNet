# HoloNet Harness — memory & infrastructure

The sandbox is disposable; the GitHub repository is the source of truth. This
directory is the project's harness: the durable memory and process
infrastructure that makes development reproducible across sandbox recycles,
long time gaps, and agent handovers.

## The rules in one breath

1. Every execution plan ends with a backup (`harness/scripts/backup.sh`) —
   event-driven, never on a time interval. A run that did not push is a run
   that did not happen.
2. No stage transition without independent adversarial consensus
   (`harness/ADVERSARIAL.md`). Every completed stage also gets a
   comprehensive hostile assessment before its results are trusted.
3. Nothing fakes success: unfinished work returns explicit milestone errors.

## Layout

| Path | Purpose |
|---|---|
| `WORKFLOW.md` | binding execution rules (plans, backups, gates, honesty) |
| `ADVERSARIAL.md` | reviewer roles, verdict format, independence, consensus rules |
| `memory/STATE.md` | current project state snapshot (re-verify after restore) |
| `memory/ROADMAP.md` | staged roadmap with measurable acceptance criteria |
| `memory/DECISIONS.md` | append-only decision log |
| `memory/LESSONS.md` | append-only failure lessons — read first on restore |
| `memory/SANDBOX-RESTORE.md` | cold-sandbox restore runbook |
| `memory/BACKUPS.md` | append-only backup log (auto-extended by `backup.sh`) |
| `memory/sessions/` | per-run journals |
| `adversarial/verdicts/` | immutable gate records, one per stage transition |
| `scripts/backup.sh` | commit + push + rolling restore tag `sandbox/latest` |

## Why a harness

The project lost a 197-test engine to two sandbox recycles. Recovery worked
because the knowledge that mattered was in the repo. The harness formalizes
that: state, roadmap, decisions, lessons, and gate verdicts are tracked
artifacts, pushed at the end of every run, so the next session — human or
agent, on any machine — resumes with full context.
