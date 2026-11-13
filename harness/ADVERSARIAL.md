# Adversarial Review Protocol

Purpose: every stage must survive hostile examination before it is trusted
or built upon. Reviewers are agents assigned adversarial ROLES. Their job
is to find the strongest reason NOT to proceed — not to approve. Approval
without evidence is a failed review; so is a BLOCK without concrete
grounds.

## Standing roles (fixed panel)

| ID | Role | Attacks |
|----|------|---------|
| A1 | Reliability Skeptic | claims vs evidence; test meaningfulness; milestone honesty; baseline trustworthiness |
| A2 | Security Red | threat model; crypto plan and risks; entropy/key handling; secret hygiene; user safety of shipped behavior |
| A3 | Strategy Adversary | roadmap sequencing and dependencies; scope realism; descope rules; acceptance-criteria measurability |
| A4 | Process Auditor | the harness/workflow itself; consensus failure modes; backup integrity; restore runbook; rubber-stamp risk |

## Independence requirements

1. Reviewers are launched in parallel; each gets this protocol plus the
   repository working tree as the ONLY shared input.
2. Reviewers must not see each other's output before filing their verdict.
3. Verdicts are filed before any aggregation happens.
4. The aggregator must not reword, drop, or soften dissent. It records
   verdicts verbatim, then computes consensus mechanically.

### Independence limits (stated honestly — added at gate 0001, A4-C4)

The rules above deliver PROCEDURAL separation, not epistemic
independence:
- All reviewers of a gate are launched by one orchestrator with one
  prompt-skeleton style and typically one model family — correlated
  blind spots are probable. When model choice is available, vary it
  between gates; rotate prompt emphasis where substance allows.
- The aggregator is typically the AUTHOR of the work under review — a
  conflict of interest that cannot be designed away in a solo project,
  only disclosed and audited. Verbatim transcription is self-attested
  unless raw replies are archived: therefore every gate record archives
  the reviewer prompts verbatim (`NNNN-reviewer-prompts.md`) and
  carries each verdict exactly as returned.
- "Independent consensus" in this protocol means role-separated blind
  review filed before aggregation — it does NOT claim independence of
  training, incentive, or perspective.

## Verdict format (strict — the last section of a reviewer's reply)

    AGENT: <ID> <role>
    VERDICT: PROCEED | PROCEED_WITH_CONDITIONS | BLOCK
    FINDINGS:
    - [F#] <finding> — evidence: <path:line> (verified | suspected)
    CONDITIONS:
    - [C#] <concrete, verifiable condition>   (required unless PROCEED)
    DISSENT/NOTES: <anything the aggregator must not smooth over>

## Consensus rule

- CONSENSUS (stage transition allowed) ⇔ ALL active reviewers return
  non-BLOCK. An "active reviewer" is one launched for this gate whose
  verdict was filed — or whose non-response is explicitly recorded in
  the gate record; a launch failure counts as non-response and requires
  a re-launch BEFORE consensus is computed.
- Any BLOCK ⇒ the transition is halted. Remediate what is addressable,
  re-run ONLY the blocking reviewer, record the re-review — and the
  re-review MUST cite the remediation commit SHAs as evidence. If the
  remediation touches anything outside the blocking finding's scope,
  the FULL panel re-runs instead (gate-0001 A4-C5). An unresolved BLOCK
  means: do not proceed; escalate to the human owner with the dissent
  quoted verbatim.
- Conditions from PROCEED_WITH_CONDITIONS verdicts are BINDING: the
  aggregator copies them into the next stage's charter (`memory/ROADMAP.md`)
  as acceptance criteria before work starts, and they are checked at the
  NEXT gate like any other criterion.
- Dissent is recorded verbatim; never paraphrased away.

## Records

- One record per gate: `verdicts/NNNN-<gate>.md` — each reviewer's verdict
  as returned, the consensus computation, the decision, binding conditions.
- Committed with the same backup as the rest of the run; immutable after.
- Tamper-evidence, honestly scoped (gate-0001 A4-C7): each record ends
  with a `chain:` line carrying the SHA-256 of the previous record's
  full text; record 0001 carries `chain: genesis`. The chain detects
  partial or sloppy rewrites ONLY — an attacker with push rights can
  rewrite history and recompute every chain. Out-of-band anchors: GitHub
  server-side push events, public third-party clones, and owner-held
  copies of record hashes. The run that pushes a gate record quotes its
  SHA-256 in its `BACKUPS.md` line, tying the log to the record.
