# Backup log (append-only; auto-extended by harness/scripts/backup.sh)

UTC time | prev-commit | run summary
---
2026-11-13T07:02:13Z | prev=53ff229 | drill: verify FAILED-marker path (expected to fail)
2026-11-13T07:02:13Z | FAILED | push did not land — run incomplete
2026-11-13T07:02:44Z | prev=5c40a7a | gate 0001 PASSED (panel consensus); harness + memory installed; entropy fail-closed + hardening applied; tests 75 green; record sha256=5bbc465cff655a2d900c8f10fdd98602c67273311cc514429a30e67c3a0ab4f4
2026-11-18T03:21:14Z | prev=82620a3 | progress review 0002 PASSED (4x PROCEED_WITH_CONDITIONS, 0 BLOCK); record+prompts archived; roadmap/threat-model/readme/state amended; gitattributes+lockfile-v3+numbering remediations; D-0011..D-0014;
2026-11-18T03:21:46Z | prev=3700d61 | record 0002 tie-in: sha256=72d8858d012b4a2d8477fd96af33c7aabcf0e7dda0d659ebd138c37ace3c05c5
2026-11-19T08:45:10Z | prev=fc9b889 | pstack protocol adopted (D-0016): PROJECT_MEMORY.md operational layer + zero-noise update_memory.py; CI-diagnosis verified closed (run 44234338593 all green except expected-red windows); session journ
2026-11-19T09:18:04Z | prev=00772a4 | harness hardening verified: A4-C2 full-tree audit + A4-C3 backup guards GREEN on CI (run 44494124628 @ 00772a4, D-0017); all record-0002 conditions closed or owner-gated
2026-11-20T03:51:12Z | prev=92b4b15 | S1 item 0 DONE + verified: Windows entropy FFI (SystemFunction036) fail-closed; windows-latest REQUIRED-green; ledger 76/75/75 (run on 92b4b15 success); A3-C3 window closed; D-0018; THREAT-MODEL G shi
2026-11-20T05:56:27Z | prev=cc4564f | cross-validation 0003 PASSED (4x PWC, panel consensus; mid-run remote divergence reconciled); residual conditions applied; tests 76 green; record sha256=2ad6fe71c58a8e6c39001966eab1d3c80a43e62b250601c
2026-11-20T07:13:21Z | prev=ef19a6f | pstack re-affirm: memory hooks D-0021 + --check gate; PROJECT_MEMORY refreshed; Cargo.lock v3 restored (live v4 regression found on origin/main); 4W fallback static 78; engine unchanged vs 2dae1ce
2026-11-20T07:13:21Z | FAILED | push did not land — run incomplete
2026-11-20T07:27:35Z | prev=203f965 | S1 hardening run 4: A2-C1 SaltCache (cap-1024 FIFO, opaque replay refusal, named test) + A3-C4 loopback-only proxy_listen bind (HOLONET_PROXY_LISTEN_ANY override, named tests); suite 76->83 local gree
2026-11-20T07:27:35Z | FAILED | push did not land — run incomplete
2026-11-20T08:30:26Z | prev=d9e137e | S1 hardening run 5: ProbeGuard decay cap-1024 (A1-F8), CSPRNG full-jitter slow-close w/ explicit 2s ceiling (A3-C10), A2-F6 auth read deadline 10s; backup push LANDED ef19a6f..d9e137e, CI 44700103379 
2026-11-20T08:30:26Z | FAILED | push did not land — run incomplete
2026-11-20T08:31:40Z | LANDED | retry push (credential helper from HOLO_GITHUB_TOKEN env; backup.sh's in-script push has no terminal for the prompt) carried d9e137e..7a00fcc incl. the FAILED marker above — the marker documents the first attempt honestly; run-5 backup 4ddd081 IS on origin/main; CI of the 86-tree triggers on this push
2026-11-20T08:34:51Z | prev=f433de4 | S1 run 5 CI-VERIFIED: run 44703200189 @ f433de4 all-green 6/6, per-OS ledger 86 Linux/85 macOS/85 Windows (socks redirect reconciled); README/ARCHITECTURE/ROADMAP/STATE/PROJECT_MEMORY updated to verif
2026-11-20T09:19:04Z | prev=1c82ad4 | S1a closing: rand-split enforcement D-0024: weak PRNG behind rand::nosec doc-hidden, re-exports closed, workspace audit test allowlist-enforced; negative demos live (audit FAIL w/ file:line + E0425); 
2026-11-20T09:19:04Z | FAILED | push did not land — run incomplete
2026-11-20T11:36:06Z | LANDED | retry push (credential helper from HOLO_GITHUB_TOKEN env; backup.sh's in-script push has no terminal for the prompt) carried 1c82ad4..5382c5f incl. the FAILED marker above — the marker documents the first attempt honestly; run-6 backup 652c346 IS on origin/main; CI of the 87-tree triggers on the closure push
2026-11-20T11:36:06Z | prev=5382c5f | backup: run-6 push landed via retry (1c82ad4..5382c5f); CI of the 87-tree triggers on this closure push
2026-11-20T11:36:06Z | FAILED | push did not land — run incomplete
2026-11-20T11:39:41Z | LANDED | retry push carried 5382c5f..937554f (closure commit 13983d5 + its FAILED marker; first retry attempt failed on a dropped env var, re-loaded from the owner upload — not a token problem) — HEAD final at 937554f
2026-11-20T11:39:41Z | LANDED | CI run 44728988531 @ 937554f SUCCESS 6/6 jobs; per-OS ledger 87 Linux / 86 macOS / 86 Windows (visible 77/76/76 + redirected socks 10, reconciled); README/ARCHITECTURE/PROJECT_MEMORY/STATE updated to the verified numbers
2026-11-20T11:39:41Z | prev=937554f | run-6 CI-VERIFIED: run 44728988531 @ 937554f all-green 6/6, per-OS ledger 87 Linux/86 macOS/86 Windows (socks redirect reconciled); README/ARCHITECTURE/STATE/PROJECT_MEMORY updated to verified counts
2026-11-20T11:39:41Z | FAILED | push did not land — run incomplete
2026-11-20T15:01:11Z | prev=6314da0 | run 7: D-0025 advisory+GHSA+v0.3.1 cut+drafts deleted; D-0026 S5 creds decided --allow-untracked
2026-11-20T15:01:11Z | FAILED | push did not land — run incomplete
2026-11-21T00:00:00Z | LANDED | (run-8 reconciliation, found at session start) the run-7 push DID land: origin/main == 17e5b8d (carries 6314da0..17e5b8d incl. the 19e0791 run-7 backup + both FAILED markers + the STATE filename fix); the 15:01:11Z FAILED line above documents only the in-script attempt. CI of the 17e5b8d tree: run 44759108489 SUCCESS (same 87/86/86 engine tree as 937554f plus docs/harness-only commits) — recorded by run 8 after the session cut
2026-11-21T05:41:44Z | prev=e2e3a83 | run 8: XChaCha wire fix D-0029 (standard XChaCha20-Poly1305-IETF, 24-byte LE SIP004 counter; draft-irtf-cfrg-xchacha-03 vectors 2.2.1/A.2.1/A.1; +5 tests, rebased-tree 92-green, static 94); mid-run di
2026-11-21T05:41:44Z | FAILED | push did not land — run incomplete
2026-11-21T05:44:00Z | LANDED | retry push (env-var credential helper) carried 05f9906..676a58c (run-8 commit e2e3a83 + backup 84dbf83 incl. the FAILED marker above); the marker documents the in-script attempt. MID-RUN DIVERGENCE NOTE: backup.sh first REFUSED — a parallel graph/RAG session had pushed bcf8da1+05f9906; reconciled per WORKFLOW §1.4 (commit + rebase origin/main; one conflict in DECISIONS.md resolved keeping BOTH sides; my XChaCha decision renumbered D-0027→D-0029 after theirs took D-0027/D-0028; stale post-rebase REBASE_HEAD cleared for the guard). **CI-VERIFIED: run 44872078593 @ 676a58c all-green (6/6) — per-OS ledger 92 Linux / 91 macOS / 91 Windows** (visible 82/81/81 + redirected socks 10, reconciled; harness-audit ran the graph coverage check + RAG smoke over the extended graph). The run-8 closure updates (README/ARCHITECTURE/STATE count citations to the verified 92/91/91) ride the NEXT backup push
2026-11-21T05:44:58Z | prev=676a58c | run 8 closure: CI-VERIFIED 44872078593 @ 676a58c all-green 6/6, per-OS ledger 92 Linux/91 macOS/91 Windows (visible 82/81/81 + socks 10 reconciled); README badge + Status block and ARCHITECTURE data-p
