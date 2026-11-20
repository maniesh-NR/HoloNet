# Session journal — 2026-11-20f: owner decisions executed (D-0025 advisory + v0.3.1, D-0026 S5 creds)

## Decisions received (owner, chat)

- **D-0025** (resolves D-0009/D-0013): option (a) — advisory + v0.3.1.
- **D-0026** (S5 credentials model): option (ii) — embedded, with
  recorded risk-acceptance (amends D-0001 for S5 operational creds;
  WORKFLOW §3.3 session secrets untouched; test fixtures stay
  synthetic; Green-R2 VPN-Gate-first ordering stands).

## Investigation before acting (the invisible-releases defect, fully diagnosed)

- Release API inventory: the per-OS v0.2.0/v0.3.0 "missing" releases
  are SEVEN maintainer-visible DRAFTS with uploaded assets:
  - v0.2.0-windows: x64+ x86 zips + SHA256SUMS (PRE-HARDENING builds)
  - v0.2.0-macos: x64+arm64 tarballs + SHA256SUMS
  - v0.2.0-android: arm64+armv7 tarballs + SHA256SUMS
  - v0.3.0-windows: x64+ x86 zips (PRE-HARDENING builds)
  - v0.3.0-macos: arm64+x64 tarballs
  - v0.3.0-linux: x64 tarball + SHA256SUMS
  - v0.3.0-android: arm64+armv7 tarballs
  The release workflows concluded "success" because
  `gh release upload` happily uploads to drafts. Public releases were
  only v0.2.0-linux / empty v0.2.0 / src-only v0.3.0.
- Affected scope precision: the WINDOWS drafts hold the pre-hardening
  builds; unix artifacts used /dev/urandom (weak fallback never
  engaged). Public v0.2.0-linux is NOT affected by SA-0001.

## Execution chain (D-0025)

1. **Advisory drafted**: docs/advisories/2026-11-20-sa-0001-…-weak-
   entropy.md (HoloNet-SA-0001) — precise publication history (drafts
   only; earlier public window unknowable per D-0013), affected
   material, fix provenance (53ff229), upgrade guidance.
2. **GHSA published**: created via REST (2 schema iterations —
   severity "medium" not "moderate"; package.ecosystem required) →
   **GHSA-8h6m-w5qj-cq9g, state=published**; CVE requested (202, id
   assigned asynchronously). Advisory file cross-referenced.
3. **v0.3.1 cut** from CI-verified `6314da0` (run 44729423292 6/6
   green): per-OS tags v0.3.1-windows/-macos/-linux/-android.
   - EVENT LOSS FOUND: pushing all 4 tags in ONE `git push` produced
     ZERO workflow runs; delete + individual re-push with 10 s gaps
     fired all four reliably (LESSONS entry). (First delete attempt
     also failed auth — the inline credential helper was on the
     re-push but not the delete; corrected.)
   - Builds: windows 44758027482, macos 44758056729, linux
     44758090961, android 44758125210 — ALL success; per-OS releases
     public with assets + per-release SHA256SUMS.
4. **Master manifest**: all 7 binaries downloaded, sha256-verified
   against their per-OS manifests (all OK), master SHA256SUMS.txt
   built (7 entries), signed Ed25519:
   - Signing: python cryptography (sandbox has no ssh-keygen; ssh-keygen
     -Y plan corrected BEFORE commit in D-0025 to the openssl-verifiable
     mechanism). Private key /home/z/my-project/keys/holonet-release-
     signing.pem (0600, OUTSIDE the repo); pubkey committed
     docs/release-signing.pub.
   - Verification self-tested BEFORE use: python-sign → stock-openssl
     verify roundtrip OK; README documents the user-side one-liner.
5. **Main release v0.3.1** created at tag (commit 6314da0) with the
   advisory in the notes + 3 assets (master SHA256SUMS.txt, .sig,
   HoloNet-SA-0001.md). Per-OS releases public (draft=False) — the
   invisible-releases defect is fixed for the new line.
6. **Draft reconciliation**: all SEVEN drafts DELETED (204 each;
   inventories quoted above = the durable record). Windows drafts
   destroyed rather than republished (republish = rebuild vulnerable
   code, never); unix drafts deleted as superseded (removes the
   one-click-publish footgun). v0.2.0-linux public release KEPT.

## Execution (D-0026)

- Recorded decision + constraints in DECISIONS; ROADMAP S5
  "OWNER DECISION REQUIRED" paragraph replaced with the recorded
  decision text. No code changes (S5 not chartered yet).

## Docs updated

README (releases paragraph rewritten to the post-D-0025 reality +
"Verifying release signatures" section), THREAT-MODEL §G (disclosure
bullet → RESOLVED with GHSA id), ROADMAP S5 (decision recorded),
DECISIONS (D-0025 with the pre-commit signing-mechanism correction +
GHSA outcome; D-0026), PROJECT_MEMORY (objective/playbook/snapshot),
STATE (run-7 header, run-6 preserved), this journal.

## Token hygiene note

- The owner PAT remains valid all session (used via env-var + inline
  credential helper, never echoed/stored; upload file untouched).
  **Rotation reminder issued again** — the token transited chat.
- One transient auth failure was caused by the env var dropping
  between shell sessions (re-load pattern; NOT a token problem), one
  by a missing inline helper on the delete pushes (my error, fixed).

## Next

1. Owner: confirm/override D-0014 (trojan default) — last open owner
   item; rotate the PAT.
2. Dev: S1 continues — XChaCha wire fix is UNBLOCKED (v0.3.1 landed
   first, per D-0013's ordering), then BLAKE2s → X25519 → AES-CFB →
   ExpandLabel → bignum/RSA (S1b/S1c).
3. After the CVE id is assigned by GitHub, backfill it into SA-0001 +
   the GHSA (small doc commit).
4. S7 packaging: re-sign under an owner-held key (or record no-go).

## Backup

- End-of-run backup.sh with the run summary; push via the env-var
  credential helper (retry pattern as runs 5–6). Outcome: BACKUPS.md
  tail.

## Backup triage note

- backup.sh first REFUSED (untracked outside harness/): the two new
  D-0025 deliverables — docs/advisories/2026-11-20-sa-0001-…md and
  docs/release-signing.pub — were never staged. Disposition:
  INTENDED for this backup (they ARE the advisory + pubkey the
  decision requires); re-run with the loud --allow-untracked bypass.
