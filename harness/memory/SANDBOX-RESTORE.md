# Cold-Sandbox Restore Runbook

Exercised and verified (steps 1–4, 2026-11-13): clone, toolchain,
identity, tests, memory reading order all ran for real. The
`sandbox/latest` fast path (step 1) activates with the first end-of-run
backup of the harness run — budget ~5–10 minutes total; time the next
cold restore and update this estimate with the real figure.

1. **Recover the repo** (the GitHub repository is the source of truth):

       git clone https://github.com/maniesh-NR/HoloNet.git \
         /home/z/my-project/download/HoloNet
       # or, for the exact last backup state (use -B to RECREATE the main
       # branch — a bare checkout leaves detached HEAD, which backup.sh's
       # main-only guard would refuse):
       git checkout -B main sandbox/latest   # rolling tag, force-updated by backup.sh

2. **Toolchain** (fresh sandbox has none):

       curl -sSfL -o /tmp/rustup-init \
         https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
       chmod +x /tmp/rustup-init
       /tmp/rustup-init -y --profile minimal --default-toolchain stable
       . "$HOME/.cargo/env" && cargo --version

3. **Git identity** (D-0006 — the owner's identity, not the anonymous
   sandbox default, so harness-era commits stay attributable):

       git -C /home/z/my-project/download/HoloNet config user.name "maniesh-NR"
       git -C /home/z/my-project/download/HoloNet config user.email "83553290+maniesh-NR@users.noreply.github.com"

4. **Verify the baseline** (never trust, always re-verify):

       cd /home/z/my-project/download/HoloNet/engine
       cargo test --workspace        # must be green (75 as of 2026-11-13)

   and check the CI badge on the GitHub repo page is green.

5. **Load memory, in this order**:
   `harness/memory/LESSONS.md` → `STATE.md` → `ROADMAP.md` → newest
   `harness/adversarial/verdicts/` record → newest
   `harness/memory/sessions/` journal.

6. **Resume** at the stage allowed by the latest gate record. Write an
   execution plan whose FINAL step is always:

       bash harness/scripts/backup.sh "<summary>"

   The token must ALREADY be in the environment — provided out-of-band by
   the orchestrator or owner (env var only; never typed into a command
   line, never in a file — WORKFLOW §3.3). Backups fire at the END of
   every execution plan and every prompt output, never on a timer.
