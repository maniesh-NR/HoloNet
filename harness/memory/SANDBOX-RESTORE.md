# Cold-Sandbox Restore Runbook

Exercised and verified (steps 1–4, 2026-11-13): clone, toolchain,
identity, tests, memory reading order all ran for real. The
`sandbox/latest` fast path (step 1) activates with the first end-of-run
backup of the harness run — budget ~5–10 minutes total; time the next
cold restore and update this estimate with the real figure.
**Windows-host variant added 2026-11-17 (progress review 0002, A4-C4)
— see step 4W.**

1. **Recover the repo** (the GitHub repository is the source of truth):

       git clone https://github.com/maniesh-NR/HoloNet.git \
         /home/z/my-project/download/HoloNet
       # or, for the exact last backup state (use -B to RECREATE the main
       # branch — a bare checkout leaves detached HEAD, which backup.sh's
       # main-only guard would refuse):
       git checkout -B main sandbox/latest   # rolling tag, force-updated by backup.sh

   Windows host (Git Bash) equivalent — clone into the workspace, then
   the same `-B main` recreate:

       git clone https://github.com/maniesh-NR/HoloNet.git \
         "$USERPROFILE/.zcode/workspace/default/HoloNet"
       cd "$USERPROFILE/.zcode/workspace/default/HoloNet"
       git checkout -B main sandbox/latest

2. **Toolchain** (fresh sandbox has none):

       curl -sSfL -o /tmp/rustup-init \
         https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
       chmod +x /tmp/rustup-init
       /tmp/rustup-init -y --profile minimal --default-toolchain stable
       . "$HOME/.cargo/env" && cargo --version

   Windows host: `winget install Rustlang.Rustup` PLUS a C toolchain
   (MSVC Build Tools — large — or the `x86_64-pc-windows-gnu` target
   under Git Bash's ucrt64). Without one of these, `cargo test` cannot
   run — use the 4W fallback instead of skipping verification silently.

3. **Git identity** (D-0006 — the owner's identity, not the anonymous
   sandbox default, so harness-era commits stay attributable):

       git -C /home/z/my-project/download/HoloNet config user.name "maniesh-NR"
       git -C /home/z/my-project/download/HoloNet config user.email "83553290+maniesh-NR@users.noreply.github.com"

   (On the Windows host the 2026-11-17 restore found the identity
   already configured globally — verify with `git config user.name`
   and only set it if missing. Push auth uses the Windows credential
   manager; HOLO_GITHUB_TOKEN is NOT required when cached credentials
   work — backup.sh falls back to `origin`.)

4. **Verify the baseline** (never trust, always re-verify):

       cd /home/z/my-project/download/HoloNet/engine
       cargo test --workspace        # must be green (75 as of 2026-11-13)

   and check the CI badge on the GitHub repo page is green.

   4W. **Toolchain-less hosts (Windows fallback, D-0012/A4-C4):** if no
   Rust toolchain/linker exists, do NOT claim test-green. The honest
   procedure: (a) static count — `grep -rn "#\[test\]" engine/crates
   --include="*.rs" | wc -l` (75 expected); (b) public CI conclusions
   for HEAD via anonymous API —
   `https://api.github.com/repos/maniesh-NR/HoloNet/actions/runs?head_sha=<sha>`
   (expected at the 2026-11-17 push: ubuntu green-again after the
   lockfile fix, 1.77.2 job green, windows-latest red-by-design until
   S1 item 0); (c) record BOTH facts in the session journal. Any
   CI-red beyond the disclosed windows job blocks baseline trust.

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
   (On the Windows host, cached credential-manager auth may substitute
   for the token — verified working 2026-11-17.)
