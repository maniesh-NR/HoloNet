# Session journal — 2026-11-21: agentic memory as a data graph + RAG (D-0027/D-0028)

Owner instructions: "Store agentic memory as a data graph accessible to
all agents" then "use retrieval augmented generation (RAG) with the data
graphs".

## Done
- `harness/memory/graph/graph.json` (D-0019): 118 nodes / 74 edges —
  decisions D-0001..D-0020, stages S0–S7, gate records, all 23 review
  conditions with statuses, components, tests (incl. planned), CI jobs,
  threats, gaps, lessons, sessions, owner decisions, tools, panel
  roles; typed relations (supersedes/implements/satisfies/gates/
  verified_by/blocks/requires_decision/affects/closes/authored/...).
  DERIVED view — binding markdown stays authoritative; every node
  cites refs.
- `memory_graph.py`: check (structure + COVERAGE vs DECISIONS/ROADMAP/
  verdicts/sessions — a new D-NNNN or record without a graph node
  fails CI) / stats / query (by id, --type:, --status:, --rel) / dot.
- `memory_rag.py` (D-0020): BM25 over the heading-chunked markdown
  corpus (231 chunks; identifiers tokenize whole so exact ids outrank
  prose) + graph-context expansion (matched node → summary + 1-hop
  edges). `ask [--json] [-k]`, per-invocation index (no staleness),
  honest limitation: lexical not semantic. `smoke` = 5 retrieval
  anchors + graph id-resolution regression.
- CI: harness-audit job now runs graph `check` + RAG `smoke` before the
  hash-integrity step (conservative YAML per L-invalid-workflow).
- PROJECT_MEMORY: agents instructed to RETRIEVE before loading files.

## Verification
- Local: check OK (118/74), smoke OK (231 chunks), ask-demos correct
  (RtlGenRandom→SystemFunction036 chunk; A2-C1 resolved by id with
  closes/satisfies edges).
- CI run on this push = the graph/RAG steps' first real execution on a
  runner; watch and record in STATE if anything platform-specific
  appears (python3 availability on ubuntu-latest is standard).

## Next
- S1 continuation (salt-replay cache, off-loopback refusal first);
  owner decisions unchanged (OD-v031, OD-s5creds, OD-d0014).
- Future gates: panel reviewers can be handed RAG queries instead of
  full file reads (token-efficiency, D-0016 alignment).
