"""memory_rag.py — retrieval-augmented generation over the HoloNet memory
graph + markdown corpus (D-0028, extends D-0027).

Agents should RETRIEVE with this tool instead of loading whole files:

    python memory_rag.py ask "salt replay protection"       # top chunks + graph context
    python memory_rag.py ask "windows entropy" --json       # machine-readable
    python memory_rag.py ask "entropy" -k 3                 # fewer chunks
    python memory_rag.py smoke                              # CI regression

Method (honest, std-only — no embeddings, no dependencies):
  1. CORPUS: the binding markdown memory + docs (DECISIONS, ROADMAP,
     STATE, LESSONS, BACKUPS, SANDBOX-RESTORE, sessions/, verdicts/,
     docs/*, README, PROJECT_MEMORY) chunked by heading (~<=60 lines).
  2. RETRIEVAL: BM25 (k1=1.5, b=0.75) over word tokens; identifiers
     like D-0018 / A2-C1 / GAP-xchacha tokenize as single tokens, so
     exact ids outrank prose.
  3. GRAPH AUGMENTATION: any memory-graph node whose id or label matches
     the query contributes its summary + 1-hop edges as GRAPH CONTEXT —
     structured recall the plain-text corpus cannot give.
The index is built per invocation (corpus < 1 MB): always fresh, no
cache to invalidate. Lexical, not semantic: paraphrases rank lower than
keyword overlaps — query with the vocabulary the project uses.
"""
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
GRAPH = HERE / "graph.json"

CORPUS = [
    REPO / "PROJECT_MEMORY.md",
    REPO / "README.md",
    REPO / "harness/WORKFLOW.md",
    REPO / "harness/ADVERSARIAL.md",
    REPO / "harness/memory/DECISIONS.md",
    REPO / "harness/memory/ROADMAP.md",
    REPO / "harness/memory/STATE.md",
    REPO / "harness/memory/LESSONS.md",
    REPO / "harness/memory/BACKUPS.md",
    REPO / "harness/memory/SANDBOX-RESTORE.md",
] + sorted((REPO / "harness/memory/sessions").glob("*.md")) \
  + sorted((REPO / "harness/adversarial/verdicts").glob("*.md")) \
  + sorted((REPO / "docs").glob("*.md"))

TOKEN_RE = re.compile(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*")
MAX_CHUNK_LINES = 60
K1, B = 1.5, 0.75


def tokens(text):
    return [t.lower() for t in TOKEN_RE.findall(text)]


def chunk_file(path):
    """Split a markdown file into (heading-path, text) chunks."""
    rel = path.relative_to(REPO).as_posix()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    chunks, heading, buf = [], "", []

    def flush():
        if not any(l.strip() for l in buf):
            return
        text_lines = buf
        for i in range(0, len(text_lines), MAX_CHUNK_LINES):
            part = text_lines[i:i + MAX_CHUNK_LINES]
            chunks.append({"ref": rel, "heading": heading or "(top)",
                           "text": "\n".join(part).strip()})

    for line in lines:
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            flush()
            buf = []
            heading = m.group(2).strip()
        buf.append(line)
    flush()
    return chunks


def build():
    chunks = []
    for p in CORPUS:
        if p.exists():
            chunks.extend(chunk_file(p))
    for c in chunks:
        c["toks"] = tokens(c["text"])
        c["tf"] = {}
        for t in c["toks"]:
            c["tf"][t] = c["tf"].get(t, 0) + 1
    n = len(chunks)
    avgdl = sum(len(c["toks"]) for c in chunks) / max(n, 1)
    df = {}
    for c in chunks:
        for t in c["tf"]:
            df[t] = df.get(t, 0) + 1
    return chunks, n, avgdl, df


def bm25(query_toks, chunks, n, avgdl, df):
    scores = []
    for i, c in enumerate(chunks):
        s = 0.0
        dl = len(c["toks"])
        for q in query_toks:
            f = c["tf"].get(q, 0)
            if not f:
                continue
            idf = math.log(1 + (n - df.get(q, 0) + 0.5) / (df.get(q, 0) + 0.5))
            s += idf * (f * (K1 + 1)) / (f + K1 * (1 - B + B * dl / avgdl))
        if s > 0:
            scores.append((s, i))
    scores.sort(reverse=True)
    return scores


def graph_context(query, g, limit=3):
    ql = query.lower()
    qtoks = set(tokens(query))
    hits = []
    for node in g["nodes"]:
        nid = node["id"].lower()
        if node["id"].lower() in qtoks or nid in ql or node["label"].lower() in ql:
            hits.append(node)
    if not hits:
        for node in g["nodes"]:
            hay = (node["id"] + " " + node["label"] + " " + node["summary"]).lower()
            if sum(1 for t in qtoks if len(t) > 3 and t in hay) >= 2:
                hits.append(node)
    hits = hits[:limit]
    if not hits:
        return []
    ids = {h["id"] for h in hits}
    out = []
    for h in hits:
        edges = [e for e in g["edges"] if e["src"] == h["id"] or e["dst"] == h["id"]]
        out.append({"node": h, "edges": edges[:8]})
    return out


def cmd_ask(query, k=5, as_json=False):
    chunks, n, avgdl, df = build()
    g = json.loads(GRAPH.read_text(encoding="utf-8"))
    scores = bm25(tokens(query), chunks, n, avgdl, df)[:k]
    picked = [{"ref": chunks[i]["ref"], "heading": chunks[i]["heading"],
               "score": round(s, 2), "text": chunks[i]["text"]} for s, i in scores]
    gctx = graph_context(query, g)
    if as_json:
        print(json.dumps({"query": query, "chunks": picked, "graph": [
            {"node": e["node"], "edges": e["edges"]} for e in gctx]}, ensure_ascii=False, indent=1))
        return 0
    print(f"QUERY: {query!r}  (corpus: {n} chunks)")
    for r, c in enumerate(picked, 1):
        print(f"\n[{r}] {c['ref']} :: {c['heading']}  (score {c['score']})")
        body = c["text"] if len(c["text"]) <= 900 else c["text"][:900] + " …"
        print(body)
    if gctx:
        print("\nGRAPH CONTEXT:")
        for e in gctx:
            nd = e["node"]
            print(f"  [{nd['type']}] {nd['id']} — {nd['label']} ({nd.get('status','?')})")
            print(f"      {nd['summary']}")
            for ed in e["edges"]:
                print(f"      {ed['src']} --{ed['rel']}--> {ed['dst']}"
                      + (f"  ({ed['note']})" if ed.get("note") else ""))
    return 0


def cmd_smoke():
    """Retrieval regressions: known facts must surface their anchors."""
    chunks, n, avgdl, df = build()
    failures = []

    def top_contains(query, needle, k=6):
        got = " ".join(chunks[i]["text"] for s, i in bm25(tokens(query), chunks, n, avgdl, df)[:k])
        if needle.lower() not in got.lower():
            failures.append(f"ask {query!r}: top-{k} lacks {needle!r}")

    top_contains("RtlGenRandom link failure windows", "SystemFunction036")
    top_contains("salt replay", "replay")
    top_contains("Cargo.lock 1.77.2", "version = 3")
    top_contains("descope rule v1.0 protocol", "trojan")
    top_contains("backup final step", "backup.sh")
    g = json.loads(GRAPH.read_text(encoding="utf-8"))
    ctx = graph_context("D-0018", g)
    if not ctx or ctx[0]["node"]["id"] != "D-0018":
        failures.append("graph context: D-0018 not resolved by id")
    if failures:
        for f in failures:
            print(f"SMOKE FAIL: {f}")
        return 1
    print(f"smoke OK: {n} chunks; 5 retrieval anchors + graph id-resolution verified")
    return 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, *rest = argv
    if cmd == "ask":
        if not rest:
            print("usage: ask <query> [k] [--json]")
            return 2
        query = rest[0]
        k = 5
        as_json = "--json" in rest
        for a in rest[1:]:
            if a.isdigit():
                k = int(a)
        return cmd_ask(query, k, as_json)
    if cmd == "smoke":
        return cmd_smoke()
    print(f"unknown command '{cmd}'; use ask|smoke")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
