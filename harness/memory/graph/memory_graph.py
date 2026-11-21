"""memory_graph.py — query/validate the HoloNet agentic memory graph (D-0027).

The graph (graph.json, same directory) is a curated, DERIVED view of the
binding harness memory; the markdown files remain authoritative. This
tool makes the graph accessible to any agent or human without loading
the prose:

    python memory_graph.py check           # structure + coverage vs sources (CI)
    python memory_graph.py stats           # node/edge counts by type/relation
    python memory_graph.py query D-0018    # node + adjacent edges + neighbors
    python memory_graph.py query --rel requires_decision   # subgraph by relation
    python memory_graph.py dot out.dot     # Graphviz export

`check` exits non-zero on: unknown node types/relations, dangling edge
endpoints, duplicate ids, or COVERAGE DRIFT (an id present in the
authoritative sources but missing from the graph — e.g. a new D-NNNN in
DECISIONS.md, a new stage header in ROADMAP.md, a new verdict record, or
a new session journal). That check runs in the harness-audit CI job so
the graph cannot silently rot.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent  # harness/memory/graph -> repo root
GRAPH = HERE / "graph.json"

DECISIONS = REPO / "harness/memory/DECISIONS.md"
ROADMAP = REPO / "harness/memory/ROADMAP.md"
VERDICTS = REPO / "harness/adversarial/verdicts"
SESSIONS = REPO / "harness/memory/sessions"


def load():
    g = json.loads(GRAPH.read_text(encoding="utf-8"))
    ids = [n["id"] for n in g["nodes"]]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    errors = []
    if dupes:
        errors.append(f"duplicate node ids: {dupes}")
    idset = set(ids)
    rels = set(g["_meta"]["relations"])
    types = set(g["_meta"]["node_types"])
    for e in g["edges"]:
        for endpoint in ("src", "dst"):
            if e[endpoint] not in idset:
                errors.append(f"edge {e['src']}-{e['rel']}->{e['dst']}: unknown {endpoint} '{e[endpoint]}'")
        if e["rel"] not in rels:
            errors.append(f"edge {e['src']}-{e['rel']}->{e['dst']}: unknown relation '{e['rel']}'")
    for n in g["nodes"]:
        if n["type"] not in types:
            errors.append(f"node {n['id']}: unknown type '{n['type']}'")
    return g, errors


def coverage(g):
    """Every source-derived id must exist in the graph."""
    missing = []
    graph_ids = {n["id"] for n in g["nodes"]}

    if DECISIONS.exists():
        for m in re.finditer(r"\*\*(D-\d+)\b", DECISIONS.read_text(encoding="utf-8")):
            if m.group(1) not in graph_ids:
                missing.append(f"decision {m.group(1)} (in DECISIONS.md, not in graph)")

    if ROADMAP.exists():
        for m in re.finditer(r"^## (S\d)\b", ROADMAP.read_text(encoding="utf-8"), re.M):
            if m.group(1) not in graph_ids:
                missing.append(f"stage {m.group(1)} (in ROADMAP.md, not in graph)")

    if VERDICTS.exists():
        for f in sorted(VERDICTS.glob("*.md")):
            # A gate RECORD is a file whose last line is `chain: ...` per
            # ADVERSARIAL.md; auxiliary files (reviewer prompts, round
            # verdicts) share the sequence number and need no own node.
            last = (f.read_text(encoding="utf-8").rstrip().rsplit("\n", 1)[-1])
            if not last.startswith("chain:"):
                continue
            seq = f.name.split("-")[0]
            node_id = f"REVIEW-{seq}" if "progress" in f.name else f"GATE-{seq}"
            if node_id not in graph_ids:
                missing.append(f"record {f.name} (no graph node {node_id})")

    if SESSIONS.exists():
        for f in sorted(SESSIONS.glob("*.md")):
            date = f.name.split("-")[0:3]
            node_id = f"SES-{'-'.join(date)}"
            if node_id not in graph_ids:
                missing.append(f"session {f.name} (no graph node {node_id})")

    return missing


def cmd_check():
    g, errors = load()
    missing = coverage(g)
    for e in errors:
        print(f"STRUCTURE ERROR: {e}")
    for m in missing:
        print(f"COVERAGE MISSING: {m}")
    if errors or missing:
        print(f"check FAILED: {len(errors)} structural, {len(missing)} coverage")
        return 1
    print(
        f"check OK: {len(g['nodes'])} nodes, {len(g['edges'])} edges,"
        f" all ids unique, all edges typed and resolved,"
        f" coverage complete vs DECISIONS/ROADMAP/verdicts/sessions"
    )
    return 0


def cmd_stats():
    g, errors = load()
    if errors:
        for e in errors:
            print(f"STRUCTURE ERROR: {e}")
        return 1
    from collections import Counter
    nt = Counter(n["type"] for n in g["nodes"])
    ns = Counter(n.get("status", "?") for n in g["nodes"])
    er = Counter(e["rel"] for e in g["edges"])
    print("nodes:", len(g["nodes"]), dict(sorted(nt.items())))
    print("statuses:", dict(sorted(ns.items())))
    print("edges:", len(g["edges"]), dict(sorted(er.items())))
    return 0


def cmd_query(needle, rel=None):
    g, _ = load()
    idset = {n["id"] for n in g["nodes"]}
    targets = set()
    if needle in idset:
        targets = {needle}
    elif needle.startswith("--status:"):
        status = needle.split(":", 1)[1]
        targets = {n["id"] for n in g["nodes"] if n.get("status") == status}
    elif needle.startswith("--type:"):
        t = needle.split(":", 1)[1]
        targets = {n["id"] for n in g["nodes"] if n["type"] == t}
    else:
        nl = needle.lower()
        targets = {
            n["id"]
            for n in g["nodes"]
            if nl in n["id"].lower() or nl in n["label"].lower()
        }
    if not targets:
        print(f"no match for '{needle}'")
        return 1
    out = []
    for n in g["nodes"]:
        if n["id"] in targets:
            out.append(f"[{n['type']}] {n['id']} — {n['label']} ({n.get('status','?')})")
            out.append(f"    {n['summary']}")
            for r in n.get("refs", []):
                out.append(f"    ref: {r}")
    for e in g["edges"]:
        if e["src"] in targets or e["dst"] in targets:
            if rel and e["rel"] != rel:
                continue
            arrow = f"{e['src']} --{e['rel']}--> {e['dst']}"
            if e.get("note"):
                arrow += f"  ({e['note']})"
            out.append("  " + arrow)
    print("\n".join(out))
    return 0


def cmd_dot(out_path):
    g, errors = load()
    if errors:
        for e in errors:
            print(f"STRUCTURE ERROR: {e}")
        return 1
    safe = lambda s: s.replace('"', '\\"')
    lines = ["digraph holonet_memory {", "  rankdir=LR;", "  node [shape=box, style=filled, fillcolor=\"#f4f6f8\", fontsize=10];"]
    color = {
        "decision": "#dbe9ff", "stage": "#dcf5e2", "gate_record": "#ffe6cc",
        "condition": "#fff2cc", "gap": "#ffd6d6", "lesson": "#f0dcff",
        "owner_decision": "#ffcccc", "threat": "#ffdddd", "ci_job": "#e2f0ff",
        "test": "#eaffe2", "component": "#e8e8e8", "session": "#f5f5f5",
        "tool": "#f0f0d8", "role": "#eeeeff",
    }
    for n in g["nodes"]:
        lines.append(
            f'  "{safe(n["id"])}" [label="{safe(n["id"])}\\n{safe(n["label"])}", fillcolor="{color.get(n["type"], "#ffffff")}"];'
        )
    for e in g["edges"]:
        lines.append(f'  "{safe(e["src"])}" -> "{safe(e["dst"])}" [label="{safe(e["rel"])}"];')
    lines.append("}")
    Path(out_path).write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"wrote {out_path} ({len(g['nodes'])} nodes, {len(g['edges'])} edges)")
    return 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, *rest = argv
    if cmd == "check":
        return cmd_check()
    if cmd == "stats":
        return cmd_stats()
    if cmd == "query":
        return cmd_query(rest[0], rest[1] if len(rest) > 1 else None)
    if cmd == "dot":
        return cmd_dot(rest[0] if rest else "memory-graph.dot")
    print(f"unknown command '{cmd}'; use check|stats|query|dot")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
