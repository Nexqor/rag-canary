#!/usr/bin/env python3
"""
rag-canary - canary tokens for RAG pipelines and AI assistants.

Plant unique, harmless markers in sensitive documents before they are indexed.
If a marker ever shows up in a model answer, a chat log, a proxy log or a paste
site, you know exactly which document leaked, and through which path.

Detects:
  * RAG over-sharing (users retrieving documents they shouldn't see)
  * prompt-injection exfiltration from knowledge bases
  * training-data / fine-tune memorization of private documents
  * copies of your docs ending up somewhere they shouldn't

Stdlib only.

Usage:
  python rag_canary.py new    --label "HR salary bands 2026" [--style email|key|phrase|id]
  python rag_canary.py embed  docs/salaries.md --label "HR salary bands" [--style key]
  python rag_canary.py scan   logs/ chat_export.json answers.txt
  python rag_canary.py list
Registry: ./canaries.json (override with --registry)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path

DEFAULT_REGISTRY = Path("canaries.json")
WORDS = ["amber", "basalt", "cobalt", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "juniper",
         "kestrel", "lumen", "marble", "nectar", "onyx", "pylon", "quartz", "raven", "sable", "tundra",
         "umber", "vesper", "willow", "xenon", "yarrow", "zephyr"]


# ------------------------------------------------------------ registry
def load_registry(p: Path) -> dict:
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"version": 1, "secret": secrets.token_hex(16), "canaries": []}


def save_registry(p: Path, reg: dict) -> None:
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


# ------------------------------------------------------------ tokens
def make_token(reg: dict, style: str) -> str:
    """Tokens carry a short HMAC tag so random look-alikes don't trigger false positives."""
    rid = secrets.token_hex(5)
    tag = hmac.new(bytes.fromhex(reg["secret"]), rid.encode(), hashlib.sha256).hexdigest()[:6]
    if style == "email":
        return f"{WORDS[int(rid[:2], 16) % 26]}.{rid}{tag}@canary-mail.invalid"
    if style == "key":
        return f"sk-canary-{rid}{tag}"
    if style == "phrase":
        a, b, c = (WORDS[int(rid[i:i + 2], 16) % 26] for i in (0, 2, 4))
        return f"{a}-{b}-{c}-{rid[6:]}{tag}"
    return f"NXQ-CANARY-{rid}{tag}".upper()


def verify(reg: dict, token: str) -> bool:
    m = re.search(r"([0-9a-f]{10})([0-9a-f]{6})", token.lower())
    if not m:
        return False
    rid, tag = m.groups()
    good = hmac.new(bytes.fromhex(reg["secret"]), rid.encode(), hashlib.sha256).hexdigest()[:6]
    return hmac.compare_digest(tag, good)


def new_canary(reg: dict, label: str, style: str, target: str = "") -> dict:
    c = {
        "token": make_token(reg, style),
        "label": label,
        "style": style,
        "target": target,
        "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    reg["canaries"].append(c)
    return c


# ------------------------------------------------------------ embedding
def embed_line(token: str, style: str, suffix: str) -> str:
    """A line that reads naturally to a model and is easy to spot for a human reviewer."""
    if style == "email":
        text = f"Escalation contact for this document: {token}"
    elif style == "key":
        text = f"Internal reference key: {token}"
    elif style == "phrase":
        text = f"Document passphrase: {token}"
    else:
        text = f"Document ID: {token}"
    if suffix in (".md", ".txt", ".rst", ""):
        return f"\n\n{text}\n"
    if suffix in (".html", ".htm"):
        return f'\n<p class="doc-ref">{text}</p>\n'
    if suffix in (".csv",):
        return f"\n# {text}\n"
    return f"\n{text}\n"


def embed(path: Path, reg: dict, label: str, style: str) -> dict:
    c = new_canary(reg, label or path.name, style, target=str(path))
    with path.open("a", encoding="utf-8") as fh:
        fh.write(embed_line(c["token"], style, path.suffix.lower()))
    return c


# ------------------------------------------------------------ scanning
TEXT_EXT = {".txt", ".md", ".json", ".jsonl", ".log", ".csv", ".html", ".htm", ".xml", ".yaml", ".yml", ".eml"}


def iter_files(paths: list[Path]):
    for p in paths:
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and (f.suffix.lower() in TEXT_EXT or f.suffix == ""):
                    yield f
        elif p.is_file():
            yield p


def scan(paths: list[Path], reg: dict, from_stdin: bool = False) -> list[dict]:
    index = {c["token"].lower(): c for c in reg["canaries"]}
    if not index:
        return []
    # one alternation regex, escaped, case-insensitive
    rx = re.compile("|".join(re.escape(t) for t in sorted(index, key=len, reverse=True)), re.I)
    tail = re.compile(r"[0-9a-f]{16}", re.I)  # catches tokens that were partially rewritten
    hits = []

    def check(text: str, where: str):
        for i, line in enumerate(text.splitlines(), 1):
            for m in rx.finditer(line):
                c = index[m.group(0).lower()]
                hits.append({"where": where, "line": i, "token": c["token"], "label": c["label"],
                             "target": c.get("target", ""), "match": "exact"})
            for m in tail.finditer(line):
                frag = m.group(0).lower()
                if any(frag in t for t in index) and not rx.search(line) and verify(reg, frag):
                    c = next(index[t] for t in index if frag in t)
                    hits.append({"where": where, "line": i, "token": c["token"], "label": c["label"],
                                 "target": c.get("target", ""), "match": "fragment"})

    if from_stdin:
        check(sys.stdin.read(), "<stdin>")
    for f in iter_files(paths):
        try:
            check(f.read_text(encoding="utf-8", errors="replace"), str(f))
        except OSError as e:
            print(f"[!] cannot read {f}: {e}", file=sys.stderr)
    return hits


# ------------------------------------------------------------ cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Canary tokens for RAG pipelines and AI assistants.")
    ap.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("new", help="create a canary token")
    s.add_argument("--label", required=True)
    s.add_argument("--style", default="id", choices=["id", "email", "key", "phrase"])
    s = sub.add_parser("embed", help="append a canary to documents")
    s.add_argument("files", nargs="+", type=Path)
    s.add_argument("--label", default="")
    s.add_argument("--style", default="id", choices=["id", "email", "key", "phrase"])
    s = sub.add_parser("scan", help="search logs / outputs for canaries")
    s.add_argument("paths", nargs="*", type=Path)
    s.add_argument("--json", metavar="FILE")
    sub.add_parser("list", help="show registered canaries")
    a = ap.parse_args(argv)

    reg = load_registry(a.registry)

    if a.cmd == "new":
        c = new_canary(reg, a.label, a.style)
        save_registry(a.registry, reg)
        print(c["token"])
        return 0

    if a.cmd == "embed":
        for f in a.files:
            if not f.is_file():
                print(f"[!] not a file: {f}", file=sys.stderr)
                continue
            c = embed(f, reg, a.label or f.name, a.style)
            print(f"[+] {f}  ->  {c['token']}")
        save_registry(a.registry, reg)
        return 0

    if a.cmd == "list":
        for c in reg["canaries"]:
            print(f"{c['created']}  {c['style']:6}  {c['token']}  {c['label']}  {c.get('target', '')}")
        print(f"\n{len(reg['canaries'])} canary token(s)")
        return 0

    if a.cmd == "scan":
        stdin = (not a.paths) or any(str(p) == "-" for p in a.paths)
        paths = [p for p in a.paths if str(p) != "-"]
        hits = scan(paths, reg, from_stdin=stdin)
        for h in hits:
            print(f"[LEAK] {h['where']}:{h['line']}  '{h['label']}'  ({h['match']})\n       token {h['token']}  planted in {h['target'] or 'n/a'}")
        print(f"\n{len(hits)} canary hit(s)." if hits else "No canaries found.")
        if a.json:
            Path(a.json).write_text(json.dumps(hits, indent=2, ensure_ascii=False), encoding="utf-8")
        return 1 if hits else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
