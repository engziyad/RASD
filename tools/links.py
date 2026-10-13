#!/usr/bin/env python3
"""
links.py - every relative link in every Markdown file must point at something that exists.

A framework whose documents link to files that moved is a framework nobody trusts. This
checks every [text](target) and <img src="target"> in the repository's Markdown: the
file or folder must exist, and a #fragment must match a heading in the target file.
External links (http, https, mailto) are not fetched - CI must not depend on the internet.

Usage
  python tools/links.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, GREEN, RED, RESET, ROOT  # noqa: E402

LINK = re.compile(r"!?\[(?:[^\]\[]|\[[^\]]*\])*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMG = re.compile(r"<img[^>]+src=\"([^\"]+)\"", re.IGNORECASE)
FENCE = re.compile(r"^(```|~~~)")
SKIP_DIRS = {".git", "node_modules", "__pycache__", "results"}


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"[`*_~]|<[^>]+>", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out, in_code = set(), False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line.strip()):
            in_code = not in_code
            continue
        if not in_code and line.startswith("#"):
            out.add(slug(line.lstrip("#")))
    return out


def targets(path: Path):
    in_code = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line.strip()):
            in_code = not in_code
            continue
        if in_code:
            continue
        for m in list(LINK.finditer(line)) + list(IMG.finditer(line)):
            yield n, m.group(1)


def check() -> list[str]:
    errors = []
    files = [p for p in ROOT.rglob("*.md") if not SKIP_DIRS & set(p.relative_to(ROOT).parts)]
    for md in sorted(files):
        for n, target in targets(md):
            if re.match(r"^(https?:|mailto:|#$)", target):
                continue
            path_part, _, fragment = target.partition("#")
            dest = md if not path_part else (md.parent / path_part).resolve()
            where = f"{md.relative_to(ROOT)}:{n}"
            if not dest.exists():
                errors.append(f"{where}: {target} does not exist")
                continue
            if fragment and dest.is_file() and dest.suffix == ".md" and fragment.lower() not in anchors(dest):
                errors.append(f"{where}: #{fragment} is not a heading in {dest.relative_to(ROOT)}")
    return errors


def main() -> int:
    errors = check()
    count = sum(1 for p in ROOT.rglob("*.md") if not SKIP_DIRS & set(p.relative_to(ROOT).parts))
    for e in errors:
        print(f"  {RED}✗{RESET} {e}")
    print(f"\n{BOLD}{count} Markdown files · {len(errors)} broken link(s){RESET}" if errors else
          f"{GREEN}{count} Markdown files · every relative link resolves{RESET}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
