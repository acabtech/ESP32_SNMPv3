#!/usr/bin/env python3
"""Assemble and build the MkDocs documentation site.

The canonical docs live in ``docs/``, but several important pages are the
READMEs of other directories (the repository root, ``src/``, ``tests/host/``,
``tests/interop/``) plus ``CONTRIBUTING.md`` and ``CHANGELOG.md``. MkDocs can
only read files below its ``docs_dir``, so this script stages a build tree in
``.mkdocs-build/docs``:

* every file in ``docs/`` is copied verbatim (assets included),
* the external READMEs are imported to stable site paths,
* relative links are rewritten. Links to files that become site pages are
  made relative to the page's new location; links to source files that are not
  published (headers, examples, scripts, LICENSE, ...) become absolute GitHub
  URLs so they still work from the site.

Usage:
    python3 scripts/docs.py build   # stage + mkdocs build --strict
    python3 scripts/docs.py serve   # stage + mkdocs serve (local preview)
    python3 scripts/docs.py sync    # stage only (debugging)
"""

from __future__ import annotations

import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / ".mkdocs-build"
STAGED_DOCS = BUILD_DIR / "docs"

REPO_URL = "https://github.com/acabtech/ESP32_SNMPv3"
BRANCH = "main"

# Canonical source -> published site path.
IMPORTS = {
    "README.md": "index.md",
    "src/README.md": "api.md",
    "tests/host/README.md": "testing/host.md",
    "tests/interop/README.md": "testing/interop.md",
    "CONTRIBUTING.md": "contributing.md",
    "CHANGELOG.md": "changelog.md",
}

INLINE_LINK = re.compile(r"\]\((?P<target>[^)\n]+)\)")
SKIP_PREFIXES = ("http://", "https://", "//", "mailto:", "tel:", "#", "data:")


def is_file(repo_path: str) -> bool:
    return (ROOT / repo_path).is_file()


def is_dir(repo_path: str) -> bool:
    return (ROOT / repo_path).is_dir()


def site_page_for(repo_path: str) -> str | None:
    """Return the staged site path for a repo path, or None if not published."""
    repo_path = repo_path.strip("/")
    if repo_path in ("", "."):
        return "index.md"
    if repo_path in IMPORTS:
        return IMPORTS[repo_path]
    if repo_path == "docs":
        return "index.md"
    if repo_path.startswith("docs/"):
        rel = repo_path[len("docs/") :]
        # Directory links must land on an index page.
        if is_dir(repo_path) or (ROOT / "docs" / rel / "index.md").is_file():
            index = f"{rel}/index.md"
            if is_file(f"docs/{index}"):
                return index
            return None
        return rel
    return None


def github_url(repo_path: str) -> str:
    kind = "tree" if is_dir(repo_path) else "blob"
    return f"{REPO_URL}/{kind}/{BRANCH}/{repo_path}"


def split_target(raw: str) -> tuple[str, str]:
    """Split a Markdown link target from an optional title."""
    raw = raw.strip()
    parts = raw.split(None, 1)
    return parts[0], (" " + parts[1]) if len(parts) > 1 else ""


def rewrite_link(target: str, source_path: str, site_path: str) -> str:
    if not target or target.startswith(SKIP_PREFIXES):
        return target

    path_part, sep, anchor = target.partition("#")
    if not path_part:
        return target

    # Resolve against the file's location in the repository.
    source_dir = PurePosixPath(source_path).parent
    resolved = posixpath.normpath(posixpath.join(str(source_dir), path_part))
    if resolved == ".." or resolved.startswith("../"):
        return target  # outside the repository; leave it alone

    target_site = site_page_for(resolved)
    if target_site is not None:
        current_dir = posixpath.dirname(site_path) or "."
        rel = posixpath.relpath(target_site, start=current_dir)
        rewritten = rel
    elif is_file(resolved) or is_dir(resolved):
        rewritten = github_url(resolved)
    else:
        return target  # unknown target; let MkDocs report it in strict mode

    return rewritten + (sep + anchor if sep else "")


def rewrite_markdown(text: str, source_path: str, site_path: str) -> str:
    def replace(match: re.Match[str]) -> str:
        target, title = split_target(match.group("target"))
        return "](" + rewrite_link(target, source_path, site_path) + title + ")"

    return INLINE_LINK.sub(replace, text)


def stage() -> None:
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    STAGED_DOCS.mkdir(parents=True)

    # Copy docs/ (including any assets) first.
    shutil.copytree(ROOT / "docs", STAGED_DOCS, dirs_exist_ok=True)

    # Build the complete page list: every copied docs page plus the imports.
    pages: dict[str, str] = {}
    for md in sorted((ROOT / "docs").rglob("*.md")):
        rel = md.relative_to(ROOT / "docs").as_posix()
        pages[rel] = f"docs/{rel}"
    pages.update({site: source for source, site in IMPORTS.items()})

    for site_path, source_path in pages.items():
        source = ROOT / source_path
        text = source.read_text(encoding="utf-8")
        rewritten = rewrite_markdown(text, source_path, site_path)
        destination = STAGED_DOCS / site_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rewritten, encoding="utf-8")

    print(f"Staged {len(pages)} pages in {STAGED_DOCS.relative_to(ROOT)}")


def run_mkdocs(command: str, extra: list[str]) -> None:
    args = [sys.executable, "-m", "mkdocs", command, *extra]
    if command == "build" and "--strict" not in args:
        args.append("--strict")
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "build"
    if command not in {"build", "serve", "sync"}:
        print(f"unknown command: {command!r} (expected build, serve or sync)", file=sys.stderr)
        return 2

    stage()
    if command != "sync":
        run_mkdocs(command, sys.argv[2:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
