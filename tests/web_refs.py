#!/usr/bin/env python3
"""Check that a static web app's page and module graph resolve on its server.

Starts at the page (index.html), collects every script, module and preload
it references (script src, link modulepreload / preload / icon / manifest /
stylesheet, and the inline module scripts' imports, workers, service worker
and literal fetches), then follows every JavaScript module it reaches: static
`import` / `export ... from`, literal dynamic `import()`, `new URL(<literal>,
import.meta.url)`, workers, worklets and `importScripts`. Every reference is
fetched through the server and must answer 200; a JavaScript module must also
be served as JavaScript (browsers refuse module scripts with another type).

The module graph is followed to its end (bounded), not one level: PhotoCraft's
page imports a boot module, which imports app/photocraft-web.js, which imports
./snippets/... relative to app/ (a path only the server's mapping provides).

Only literal, relative, same-origin references are checked; data:, blob:,
other origins and computed URLs are skipped. One exception is not asserted:
wasm-bindgen's fallback `module_or_path = new URL('<name>_bg.wasm',
import.meta.url)`, used only when init() gets no path, when the page passes
`module_or_path` itself (every Craft page does; their fallback names often
don't exist).

    # Craft tests (through the app's own nginx, from inside its container):
    python3 tests/web_refs.py --docker-exec portcullis-photocraft-1 http://127.0.0.1:8080/
    # An unpacked archive on disk (no server; files only):
    python3 tests/web_refs.py --root /tmp/x/photocraft-web-0.19.0

Exits 1 when the page or any reference fails (2: usage error).
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

MAX_MODULES = 200

_Q = r"""(['"`])([^'"`\n\\]+)\1"""
# import x from '…' / import {a, b} from '…' / import '…' / export … from '…'
STATIC_IMPORT_RE = re.compile(
    r"""(?:^|[;\s}])(?:import\s*(?:[\w$*{}\s,]+?\s*from\s*)?|export\s*(?:[\w$*{}\s,]+?)\s*from\s*)""" + _Q)
DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*""" + _Q)
META_URL_RE = re.compile(r"""\bnew\s+URL\s*\(\s*""" + _Q + r"""\s*(?:\+[^,()]*)?,\s*import\.meta\.url\s*\)""")
PAGE_URL_RE = re.compile(r"""\bnew\s+URL\s*\(\s*""" + _Q + r"""\s*(?:\+[^,()]*)?,\s*(?:location\.href|document\.baseURI|self\.location(?:\.href)?)\s*\)""")
WORKER_RE = re.compile(r"""\bnew\s+(?:Shared)?Worker\s*\(\s*""" + _Q)
WORKLET_RE = re.compile(r"""\.addModule\s*\(\s*""" + _Q)
SW_RE = re.compile(r"""serviceWorker\.register\s*\(\s*""" + _Q)
IMPORT_SCRIPTS_RE = re.compile(r"""\bimportScripts\s*\(\s*""" + _Q)
FETCH_RE = re.compile(r"""\bfetch\s*\(\s*""" + _Q)
# wasm-bindgen's default path, used only when init() is called without one.
WASM_BINDGEN_DEFAULT_RE = re.compile(r"""module_or_path\s*=\s*new\s+URL\s*\(\s*""" + _Q + r"""\s*,\s*import\.meta\.url\s*\)""")

LINK_RELS = {"modulepreload", "preload", "icon", "shortcut icon", "apple-touch-icon", "manifest", "stylesheet"}

# (kind, reference, is_module): is_module = fetched and followed as JavaScript.
Ref = Tuple[str, str, bool]


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: List[Ref] = []
        self.inline: List[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.refs.append(("script src", a["src"], True))
            elif a.get("type", "").strip().lower() in ("module", "", "text/javascript", "application/javascript"):
                self._in_script = True
        elif tag == "link" and a.get("href"):
            rel = " ".join(a.get("rel", "").lower().split())
            if rel in LINK_RELS:
                self.refs.append((f"link {rel}", a["href"], rel == "modulepreload"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.inline.append(data)


def script_refs(src: str, skip_wasm_default: bool) -> List[Ref]:
    """References in one JavaScript source (a module or an inline script)."""
    skipped = set()
    if skip_wasm_default:
        skipped = {m.start(2) for m in WASM_BINDGEN_DEFAULT_RE.finditer(src)}
    out: List[Ref] = []
    for rx, kind, module in (
        (STATIC_IMPORT_RE, "import", True),
        (DYNAMIC_IMPORT_RE, "import()", True),
        (WORKER_RE, "worker", True),
        (WORKLET_RE, "worklet", True),
        (SW_RE, "service worker", True),
        (IMPORT_SCRIPTS_RE, "importScripts", True),
        (META_URL_RE, "new URL(import.meta.url)", False),
        (PAGE_URL_RE, "new URL(location)", False),
        (FETCH_RE, "fetch", False),
    ):
        for m in rx.finditer(src):
            if m.group(1) == "`" and "${" in m.group(2):
                continue
            if kind == "new URL(import.meta.url)" and m.start(2) in skipped:
                continue
            out.append((kind, m.group(2), module))
    return out


def page_refs(html: str) -> Tuple[List[Ref], bool]:
    """References of the page, and whether it passes module_or_path itself."""
    p = _Page()
    p.feed(html)
    passes_path = "module_or_path" in "\n".join(p.inline)
    refs = list(p.refs)
    for s in p.inline:
        refs += script_refs(s, passes_path)
    return refs, passes_path


def _checkable(ref: str) -> Optional[str]:
    """None when the reference is not a literal same-origin relative path."""
    r = ref.strip()
    if not r or r.startswith(("data:", "blob:", "#", "javascript:", "mailto:")):
        return "not a file"
    if re.match(r"^[a-z][a-z0-9+.-]*:", r, re.I) or r.startswith("//"):
        return "other origin"
    return None


Fetch = Callable[[str], Tuple[int, str, bytes]]   # path -> (status, content-type, body)


def check(fetch: Fetch, page_path: str = "/") -> List[str]:
    """Crawl from page_path; returns failure lines (empty = all good)."""
    failures: List[str] = []
    status, _, body = fetch(page_path)
    if status != 200:
        return [f"{page_path}: page answered {status}"]
    base = "http://site" + page_path
    refs, passes_path = page_refs(body.decode("utf-8", "replace"))
    queue: List[Tuple[str, str, str, bool]] = [(page_path, k, r, m) for k, r, m in refs]
    checked: Set[str] = set()
    modules: Set[str] = set()
    failed: Set[str] = set()
    origin = {page_path: base}
    while queue:
        frm, kind, ref, is_module = queue.pop(0)
        if _checkable(ref):
            continue
        if not ref.startswith(("./", "../", "/")) and kind in ("import", "import()"):
            failures.append(f"{frm}: {kind} '{ref}' is a bare specifier (no import map): a browser can't load it")
            continue
        path = urlsplit(urljoin(origin.get(frm, base), ref)).path
        if path in failed or (path in checked and (not is_module or path in modules)):
            continue
        checked.add(path)
        st, ctype, data = fetch(path)
        print(f"  {st} {path}  ({kind} from {frm})")
        if st != 200:
            failures.append(f"{frm}: {kind} '{ref}' -> {path} answered {st}")
            failed.add(path)
            continue
        if not is_module:
            continue
        if not re.match(r"^\s*(text|application)/(x-)?javascript\b", ctype, re.I):
            failures.append(f"{frm}: {kind} '{ref}' -> {path} served as '{ctype}', not JavaScript")
        if path in modules:
            continue
        modules.add(path)
        if len(modules) > MAX_MODULES:
            failures.append(f"more than {MAX_MODULES} modules: stopping")
            break
        origin[path] = "http://site" + path
        for k, r, m in script_refs(data.decode("utf-8", "replace"), passes_path):
            queue.append((path, k, r, m))
    return failures


def docker_fetcher(container: str, base_url: str) -> Fetch:
    base_url = base_url.rstrip("/")

    def fetch(path: str) -> Tuple[int, str, bytes]:
        # busybox / GNU wget: -S prints the response headers to stderr, also on errors.
        p = subprocess.run(["docker", "exec", container, "wget", "-q", "-S", "-O", "-", base_url + path],
                           capture_output=True, timeout=120)
        head = p.stderr.decode("latin-1")
        codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
        ctypes = re.findall(r"(?im)^\s*content-type:\s*([^\r\n]+)", head)
        status = int(codes[-1]) if codes else 0
        return status, (ctypes[-1].strip() if ctypes else ""), (p.stdout if p.returncode == 0 else b"")
    return fetch


JS_EXT = (".js", ".mjs")


def root_fetcher(root: str) -> Fetch:
    root = os.path.realpath(root)

    def fetch(path: str) -> Tuple[int, str, bytes]:
        rel = path.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        f = os.path.realpath(os.path.join(root, rel))
        if not f.startswith(root + os.sep) or not os.path.isfile(f):
            return 404, "", b""
        with open(f, "rb") as fh:
            data = fh.read()
        return 200, ("text/javascript" if f.endswith(JS_EXT) else "application/octet-stream"), data
    return fetch


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--docker-exec", metavar="CONTAINER", help="fetch with wget inside this container")
    g.add_argument("--root", metavar="DIR", help="read an unpacked site from disk instead")
    ap.add_argument("base_url", nargs="?", default="http://127.0.0.1:8080/")
    ap.add_argument("--page", default="/", help="page path (default /)")
    a = ap.parse_args(argv)
    fetch = docker_fetcher(a.docker_exec, a.base_url) if a.docker_exec else root_fetcher(a.root)
    failures = check(fetch, a.page)
    for f in failures:
        print(f"web_refs: FAIL {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
