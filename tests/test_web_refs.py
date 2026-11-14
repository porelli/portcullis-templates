#!/usr/bin/env python3
"""Unit tests for tests/web_refs.py (the Craft tests' page / module graph check).

    python3 -m unittest discover -s tests -p 'test_*.py'
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from typing import Dict, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import web_refs as w  # noqa: E402

# The shape of PhotoCraft 0.19.0's release zip: the boot module imports
# app/photocraft-web.js, which imports ./snippets/ relative to app/, while the
# zip has snippets/ only at its top level.
PHOTOCRAFT = {
    "index.html": """<!DOCTYPE html><html><head>
<script type="module">
import init, * as bindings from './boot-1.js';
const wasm = await init({ module_or_path: './boot-1_bg.wasm' });
</script>
<link rel="modulepreload" href="./boot-1.js"><link rel="modulepreload" href="./snippets/eframe-1/inline0.js">
<link rel="preload" href="./boot-1_bg.wasm" as="fetch"></head><body></body></html>""",
    "boot-1.js": """import { default as _default } from './app/web.js';
if (typeof module_or_path === 'undefined') { module_or_path = new URL('boot_bg.wasm', import.meta.url); }""",
    "boot-1_bg.wasm": "\0asm",
    "app/web.js": """import * as import1 from "./snippets/eframe-1/inline0.js"
import { egui_text_agent_activate } from './snippets/eframe-1/inline0.js';""",
    "snippets/eframe-1/inline0.js": "export function egui_text_agent_activate() {}",
}


def site(files: Dict[str, str]) -> str:
    d = tempfile.mkdtemp()
    for name, body in files.items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
    return d


def fake(files: Dict[str, str], ctype: Dict[str, str] = None) -> w.Fetch:
    def fetch(path: str) -> Tuple[int, str, bytes]:
        rel = path.lstrip("/") or "index.html"
        if rel not in files:
            return 404, "", b""
        t = (ctype or {}).get(rel, "text/javascript" if rel.endswith(".js") else "text/html")
        return 200, t, files[rel].encode()
    return fetch


class WebRefsTests(unittest.TestCase):
    def test_photocraft_layout_fails_two_modules_deep(self) -> None:
        f = w.check(w.root_fetcher(site(PHOTOCRAFT)))
        self.assertEqual(len(f), 1, f)
        self.assertIn("/app/snippets/eframe-1/inline0.js answered 404", f[0])
        self.assertIn("/app/web.js", f[0])

    def test_photocraft_with_the_nginx_mapping_passes(self) -> None:
        # nginx.conf's location ^~ /app/snippets/ { alias .../snippets/; }
        inner = w.root_fetcher(site(PHOTOCRAFT))

        def mapped(path: str) -> Tuple[int, str, bytes]:
            if path.startswith("/app/snippets/"):
                path = path[len("/app"):]
            return inner(path)
        self.assertEqual(w.check(mapped), [])

    def test_wasm_bindgen_default_checked_when_page_passes_no_path(self) -> None:
        files = dict(PHOTOCRAFT)
        files["index.html"] = files["index.html"].replace("init({ module_or_path: './boot-1_bg.wasm' })", "init()")
        files["app/snippets/eframe-1/inline0.js"] = files["snippets/eframe-1/inline0.js"]
        f = w.check(fake(files))
        self.assertEqual(len(f), 1, f)
        self.assertIn("/boot_bg.wasm answered 404", f[0])

    def test_module_with_wrong_type_fails(self) -> None:
        files = {"index.html": '<script type="module" src="./a.js"></script>', "a.js": ""}
        f = w.check(fake(files, {"a.js": "application/octet-stream"}))
        self.assertEqual(len(f), 1, f)
        self.assertIn("not JavaScript", f[0])

    def test_reference_kinds(self) -> None:
        files = {
            "index.html": """<link rel="icon" href="data:,"><link rel="manifest" href="m.webmanifest">
<script type="module">
import init from "./a.js";
navigator.serviceWorker.register("sw.js");
const u = new URL("x_bg.wasm", location.href);
fetch("./font.otf");
const { default: i } = await import("./b.js" + v);
</script><script src="https://cdn.example/x.js"></script>""",
            "m.webmanifest": "{}", "a.js": 'export * from "./c.js"; new Worker(new URL("./w.js", import.meta.url));',
            "sw.js": "", "x_bg.wasm": "", "font.otf": "", "b.js": "", "c.js": "", "w.js": "",
        }
        self.assertEqual(w.check(fake(files)), [])
        del files["w.js"]
        f = w.check(fake(files))
        self.assertEqual(len(f), 1, f)
        self.assertIn("/w.js answered 404", f[0])

    def test_bare_specifier_and_missing_page(self) -> None:
        f = w.check(fake({"index.html": '<script type="module">import x from "lodash";</script>'}))
        self.assertTrue(f and "bare specifier" in f[0], f)
        self.assertEqual(w.check(fake({})), ["/: page answered 404"])

    def test_root_fetcher_stays_inside(self) -> None:
        d = site({"index.html": '<script src="../../etc/passwd"></script>'})
        self.assertEqual(w.root_fetcher(d)("/../../etc/passwd")[0], 404)


if __name__ == "__main__":
    unittest.main()
