"""The logo lint of contract §3 ("Logo lint"): an allowlist check of a
template's SVG logo, the same rules as the Hub's (shared vectors:
tests/svg_vectors.json).

    check(data) -> None when the logo is fine, else the reason (text shared
    with the Hub, byte for byte).

It catches mistakes and obvious hostile content (script, event handlers,
foreign objects, external references, DTDs and entities). It is a lint,
not the security boundary: the Hub only ever shows a logo as <img src>
from its catalog route with a sandboxing CSP (contract §11.7).
"""
from __future__ import annotations

import io
import re
from typing import List, Optional
from xml.etree import ElementTree as ET

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as DET

MAX_BYTES = 64 << 10
MAX_DEPTH = 64

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
XML_NS = "http://www.w3.org/XML/1998/namespace"

ELEMENTS = frozenset("svg g path circle ellipse rect line polyline polygon defs linearGradient radialGradient "
                     "stop clipPath mask use symbol title desc".split())
# Text is kept only in these.
TEXT_ELEMENTS = frozenset(("title", "desc"))
ATTRIBUTES = frozenset("fill stroke opacity fill-opacity fill-rule clip-rule transform viewBox width height x y "
                       "x1 y1 x2 y2 cx cy r rx ry d points offset stop-color stop-opacity gradientUnits "
                       "gradientTransform id clip-path mask preserveAspectRatio".split())
# stroke-width, stroke-linecap, stroke-dasharray, ...
ATTRIBUTE_PREFIXES = ("stroke-",)
NAMESPACES = frozenset((SVG_NS, XLINK_NS))

LOCAL_REF = re.compile(r"#[A-Za-z_][A-Za-z0-9_.:-]*")
URL_OPEN = re.compile(r"url\(", re.IGNORECASE)
LOCAL_URL = re.compile(r"url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)", re.IGNORECASE)
XML_DECL = re.compile(r"<\?xml\s[^>]*?\bencoding\s*=\s*[\"']([^\"']*)[\"']")


def _split(name: str) -> tuple:
    if name.startswith("{"):
        ns, _, local = name[1:].partition("}")
        return ns, local
    return "", name


def _attr_problem(key: str, value: str) -> Optional[str]:
    ns, local = _split(key)
    # A CSS escape (\75 rl(, u\rl() decodes to url( in a browser's CSS
    # tokenizer: no logo needs a backslash anywhere.
    if "\\" in value:
        return "backslash refused"
    if local.lower().startswith("on"):
        return f"event attribute {local} refused"
    if local == "style" and ns == "":
        return "style refused"
    if local == "href" and ns in ("", XLINK_NS):
        if not LOCAL_REF.fullmatch(value):
            return "href must be a local #id reference"
        return None
    if ns == XLINK_NS:
        return f"attribute xlink:{local} refused"
    if ns == XML_NS:
        return f"attribute xml:{local} refused"
    if ns:
        return f"attribute {local} in namespace {ns} refused"
    if local not in ATTRIBUTES and not local.startswith(ATTRIBUTE_PREFIXES):
        return f"attribute {local} refused"
    for m in URL_OPEN.finditer(value):
        if not LOCAL_URL.match(value, m.start()):
            return "url() must be a local #id reference"
    return None


def check(data: bytes) -> Optional[str]:
    """None when data is an acceptable logo, else the reason."""
    if len(data) > MAX_BYTES:
        return "over 64 KiB"
    if data.startswith(b"\xef\xbb\xbf"):
        return "not UTF-8"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "not UTF-8"
    decl = XML_DECL.match(text)
    if decl and decl.group(1).lower() not in ("utf-8", "utf8"):
        return "encoding must be UTF-8"
    # Before parsing: what the parser would otherwise act on or hide.
    if "<!ENTITY" in text:
        return "entity refused"
    if "<!DOCTYPE" in text.upper():
        return "DOCTYPE refused"
    if "<![CDATA[" in text:
        return "CDATA refused"

    stack: List[str] = []
    seen_root = False
    try:
        events = DET.iterparse(io.BytesIO(data), events=("start", "end", "start-ns", "pi"),
                               forbid_dtd=True, forbid_entities=True, forbid_external=True)
        for event, item in events:
            if event == "start-ns":
                _prefix, uri = item
                if uri not in NAMESPACES:
                    return f"namespace {uri} refused"
            elif event == "pi":
                return "processing instruction refused"
            elif event == "start":
                ns, local = _split(item.tag)
                if ns != SVG_NS:
                    return f"element {local} is not in the SVG namespace"
                if not seen_root:
                    seen_root = True
                    if local != "svg":
                        return "root must be svg"
                    if "viewBox" not in item.attrib:
                        return "svg has no viewBox"
                if local == "style":
                    return "style refused"
                if local not in ELEMENTS:
                    return f"element {local} refused"
                stack.append(local)
                if len(stack) > MAX_DEPTH:
                    return f"nested deeper than {MAX_DEPTH}"
                for key, value in item.attrib.items():
                    problem = _attr_problem(key, value)
                    if problem:
                        return problem
            elif event == "end":
                local = stack.pop()
                if local not in TEXT_ELEMENTS:
                    if (item.text or "").strip() or any((c.tail or "").strip() for c in item):
                        return "text outside title and desc refused"
    except DefusedXmlException as e:
        return "DOCTYPE refused" if "DTD" in type(e).__name__ else "entity refused"
    except ET.ParseError:
        return "not well-formed XML"
    if not seen_root:
        return "not well-formed XML"
    return None
