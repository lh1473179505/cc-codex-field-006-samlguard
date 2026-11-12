"""XML loading helpers. The loader refuses DTDs so callers do not resolve external entities."""

from __future__ import annotations

from lxml import etree

from .errors import FormatError


def parse_bytes(data: bytes) -> etree._Element:
    # Reject DOCTYPE / DTD up front. The parser is also created with
    # resolve_entities disabled and no network.
    if b"<!DOCTYPE" in data or b"<!doctype" in data:
        raise FormatError("DOCTYPE is not allowed in SAML messages")
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
        huge_tree=False,
    )
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as e:
        raise FormatError(f"invalid XML: {e}") from e


def parse_path(path: str) -> etree._Element:
    with open(path, "rb") as f:
        return parse_bytes(f.read())


def localname(el: etree._Element) -> str:
    q = etree.QName(el)
    return q.localname


def qn(ns: str, name: str) -> str:
    return f"{{{ns}}}{name}"


def child(el: etree._Element, ns: str, name: str):
    return el.find(qn(ns, name))


def children(el: etree._Element, ns: str, name: str):
    return el.findall(qn(ns, name))


def text_content(el: etree._Element | None) -> str:
    """Direct text of an element, excluding comments and child elements.

    This is a low-level helper. SAML NameID handling belongs in the verifier
    (not implemented here) and must be robust against comment injection.
    """
    if el is None:
        return ""
    return (el.text or "").strip()
