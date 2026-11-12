"""Structural inspect of a SAML Response, without validating signatures."""

from __future__ import annotations

from lxml import etree

from .ns import NSMAP
from .xmlutil import localname, parse_path, text_content


def inspect_path(path: str) -> str:
    root = parse_path(path)
    lines = [f"root {localname(root)} tag={root.tag} id={root.get('ID') or root.get('Id') or ''}"]
    dest = root.get("Destination")
    irt = root.get("InResponseTo")
    inst = root.get("IssueInstant")
    if dest or irt or inst:
        lines.append(f"  destination={dest} in_response_to={irt} issue_instant={inst}")

    def walk(el: etree._Element, indent: int) -> None:
        if not isinstance(getattr(el, "tag", None), str):
            return
        pad = "  " * indent
        ln = localname(el)
        extra = ""
        if ln in ("Issuer", "NameID", "Audience", "StatusCode", "AttributeValue", "AuthnContextClassRef"):
            if ln == "StatusCode":
                extra = f" value={el.get('Value')}"
            elif ln == "AttributeValue" or ln in ("Issuer", "NameID", "Audience", "AuthnContextClassRef"):
                extra = f" text={text_content(el)!r}"
            if ln == "NameID" and el.get("Format"):
                extra += f" format={el.get('Format')}"
        if ln == "Attribute":
            extra = f" name={el.get('Name')}"
        if ln == "Assertion":
            extra = f" id={el.get('ID')}"
        if ln == "Conditions":
            extra = f" not_before={el.get('NotBefore')} not_on_or_after={el.get('NotOnOrAfter')}"
        if ln == "SubjectConfirmationData":
            extra = (
                f" recipient={el.get('Recipient')} not_on_or_after={el.get('NotOnOrAfter')} "
                f"in_response_to={el.get('InResponseTo')}"
            )
        if ln == "Signature":
            extra = " (ds:Signature)"
        lines.append(f"{pad}{ln}{extra}")
        for child in el:
            walk(child, indent + 1)

    for child in root:
        walk(child, 1)
    n_assert = len(root.findall(".//saml:Assertion", NSMAP))
    n_sig = len(root.findall(".//ds:Signature", NSMAP))
    lines.append(f"counts assertions={n_assert} signatures={n_sig}")
    return "\n".join(lines)
