#!/usr/bin/env python3
"""Build signed and adversarially wrapped SAML fixtures. Run from the repo root."""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

from lxml import etree

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from samlguard.crypto import load_cert_pem, load_key_pem, sign_enveloped
from samlguard.ns import NSMAP
from samlguard.xmlutil import qn

SAML = NSMAP["saml"]
SAMLP = NSMAP["samlp"]
DS = NSMAP["ds"]

ISSUER = "https://idp.test.example/idp/shibboleth"
AUDIENCE = "https://sp.test.example/shibboleth"
ACS = "https://sp.test.example/sso/acs"
REQ = "id-req-1"
INSTANT = "2026-11-12T01:00:00Z"
NB = "2026-01-01T00:00:00Z"
NA = "2028-01-01T00:00:00Z"


def el(parent, ns, name, **attrs):
    node = etree.SubElement(parent, qn(ns, name), **attrs)
    return node


def move_signature_after_issuer(node):
    sig = node.find(qn(DS, "Signature"))
    issuer = node.find(qn(SAML, "Issuer"))
    if sig is not None and issuer is not None:
        node.remove(sig)
        issuer.addnext(sig)


def make_assertion(
    aid: str,
    nameid: str,
    attrs: dict[str, str],
    not_before: str = NB,
    not_after: str = NA,
    audience: str = AUDIENCE,
    recipient: str = ACS,
    in_response_to: str = REQ,
    issue_instant: str = INSTANT,
    nameid_inner_xml: str | None = None,
):
    a = etree.Element(
        qn(SAML, "Assertion"),
        nsmap={"saml": SAML, "ds": DS},
        ID=aid,
        Version="2.0",
        IssueInstant=issue_instant,
    )
    iss = el(a, SAML, "Issuer")
    iss.text = ISSUER
    subj = el(a, SAML, "Subject")
    nid = el(subj, SAML, "NameID", Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    if nameid_inner_xml is not None:
        # Used only for the comment-injection fixture. The string is parsed
        # as inner XML of NameID.
        nid.append(etree.fromstring(f"<wrap xmlns:saml='{SAML}'>{nameid_inner_xml}</wrap>")[0]) if False else None
        # Simpler: set nid text via a temporary fragment
        frag = etree.fromstring(
            f'<saml:NameID xmlns:saml="{SAML}" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{nameid_inner_xml}</saml:NameID>'
        )
        # replace node
        subj.replace(nid, frag)
        nid = frag
    else:
        nid.text = nameid
    sc = el(subj, SAML, "SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    el(
        sc,
        SAML,
        "SubjectConfirmationData",
        Recipient=recipient,
        NotOnOrAfter=not_after,
        InResponseTo=in_response_to,
    )
    cond = el(a, SAML, "Conditions", NotBefore=not_before, NotOnOrAfter=not_after)
    rest = el(cond, SAML, "AudienceRestriction")
    aud = el(rest, SAML, "Audience")
    aud.text = audience
    stmt = el(a, SAML, "AuthnStatement", AuthnInstant=issue_instant, SessionIndex="sess-1")
    ctx = el(stmt, SAML, "AuthnContext")
    href = el(ctx, SAML, "AuthnContextClassRef")
    href.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    if attrs:
        ast = el(a, SAML, "AttributeStatement")
        for name, value in attrs.items():
            at = el(ast, SAML, "Attribute", Name=name, NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
            val = el(at, SAML, "AttributeValue")
            val.text = value
    return a


def make_response(rid: str, assertion: etree._Element, destination: str = ACS, in_response_to: str = REQ, status="Success"):
    r = etree.Element(
        qn(SAMLP, "Response"),
        nsmap={"samlp": SAMLP, "saml": SAML, "ds": DS},
        ID=rid,
        Version="2.0",
        IssueInstant=INSTANT,
        Destination=destination,
        InResponseTo=in_response_to,
    )
    iss = el(r, SAML, "Issuer")
    iss.text = ISSUER
    st = el(r, SAMLP, "Status")
    el(st, SAMLP, "StatusCode", Value=f"urn:oasis:names:tc:SAML:2.0:status:{status}")
    r.append(assertion)
    return r


def sign_assertion(assertion, key, cert):
    sign_enveloped(assertion, key, cert)
    move_signature_after_issuer(assertion)
    return assertion


def write(path: Path, root: etree._Element):
    path.parent.mkdir(parents=True, exist_ok=True)
    xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=False)
    path.write_bytes(xml)
    print(f"wrote {path} ({path.stat().st_size} bytes)")


def main() -> None:
    key = load_key_pem(str(ROOT / "fixtures/certs/idp.key.pem"))
    cert = load_cert_pem(str(ROOT / "fixtures/certs/idp.cert.pem"))
    out = ROOT / "fixtures/responses"

    # 1. valid success, assertion signed
    a = make_assertion("id-assert-valid", "alice@shop.test", {"role": "cashier", "dept": "front"})
    sign_assertion(a, key, cert)
    r = make_response("id-resp-valid", a)
    write(out / "valid_success.xml", r)

    # 2. expired conditions
    a = make_assertion("id-assert-expired", "alice@shop.test", {"role": "cashier"}, not_before="2019-01-01T00:00:00Z", not_after="2020-01-01T00:00:00Z")
    sign_assertion(a, key, cert)
    write(out / "expired.xml", make_response("id-resp-expired", a))

    # 3. not yet valid
    a = make_assertion("id-assert-future", "alice@shop.test", {"role": "cashier"}, not_before="2029-01-01T00:00:00Z", not_after="2030-01-01T00:00:00Z")
    sign_assertion(a, key, cert)
    write(out / "not_yet_valid.xml", make_response("id-resp-future", a))

    # 4. wrong audience
    a = make_assertion("id-assert-aud", "alice@shop.test", {"role": "cashier"}, audience="https://other-sp.example/shibboleth")
    sign_assertion(a, key, cert)
    write(out / "wrong_audience.xml", make_response("id-resp-aud", a))

    # 5. wrong recipient / destination (assertion Recipient + response Destination)
    a = make_assertion("id-assert-rcp", "alice@shop.test", {"role": "cashier"}, recipient="https://evil.example/acs")
    sign_assertion(a, key, cert)
    write(out / "wrong_recipient.xml", make_response("id-resp-rcp", a, destination="https://evil.example/acs"))

    # 6. wrong InResponseTo
    a = make_assertion("id-assert-irt", "alice@shop.test", {"role": "cashier"}, in_response_to="id-req-OTHER")
    sign_assertion(a, key, cert)
    write(out / "wrong_inresponseto.xml", make_response("id-resp-irt", a, in_response_to="id-req-OTHER"))

    # 7. failed status
    a = make_assertion("id-assert-status", "alice@shop.test", {"role": "cashier"})
    sign_assertion(a, key, cert)
    write(out / "status_requester.xml", make_response("id-resp-status", a, status="Requester"))

    # 8. broken signature (flip a byte in SignatureValue)
    a = make_assertion("id-assert-badsig", "alice@shop.test", {"role": "cashier"})
    sign_assertion(a, key, cert)
    r = make_response("id-resp-badsig", a)
    sv = r.find(".//{%s}SignatureValue" % DS)
    raw = "".join(sv.text.split())
    import base64
    b = bytearray(base64.b64decode(raw))
    b[0] ^= 0x01
    sv.text = base64.b64encode(bytes(b)).decode("ascii")
    write(out / "bad_signature.xml", r)

    # 9. unsigned evil assertion first, then a valid signed alice assertion
    evil = make_assertion("id-assert-evil", "admin@shop.test", {"role": "admin"})
    good = make_assertion("id-assert-goodwrap", "alice@shop.test", {"role": "cashier"})
    sign_assertion(good, key, cert)
    r = make_response("id-resp-wrap-sibling", deepcopy(good))
    # insert unsigned evil before the signed assertion
    # rebuild
    r = make_response("id-resp-wrap-sibling", evil)
    r.append(deepcopy(good))
    write(out / "wrapping_unsigned_sibling.xml", r)

    # 10. comment injection in NameID: visually "alice@shop.test" if comments are dropped
    #     but naive string concatenation of all itertext() might yield aliceadmin@shop.test
    a = make_assertion(
        "id-assert-comment",
        "alice@shop.test",
        {"role": "cashier"},
        nameid_inner_xml="alice<!-- ignore -->admin@shop.test",
    )
    # The nameid_inner_xml path already built the NameID. Sign it.
    sign_assertion(a, key, cert)
    write(out / "nameid_comment.xml", make_response("id-resp-comment", a))

    # 11. unsigned assertion only
    a = make_assertion("id-assert-unsigned", "alice@shop.test", {"role": "cashier"})
    write(out / "unsigned_assertion.xml", make_response("id-resp-unsigned", a))

    # 12. XXE / DOCTYPE (must be rejected at parse)
    xxe = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ELEMENT foo ANY>\n'
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        ']>\n'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="id-resp-xxe" Version="2.0" IssueInstant="2026-11-12T01:00:00Z">&xxe;</samlp:Response>\n'
    )
    (out / "doctype_xxe.xml").write_text(xxe)
    print(f"wrote {out / 'doctype_xxe.xml'}")

    # Re-parse and confirm signatures that should verify still do.
    from samlguard.crypto import verify_enveloped
    from samlguard.xmlutil import parse_path

    must_ok = [
        "valid_success.xml",
        "expired.xml",
        "not_yet_valid.xml",
        "wrong_audience.xml",
        "wrong_recipient.xml",
        "wrong_inresponseto.xml",
        "status_requester.xml",
        "nameid_comment.xml",
    ]
    for name in must_ok:
        root = parse_path(str(out / name))
        a = root.find(".//{%s}Assertion" % "urn:oasis:names:tc:SAML:2.0:assertion")
        verify_enveloped(a, cert)
        print(f"  signature ok: {name}")
    root = parse_path(str(out / "wrapping_unsigned_sibling.xml"))
    assertions = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    verify_enveloped(assertions[1], cert)
    print("  signature ok: wrapping_unsigned_sibling.xml (second assertion)")
    root = parse_path(str(out / "bad_signature.xml"))
    a = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    try:
        verify_enveloped(a, cert)
        raise SystemExit("bad_signature.xml unexpectedly verified")
    except Exception as e:
        print(f"  bad_signature correctly fails: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
