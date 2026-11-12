"""SAML 2.0 response processing per docs/processing.md.

Trust boundary: every value placed in a successful result is read from the
single Assertion covered by a valid signature -- either an enveloped
signature on that Assertion itself, or a valid enveloped signature on the
enclosing Response. Unsigned sibling Assertions are never consulted, so
Subject/attributes from an unsigned node can never be mixed with a signature
from another node.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from lxml import etree

from .crypto import load_cert_pem, verify_enveloped
from .errors import CryptoError, FormatError
from .ns import NSMAP
from .xmlutil import child, localname, parse_path, qn, text_content

SAML = NSMAP["saml"]
SAMLP = NSMAP["samlp"]
DS = NSMAP["ds"]

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


def _err(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _failure(error: dict[str, str]) -> dict[str, Any]:
    return {
        "ok": False,
        "subject": None,
        "issuer": None,
        "session_index": None,
        "attributes": {},
        "assertion_id": None,
        "errors": [error],
    }


def _parse_time(value: str, what: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as e:
        raise FormatError(f"invalid {what}: {value!r}") from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _select_trusted_assertion(root: etree._Element, cert) -> tuple[etree._Element | None, dict[str, str] | None]:
    """Pick the one Assertion covered by a signature that verifies under *cert*.

    Returns (assertion, None) on success or (None, error) on failure.
    """
    assertions = root.findall(qn(SAML, "Assertion"))
    verified: list[etree._Element] = []
    saw_signature = False
    for assertion in assertions:
        if not assertion.findall(qn(DS, "Signature")):
            continue
        saw_signature = True
        try:
            verify_enveloped(assertion, cert)
        except (CryptoError, FormatError):
            continue
        verified.append(assertion)

    if len(verified) == 1:
        return verified[0], None
    if len(verified) > 1:
        return None, _err("wrapping", "multiple assertions carry valid signatures; refusing to choose one")

    # No Assertion-level signature verified. A valid Response signature covers
    # every Assertion in the document (a tampered sibling would break it).
    response_signatures = root.findall(qn(DS, "Signature"))
    if len(response_signatures) == 1:
        try:
            verify_enveloped(root, cert)
        except (CryptoError, FormatError) as e:
            return None, _err("signature", f"response signature verification failed: {e}")
        if assertions:
            return assertions[0], None
        return None, _err("unsigned", "response contains no assertion")

    if saw_signature:
        return None, _err("signature", "no assertion signature verifies under the IdP certificate")
    if len(assertions) > 1:
        return None, _err("wrapping", "response contains multiple assertions but none is signed")
    if not assertions:
        return None, _err("unsigned", "response contains no assertion")
    return None, _err("unsigned", "assertion is not signed")


def _bearer_confirmations(assertion: etree._Element) -> list[etree._Element]:
    result = []
    for confirmation in assertion.iter(qn(SAML, "SubjectConfirmation")):
        method = confirmation.get("Method")
        if method is not None and method != BEARER_METHOD:
            continue
        result.extend(confirmation.findall(qn(SAML, "SubjectConfirmationData")))
    return result


def _check_conditions(
    assertion: etree._Element, clock_dt: datetime, skew: timedelta, expected_audience: str
) -> dict[str, str] | None:
    conditions = child(assertion, SAML, "Conditions")
    restrictions = conditions.findall(qn(SAML, "AudienceRestriction")) if conditions is not None else []
    if not restrictions:
        return _err("audience", "assertion has no AudienceRestriction")
    for restriction in restrictions:
        audiences = [text_content(node) for node in restriction.findall(qn(SAML, "Audience"))]
        if expected_audience not in audiences:
            return _err("audience", f"audience {expected_audience!r} is not listed in an AudienceRestriction")

    if conditions is None:
        return None
    not_before = conditions.get("NotBefore")
    if not_before:
        if clock_dt + skew < _parse_time(not_before, "NotBefore"):
            return _err("not_yet_valid", f"assertion NotBefore {not_before} is after the evaluation time (with skew)")
    not_on_or_after = conditions.get("NotOnOrAfter")
    if not_on_or_after:
        if clock_dt - skew >= _parse_time(not_on_or_after, "NotOnOrAfter"):
            return _err("expired", f"assertion NotOnOrAfter {not_on_or_after} is at or before the evaluation time (with skew)")
    return None


def _extract_nameid(assertion: etree._Element) -> tuple[str | None, dict[str, str] | None]:
    nameid = assertion.find(qn(SAML, "Subject") + "/" + qn(SAML, "NameID"))
    if nameid is None:
        return None, _err("nameid", "trusted assertion has no Subject/NameID")
    # Comments, processing instructions and child elements all count as child
    # nodes. Reject them instead of concatenating or dropping text fragments.
    if len(nameid) > 0:
        return None, _err("nameid", "NameID must contain only text (comments and child elements are rejected)")
    subject = (nameid.text or "").strip()
    if not subject:
        return None, _err("nameid", "NameID text is empty")
    return subject, None


def _extract_attributes(assertion: etree._Element) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for attribute in assertion.iter(qn(SAML, "Attribute")):
        name = attribute.get("Name")
        value_node = attribute.find(qn(SAML, "AttributeValue"))
        if name is None or value_node is None:
            continue
        attributes[name] = text_content(value_node)
    return attributes


def verify_response(
    response_path: str,
    idp_cert_path: str,
    audience: str,
    recipient: str,
    in_response_to: str | None,
    clock: str,
    skew_seconds: int = 60,
) -> dict[str, Any]:
    try:
        cert = load_cert_pem(idp_cert_path)
    except FileNotFoundError:
        raise
    except ValueError as e:
        raise FormatError(f"cannot load IdP certificate {idp_cert_path!r}: {e}") from e

    try:
        root = parse_path(response_path)
    except FormatError as e:
        code = "xml_dtd" if "DOCTYPE" in str(e) else "xml"
        return _failure(_err(code, str(e)))

    if etree.QName(root).namespace != SAMLP or localname(root) != "Response":
        return _failure(_err("xml", "root element is not a samlp:Response"))

    status_code = root.find(qn(SAMLP, "Status") + "/" + qn(SAMLP, "StatusCode"))
    status_value = status_code.get("Value") if status_code is not None else None
    if status_value != STATUS_SUCCESS:
        return _failure(_err("status", f"StatusCode {status_value!r} is not Success"))

    assertion, signature_error = _select_trusted_assertion(root, cert)
    if assertion is None:
        return _failure(signature_error)

    clock_dt = _parse_time(clock, "clock")
    skew = timedelta(seconds=skew_seconds)

    condition_error = _check_conditions(assertion, clock_dt, skew, audience)
    if condition_error is not None:
        return _failure(condition_error)

    destination = root.get("Destination")
    if destination is not None and destination != recipient:
        return _failure(_err("destination", f"Response Destination {destination!r} does not match {recipient!r}"))

    confirmations = _bearer_confirmations(assertion)
    for confirmation_data in confirmations:
        confirmed_recipient = confirmation_data.get("Recipient")
        if confirmed_recipient is not None and confirmed_recipient != recipient:
            return _failure(_err("recipient", f"SubjectConfirmationData Recipient {confirmed_recipient!r} does not match {recipient!r}"))

    if in_response_to is not None:
        response_irt = root.get("InResponseTo")
        if response_irt is not None and response_irt != in_response_to:
            return _failure(_err("in_response_to", f"Response InResponseTo {response_irt!r} does not match {in_response_to!r}"))
        for confirmation_data in confirmations:
            confirmed_irt = confirmation_data.get("InResponseTo")
            if confirmed_irt is not None and confirmed_irt != in_response_to:
                return _failure(_err("in_response_to", f"SubjectConfirmationData InResponseTo {confirmed_irt!r} does not match {in_response_to!r}"))

    subject, nameid_error = _extract_nameid(assertion)
    if nameid_error is not None:
        return _failure(nameid_error)

    issuer_node = child(assertion, SAML, "Issuer")
    issuer = text_content(issuer_node) if issuer_node is not None else None

    authn_statement = assertion.find(".//" + qn(SAML, "AuthnStatement"))
    session_index = authn_statement.get("SessionIndex") if authn_statement is not None else None

    return {
        "ok": True,
        "subject": subject,
        "issuer": issuer,
        "session_index": session_index,
        "attributes": _extract_attributes(assertion),
        "assertion_id": assertion.get("ID") or assertion.get("Id"),
        "errors": [],
    }
