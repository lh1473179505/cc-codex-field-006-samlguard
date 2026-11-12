"""Enveloped XML-DSig (RSA-SHA256) using exclusive C14N.

These helpers sign or verify a single element that already contains, or will
contain, a ds:Signature child. They do **not** implement the SAML processing
model (wrapping resistance, conditions, audience, etc.).
"""

from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

from .c14n import exclusive_c14n
from .errors import CryptoError, FormatError
from .ns import DS_C14N_EXCL, DS_ENVEL, DS_RSA_SHA256, DS_SHA256, NSMAP


DS = NSMAP["ds"]


def load_cert_pem(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_key_pem(path: str) -> rsa.RSAPrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("only RSA private keys are supported")
    return key


def cert_from_pem_bytes(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def cert_to_b64(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def _find_signature(element: etree._Element) -> etree._Element:
    sigs = element.findall(f"{{{DS}}}Signature")
    if not sigs:
        # also allow a signature anywhere in the subtree? No: callers pass the signed node.
        raise FormatError("no ds:Signature child on the signed element")
    if len(sigs) > 1:
        raise FormatError("multiple ds:Signature children on the signed element")
    return sigs[0]


def _reference_id(element: etree._Element, signature: etree._Element) -> str:
    refs = signature.findall(f"{{{DS}}}SignedInfo/{{{DS}}}Reference")
    if len(refs) != 1:
        raise FormatError("exactly one ds:Reference is required")
    uri = refs[0].get("URI") or ""
    if not uri.startswith("#") or len(uri) < 2:
        raise FormatError(f"unsupported Reference URI: {uri!r}")
    return uri[1:]


def _enveloped_copy(element: etree._Element) -> etree._Element:
    clone = copy.deepcopy(element)
    for sig in clone.findall(f"{{{DS}}}Signature"):
        clone.remove(sig)
    return clone


def digest_element(element: etree._Element) -> bytes:
    """SHA-256 digest of the exclusive C14N of *element* after removing ds:Signature children."""
    body = exclusive_c14n(_enveloped_copy(element))
    return hashlib.sha256(body).digest()


def sign_enveloped(element: etree._Element, key: rsa.RSAPrivateKey, cert: x509.Certificate | None = None) -> etree._Element:
    """Add / replace a ds:Signature child on *element* and return the same element.

    The element must have an ID / Id / wsu:Id / xml:id attribute used as the
    reference. This code looks at the attribute literally named "ID" first,
    then "Id".
    """
    ident = element.get("ID") or element.get("Id")
    if not ident:
        raise FormatError("signed element needs an ID or Id attribute")

    # Drop any previous signature so we can write a fresh one.
    for old in element.findall(f"{{{DS}}}Signature"):
        element.remove(old)

    sig = etree.SubElement(element, f"{{{DS}}}Signature")
    si = etree.SubElement(sig, f"{{{DS}}}SignedInfo")
    c14 = etree.SubElement(si, f"{{{DS}}}CanonicalizationMethod")
    c14.set("Algorithm", DS_C14N_EXCL)
    sm = etree.SubElement(si, f"{{{DS}}}SignatureMethod")
    sm.set("Algorithm", DS_RSA_SHA256)
    ref = etree.SubElement(si, f"{{{DS}}}Reference")
    ref.set("URI", f"#{ident}")
    trans = etree.SubElement(ref, f"{{{DS}}}Transforms")
    t1 = etree.SubElement(trans, f"{{{DS}}}Transform")
    t1.set("Algorithm", DS_ENVEL)
    t2 = etree.SubElement(trans, f"{{{DS}}}Transform")
    t2.set("Algorithm", DS_C14N_EXCL)
    dm = etree.SubElement(ref, f"{{{DS}}}DigestMethod")
    dm.set("Algorithm", DS_SHA256)
    dv = etree.SubElement(ref, f"{{{DS}}}DigestValue")
    dv.text = base64.b64encode(digest_element(element)).decode("ascii")

    si_c14n = exclusive_c14n(si)
    signature = key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())
    sv = etree.SubElement(sig, f"{{{DS}}}SignatureValue")
    sv.text = base64.b64encode(signature).decode("ascii")

    if cert is not None:
        ki = etree.SubElement(sig, f"{{{DS}}}KeyInfo")
        x509el = etree.SubElement(ki, f"{{{DS}}}X509Data")
        certel = etree.SubElement(x509el, f"{{{DS}}}X509Certificate")
        certel.text = cert_to_b64(cert)
    return element


def verify_enveloped(element: etree._Element, cert: x509.Certificate) -> None:
    """Verify the enveloped RSA-SHA256 signature on *element* with *cert*.

    Raises CryptoError if the digest or signature is wrong. This function
    only checks the signature over this element. It does not walk parent
    documents or decide which SAML node should be trusted.
    """
    signature = _find_signature(element)
    ident = element.get("ID") or element.get("Id")
    ref_id = _reference_id(element, signature)
    if ident != ref_id:
        raise CryptoError(f"Reference URI #{ref_id} does not match element ID {ident!r}")

    # Digest
    dv_el = signature.find(f"{{{DS}}}SignedInfo/{{{DS}}}Reference/{{{DS}}}DigestValue")
    if dv_el is None or not (dv_el.text or "").strip():
        raise FormatError("missing DigestValue")
    try:
        claimed = base64.b64decode(dv_el.text.strip(), validate=True)
    except Exception as e:
        raise FormatError(f"invalid DigestValue: {e}") from e
    actual = digest_element(element)
    if claimed != actual:
        raise CryptoError("digest mismatch")

    si = signature.find(f"{{{DS}}}SignedInfo")
    if si is None:
        raise FormatError("missing SignedInfo")
    c14 = si.find(f"{{{DS}}}CanonicalizationMethod")
    if c14 is None or c14.get("Algorithm") != DS_C14N_EXCL:
        raise CryptoError("CanonicalizationMethod must be exclusive C14N")
    sm = si.find(f"{{{DS}}}SignatureMethod")
    if sm is None or sm.get("Algorithm") != DS_RSA_SHA256:
        raise CryptoError("SignatureMethod must be rsa-sha256")

    sv_el = signature.find(f"{{{DS}}}SignatureValue")
    if sv_el is None or not (sv_el.text or "").strip():
        raise FormatError("missing SignatureValue")
    try:
        sig_bytes = base64.b64decode("".join(sv_el.text.split()), validate=False)
    except Exception as e:
        raise FormatError(f"invalid SignatureValue: {e}") from e

    si_c14n = exclusive_c14n(si)
    try:
        cert.public_key().verify(sig_bytes, si_c14n, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise CryptoError(f"signature mismatch: {e}") from e
