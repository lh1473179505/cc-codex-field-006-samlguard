"""SAML 2.0 response processing. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from .errors import NotImplementedVerify


def verify_response(
    response_path: str,
    idp_cert_path: str,
    audience: str,
    recipient: str,
    in_response_to: str | None,
    clock: str,
    skew_seconds: int = 60,
) -> dict[str, Any]:
    raise NotImplementedVerify(
        "samlguard.verify.verify_response is not implemented in this snapshot"
    )
