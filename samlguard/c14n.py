"""Exclusive XML canonicalization (C14N 1.0 exclusive, without comments).

This is a thin wrapper around lxml so signature code has a single entry point.
"""

from __future__ import annotations

from lxml import etree

from .ns import DS_C14N_EXCL


def exclusive_c14n(element: etree._Element, inclusive_ns_prefixes: list[str] | None = None) -> bytes:
    """Return the exclusive C14N octet stream of *element* (no comments)."""
    return etree.tostring(
        element,
        method="c14n",
        exclusive=True,
        with_comments=False,
        inclusive_ns_prefixes=inclusive_ns_prefixes or None,
    )


def algorithm_uri() -> str:
    return DS_C14N_EXCL
