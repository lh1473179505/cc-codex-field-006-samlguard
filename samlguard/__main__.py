"""CLI: inspect a SAML Response, or verify it (verify is the work to implement)."""

from __future__ import annotations

import argparse
import json
import sys

from .errors import NotImplementedVerify, SamlguardError
from .inspect import inspect_path
from .verify import verify_response


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="samlguard")
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="print the structure of a SAML Response")
    ins.add_argument("response")

    ver = sub.add_parser("verify", help="validate a SAML 2.0 Response")
    ver.add_argument("--response", required=True)
    ver.add_argument("--idp-cert", required=True, dest="idp_cert")
    ver.add_argument("--audience", required=True)
    ver.add_argument("--recipient", required=True)
    ver.add_argument("--in-response-to", dest="in_response_to", default=None)
    ver.add_argument("--clock", required=True, help="ISO-8601 UTC time, e.g. 2026-11-12T01:05:00Z")
    ver.add_argument("--skew-seconds", type=int, default=60, dest="skew_seconds")
    ver.add_argument("--out", required=True, help="JSON result path")
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    try:
        if args.cmd == "inspect":
            print(inspect_path(args.response))
            return 0
        if args.cmd == "verify":
            result = verify_response(
                response_path=args.response,
                idp_cert_path=args.idp_cert,
                audience=args.audience,
                recipient=args.recipient,
                in_response_to=args.in_response_to,
                clock=args.clock,
                skew_seconds=args.skew_seconds,
            )
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
                f.write("\n")
            print(f"wrote {args.out} ok={result.get('ok')}")
            return 0 if result.get("ok") else 1
        p.error("unknown command")
        return 2
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename or e}", file=sys.stderr)
        return 2
    except NotImplementedVerify as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SamlguardError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
