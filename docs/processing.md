# SAML 2.0 Response processing

`inspect` only prints structure. `verify` must implement this contract and write a JSON result.

## Command and result

```
python -m samlguard verify \
  --response <xml> \
  --idp-cert fixtures/certs/idp.cert.pem \
  --audience https://sp.test.example/shibboleth \
  --recipient https://sp.test.example/sso/acs \
  --in-response-to id-req-1 \
  --clock 2026-11-12T01:05:00Z \
  --skew-seconds 60 \
  --out /tmp/saml-result.json
```

`--clock` is the evaluation time in ISO-8601 (the `Z` suffix means UTC). `--skew-seconds` is the allowed clock skew (default 60).

The JSON result must contain at least:

```
{
  "ok": true,
  "subject": "alice@shop.test",
  "issuer": "https://idp.test.example/idp/shibboleth",
  "session_index": "sess-1",
  "attributes": {"role": "cashier", "dept": "front"},
  "assertion_id": "id-assert-valid",
  "errors": []
}
```

When verification fails, `ok` is false, `errors` is a non-empty list of `{"code": "...", "message": "..."}`, and `subject` / `attributes` must not be taken from untrusted (unsigned or wrapping) nodes. It is acceptable to leave `subject` null on failure. The process may still exit 0 after writing a failed result, or exit 1; the JSON is the contract that matters. Input/XML/cert problems that prevent a result from being written should still be a non-zero exit with a stderr message.

Suggested error codes (use these names when they apply): `xml_dtd`, `status`, `unsigned`, `signature`, `wrong_cert`, `wrapping`, `expired`, `not_yet_valid`, `audience`, `destination`, `recipient`, `in_response_to`, `nameid`.

## Processing rules

1. **XML safety.** Refuse documents with a DOCTYPE / DTD. Do not resolve external entities. `samlguard.xmlutil.parse_path` already does this and should be reused.

2. **Status.** The Response `StatusCode` must be `urn:oasis:names:tc:SAML:2.0:status:Success`. Any other code fails with `status`.

3. **Signatures.** Use `samlguard.crypto.verify_enveloped` and the IdP certificate passed as `--idp-cert`. A signature that does not verify under that certificate fails (`signature` or `wrong_cert`). Do not implement a second, incompatible signature stack.

4. **Which assertion is trusted (wrapping).** This is the core constraint.
   - Only data covered by a valid signature on the Assertion actually used (or by a valid signature on the Response that covers that Assertion) may be trusted.
   - If the Response contains more than one Assertion, you must not pick an unsigned Assertion, even if it appears first, and you must not mix a Subject / attributes from an unsigned node with a signature from another node.
   - `fixtures/responses/wrapping_unsigned_sibling.xml` has an unsigned `admin@shop.test` Assertion followed by a valid signed `alice@shop.test` Assertion. The correct result is either to accept **alice** (the signed one) or to fail the whole message as `wrapping`. It is never correct to accept **admin**.
   - An Assertion with no signature, when it is the only Assertion, fails with `unsigned`.

5. **Conditions and skew.** For the trusted Assertion:
   - `NotBefore` is satisfied when `clock + skew >= NotBefore`
   - `NotOnOrAfter` is satisfied when `clock - skew < NotOnOrAfter`
   - Use `--clock` and `--skew-seconds`. The fixtures are written so that at `2026-11-12T01:05:00Z` with 60 seconds of skew, `valid_success.xml` is in range, `expired.xml` is expired, and `not_yet_valid.xml` is not yet valid.

6. **Audience.** Every `AudienceRestriction` on the trusted Assertion must include `--audience`. A restriction that only lists some other audience fails with `audience`.

7. **Destination and Recipient.** The Response `Destination`, if present, must equal `--recipient`. The bearer `SubjectConfirmationData@Recipient`, if present, must also equal `--recipient`. Failures use `destination` or `recipient`.

8. **InResponseTo.** If `--in-response-to` is provided, the Response `InResponseTo` and the bearer `SubjectConfirmationData@InResponseTo` (when present) must equal it. Failure uses `in_response_to`.

9. **NameID.** The subject is the trusted Assertion's `NameID`. If the NameID element contains comments or child elements, fail with `nameid`. Do not concatenate text on both sides of a comment (that would turn `alice<!-- ignore -->admin@shop.test` into `aliceadmin@shop.test`), and do not silently drop the comment to invent a different identifier.

10. **Issuer.** The trusted Assertion issuer must be recorded in the result. The checked-in fixtures issued by the test IdP use `https://idp.test.example/idp/shibboleth`.

Attributes in the result are a map of `Attribute@Name` to the (single) `AttributeValue` text of each attribute on the trusted Assertion.

## Compatibility

Reuse `xmlutil`, `crypto`, and `inspect`. Do not change the checked-in certificates or the Response fixtures to make verification easier. `python -m samlguard inspect` must keep working.
