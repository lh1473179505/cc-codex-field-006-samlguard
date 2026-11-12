# Fixtures

`certs/` holds a synthetic test CA and IdP (and an unrelated "other" cert). Private keys are unencrypted test material; see `certs/README.md`.

`responses/` contains SAML 2.0 Response documents:

- `valid_success.xml` — Success status, assertion signed by the test IdP, subject `alice@shop.test`
- `expired.xml` / `not_yet_valid.xml` — same shape, conditions outside the intended evaluation time
- `wrong_audience.xml`, `wrong_recipient.xml`, `wrong_inresponseto.xml` — signed, but the corresponding field does not match the SP in the docs
- `status_requester.xml` — signed, non-success status
- `bad_signature.xml` — a SignatureValue byte has been flipped
- `wrapping_unsigned_sibling.xml` — an unsigned `admin@shop.test` assertion followed by a signed `alice@shop.test` assertion
- `nameid_comment.xml` — signed, NameID contains a comment
- `unsigned_assertion.xml` — no signature
- `doctype_xxe.xml` — a DOCTYPE that must be refused

Regenerate the Responses with `python scripts/make_fixtures.py` from the repository root (this re-signs them with `fixtures/certs/idp.key.pem`).
