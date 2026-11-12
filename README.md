# samlguard

A small SAML 2.0 service-provider helper. This snapshot already has:

- A DTD-refusing XML loader
- Exclusive C14N and enveloped RSA-SHA256 sign/verify (`samlguard.crypto`)
- `python -m samlguard inspect` for a structural dump of a Response
- `python -m samlguard verify` implementing the processing rules in `docs/processing.md`
- Checked-in test certificates and a set of Responses (valid, expired, wrapped, and so on)

`verify` writes a JSON result to `--out`: `ok`, `subject`, `issuer`,
`session_index`, `attributes`, `assertion_id`, and an `errors` list of
`{"code", "message"}`. Only data covered by a valid enveloped signature on the
used Assertion (or on the enclosing Response) is ever trusted.

## Requirements

- Python 3.11+
- `cryptography` and `lxml` (see `requirements.txt`). Both are already available in the prepared environment.
- No containers. Do not add Docker files.

The keys under `fixtures/certs/` are synthetic test material. They have no production value and exist so signatures can be verified offline.

## Usage

```bash
python -m samlguard inspect fixtures/responses/valid_success.xml
python -m samlguard verify \
  --response fixtures/responses/valid_success.xml \
  --idp-cert fixtures/certs/idp.cert.pem \
  --audience https://sp.test.example/shibboleth \
  --recipient https://sp.test.example/sso/acs \
  --in-response-to id-req-1 \
  --clock 2026-11-12T01:05:00Z \
  --skew-seconds 60 \
  --out /tmp/saml-result.json
```

## Layout

- `samlguard/` — library and CLI
- `docs/processing.md` — verification contract
- `fixtures/certs/` — test CA / IdP certificates and keys
- `fixtures/responses/` — signed and adversarial Responses
- `scripts/make_fixtures.py` — regenerates the Responses
