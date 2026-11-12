# samlguard

A small SAML 2.0 service-provider helper. This snapshot already has:

- A DTD-refusing XML loader
- Exclusive C14N and enveloped RSA-SHA256 sign/verify (`samlguard.crypto`)
- `python -m samlguard inspect` for a structural dump of a Response
- Checked-in test certificates and a set of Responses (valid, expired, wrapped, and so on)

The SAML processing model itself is **not** implemented. `python -m samlguard verify` is the stub you are expected to fill in, following `docs/processing.md`.

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
