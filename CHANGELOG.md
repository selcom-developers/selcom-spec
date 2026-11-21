# Changelog

All notable changes to this specification are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-21

### Security

- Webhook verification closes a forgery in which a value containing `&` imitates further signed fields. A delivery with `Signed-Fields: transid` and a `transid` carrying the rest of a genuine signing string verified as `VALID` while its `order_id` was unsigned. See [docs/webhooks.md](docs/webhooks.md#verification).

### Changed

- `docs/webhooks.md`: a delivery is `INVALID` when `Signed-Fields` does not include both `order_id` and `transid`, and when any signed name or value contains `&`.
- `docs/signing.md`: a note that `&` in a request value signs like separate fields, why this is not exploitable for requests, and that request signing is unchanged.
- `tools/selcom_reference.py`: `verify_webhook` applies both rules.

### Added

- Four webhook samples in `vectors/responses/checkout.webhook.json`, each expecting `INVALID`: `signed-fields-missing-order-id`, `signed-fields-missing-transid`, `signed-value-with-ampersand` and `signed-field-name-with-ampersand`. `tools/generate_vectors.py` now builds them.
- This changelog.

Clients should add the two rules to their verifiers and refresh their copy of the vectors. Existing samples and `vectors/signing.json` keep their verdicts and values.
- Webhook verification: value normalisation before the digest check must be bounded and must not throw; out-of-range numbers are `INVALID`.
- Webhook replay store: keep each digest until max(now, `Timestamp`) + window.

## [0.1.0] - 2026-11-21

First release of the shared spec for the community Selcom clients.

### Added

- Signing rules (HS256): header set, flattening of nested fields, value text, timestamp format, `Signed-Fields` order, query-string and body encoding (`docs/signing.md`).
- v1 API notes for checkout, wallet cash-in, utility payments and vendor balance (`docs/api-v1.md`), result-code mapping (`docs/results.md`), webhook verification (`docs/webhooks.md`) and client requirements (`docs/client-requirements.md`).
- Test vectors: `vectors/signing.json` (20 signing cases, 11 must-reject cases) and `vectors/responses/` (131 response scenarios and webhook samples across 17 operations).
- Python reference implementation and generators under `tools/`, checked in CI.

[0.2.0]: https://github.com/selcom-developers/selcom-spec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/selcom-developers/selcom-spec/releases/tag/v0.1.0
