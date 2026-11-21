# selcom-spec

Shared API notes, rules and test vectors for the community Selcom API clients: Java, Node/TypeScript, framework-agnostic PHP, and a Laravel package.

The community clients must sign requests identically, read results identically, and pass the same test vectors.

> **Not affiliated with Selcom Paytech Ltd.** For API access, credentials, contracts and support, go to Selcom: <https://developers.selcommobile.com/>.

## Contents

| Path | What it is |
|---|---|
| [docs/signing.md](docs/signing.md) | The exact request-signing algorithm, with worked examples and pitfalls |
| [docs/api-v1.md](docs/api-v1.md) | The operations in scope for v1: checkout and payouts |
| [docs/results.md](docs/results.md) | Result codes, the typed statuses, and the retry and idempotency rules |
| [docs/webhooks.md](docs/webhooks.md) | Verifying and handling checkout webhooks |
| [docs/client-requirements.md](docs/client-requirements.md) | What every client must do |
| [vectors/signing.json](vectors/signing.json) | Signing test vectors (generated) |
| [vectors/responses/](vectors/responses/) | Response fixtures for each v1 operation, and webhook samples |
| [tools/](tools/) | The Python reference implementation, the vector generator and the fixture checker |

## Using the vectors in a client

Bring this repository into the client's tests at a pinned version: a git submodule, or a copy refreshed by a script, recorded with the commit SHA or tag it came from. Then:

**`vectors/signing.json`**

- For each entry in `cases`, call the client's pure signing function with `params`, `timestamp`, `api_key` and `secret` (and `method`). Assert that the result matches `expected.flattened`, `signed_fields`, `signing_string`, `digest` and `authorization`.
- For GET and DELETE cases, assert the query string equals `expected.query`.
- For POST cases, parse `expected.body` and the client's body and assert the same keys, in the same order, with the same values and JSON types. The bytes may differ in whitespace and string escaping.
- `params` is an ordered JSON object: read it with a parser that keeps key order. `expected.flattened` is a list of `[key, value]` pairs and is ordered whatever the parser does.
- For each entry in `rejects`, assert that the signer raises and that no request is built. Matching the `error` code is recommended but not required.
- Entries with `"known": true` hold values that are fixed outside this repository. They never change.
- Entries with `"scope": "signer"` test the signer alone and are not real requests.

**`vectors/responses/<operation>.json`**

- Each file describes one operation and its `kind`. For each scenario, feed `http_status` and the body (`raw_body` as-is, or `body` serialised as JSON) to the client's response handling for that operation. Assert the typed status equals `expected_status`, or that the client raises the error in `expected_error`.
- `checkout.webhook.json` holds webhook deliveries. Run the samples in order through one replay store, with the secret, clock and window from `verification`. Assert each `expected_verification` verdict and `expected_amount_tzs`.

All credentials in this repository are the sample values printed in Selcom's public documentation, or made up. None of them works against the gateway. All other data is fake: phone numbers in the `2557000000xx` range, e-mail addresses on `example.com`, vendor `TILL123`.

## Changing the rules

1. Change the doc in `docs/` and the reference in `tools/selcom_reference.py` in the same pull request.
2. Regenerate the vectors: `python tools/generate_vectors.py`. Never edit `vectors/signing.json` by hand.
3. Add or update fixtures in `vectors/responses/` and run `python tools/check_fixtures.py`.
4. Open issues in each client for the change.

CI runs `python tools/generate_vectors.py --check` and `python tools/check_fixtures.py` and fails if the committed vectors drift from the reference or a fixture breaks the rules. The tools need Python 3.10 or later and nothing outside the standard library.

Never commit real credentials, real customer data, or details of any merchant's integration.

## License

[Apache License 2.0](LICENSE). Copyright The Selcom Developers community contributors.
