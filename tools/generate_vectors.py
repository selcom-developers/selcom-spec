"""Generate vectors/signing.json from the reference implementation.

    python tools/generate_vectors.py           # rewrite vectors/signing.json
    python tools/generate_vectors.py --check   # exit 1 if the committed file drifts

Before writing anything, the script checks the reference against the known
values from Selcom's published documentation sample. If those do not match,
it stops: the reference is wrong, not the vectors.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from selcom_reference import SigningError, sign_request  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "vectors" / "signing.json"

# Sample credentials printed in Selcom's public developer documentation.
# They are illustrative values, not working credentials.
DOCS_KEY = "202cb962ac59075b964b07152d234b70"
DOCS_SECRET = "81dc9bdb52d04dc20036dbd8313ed055"
DOCS_TIMESTAMP = "2019-02-26T09:30:46+03:00"

# Made-up credentials for the cases that need a second key.
OTHER_KEY = "test-key-0001"
OTHER_SECRET = "test-secret-0001"

TS = "2026-11-21T10:30:46+03:00"

KNOWN = {
    "authorization": "SELCOM MjAyY2I5NjJhYzU5MDc1Yjk2NGIwNzE1MmQyMzRiNzA=",
    "known-get-single-field": "pR8qs83hQ34a6EoxXGOKL4yg+JDeJAtzOY6E8fTlvwk=",
    "known-post-nested-billing": "1RVQp/zJv4qFUPBYjAGwZ9kUPINsYSLc9030CfIWwPM=",
}


def b64(url: str) -> str:
    return base64.b64encode(url.encode("utf-8")).decode("ascii")


UTILITY_PAYMENT = {
    "transid": "TXN-UTL-0001",
    "utilitycode": "LUKU",
    "utilityref": "01234567891",
    "amount": 8000,
    "vendor": "TILL123",
    "pin": "0000",
    "msisdn": "255700000000",
}

CASES = [
    {
        "id": "known-get-single-field",
        "description": "Known vector. One field on a GET; also fixes the Authorization value for the docs sample key.",
        "known": True,
        "method": "GET",
        "path": "/v1/checkout/order-status",
        "timestamp": DOCS_TIMESTAMP,
        "params": {"order_id": "ORD-1001"},
    },
    {
        "id": "known-post-nested-billing",
        "description": "Known vector. A nested billing object flattens to billing.firstname; the integer amount signs as 8000.",
        "known": True,
        "method": "POST",
        "path": "/v1/checkout/create-order",
        "timestamp": DOCS_TIMESTAMP,
        "params": {"vendor": "TILL123", "order_id": "ORD-1001", "amount": 8000, "billing": {"firstname": "John"}},
    },
    {
        "id": "flat-dotted-key-same-as-nested",
        "description": "The caller passes billing.firstname already flat. Same wire form and digest as known-post-nested-billing.",
        "method": "POST",
        "path": "/v1/checkout/create-order",
        "timestamp": DOCS_TIMESTAMP,
        "params": {"vendor": "TILL123", "order_id": "ORD-1001", "amount": 8000, "billing.firstname": "John"},
    },
    {
        "id": "delete-same-digest-as-get",
        "description": "DELETE with the same field and timestamp as known-get-single-field. Method and path are not signed, so the digest is identical.",
        "method": "DELETE",
        "path": "/v1/checkout/cancel-order",
        "timestamp": DOCS_TIMESTAMP,
        "params": {"order_id": "ORD-1001"},
    },
    {
        "id": "get-query-three-params",
        "description": "GET with three query parameters, signed in send order.",
        "method": "GET",
        "path": "/v1/utilitypayment/lookup",
        "timestamp": TS,
        "params": {"utilitycode": "LUKU", "utilityref": "01234567891", "transid": "TXN-LKP-0001"},
    },
    {
        "id": "get-list-orders-date-range",
        "description": "GET with date values; hyphens are unreserved and stay as they are in the query string.",
        "method": "GET",
        "path": "/v1/checkout/list-orders",
        "timestamp": TS,
        "params": {"fromdate": "2026-11-01", "todate": "2026-11-21"},
    },
    {
        "id": "delete-integer-param",
        "description": "DELETE with an integer id. It signs and encodes as plain digits.",
        "method": "DELETE",
        "path": "/v1/checkout/delete-card",
        "timestamp": TS,
        "params": {"id": 23, "gateway_buyer_uuid": "GBU-TEST-0001"},
    },
    {
        "id": "get-null-becomes-empty",
        "description": "A null value signs as an empty string and is sent as key= with nothing after the equals sign.",
        "method": "GET",
        "path": "/v1/checkout/stored-cards",
        "timestamp": TS,
        "params": {"gateway_buyer_uuid": "GBU-TEST-0001", "buyer_userid": None},
    },
    {
        "id": "post-nested-billing-with-null",
        "description": "Several billing fields flatten in order, in place. The null address_2 signs and is sent as an empty string.",
        "method": "POST",
        "path": "/v1/checkout/create-order",
        "timestamp": TS,
        "params": {
            "vendor": "TILL123",
            "order_id": "ORD-1002",
            "amount": 15000,
            "currency": "TZS",
            "billing": {
                "firstname": "Test",
                "lastname": "Buyer",
                "address_1": "1 Example Street",
                "address_2": None,
                "city": "Dar es Salaam",
                "phone": "255700000000",
            },
            "no_of_items": 1,
        },
    },
    {
        "id": "amount-as-integer",
        "description": "Utility payment with the amount as a JSON integer. Compare with amount-as-string.",
        "method": "POST",
        "path": "/v1/utilitypayment/process",
        "timestamp": TS,
        "params": UTILITY_PAYMENT,
    },
    {
        "id": "amount-as-string",
        "description": "The same payment with the amount as a string. Same signing string and digest; only the body differs.",
        "method": "POST",
        "path": "/v1/utilitypayment/process",
        "timestamp": TS,
        "params": {**UTILITY_PAYMENT, "amount": "8000"},
    },
    {
        "id": "unicode-values",
        "description": "Non-ASCII values, including a character outside the Basic Multilingual Plane. HMAC runs over UTF-8 bytes.",
        "method": "POST",
        "path": "/v1/checkout/create-order-minimal",
        "timestamp": TS,
        "params": {
            "vendor": "TILL123",
            "order_id": "ORD-1003",
            "buyer_email": "test.buyer@example.com",
            "buyer_name": "Tést Bùyer Ñandú",
            "buyer_phone": "255700000001",
            "amount": 5000,
            "currency": "TZS",
            "buyer_remarks": "Asante sana ☕ 🙂 日本",
            "no_of_items": 1,
        },
    },
    {
        "id": "reserved-characters-post",
        "description": "Values with & = + space % / ? # in a JSON body. They go into the signing string raw, with no escaping.",
        "method": "POST",
        "path": "/v1/checkout/create-order-minimal",
        "timestamp": TS,
        "params": {
            "vendor": "TILL123",
            "order_id": "ORD-1004",
            "buyer_email": "test.buyer@example.com",
            "buyer_name": "Test Buyer",
            "buyer_phone": "255700000001",
            "amount": 1000,
            "currency": "TZS",
            "webhook": b64("https://shop.example.com/selcom/webhook?order=ORD-1004&src=test"),
            "merchant_remarks": "a&b=c+d e%20f/g?h#i",
            "no_of_items": 2,
        },
    },
    {
        "id": "reserved-characters-get",
        "description": "Reserved characters in a query value. The query string is percent-encoded (space is %20, plus is %2B); the signature covers the decoded value.",
        "method": "GET",
        "path": "/v1/utilitypayment/lookup",
        "timestamp": TS,
        "params": {"utilitycode": "LUKU", "utilityref": "A&B=C+D E/F%G~H", "transid": "TXN-LKP-0002"},
    },
    {
        "id": "single-field-get",
        "description": "Status query with one field.",
        "method": "GET",
        "path": "/v1/utilitypayment/query",
        "timestamp": TS,
        "params": {"transid": "TXN-UTL-0001"},
    },
    {
        "id": "long-field-list",
        "description": "Full card checkout order: base64 URLs, billing and shipping objects, colours and expiry. Checks order over many fields.",
        "method": "POST",
        "path": "/v1/checkout/create-order",
        "timestamp": TS,
        "params": {
            "vendor": "TILL123",
            "order_id": "ORD-1005",
            "buyer_email": "test.buyer@example.com",
            "buyer_name": "Test Buyer",
            "buyer_userid": "test-user-0001",
            "buyer_phone": "255700000001",
            "gateway_buyer_uuid": "",
            "amount": 125000,
            "currency": "TZS",
            "payment_methods": "ALL",
            "redirect_url": b64("https://shop.example.com/checkout/complete?order=ORD-1005"),
            "cancel_url": b64("https://shop.example.com/checkout/cancel?order=ORD-1005"),
            "webhook": b64("https://shop.example.com/selcom/webhook"),
            "billing": {
                "firstname": "Test",
                "lastname": "Buyer",
                "address_1": "1 Example Street",
                "address_2": "Unit 0",
                "city": "Dar es Salaam",
                "state_or_region": "Dar es Salaam",
                "postcode_or_pobox": "00000",
                "country": "TZ",
                "phone": "255700000001",
            },
            "shipping": {
                "firstname": "Test",
                "lastname": "Receiver",
                "address_1": "2 Example Road",
                "address_2": "",
                "city": "Arusha",
                "state_or_region": "Arusha",
                "postcode_or_pobox": "00000",
                "country": "TZ",
                "phone": "255700000002",
            },
            "buyer_remarks": "None",
            "merchant_remarks": "Test order",
            "no_of_items": 3,
            "header_colour": "#FF0012",
            "link_colour": "#0000FF",
            "button_colour": "#00AA00",
            "expiry": 60,
        },
    },
    {
        "id": "other-key-and-utc-offset",
        "description": "A different key and secret, and a +00:00 offset. Authorization changes with the key; the offset is signed exactly as sent.",
        "method": "POST",
        "path": "/v1/checkout/wallet-payment",
        "api_key": OTHER_KEY,
        "secret": OTHER_SECRET,
        "timestamp": "2026-11-21T07:30:46+00:00",
        "params": {"transid": "TXN-WLT-0001", "order_id": "ORD-1003", "msisdn": "255700000001"},
    },
    {
        "id": "timestamp-offset-without-colon",
        "description": "The basic offset form +0300 is accepted and signed exactly as sent. Its digest differs from the +03:00 form because the timestamp text differs.",
        "method": "GET",
        "path": "/v1/checkout/order-status",
        "api_key": DOCS_KEY,
        "secret": DOCS_SECRET,
        "timestamp": "2026-11-21T10:30:46+0300",
        "params": {"order_id": "ORD-1001"},
    },
    {
        "id": "wallet-cashin-payout",
        "description": "Wallet cash-in payout with a PIN. The PIN is signed like any other field and must never be logged.",
        "method": "POST",
        "path": "/v1/walletcashin/process",
        "timestamp": TS,
        "params": {
            "transid": "TXN-CSH-0001",
            "utilitycode": "CASHIN",
            "utilityref": "255700000002",
            "amount": 2500,
            "vendor": "TILL123",
            "pin": "0000",
            "msisdn": "255700000000",
        },
    },
    {
        "id": "signer-booleans-negative-integral-float",
        "description": "Signer-level test, not a real request: no v1 field takes these. Booleans sign as true/false, a negative integer keeps its sign, and 8000.0 signs and is sent as 8000.",
        "scope": "signer",
        "method": "POST",
        "path": "/v1/signer-test",
        "timestamp": TS,
        "params": {"flag_on": True, "flag_off": False, "delta": -5, "whole": 8000.0},
    },
]

REJECTS = [
    {
        "id": "reject-empty-secret",
        "description": "Fail closed: never produce or send an empty Digest.",
        "secret": "",
        "params": {"order_id": "ORD-1001"},
        "error": "EMPTY_SECRET",
    },
    {
        "id": "reject-empty-api-key",
        "description": "An empty key would send 'SELCOM ' with nothing after it.",
        "api_key": "",
        "params": {"order_id": "ORD-1001"},
        "error": "EMPTY_API_KEY",
    },
    {
        "id": "reject-fractional-amount",
        "description": "Amounts are whole shillings. Reject, never round or truncate.",
        "params": {"order_id": "ORD-1001", "amount": 8000.5},
        "error": "NON_INTEGER_NUMBER",
    },
    {
        "id": "reject-unsafe-integer",
        "description": "Integers above 2^53-1 lose precision in JavaScript. Send them as strings.",
        "params": {"order_id": "ORD-1001", "amount": 9007199254740993},
        "error": "NUMBER_OUT_OF_RANGE",
    },
    {
        "id": "reject-array-value",
        "description": "Arrays have no flat form. payment_methods is a comma-separated string, not a list.",
        "params": {"order_id": "ORD-1001", "payment_methods": ["CARD", "MOBILEMONEYPULL"]},
        "error": "UNSUPPORTED_TYPE",
    },
    {
        "id": "reject-key-with-comma",
        "description": "A comma in a key would corrupt Signed-Fields.",
        "params": {"order,id": "ORD-1001"},
        "error": "INVALID_KEY",
    },
    {
        "id": "reject-duplicate-after-flattening",
        "description": "billing.firstname given both flat and nested.",
        "params": {"billing.firstname": "Test", "billing": {"firstname": "Other"}},
        "error": "DUPLICATE_KEY",
    },
    {
        "id": "reject-empty-nested-object",
        "description": "An empty object has no flat form. Omit it.",
        "params": {"order_id": "ORD-1001", "billing": {}},
        "error": "EMPTY_OBJECT",
    },
    {
        "id": "reject-empty-params",
        "description": "Every v1 operation sends at least one field. An empty Signed-Fields is never valid.",
        "params": {},
        "error": "EMPTY_PARAMS",
    },
    {
        "id": "reject-timestamp-z",
        "description": "Use +00:00, not Z.",
        "timestamp": "2026-11-21T07:30:46Z",
        "params": {"order_id": "ORD-1001"},
        "error": "INVALID_TIMESTAMP",
    },
    {
        "id": "reject-timestamp-fractional-seconds",
        "description": "No fractional seconds.",
        "timestamp": "2026-11-21T10:30:46.123+03:00",
        "params": {"order_id": "ORD-1001"},
        "error": "INVALID_TIMESTAMP",
    },
]


def check_known(cases: list[dict]) -> None:
    by_id = {case["id"]: case for case in cases}
    problems = []
    for case_id in ("known-get-single-field", "known-post-nested-billing"):
        got = by_id[case_id]["expected"]["digest"]
        if got != KNOWN[case_id]:
            problems.append(f"{case_id}: digest {got} != {KNOWN[case_id]}")
    got_auth = by_id["known-get-single-field"]["expected"]["authorization"]
    if got_auth != KNOWN["authorization"]:
        problems.append(f"authorization {got_auth} != {KNOWN['authorization']}")
    if problems:
        raise SystemExit("Reference does not reproduce the known vectors:\n  " + "\n  ".join(problems))


def build() -> dict:
    cases = []
    for spec in CASES:
        api_key = spec.get("api_key", DOCS_KEY)
        secret = spec.get("secret", DOCS_SECRET)
        signed = sign_request(spec["method"], spec["path"], spec["params"], spec["timestamp"], api_key, secret)
        expected = {
            "flattened": signed["flattened"],
            "signed_fields": signed["signed_fields"],
            "signing_string": signed["signing_string"],
            "digest": signed["digest"],
            "authorization": signed["authorization"],
            "digest_method": "HS256",
        }
        if signed["query"] is not None:
            expected["query"] = signed["query"]
        if signed["body"] is not None:
            expected["body"] = signed["body"]
        cases.append(
            {
                "id": spec["id"],
                "description": spec["description"],
                "known": spec.get("known", False),
                "scope": spec.get("scope", "request"),
                "method": spec["method"],
                "path": spec["path"],
                "timestamp": spec["timestamp"],
                "api_key": api_key,
                "secret": secret,
                "params": spec["params"],
                "expected": expected,
            }
        )
    check_known(cases)

    rejects = []
    for spec in REJECTS:
        item = {
            "id": spec["id"],
            "description": spec["description"],
            "method": "POST",
            "path": "/v1/checkout/create-order",
            "timestamp": spec.get("timestamp", TS),
            "api_key": spec.get("api_key", DOCS_KEY),
            "secret": spec.get("secret", DOCS_SECRET),
            "params": spec["params"],
            "error": spec["error"],
        }
        try:
            sign_request(item["method"], item["path"], item["params"], item["timestamp"], item["api_key"], item["secret"])
        except SigningError as exc:
            if exc.code != item["error"]:
                raise SystemExit(f"{item['id']}: expected {item['error']}, reference raised {exc.code}")
        else:
            raise SystemExit(f"{item['id']}: reference signed a request it must reject")
        rejects.append(item)

    return {
        "$comment": "Generated by tools/generate_vectors.py from tools/selcom_reference.py. Do not edit by hand. Rules: docs/signing.md.",
        "version": 1,
        "credentials_note": "api_key and secret values are the sample values printed in Selcom's public documentation, or made up. None of them is a working credential.",
        "cases": cases,
        "rejects": rejects,
    }


def _is_pair_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, list) and len(item) == 2 and not isinstance(item[1], (dict, list)) for item in value)
    )


def _render(value: object, indent: int) -> str:
    """json.dumps(indent=2), except [key, value] pairs stay on one line each."""
    pad, inner = "  " * indent, "  " * (indent + 1)
    if isinstance(value, dict) and value:
        items = [f"{inner}{json.dumps(k, ensure_ascii=False)}: {_render(v, indent + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"
    if _is_pair_list(value):
        items = [inner + json.dumps(item, ensure_ascii=False) for item in value]
        return "[\n" + ",\n".join(items) + "\n" + pad + "]"
    if isinstance(value, list) and value:
        items = [inner + _render(item, indent + 1) for item in value]
        return "[\n" + ",\n".join(items) + "\n" + pad + "]"
    return json.dumps(value, ensure_ascii=False)


def render(doc: dict) -> str:
    return _render(doc, 0) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if vectors/signing.json is out of date")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    text = render(build())
    if json.loads(text) != json.loads(json.dumps(build(), ensure_ascii=False)):
        raise SystemExit("renderer changed the data")
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8").replace("\r\n", "\n") if OUTPUT.exists() else ""
        if current != text:
            diff = difflib.unified_diff(
                current.splitlines(), text.splitlines(), "committed", "generated", lineterm="", n=2
            )
            print("\n".join(list(diff)[:200]))
            print(f"\n{OUTPUT.relative_to(ROOT)} is out of date. Run: python tools/generate_vectors.py")
            return 1
        doc = json.loads(text)
        print(f"OK: {len(doc['cases'])} cases and {len(doc['rejects'])} rejects match; known vectors reproduced.")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    doc = json.loads(text)
    print(f"Wrote {OUTPUT.relative_to(ROOT)}: {len(doc['cases'])} cases, {len(doc['rejects'])} rejects.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
