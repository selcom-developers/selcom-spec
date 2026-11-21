"""Reference implementation of the rules in this repository.

This module exists to generate and check the shared test vectors. It uses only
the Python standard library and never opens a network connection. It is not a
client and is not published as a package.

    Signing rules:   docs/signing.md
    Result rules:    docs/results.md
    Webhook rules:   docs/webhooks.md

When this file and the docs disagree, that is a bug: fix both in one change.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from datetime import datetime
from typing import Any, Iterable, Mapping, MutableSet
from urllib.parse import quote

# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------

TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}$")
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")
MAX_SAFE_INTEGER = 2**53 - 1
METHODS = ("GET", "POST", "DELETE")


class SigningError(ValueError):
    """The request cannot be signed. A client must not send it."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def normalise_value(key: str, value: Any) -> Any:
    """Return the scalar that is both transmitted and signed for one field."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise SigningError("NUMBER_OUT_OF_RANGE", f"{key}: send integers above 2^53-1 as strings")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise SigningError("NON_INTEGER_NUMBER", f"{key}: {value!r} has a fractional part")
        return normalise_value(key, int(value))
    if isinstance(value, str):
        return value
    raise SigningError("UNSUPPORTED_TYPE", f"{key}: {type(value).__name__} values cannot be signed")


def format_value(value: Any) -> str:
    """Text form of a normalised value inside the signing string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise SigningError("UNSUPPORTED_TYPE", f"{type(value).__name__} is not a normalised value")


def flatten(params: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Flatten nested objects to dotted keys, keeping send order."""
    if not isinstance(params, Mapping):
        raise SigningError("UNSUPPORTED_TYPE", "params must be an object")
    flat: list[tuple[str, Any]] = []
    seen: set[str] = set()

    def walk(prefix: str, obj: Mapping[str, Any]) -> None:
        for raw_key, value in obj.items():
            if not isinstance(raw_key, str) or raw_key == "":
                raise SigningError("INVALID_KEY", f"empty or non-string key under {prefix or 'root'}")
            key = f"{prefix}.{raw_key}" if prefix else raw_key
            if not KEY_PATTERN.match(key):
                raise SigningError("INVALID_KEY", f"{key!r} has characters outside [A-Za-z0-9_.-]")
            if isinstance(value, Mapping):
                if not value:
                    raise SigningError("EMPTY_OBJECT", f"{key} is an empty object; omit it")
                walk(key, value)
                continue
            if key in seen:
                raise SigningError("DUPLICATE_KEY", f"{key} appears twice after flattening")
            seen.add(key)
            flat.append((key, normalise_value(key, value)))

    walk("", params)
    if not flat:
        raise SigningError("EMPTY_PARAMS", "there is nothing to sign")
    return flat


def check_timestamp(timestamp: str) -> None:
    if not isinstance(timestamp, str) or not TIMESTAMP_PATTERN.match(timestamp):
        raise SigningError("INVALID_TIMESTAMP", f"{timestamp!r} is not yyyy-MM-ddTHH:mm:ss+HH:MM or +HHMM")
    datetime.fromisoformat(timestamp)  # rejects impossible dates such as month 13


def signed_fields(flat: Iterable[tuple[str, Any]]) -> str:
    return ",".join(key for key, _ in flat)


def signing_string(timestamp: str, flat: Iterable[tuple[str, Any]]) -> str:
    return "timestamp=" + timestamp + "".join(f"&{key}={format_value(value)}" for key, value in flat)


def hs256_digest(secret: str, message: str) -> str:
    if not secret:
        raise SigningError("EMPTY_SECRET", "refusing to sign with an empty secret")
    mac = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def authorization_header(api_key: str) -> str:
    if not api_key:
        raise SigningError("EMPTY_API_KEY", "refusing to build Authorization from an empty key")
    return "SELCOM " + base64.b64encode(api_key.encode("utf-8")).decode("ascii")


def encode_query(flat: Iterable[tuple[str, Any]]) -> str:
    """RFC 3986: everything except A-Z a-z 0-9 - . _ ~ is percent-encoded (UTF-8)."""
    return "&".join(
        quote(key, safe="") + "=" + quote(format_value(value), safe="") for key, value in flat
    )


def json_body(flat: Iterable[tuple[str, Any]]) -> str:
    """Compact JSON object, flat keys, in send order."""
    return json.dumps(dict(flat), ensure_ascii=False, separators=(",", ":"))


def sign_request(
    method: str,
    path: str,
    params: Mapping[str, Any],
    timestamp: str,
    api_key: str,
    secret: str,
) -> dict[str, Any]:
    """Everything a client puts on the wire for one request."""
    method = method.upper()
    if method not in METHODS:
        raise SigningError("UNSUPPORTED_METHOD", method)
    authorization = authorization_header(api_key)
    if not secret:
        raise SigningError("EMPTY_SECRET", "refusing to sign with an empty secret")
    check_timestamp(timestamp)
    flat = flatten(params)
    message = signing_string(timestamp, flat)
    digest = hs256_digest(secret, message)
    if not digest:  # unreachable with HMAC, kept as the fail-closed rule
        raise SigningError("EMPTY_DIGEST", "refusing to send an empty Digest")
    return {
        "flattened": [[key, value] for key, value in flat],
        "signed_fields": signed_fields(flat),
        "signing_string": message,
        "digest": digest,
        "authorization": authorization,
        "headers": {
            "Authorization": authorization,
            "Digest-Method": "HS256",
            "Digest": digest,
            "Timestamp": timestamp,
            "Signed-Fields": signed_fields(flat),
        },
        "query": encode_query(flat) if method in ("GET", "DELETE") else None,
        "body": json_body(flat) if method == "POST" else None,
    }


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

SUCCESS = "SUCCESS"
PENDING = "PENDING"
AMBIGUOUS = "AMBIGUOUS"
FAILED = "FAILED"
NOT_FOUND = "NOT_FOUND"
STATUSES = (SUCCESS, PENDING, AMBIGUOUS, FAILED, NOT_FOUND)

# Operation kinds (docs/api-v1.md, "Operation kinds")
PAYMENT = "payment"            # moves money; never retried
STATUS_QUERY = "status-query"  # the resultcode is the verdict on an earlier payment
ORDER_STATUS = "order-status"  # the verdict is data[0].payment_status
OTHER = "other"                # everything else
KINDS = (PAYMENT, STATUS_QUERY, ORDER_STATUS, OTHER)

PAYMENT_STATUS_MAP = {
    "COMPLETED": SUCCESS,
    "COMPLETE": SUCCESS,
    "PENDING": PENDING,
    "INPROGRESS": PENDING,
    "CANCELLED": FAILED,
    "CANCELED": FAILED,
    "CANCEL": FAILED,
    "USERCANCELLED": FAILED,
    "USERCANCELED": FAILED,
    "REJECTED": FAILED,
    "FAILED": FAILED,
}


class InvalidResponse(ValueError):
    """The response carries no verdict, and the operation does not move money."""


def normalise_resultcode(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"{value:03d}" if value >= 0 else None
    if isinstance(value, str):
        return value.strip() or None
    return None


def classify(kind: str, body: Any) -> str:
    """Typed status for one response body (already JSON-decoded, or None)."""
    if kind not in KINDS:
        raise ValueError(f"unknown operation kind {kind!r}")
    code = normalise_resultcode(body.get("resultcode")) if isinstance(body, dict) else None
    if code is None:
        if kind == OTHER:
            raise InvalidResponse("no resultcode in the response")
        return AMBIGUOUS
    if code == "000":
        return classify_payment_status(body) if kind == ORDER_STATUS else SUCCESS
    if code in ("111", "927"):
        return PENDING
    if code == "999":
        return AMBIGUOUS
    if code == "404" and kind in (STATUS_QUERY, ORDER_STATUS):
        return NOT_FOUND
    if kind == ORDER_STATUS:
        return AMBIGUOUS  # the query failed; it says nothing about the order
    return FAILED


def classify_payment_status(body: dict) -> str:
    data = body.get("data")
    if not isinstance(data, list):
        return AMBIGUOUS
    if not data:
        return NOT_FOUND
    entry = data[0]
    status = entry.get("payment_status") if isinstance(entry, dict) else None
    if not isinstance(status, str):
        return AMBIGUOUS
    return PAYMENT_STATUS_MAP.get(status.strip().upper(), AMBIGUOUS)


# --------------------------------------------------------------------------
# Webhooks
# --------------------------------------------------------------------------

VALID = "VALID"
UNSIGNED = "UNSIGNED"
INVALID = "INVALID"
STALE = "STALE"
REPLAY = "REPLAY"
VERIFICATIONS = (VALID, UNSIGNED, INVALID, STALE, REPLAY)

# The signing string joins "k=v" pairs with "&" and nothing marks where a value
# ends, so a value containing "&" can imitate further fields. A verifier
# therefore insists that these two fields are always signed, and refuses any
# signed name or value that contains "&". See docs/webhooks.md.
REQUIRED_SIGNED_FIELDS = ("order_id", "transid")


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _lookup(body: Mapping[str, Any], field: str) -> tuple[bool, Any]:
    if field in body:
        return True, body[field]
    node: Any = body
    for part in field.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def verify_webhook(
    headers: Mapping[str, str],
    raw_body: str,
    secret: str,
    now: datetime,
    window_seconds: int = 300,
    seen: MutableSet[str] | None = None,
) -> str:
    """Verification verdict for one delivery. See docs/webhooks.md."""
    digest = _header(headers, "Digest")
    if digest is None:
        return UNSIGNED
    if not digest or _header(headers, "Digest-Method") != "HS256" or not secret:
        return INVALID
    timestamp = _header(headers, "Timestamp") or ""
    fields_header = _header(headers, "Signed-Fields") or ""
    try:
        check_timestamp(timestamp)
        body = json.loads(raw_body)
    except (SigningError, ValueError):
        return INVALID
    if not isinstance(body, dict) or not fields_header:
        return INVALID
    names = fields_header.split(",")
    if any(required not in names for required in REQUIRED_SIGNED_FIELDS):
        return INVALID
    flat = []
    for field in names:
        found, value = _lookup(body, field)
        if not found or "&" in field:
            return INVALID
        try:
            normalised = normalise_value(field, value)
            if "&" in format_value(normalised):
                return INVALID
            flat.append((field, normalised))
        except SigningError:
            return INVALID
    expected = hs256_digest(secret, signing_string(timestamp, flat))
    if not hmac.compare_digest(expected.encode("ascii"), digest.encode("ascii", "replace")):
        return INVALID
    if abs((now - datetime.fromisoformat(timestamp)).total_seconds()) > window_seconds:
        return STALE
    if seen is not None:
        if digest in seen:
            return REPLAY
        seen.add(digest)
    return VALID


AMOUNT_PATTERN = re.compile(r"^\d{1,3}(,\d{3})+(\.0+)?$|^\d+(\.0+)?$")


def parse_amount_tzs(value: Any) -> int:
    """Whole-shilling amount from a callback field ("10000", "10,000", 10000)."""
    if isinstance(value, bool):
        raise ValueError("boolean is not an amount")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and AMOUNT_PATTERN.match(value.strip()):
        return int(value.strip().split(".")[0].replace(",", ""))
    raise ValueError(f"{value!r} is not a whole-shilling amount")
