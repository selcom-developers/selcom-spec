"""Check vectors/responses/*.json against the reference rules.

    python tools/check_fixtures.py

For every response scenario, the reference classifier (docs/results.md) must
produce the expected typed status or error. For every webhook sample, the
reference verifier (docs/webhooks.md) must produce the expected verdict.
Every file under vectors/ must also pass the fake-data guard: phone numbers in
the 2557000000xx range, e-mail addresses on example domains, vendor TILL123.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from selcom_reference import (  # noqa: E402
    KINDS,
    STATUSES,
    VERIFICATIONS,
    InvalidResponse,
    classify,
    parse_amount_tzs,
    verify_webhook,
)

ROOT = Path(__file__).resolve().parent.parent
RESPONSES = ROOT / "vectors" / "responses"

V1_OPERATIONS = {
    "checkout.create-order",
    "checkout.create-order-minimal",
    "checkout.wallet-payment",
    "checkout.card-payment",
    "checkout.order-status",
    "checkout.cancel-order",
    "checkout.list-orders",
    "checkout.stored-cards",
    "checkout.delete-card",
    "utilitypayment.process",
    "utilitypayment.lookup",
    "utilitypayment.query",
    "walletcashin.process",
    "walletcashin.namelookup",
    "walletcashin.query",
    "vendor.balance",
    "checkout.webhook",
}

PHONE = re.compile(r"(?<!\d)255\d{9}(?!\d)")
FAKE_PHONE = re.compile(r"^2557000000\d\d$")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
FAKE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")


def fake_data_problems(path: Path, node: object, where: str = "") -> list[str]:
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "vendor" and isinstance(value, str) and value != "TILL123":
                problems.append(f"{path.name}{where}.vendor: use TILL123, not {value!r}")
            problems += fake_data_problems(path, value, f"{where}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            problems += fake_data_problems(path, value, f"{where}[{index}]")
    elif isinstance(node, str):
        for phone in PHONE.findall(node):
            if not FAKE_PHONE.match(phone):
                problems.append(f"{path.name}{where}: phone {phone} is outside 2557000000xx")
        for domain in EMAIL.findall(node):
            if not domain.lower().endswith(FAKE_EMAIL_DOMAINS):
                problems.append(f"{path.name}{where}: e-mail domain {domain} is not an example domain")
        if node.lstrip().startswith("{"):
            try:
                problems += fake_data_problems(path, json.loads(node), where + "<json>")
            except ValueError:
                pass
    return problems


def check_scenarios(path: Path, doc: dict) -> tuple[int, list[str]]:
    problems: list[str] = []
    kind = doc.get("kind")
    if kind not in KINDS:
        return 0, [f"{path.name}: unknown kind {kind!r}"]
    for scenario in doc.get("scenarios", []):
        name = f"{path.name}#{scenario.get('name')}"
        if "raw_body" in scenario:
            try:
                body = json.loads(scenario["raw_body"])
            except ValueError:
                body = None
        else:
            body = scenario.get("body")
        expected_status = scenario.get("expected_status")
        expected_error = scenario.get("expected_error")
        if (expected_status is None) == (expected_error is None):
            problems.append(f"{name}: give exactly one of expected_status and expected_error")
            continue
        if expected_status is not None and expected_status not in STATUSES:
            problems.append(f"{name}: {expected_status!r} is not a typed status")
            continue
        try:
            got = classify(kind, body)
        except InvalidResponse:
            got = "error:INVALID_RESPONSE"
        want = expected_status if expected_status is not None else f"error:{expected_error}"
        if got != want:
            problems.append(f"{name}: expected {want}, reference gives {got}")
    return len(doc.get("scenarios", [])), problems


def check_webhooks(path: Path, doc: dict) -> tuple[int, list[str]]:
    problems: list[str] = []
    config = doc["verification"]
    now = datetime.fromisoformat(config["now"])
    seen: set[str] = set()
    for sample in doc["samples"]:
        name = f"{path.name}#{sample['name']}"
        if sample["expected_verification"] not in VERIFICATIONS:
            problems.append(f"{name}: unknown verdict {sample['expected_verification']!r}")
            continue
        got = verify_webhook(sample["headers"], sample["raw_body"], config["secret"], now, config["window_seconds"], seen)
        if got != sample["expected_verification"]:
            problems.append(f"{name}: expected {sample['expected_verification']}, reference gives {got}")
        amount = parse_amount_tzs(json.loads(sample["raw_body"]).get("amount"))
        if amount != sample["expected_amount_tzs"]:
            problems.append(f"{name}: amount parses to {amount}, expected {sample['expected_amount_tzs']}")
    return len(doc["samples"]), problems


def main() -> int:
    problems: list[str] = []
    operations: set[str] = set()
    count = 0
    for path in sorted(RESPONSES.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        operations.add(doc.get("operation", ""))
        if path.stem != doc.get("operation"):
            problems.append(f"{path.name}: file name must match operation {doc.get('operation')!r}")
        if "samples" in doc:
            n, found = check_webhooks(path, doc)
        else:
            n, found = check_scenarios(path, doc)
        count += n
        problems += found
    for missing in sorted(V1_OPERATIONS - operations):
        problems.append(f"no fixture file for {missing}")
    for path in sorted((ROOT / "vectors").rglob("*.json")):
        problems += fake_data_problems(path, json.loads(path.read_text(encoding="utf-8")))
    if problems:
        print("\n".join(problems))
        print(f"\n{len(problems)} problem(s).")
        return 1
    print(f"OK: {count} response scenarios and webhook samples across {len(operations)} operations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
