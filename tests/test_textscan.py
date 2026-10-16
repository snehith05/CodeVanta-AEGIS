from aegis.sandbox import data
from aegis.textscan import (extract_indicators, lookalike_of, luhn_valid, redact_text, scan_injection, scan_pii,
                            verhoeff_check_digit, verhoeff_valid)


def test_verhoeff_reference_values():
    assert verhoeff_check_digit("236") == "3"
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


def test_synthetic_aadhaar_numbers_are_checksum_valid():
    assert all(verhoeff_valid(c["aadhaar"]) for c in data.CUSTOMERS)


def test_luhn():
    assert luhn_valid("4111111111111111")
    for account in ("50100023456781", "31245678902", "919020012345678", "50200099887766"):
        assert not scan_pii(f"A/c {account}").total, account  # bank accounts must not look like cards/Aadhaar


def test_pii_detection_is_checksum_based_not_keyword_based():
    c = data.CUSTOMERS[0]
    spaced = f"{c['aadhaar'][:4]} {c['aadhaar'][4:8]} {c['aadhaar'][8:]}"
    rep = scan_pii(f"Aadhaar {spaced}, PAN {c['pan']}, mobile +91 {c['phone']}")
    assert rep.aadhaar == [c["aadhaar"]] and rep.pan == [c["pan"]] and rep.phones == [c["phone"]]
    # a random 12-digit order number that fails the Verhoeff check is not an Aadhaar number
    bad = c["aadhaar"][:-1] + str((int(c["aadhaar"][-1]) + 1) % 10)
    assert not scan_pii(f"Order ref {bad}").aadhaar


def test_secret_detection():
    rep = scan_pii("RAZORPAY_KEY_ID=rzp_test_DEMOFAKEKEY000 and AKIAKUDLA2026DEMO000")
    kinds = {k for k, _ in rep.secrets}
    assert "Razorpay key" in kinds and "AWS access key" in kinds


def test_redaction_masks_aadhaar_like_uidai():
    c = data.CUSTOMERS[0]
    text, counts = redact_text(f"Aadhaar {c['aadhaar']} phone {c['phone']}", {"aadhaar"})
    assert f"XXXX XXXX {c['aadhaar'][-4:]}" in text and c["phone"] in text and counts == {"aadhaar": 1}


def test_injection_scores():
    by_id = {e["id"]: e for e in data.INBOX}
    assert scan_injection(by_id["E-1043"]["body"])[0] > 0.8
    assert scan_injection(by_id["E-1041"]["body"])[0] < 0.3   # a normal invoice is not an attack
    assert scan_injection(data.TICKETS[0]["body"])[0] >= 0.5  # fake compliance note
    assert scan_injection(data.TICKETS[1]["body"])[0] < 0.3
    assert scan_injection(data.WEB["https://cashewprices.example/today"])[0] >= 0.5
    assert scan_injection("Hello​ world")[0] > 0  # zero-width smuggling


def test_lookalike_domains():
    trusted = ["kudlacashew.in", "coastalpack.in", "rawcashewtraders.in"]
    assert lookalike_of("kudlacashew-payments.co", trusted) == "kudlacashew.in"
    assert lookalike_of("coastalpak.in", trusted) == "coastalpack.in"
    assert lookalike_of("kudIacashew.in", trusted) == "kudlacashew.in"  # capital I for l
    assert lookalike_of("gmail.com", trusted) is None
    assert lookalike_of("kudlacashew.in", trusted) is None


def test_indicator_extraction():
    ind = extract_indicators("Pay Rs 42,000 to A/c 50200099887766, IFSC HDFC0004321, mail x@evil.co")
    assert ind["50200099887766"] == "account" and ind["hdfc0004321"] == "ifsc" and ind["amount:42000"] == "amount"
    assert ind["x@evil.co"] == "email" and ind["evil.co"] == "domain"
