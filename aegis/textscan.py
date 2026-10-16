"""Text analysis used by the detectors: PII, secrets, prompt injection, indicators, domains.

Everything here is deterministic and runs in microseconds, so the enforcement
layer itself cannot be prompt-injected or talked out of a decision.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- checksums

_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(digits: str) -> bool:
    """Aadhaar numbers carry a Verhoeff check digit; random 12-digit numbers mostly fail it."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    return str(_VINV[c])


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# --------------------------------------------------------------------------- patterns

AADHAAR_RE = re.compile(r"(?<![\dA-Za-z])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\dA-Za-z])")
PAN_RE = re.compile(r"\b([A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z])\b")
CARD_RE = re.compile(r"(?<![\d-])([2-6]\d{3}(?:[ -]?\d){9,15})(?![\d-])")
PHONE_RE = re.compile(r"(?<![\d+])(?:\+91[ -]?|0)?([6-9]\d{4}[ -]?\d{5})(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
ACCOUNT_RE = re.compile(r"(?<![\dA-Za-z])(\d[\d -]{7,22}\d)(?![\dA-Za-z])")
UPI_RE = re.compile(
    r"\b[\w.-]{2,}@(?:ok(?:sbi|hdfcbank|icici|axis)|ybl|paytm|upi|ibl|axl|apl|sbi|icici|hdfcbank|kotak)\b", re.I
)
AMOUNT_RE = re.compile(r"(?:₹|\bINR|\bRs\.?)\s*([\d,]+(?:\.\d{1,2})?)", re.I)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("API secret key", re.compile(r"\bsk-(?:ant-|proj-|live-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Razorpay key", re.compile(r"\brzp_(?:live|test)_[A-Za-z0-9]{14,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Connection string", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
    ("Credential assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|db_pass(?:word)?|secret(?:_key)?|api[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"']?([^\s\"',;]{6,})")),
]


# --------------------------------------------------------------------------- PII

@dataclass
class PiiReport:
    aadhaar: list[str] = field(default_factory=list)
    pan: list[str] = field(default_factory=list)
    cards: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    secrets: list[tuple[str, str]] = field(default_factory=list)

    @property
    def identity_count(self) -> int:
        """Government ID / financial identifiers - the data that hurts most when leaked."""
        return len(self.aadhaar) + len(self.pan) + len(self.cards)

    @property
    def total(self) -> int:
        return self.identity_count + len(self.phones) + len(self.emails)

    def summary(self) -> dict[str, int]:
        out = {
            "aadhaar": len(self.aadhaar), "pan": len(self.pan), "cards": len(self.cards),
            "phones": len(self.phones), "emails": len(self.emails), "secrets": len(self.secrets),
        }
        return {k: v for k, v in out.items() if v}

    def describe(self) -> str:
        names = {"aadhaar": ("Aadhaar", "Aadhaar numbers"), "pan": ("PAN", "PANs"),
                 "cards": ("card number", "card numbers"), "phones": ("phone number", "phone numbers"),
                 "emails": ("email address", "email addresses"), "secrets": ("secret", "secrets")}
        parts = [f"{n} {names[key][n > 1]}" for key, n in self.summary().items()]
        return ", ".join(parts) if parts else "no sensitive data"


def _uniq(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen)


def scan_pii(text: str) -> PiiReport:
    if not text:
        return PiiReport()
    rep = PiiReport()
    rep.aadhaar = _uniq([
        "".join(m.groups()) for m in AADHAAR_RE.finditer(text) if verhoeff_valid("".join(m.groups()))
    ])
    rep.pan = _uniq(PAN_RE.findall(text))
    cards = []
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if 13 <= len(digits) <= 19 and len(set(digits)) > 1 and luhn_valid(digits):
            cards.append(digits)
    rep.cards = _uniq(cards)
    aadhaar_set = set(rep.aadhaar)
    rep.phones = _uniq([
        re.sub(r"\D", "", m.group(1)) for m in PHONE_RE.finditer(text)
        if re.sub(r"\D", "", m.group(1)) not in aadhaar_set
    ])
    rep.emails = _uniq([e.lower() for e in EMAIL_RE.findall(text)])
    rep.secrets = [(name, m.group(0)) for name, rx in SECRET_PATTERNS for m in rx.finditer(text)]
    return rep


def mask_aadhaar(digits: str) -> str:
    return f"XXXX XXXX {digits[-4:]}"


def mask_pan(pan: str) -> str:
    return "XXXXXX" + pan[-4:]


def mask_card(digits: str) -> str:
    return "XXXX XXXX XXXX " + digits[-4:]


def mask_phone(digits: str) -> str:
    return digits[:2] + "XXXXXX" + digits[-2:]


def redact_text(text: str, kinds: set[str], keep: set[str] | None = None) -> tuple[str, dict[str, int]]:
    """Mask the requested kinds of sensitive data. Values in ``keep`` are left alone."""
    keep = keep or set()
    counts: dict[str, int] = {}

    def bump(kind: str) -> None:
        counts[kind] = counts.get(kind, 0) + 1

    if "secret" in kinds:
        for name, rx in SECRET_PATTERNS:
            def _sec(m: re.Match[str], name: str = name) -> str:
                bump("secret")
                return f"[REDACTED {name.upper()}]"
            text = rx.sub(_sec, text)
    if "aadhaar" in kinds:
        def _aad(m: re.Match[str]) -> str:
            digits = "".join(m.groups())
            if verhoeff_valid(digits) and digits not in keep:
                bump("aadhaar")
                return mask_aadhaar(digits)
            return m.group(0)
        text = AADHAAR_RE.sub(_aad, text)
    if "pan" in kinds:
        def _pan(m: re.Match[str]) -> str:
            if m.group(1) in keep:
                return m.group(0)
            bump("pan")
            return mask_pan(m.group(1))
        text = PAN_RE.sub(_pan, text)
    if "card" in kinds:
        def _card(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(1))
            if 13 <= len(digits) <= 19 and luhn_valid(digits) and digits not in keep:
                bump("card")
                return mask_card(digits)
            return m.group(0)
        text = CARD_RE.sub(_card, text)
    if "phone" in kinds:
        def _phone(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(1))
            if digits in keep:
                return m.group(0)
            bump("phone")
            return mask_phone(digits)
        text = PHONE_RE.sub(_phone, text)
    if "email" in kinds:
        def _email(m: re.Match[str]) -> str:
            if m.group(0).lower() in keep:
                return m.group(0)
            bump("email")
            return "[REDACTED EMAIL]"
        text = EMAIL_RE.sub(_email, text)
    return text, counts


# --------------------------------------------------------------------------- prompt injection

_ZERO_WIDTH = re.compile("[​-‏⁠⁡⁢⁣﻿]")
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")

INJECTION_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    ("instruction override", 0.45, re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|all|your|system|any)\b"
        r"[^.\n]{0,25}?\b(?:instructions?|prompts?|rules?|guidelines?|limits?|polic(?:y|ies)|guardrails?)\b")),
    ("role hijack", 0.30, re.compile(
        r"(?i)\b(?:you are now|act as (?:an?|the)|pretend to be|from now on,? you|new persona|developer mode|"
        r"priority mode|admin mode|god mode|jailbreak)\b")),
    ("fake system / AI-addressed text", 0.35, re.compile(
        r"(?i)(?:^|\n)\s*(?:system|assistant)\s*:|\[/?(?:system|inst)\]|<\|im_start\|>|<\|system\|>|###\s*(?:system|instruction)"
        r"|\b(?:note|instructions?|message) (?:to|for) (?:the )?(?:ai|assistant|agent|llm|bot)\b"
        r"|\bai (?:assistant|agent) instruction\b")),
    ("secrecy demand", 0.30, re.compile(
        r"(?i)\b(?:do not|don't|never)\s+(?:tell|mention|inform|reveal|disclose|notify|report|log|flag|ask)\b"
        r"|\bkeep (?:this|it) (?:secret|confidential|between us|quiet)\b"
        r"|\bwithout (?:asking|confirmation|approval|telling|notifying)\b")),
    ("tool-directed command", 0.25, re.compile(
        r"(?i)\b(?:transfer|wire|send|forward|e-?mail|export|upload|delete|drop|grant|execute|run|curl|wget)\b"
        r"[^.\n]{0,80}?\b(?:to|into|on)\b[^.\n]{0,50}?(?:account|a/c|@|https?://|admin|role|server)")),
    ("authority / urgency pressure", 0.12, re.compile(
        r"(?i)\b(?:pre-?approved|approved by (?:the )?(?:ceo|cfo|md|director)|on behalf of (?:the )?(?:ceo|cfo)|"
        r"mandatory|rbi audit|immediately|urgent(?:ly)?|within the hour|right now)\b")),
    ("exfiltration link", 0.35, re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=")),
]


def scan_injection(text: str) -> tuple[float, list[dict[str, str]]]:
    """Score how much a piece of untrusted content looks like it is trying to steer an agent."""
    if not text:
        return 0.0, []
    found: list[dict[str, str]] = []
    weights: list[float] = []
    for name, weight, rx in INJECTION_RULES:
        m = rx.search(text)
        if m:
            found.append({"indicator": name, "excerpt": _excerpt(text, m.start(), m.end())})
            weights.append(weight)
    for m in re.finditer(r"<!--([\s\S]*?)-->", text):
        if len(re.sub(r"\W", "", m.group(1))) >= 20:
            found.append({"indicator": "hidden HTML comment", "excerpt": _excerpt(text, m.start(), m.end())})
            weights.append(0.25)
            break
    if re.search(r"(?i)(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?\b|white))", text):
        found.append({"indicator": "CSS-hidden text", "excerpt": "style hides text from human readers"})
        weights.append(0.2)
    if _ZERO_WIDTH.search(text):
        found.append({"indicator": "zero-width characters", "excerpt": "invisible Unicode characters present"})
        weights.append(0.3)
    if _TAG_CHARS.search(text):
        found.append({"indicator": "Unicode tag smuggling", "excerpt": "invisible Unicode tag characters (ASCII smuggling)"})
        weights.append(0.5)
    if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", text):
        found.append({"indicator": "large encoded blob", "excerpt": "base64-like payload"})
        weights.append(0.15)
    return combine(weights), found


def combine(scores: list[float]) -> float:
    """Noisy-OR: independent pieces of evidence add up without ever exceeding 1."""
    p = 1.0
    for s in scores:
        p *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - p


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    snippet = re.sub(r"\s+", " ", text[s:e]).strip()
    return ("…" if s > 0 else "") + snippet + ("…" if e < len(text) else "")


# --------------------------------------------------------------------------- indicators (taint tracking)

def parse_amount(raw: str) -> float | None:
    try:
        return float(raw.replace(",", ""))
    except ValueError:
        return None


def extract_indicators(text: str) -> dict[str, str]:
    """Pull out actionable values (accounts, IFSC, emails, URLs, amounts...) with their kind."""
    out: dict[str, str] = {}
    if not text:
        return out
    for m in ACCOUNT_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if 9 <= len(digits) <= 18:
            out[digits] = "account"
    for m in IFSC_RE.finditer(text):
        out[m.group(0).lower()] = "ifsc"
    for m in EMAIL_RE.finditer(text):
        e = m.group(0).lower()
        out[e] = "email"
        out[domain_of(e)] = "domain"
    for m in URL_RE.finditer(text):
        u = m.group(0).lower().rstrip(".,;")
        out[u] = "url"
        out[domain_of(u)] = "domain"
    for m in UPI_RE.finditer(text):
        out[m.group(0).lower()] = "upi"
    for m in AMOUNT_RE.finditer(text):
        amt = parse_amount(m.group(1))
        if amt:
            out[f"amount:{amt:.0f}"] = "amount"
    return out


def normalize_value(value: object) -> list[str]:
    """Turn an argument value into the same normalised forms ``extract_indicators`` produces."""
    if value is None:
        return []
    if isinstance(value, (int, float)):
        return [f"amount:{float(value):.0f}"]
    s = str(value).strip()
    if not s:
        return []
    forms: set[str] = set()
    digits = re.sub(r"[\s-]", "", s)
    if digits.isdigit():
        forms.add(digits)
    if EMAIL_RE.fullmatch(s):
        forms.add(s.lower())
        forms.add(domain_of(s))
    for k in extract_indicators(s):
        forms.add(k)
    return sorted(forms)


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


# --------------------------------------------------------------------------- domains

_MULTI_SUFFIX = {"co.in", "org.in", "net.in", "ac.in", "gov.in", "co.uk", "com.au", "co.jp"}
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "|": "l", "!": "i",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ӏ": "l", "ԁ": "d", "ս": "u",
})


def domain_of(value: str) -> str:
    v = (value or "").strip().lower()
    if "@" in v and "://" not in v:
        return v.rsplit("@", 1)[1].strip(">")
    v = re.sub(r"^[a-z]+://", "", v)
    return v.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]


def registrable_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_label(domain: str) -> str:
    reg = registrable_domain(domain)
    parts = reg.split(".")
    return parts[0] if parts else reg


def is_internal(address_or_url: str, internal_domains: list[str]) -> bool:
    d = domain_of(address_or_url)
    return any(d == x or d.endswith("." + x) for x in internal_domains)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s.lower()).translate(_HOMOGLYPHS)
    return s.replace("rn", "m").replace("vv", "w")


def lookalike_of(domain: str, trusted: list[str]) -> str | None:
    """Return the trusted domain that ``domain`` imitates, if any."""
    d = domain.lower()
    if not d or any(d == t or d.endswith("." + t) for t in trusted):
        return None
    lbl = domain_label(d)
    sk = skeleton(lbl)
    for t in trusted:
        tl = domain_label(t)
        if len(tl) < 5:
            continue
        if sk == skeleton(tl):
            return t  # same name, different TLD or homoglyph swap
        if levenshtein(sk, skeleton(tl)) <= max(1, len(tl) // 6):
            return t  # typo-squat
        if tl in lbl and lbl != tl:
            return t  # brand plus a suffix, e.g. kudlacashew-payments
    return None
