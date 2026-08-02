import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Detection:
    category: str
    value: str
    start: int
    end: int
    confidence: str
    replacement: str
    risk: str


def is_valid_credit_card(value: str) -> bool:
    """Validate a possible payment-card number with the Luhn algorithm."""
    digits = re.sub(r"\D", "", value)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    for index, digit in enumerate(reversed(digits)):
        number = int(digit)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number

    return total % 10 == 0


def is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


DETECTORS = [
    {
        "category": "Email Address",
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "replacement": "[EMAIL REDACTED]",
        "confidence": "High",
        "risk": "Personal contact information can identify an individual.",
    },
    {
        "category": "Phone Number",
        "pattern": re.compile(
            r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?"
            r"(?:\(?\d{3}\)?[-.\s]?)"
            r"\d{3}[-.\s]?\d{4}(?!\w)"
        ),
        "replacement": "[PHONE REDACTED]",
        "confidence": "Medium",
        "risk": "Phone numbers can expose personal contact information.",
    },
    {
        "category": "IPv4 Address",
        "pattern": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "replacement": "[IP ADDRESS REDACTED]",
        "confidence": "High",
        "risk": "Internal IP addresses can reveal infrastructure details.",
        "validator": is_valid_ipv4,
    },
    {
        "category": "Credit Card",
        "pattern": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
        "replacement": "[CARD REDACTED]",
        "confidence": "High",
        "risk": "Payment-card data is highly sensitive financial information.",
        "validator": is_valid_credit_card,
    },
    {
        "category": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "replacement": "[AWS KEY REDACTED]",
        "confidence": "High",
        "risk": "Cloud credentials may allow unauthorized account access.",
    },
    {
        "category": "JWT Token",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "replacement": "[JWT REDACTED]",
        "confidence": "High",
        "risk": "Session tokens can provide access to protected systems.",
    },
    {
        "category": "API Key",
        "pattern": re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?"
        ),
        "replacement": "[API KEY REDACTED]",
        "confidence": "Medium",
        "risk": "API keys can be abused to access services or create charges.",
    },
    {
        "category": "Password",
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s,\"']{4,})[\"']?"
        ),
        "replacement": "[PASSWORD REDACTED]",
        "confidence": "Medium",
        "risk": "Passwords can compromise user or system accounts.",
    },
    {
        "category": "Indian Aadhaar Number",
        "pattern": re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"),
        "replacement": "[AADHAAR REDACTED]",
        "confidence": "Medium",
        "risk": "Government identifiers are sensitive identity information.",
    },
]


def detect_sensitive_data(text: str) -> list[Detection]:
    detections: list[Detection] = []

    for detector in DETECTORS:
        pattern = detector["pattern"]
        validator: Optional[Callable[[str], bool]] = detector.get("validator")

        for match in pattern.finditer(text):
            value = match.group(0)

            if validator and not validator(value):
                continue

            detections.append(
                Detection(
                    category=detector["category"],
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    confidence=detector["confidence"],
                    replacement=detector["replacement"],
                    risk=detector["risk"],
                )
            )

    return remove_overlapping_detections(detections)


def remove_overlapping_detections(detections: list[Detection]) -> list[Detection]:
    ordered = sorted(detections, key=lambda item: (item.start, -(item.end - item.start)))
    result: list[Detection] = []

    for detection in ordered:
        overlaps = any(
            detection.start < existing.end and detection.end > existing.start
            for existing in result
        )
        if not overlaps:
            result.append(detection)

    return sorted(result, key=lambda item: item.start)


def redact_text(text: str, detections: list[Detection]) -> str:
    redacted = text

    for detection in sorted(detections, key=lambda item: item.start, reverse=True):
        redacted = (
            redacted[: detection.start]
            + detection.replacement
            + redacted[detection.end :]
        )

    return redacted


def calculate_risk_score(detections: list[Detection]) -> int:
    weights = {"High": 30, "Medium": 18, "Low": 8}
    return min(100, sum(weights.get(item.confidence, 10) for item in detections))


def audit_text(text: str) -> tuple[list[Detection], str, int]:
    detections = detect_sensitive_data(text)
    redacted = redact_text(text, detections)
    score = calculate_risk_score(detections)
    return detections, redacted, score
