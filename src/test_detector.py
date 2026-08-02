from detector import audit_text, detect_sensitive_data


def categories(text: str) -> set[str]:
    return {item.category for item in detect_sensitive_data(text)}


def test_detects_email():
    assert "Email Address" in categories("Contact alice@example.com")


def test_detects_phone():
    assert "Phone Number" in categories("Call 415-555-2671")


def test_detects_credit_card():
    assert "Credit Card" in categories("Card: 4111 1111 1111 1111")


def test_rejects_invalid_credit_card():
    assert "Credit Card" not in categories("Reference: 1234 5678 9012 3456")


def test_detects_valid_ip_address():
    assert "IPv4 Address" in categories("Server: 192.168.1.10")


def test_rejects_invalid_ip_address():
    assert "IPv4 Address" not in categories("Server: 999.999.1.10")


def test_detects_aws_key():
    assert "AWS Access Key" in categories("Key: AKIAIOSFODNN7EXAMPLE")


def test_detects_password():
    assert "Password" in categories("password=SuperSecret123")


def test_detects_api_key():
    assert "API Key" in categories("api_key=abcdefghijklmnop123456")


def test_detects_aadhaar():
    assert "Indian Aadhaar Number" in categories("Aadhaar: 2345 6789 1234")


def test_safe_sentence_stays_unchanged():
    text = "The design meeting starts tomorrow morning."
    detections, redacted, score = audit_text(text)
    assert detections == []
    assert redacted == text
    assert score == 0


def test_safe_business_text_stays_unchanged():
    text = "Revenue increased by twelve percent this quarter."
    detections, redacted, _ = audit_text(text)
    assert detections == []
    assert redacted == text


def test_email_is_redacted():
    _, redacted, _ = audit_text("Send it to alice@example.com")
    assert "alice@example.com" not in redacted
    assert "[EMAIL REDACTED]" in redacted


def test_multiple_items_are_redacted():
    text = "Email alice@example.com and call 415-555-2671."
    detections, redacted, score = audit_text(text)
    assert len(detections) == 2
    assert "[EMAIL REDACTED]" in redacted
    assert "[PHONE REDACTED]" in redacted
    assert score > 0
