import pytest
from core.feature_extraction import extract_features_from_eml

def test_extract_features_valid_eml():
    eml_content = b"""From: sender@example.com
To: receiver@example.com
Subject: Urgent Security Notice
Content-Type: text/html

<html>
    <body>
        <p>Please click here: <a href="http://malicious.com/login">Login</a></p>
    </body>
</html>
"""
    features = extract_features_from_eml(eml_content)
    
    assert features["subject_len"] > 0
    assert features["has_sender"] == 1
    assert features["total_links"] == 1
    # total links = 1. sender_domain = example.com. href domain = malicious.com. Thus, 100% external.
    assert features["PctExtHyperlinks"] == 1.0

def test_extract_features_malformed_eml():
    # Empty byte string
    eml_content = b""
    try:
        features = extract_features_from_eml(eml_content)
        assert isinstance(features, dict)
        assert features["total_links"] == 0
        assert features["subject_len"] == 0
    except Exception as e:
        pytest.fail(f"Parser crashed on empty byte string: {e}")

def test_extract_features_no_html_links():
    eml_content = b"""Subject: Just text
Content-Type: text/plain

No links here, just text.
"""
    features = extract_features_from_eml(eml_content)
    assert features["total_links"] == 0
    assert features["PctExtHyperlinks"] == 0.0
