"""Unit tests for services.logs_service.obfuscate_string / obfuscate_email (pure functions)."""

import pytest

from services.logs_service import obfuscate_email, obfuscate_string


@pytest.mark.parametrize(
    "value, expected",
    [
        ("", "*"),
        ("a", "*"),
        ("ab", "*b"),
        ("abc", "**c"),
        ("abcd", "a**d"),
        ("abcde", "a***e"),
        ("jdoe", "j**e"),
        ("example", "e****le"),
    ],
)
def test_obfuscate_string_matches_ruby_port(value, expected):
    assert obfuscate_string(value) == expected


def test_obfuscate_string_custom_char():
    assert obfuscate_string("abcd", char="#") == "a##d"


@pytest.mark.parametrize(
    "address, expected",
    [
        ("jdoe@example.com", "j**e@ex******com"),
        ("a@b", "*@*"),
        ("foo@", "**o@*"),
        ("@foo.com", "*@f****om"),
        ("no-at-sign", None),
        ("", None),
        (None, None),
    ],
)
def test_obfuscate_email_matches_ruby_port(address, expected):
    assert obfuscate_email(address) == expected


def test_obfuscate_email_never_reveals_full_local_or_domain():
    obfuscated = obfuscate_email("jdoe@example.com")
    assert "jdoe" not in obfuscated
    assert "example" not in obfuscated
