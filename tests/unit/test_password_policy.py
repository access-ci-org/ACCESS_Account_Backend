"""Unit tests for services.password_policy.validate_access_password (pure function)."""

import pytest

from services.password_policy import validate_access_password


def test_valid_password_passes():
    # 3 categories (lower, upper, digit), length in [12, 64].
    result = validate_access_password("GoodPassword1")
    assert result.valid is True
    assert result.errors == []


def test_none_password_is_required():
    result = validate_access_password(None)  # type: ignore[arg-type]
    assert result.valid is False
    assert result.errors == ["Password is required."]


@pytest.mark.parametrize(
    "password, length_ok",
    [
        ("Ab1" + "x" * 8, False),  # 11 chars -> too short
        ("Ab1" + "x" * 9, True),  # 12 chars -> boundary OK
        ("Ab1" + "x" * 61, True),  # 64 chars -> boundary OK
        ("Ab1" + "x" * 62, False),  # 65 chars -> too long
    ],
)
def test_length_boundaries(password, length_ok):
    result = validate_access_password(password)
    length_error = (
        "Your new password must be between 12 and 64 characters in length."
    )
    assert (length_error not in result.errors) == length_ok


def test_requires_three_character_categories():
    # Only lowercase + uppercase = 2 categories -> fails the category rule.
    result = validate_access_password("OnlyLettersHere")
    assert result.valid is False
    assert any("at least three" in e for e in result.errors)


def test_symbol_counts_as_a_category():
    # lower + digit + symbol = 3 categories, length OK -> valid.
    result = validate_access_password("abcdef123456!")
    assert result.valid is True


def test_short_and_low_category_reports_both_errors():
    result = validate_access_password("abc")  # too short AND only 1 category
    assert result.valid is False
    assert len(result.errors) == 2
