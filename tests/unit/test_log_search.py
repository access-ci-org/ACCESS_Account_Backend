"""Tests for services.log_search and the `logs search` CLI command."""

from datetime import datetime

import pytest
from click.testing import CliRunner

import cli
from services.log_search import iter_records, search_log, search_pattern, search_term

ADA_EMAIL = search_term("ada@example.edu")  # **a@ex******edu
ADA_EMAIL_IN_URL = ADA_EMAIL.replace("@", "%40")

LOG = f"""\
rest of a record cut off by rotation, mentioning ada
2026-11-04 23:59:59,001 - INFO - access_account_api.access - 1.2.3.4 ada GET /account 200 10.0ms
    -> GET    https://registry.example.org/co_people.json?search.identifier=ada 200 5.0ms
2026-11-05 08:00:00,000 - INFO - access_account_api.access - 1.2.3.4 adam GET /account 200 10.0ms
2026-11-05 09:00:00,000 - ERROR - access_account_api.access - 1.2.3.4 bob POST /ssh-key 400 10.0ms
    -> POST   https://registry.example.org/ssh_keys.json 201 5.0ms
    !! Could not add SSH key for ada
       Traceback (most recent call last):
         ValueError: bad key
2026-11-05 10:00:00,000 - WARNING - access_account_api.access - 1.2.3.4 {ADA_EMAIL} POST /auth/verify-otp 400 3.0ms
    -- WARNING access_account_api.otp - OTP mismatch for email={ADA_EMAIL}
2026-11-05 11:00:00,000 - INFO - access_account_api.access - 1.2.3.4 - POST /email-callback 200 1.0ms
    -- INFO access_account_api.email - SES Bounce for {ADA_EMAIL_IN_URL}
2026-11-05 12:00:00,000 - INFO - access_account_api - Refreshed IdP domain mapping
2026-11-06 00:00:00,000 - INFO - access_account_api.access - 1.2.3.4 ada GET /profile 200 10.0ms
"""


def lines():
    return LOG.splitlines(keepends=True)


def times(records):
    return [r.timestamp for r in records]


def test_iter_records_groups_subentries():
    records = list(iter_records(lines()))
    assert [len(r.lines) for r in records] == [1, 2, 1, 5, 2, 2, 1, 1]
    assert records[0].timestamp is None
    assert records[3].timestamp == datetime(2026, 11, 5, 9)
    assert records[3].level == "ERROR"


def test_iter_records_reads_the_request_user():
    records = list(iter_records(lines()))
    assert [r.user for r in records] == [
        None,  # no header
        "ada",
        "adam",
        "bob",
        ADA_EMAIL,
        None,  # a request with no user
        None,  # not a request
        "ada",
    ]


def test_request_records_match_on_their_user_field():
    found = list(search_log(lines(), "ada"))
    # The cut-off text has no user field, so it's matched by its text.
    assert times(found) == [
        None,
        datetime(2026, 11, 4, 23, 59, 59),
        datetime(2026, 11, 6),
    ]
    assert found[1].lines[1].startswith("    -> GET")
    # bob's request mentions ada in a subentry, but it's bob's request.
    assert not any("bob" in r.text for r in found)


def test_search_is_case_insensitive():
    assert len(list(search_log(lines(), "ADA"))) == 3


def test_search_by_email_uses_the_obfuscated_address():
    found = list(search_log(lines(), " Ada@Example.edu "))
    # The OTP request by its user field; the email callback, which has no user,
    # by the (percent-encoded) address in its text.
    assert times(found) == [datetime(2026, 11, 5, 10), datetime(2026, 11, 5, 11)]
    assert found[0].lines[1].endswith(f"OTP mismatch for email={ADA_EMAIL}")
    assert found[1].lines[1].endswith(f"SES Bounce for {ADA_EMAIL_IN_URL}")


@pytest.mark.parametrize(
    "text, matches",
    [
        ("user ada.", True),
        ("user ada, then", True),
        ("ada@access-ci.org", True),
        ("/account/ada?x=1", True),
        ("ada.lovelace", False),
        ("adam", False),
        ("x-ada", False),
        ("a**a", False),
    ],
)
def test_access_id_boundaries(text, matches):
    assert bool(search_pattern("ada").search(text)) is matches


def test_single_letter_id_does_not_match_obfuscated_email():
    assert not search_pattern("j").search("email=j**e@ex******org")


def test_time_range():
    found = list(
        search_log(
            lines(),
            "ada",
            start=datetime(2026, 11, 4, 12),
            end=datetime(2026, 11, 6),
        )
    )
    # The untimestamped record is left out once a range is given.
    assert times(found) == [datetime(2026, 11, 4, 23, 59, 59)]


# --- CLI ----------------------------------------------------------------------
@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "app.log"
    path.write_text(LOG)
    return path


def run(log_file, *args):
    return CliRunner().invoke(
        cli.cli, ["logs", "search", *args, "--log-file", str(log_file)]
    )


def test_cli_prints_matching_entries_with_subentries(log_file):
    result = run(log_file, "ada@example.edu", "--start", "2026-11-05 09:30")
    assert result.exit_code == 0, result.output
    assert (
        f"    -- WARNING access_account_api.otp - OTP mismatch for email={ADA_EMAIL}"
        in (result.stdout)
    )
    assert "/email-callback" in result.stdout
    assert "2 matching entries" in result.stderr


def test_cli_date_only_end_includes_that_day(log_file):
    result = run(log_file, "ada", "--start", "2026-11-04", "--end", "2026-11-04")
    assert result.exit_code == 0, result.output
    assert "ada GET /account" in result.stdout
    assert "search.identifier=ada" in result.stdout
    assert "/profile" not in result.stdout
    assert "1 matching entry" in result.stderr


def test_cli_email(log_file):
    result = run(log_file, "ada@example.edu")
    assert result.exit_code == 0, result.output
    assert f"Searching for {ADA_EMAIL}" in result.stderr
    assert "2 matching entries" in result.stderr


def test_cli_rejects_bad_datetime(log_file):
    result = run(log_file, "ada", "--start", "yesterday")
    assert result.exit_code == 2
    assert "is not a date or datetime" in result.output


def test_cli_rejects_reversed_range(log_file):
    result = run(log_file, "ada", "--start", "2026-11-06", "--end", "2026-11-05")
    assert result.exit_code == 2
    assert "--start must be before --end" in result.output


def test_cli_missing_log_file(tmp_path):
    result = run(tmp_path / "missing.log", "ada")
    assert result.exit_code == 2
    assert "does not exist" in result.output
