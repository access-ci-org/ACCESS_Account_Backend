"""Tests for the `account` CLI command, with both service clients mocked."""

from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner
from fastapi import HTTPException
from test_account_verification import TANDC, make_person, make_user

import cli


@pytest.fixture
def clients(monkeypatch):
    comanage = AsyncMock()
    comanage.get_access_id_for_email.return_value = "ada"
    comanage.get_user_info.return_value = make_user(
        with_external=True,
        SshKey=[
            {
                "skey": "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE",
                "type": "ssh-ed25519",
                "comment": "laptop",
                "meta": {"id": 55, "created": "2026-01-02 03:04:05", "deleted": False},
            }
        ],
    )
    comanage.get_tandc_agreements.return_value = TANDC

    identity = AsyncMock()
    identity.get_person.return_value = make_person(
        academicDegrees=[{"degreeId": 1, "degreeField": "Mathematics"}]
    )
    identity.get_site_logins.return_value = [
        {
            "organizationId": 848,
            "organizationName": "Pittsburgh Supercomputing Center",
            "logins": [
                {
                    "resourceName": "bridges2-rm.psc.xsede.org",
                    "displayName": "Bridges-2",
                    "rdrResourceId": None,
                    "ciderResourceId": "bridges2-rm.psc.access-ci.org",
                    "username": "ada2",
                },
                {
                    "resourceName": "portal.teragrid",
                    "displayName": None,
                    "rdrResourceId": None,
                    "ciderResourceId": "portal.teragrid",
                    "username": "ada",
                },
            ],
        },
        {
            "organizationId": 1,
            "organizationName": "ACCESS",
            "logins": [
                {
                    "resourceName": "portal.teragrid",
                    "displayName": None,
                    "rdrResourceId": None,
                    "ciderResourceId": "portal.teragrid",
                    "username": "ada",
                }
            ],
        },
    ]
    identity.get_organization.return_value = {"organization_name": "Example U"}
    identity.get_academic_statuses.return_value = [
        {"nsfStatusCodeId": 3, "nsfStatusCodeName": "Faculty"}
    ]
    identity.get_countries.return_value = [
        {"countryId": 210, "countryName": "United States"}
    ]
    identity.get_degrees.return_value = [{"degreeId": 1, "description": "Ph.D."}]

    monkeypatch.setattr(cli, "comanage_client", comanage)
    monkeypatch.setattr(cli, "identity_client", identity)
    return comanage, identity


def run(*args):
    return CliRunner().invoke(cli.cli, ["account", *args])


def test_account_by_access_id(clients):
    comanage, _ = clients
    result = run("ada")
    assert result.exit_code == 0, result.output
    comanage.get_access_id_for_email.assert_not_called()
    comanage.get_user_info.assert_awaited_once_with("ada", include_inactive=True)
    comanage.get_tandc_agreements.assert_not_called()

    out = result.output
    assert "ACCESS ID:" in out and "ada" in out
    assert "Lovelace" in out
    assert "Example U (7)" in out
    assert "Faculty (3)" in out
    assert "United States (210)" in out
    assert "Ph.D. (1): Mathematics" in out
    assert "SHA256:" in out and "laptop" in out
    assert "Bridges-2: ada2" in out
    assert "Pittsburgh Supercomputing Center" in out
    assert "  ACCESS\n" not in out
    assert "portal" not in out.split("Resource Usernames")[1].split("Linked")[0]
    assert "ada@access-ci.org [login]" in out
    assert "Example University" in out
    assert "Verification" not in out


def test_account_by_email(clients):
    comanage, _ = clients
    result = run(" Ada@Example.edu")
    assert result.exit_code == 0, result.output
    comanage.get_access_id_for_email.assert_awaited_once_with("ada@example.edu")
    comanage.get_user_info.assert_awaited_once_with("ada", include_inactive=True)


def test_unknown_email(clients):
    comanage, _ = clients
    comanage.get_access_id_for_email.return_value = None
    result = run("nobody@example.edu")
    assert result.exit_code == 1
    assert "No active CoPerson found with email nobody@example.edu" in result.output


def test_comanage_error_is_reported(clients):
    comanage, _ = clients
    comanage.get_user_info.side_effect = HTTPException(
        404, "Could not find a user with ACCESS ID: ada"
    )
    result = run("ada")
    assert result.exit_code == 1
    assert "Error: Could not find a user with ACCESS ID: ada" in result.output


def test_missing_identity_person(clients):
    _, identity = clients
    identity.get_person.side_effect = HTTPException(404, "not found")
    identity.get_site_logins.side_effect = HTTPException(404, "not found")
    result = run("ada", "--verify")
    assert result.exit_code == 1
    assert "No Identity Service person record" in result.output
    assert "Identity Service has a person record " in result.output
    assert "FAILED" in result.output and "SKIPPED" in result.output
    identity.get_organization.assert_not_called()


def test_verify_passes(clients):
    comanage, _ = clients
    result = run("ada", "--verify")
    assert result.exit_code == 0, result.output
    comanage.get_tandc_agreements.assert_awaited_once_with(123)
    out = result.output
    assert "matches registered with an existing identity ." in out
    assert "PASSED" in out
    assert "FAILED" not in out and "WARNING" not in out
    summary = out.rstrip().splitlines()[-1]
    assert summary.startswith("=") and " passed " in summary
    assert "failed" not in summary


def test_verify_fails(clients):
    comanage, _ = clients
    comanage.get_tandc_agreements.return_value = []
    result = run("ada", "--verify")
    assert result.exit_code == 1
    out = result.output
    tandc_line = next(
        line for line in out.splitlines() if "Terms and Conditions" in line
    )
    assert tandc_line.endswith("FAILED")
    assert "matches a registration pattern" in out
    summary = out.rstrip().splitlines()[-1]
    assert " 2 failed, " in summary and " passed " in summary
