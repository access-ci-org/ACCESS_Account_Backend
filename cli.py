"""Command line client for looking up and checking ACCESS accounts.

Reads the same configuration as the API (`.env`, or the file named by
APP_CONFIG), so run it from this directory:

    uv run cli.py account <ACCESS ID or email> [--verify]
"""

import asyncio
from asyncio import gather

import click
from fastapi import HTTPException, status

from services.account_service import (
    comanage_client,
    identity_client,
    safe_get,
    visible_resource_usernames,
)
from services.account_verification import (
    Status,
    VerificationResult,
    verify_account,
)
from services.comanage_registry_client import CoManageUser
from services.ssh_key_service import calculate_ssh_fingerprint_sha256


@click.group()
def cli():
    """Look up and check ACCESS accounts."""


async def _none_if_not_found(coroutine, default=None):
    try:
        return await coroutine
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return default
        raise


async def resolve_access_id(user: str) -> str:
    """Return the ACCESS ID for an ACCESS ID or email address."""
    if "@" not in user:
        return user
    access_id = await comanage_client.get_access_id_for_email(user.strip().lower())
    if not access_id:
        raise click.ClickException(f"No active CoPerson found with email {user}")
    return access_id


async def fetch_account(access_id: str, verify: bool) -> dict:
    """Fetch everything the Profile, SSH Keys and Linked Identities pages show."""
    comanage_user, identity_person, site_logins = await gather(
        comanage_client.get_user_info(access_id, include_inactive=True),
        _none_if_not_found(identity_client.get_person(access_id)),
        _none_if_not_found(identity_client.get_site_logins(access_id), default=[]),
    )

    (
        academic_statuses,
        countries,
        degrees,
        organization,
        tandc_agreements,
    ) = await gather(
        identity_client.get_academic_statuses(),
        identity_client.get_countries(),
        identity_client.get_degrees(),
        _none_if_not_found(
            identity_client.get_organization(identity_person["organizationId"])
        )
        if identity_person and identity_person.get("organizationId")
        else asyncio.sleep(0),
        comanage_client.get_tandc_agreements(comanage_user["CoPerson"]["meta"]["id"])
        if verify
        else asyncio.sleep(0, result=[]),
    )

    return {
        "comanage_user": comanage_user,
        "identity_person": identity_person,
        "site_logins": site_logins,
        "organization": organization,
        "tandc_agreements": tandc_agreements,
        "academic_statuses": {
            s["nsfStatusCodeId"]: s["nsfStatusCodeName"] for s in academic_statuses
        },
        "countries": {c["countryId"]: c["countryName"] for c in countries},
        "degrees": {d["degreeId"]: d["description"] for d in degrees},
    }


def _heading(text: str):
    click.echo()
    click.secho(text, bold=True)
    click.secho("=" * len(text), bold=True)


def _subheading(text: str):
    click.echo()
    click.secho(text, bold=True)


def _field(label: str, value):
    if value is None or value == "" or value == []:
        value = click.style("(none)", dim=True)
    click.echo(f"  {label + ':':<28} {value}")


def _lookup(names: dict, value_id):
    if value_id is None:
        return None
    return f"{names.get(value_id, 'Unknown')} ({value_id})"


def print_profile(access_id: str, data: dict):
    comanage_user: CoManageUser = data["comanage_user"]
    person = data["identity_person"] or {}
    primary_name = comanage_user.get_primary_name() or {}
    co_person_status = safe_get(comanage_user, "CoPerson", "status")

    _heading("Profile")
    _field("ACCESS ID", access_id)
    if co_person_status != "A":
        _field("CoPerson status", click.style(str(co_person_status), fg="red"))
    if data["identity_person"] is None:
        click.secho("  No Identity Service person record", fg="red")
    _field("First Name", primary_name.get("given"))
    _field("Last Name", primary_name.get("family"))
    _field("Primary Email", comanage_user.get_primary_email())
    _field(
        "Recovery Emails",
        ", ".join(e["mail"] for e in comanage_user.get_recovery_emails()),
    )

    organization_id = person.get("organizationId")
    organization = data["organization"]
    _field(
        "Institution",
        f"{organization.get('organization_name', 'Unknown')} ({organization_id})"
        if organization
        else _lookup({}, organization_id),
    )
    _field("Department", person.get("department"))
    _field(
        "Academic Status",
        _lookup(data["academic_statuses"], person.get("nsfStatusCodeId")),
    )
    _field("Country of Residence", _lookup(data["countries"], person.get("countryId")))
    _field(
        "Country of Citizenship",
        ", ".join(
            _lookup(data["countries"], c.get("countryId"))
            for c in person.get("citizenships") or []
        ),
    )
    _field(
        "Degrees",
        "; ".join(
            f"{_lookup(data['degrees'], d.get('degreeId'))}: {d.get('degreeField')}"
            for d in person.get("academicDegrees") or []
        ),
    )
    _field("Time Zone", safe_get(comanage_user, "CoPerson", "timezone"))


def print_ssh_keys(data: dict):
    comanage_user: CoManageUser = data["comanage_user"]

    _heading("SSH Keys and Resource Usernames")
    _subheading("SSH Keys")
    ssh_keys = [
        k
        for k in comanage_user.get("SshKey", [])
        if not k.get("meta", {}).get("deleted")
    ]
    if not ssh_keys:
        click.echo("  No SSH keys added yet.")
    for key in ssh_keys:
        click.echo(
            f"  {calculate_ssh_fingerprint_sha256(key.get('skey'))}  "
            f"{key.get('type')}  {key.get('comment') or ''}".rstrip()
        )
        click.echo(
            f"    Added on {key['meta'].get('created')} (key ID {key['meta']['id']})"
        )

    _subheading("Resource Usernames")
    organizations = visible_resource_usernames(data["site_logins"])
    if not organizations:
        click.echo("  No resource usernames.")
    for organization in organizations:
        click.echo(f"  {organization.organization_name}")
        for login in organization.logins:
            resource = login.display_name or login.resource_name
            click.echo(f"    {resource}: {login.username}")


def print_linked_identities(data: dict):
    comanage_user: CoManageUser = data["comanage_user"]

    _heading("Linked Identities")
    org_identities = [
        o
        for o in comanage_user.get("OrgIdentity", [])
        if not o.get("meta", {}).get("deleted")
    ]
    if not org_identities:
        click.echo("  No accounts linked yet.")
    for org_identity in org_identities:
        identifiers = sorted(
            (
                i
                for i in org_identity.get("Identifier") or []
                if not i.get("meta", {}).get("deleted")
            ),
            key=lambda i: i.get("type") or "",
        )
        title = org_identity.get("o") or (
            identifiers[0].get("identifier") if identifiers else "(no identifiers)"
        )
        login = (
            "Used for login"
            if any(i.get("login") for i in identifiers)
            else "Not used for login"
        )
        click.echo()
        click.echo(
            f"  {click.style(title, bold=True)}  "
            f"(OrgIdentity {org_identity['meta']['id']}, {login})"
        )
        for identifier in identifiers:
            login_flag = " [login]" if identifier.get("login") else ""
            click.echo(
                f"    {identifier.get('type')}: {identifier.get('identifier')}"
                f"{login_flag}"
            )


STATUS_COLORS = {
    Status.PASSED: "green",
    Status.FAILED: "red",
    Status.WARNING: "yellow",
    Status.SKIPPED: "bright_black",
}

# Width of a check line, from the indent to the end of the status.
CHECK_LINE_WIDTH = 79


def print_verification(result: VerificationResult):
    _heading("Verification")
    section = None
    for check in result.checks:
        if check.section != section:
            section = check.section
            _subheading(section)
        status = str(check.status)
        dots = "." * max(3, CHECK_LINE_WIDTH - len(check.name) - len(status) - 4)
        click.echo(
            f"  {check.name} {dots} "
            + click.style(status, fg=STATUS_COLORS[check.status], bold=True)
        )
        if check.detail:
            click.secho(f"      {check.detail}", fg=STATUS_COLORS[check.status])

    # Summarize the way pytest does, worst outcome first.
    counts = [
        (len(result.with_status(status)), status)
        for status in (Status.FAILED, Status.PASSED, Status.WARNING, Status.SKIPPED)
    ]
    summary = ", ".join(
        f"{count} {status.lower()}"
        + ("s" if status == Status.WARNING and count > 1 else "")
        for count, status in counts
        if count
    )
    color = next(
        (
            STATUS_COLORS[status]
            for count, status in counts
            if count and status in (Status.FAILED, Status.WARNING)
        ),
        "green",
    )
    click.echo()
    click.secho(f" {summary} ".center(CHECK_LINE_WIDTH + 2, "="), fg=color, bold=True)


@cli.command()
@click.argument("user")
@click.option(
    "--verify",
    is_flag=True,
    help="Check that the records are complete and that the CoManage records "
    "match a registration pattern. Exits with status 1 if any check fails.",
)
def account(user: str, verify: bool):
    """Show the account for USER, an ACCESS ID or email address."""

    async def run():
        access_id = await resolve_access_id(user)
        return access_id, await fetch_account(access_id, verify)

    try:
        access_id, data = asyncio.run(run())
    except HTTPException as exc:
        raise click.ClickException(str(exc.detail)) from exc

    print_profile(access_id, data)
    print_ssh_keys(data)
    print_linked_identities(data)

    if verify:
        result = verify_account(
            data["comanage_user"], data["identity_person"], data["tandc_agreements"]
        )
        print_verification(result)
        if result.failed:
            raise SystemExit(1)


if __name__ == "__main__":
    cli()
