from asyncio import gather

from models import ResourceUsernameOrganization
from services.comanage_registry_client import CoManageRegistryClient, CoManageUser
from services.identity_client import (
    ACCESS_PORTAL_CIDER_RESOURCE_ID,
    IdentityServiceClient,
)

comanage_client = CoManageRegistryClient(propagate_errors=True)
identity_client = IdentityServiceClient(propagate_errors=True)


def safe_get(d: dict, *keys, default=None):
    """Safely get a nested value from a dictionary."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


async def get_account_data(username: str) -> tuple[CoManageUser, dict]:
    return await gather(
        comanage_client.get_user_info(username),
        identity_client.get_account(username),
    )


def visible_resource_usernames(
    site_logins: list[dict],
) -> list[ResourceUsernameOrganization]:
    """Parse Identity Service site logins into the organizations users see.

    Leaves out the ACCESS portal login, and any organization left with no logins.
    """
    organizations = []
    for org in site_logins:
        organization = ResourceUsernameOrganization.model_validate(org)
        organization.logins = [
            login
            for login in organization.logins
            if login.cider_resource_id != ACCESS_PORTAL_CIDER_RESOURCE_ID
        ]
        if organization.logins:
            organizations.append(organization)
    return organizations
