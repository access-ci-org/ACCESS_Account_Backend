from asyncio import gather

from services.comanage_registry_client import CoManageRegistryClient
from services.identity_client import IdentityServiceClient

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


async def get_account_data(username: str):
    return list(await gather(
        comanage_client.get_user_info(username),
        identity_client.get_account(username),
    ))
