from asyncio import gather

from fastapi import HTTPException
from httpx import HTTPStatusError

from services.comanage_registry_client import CoManageRegistryClient
from services.identity_client import IdentityServiceClient
from services.logs_service import logger

comanage_client = CoManageRegistryClient()
identity_client = IdentityServiceClient()


def safe_get(d: dict, *keys, default=None):
    """Safely get a nested value from a dictionary."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


async def get_account_data(username: str):
    comanage_task = comanage_client.get_user_info(username)
    identity_task = identity_client.get_account(username)

    comanage_res, identity_res = await gather(
        comanage_task, identity_task, return_exceptions=True
    )

    # Identify which upstream failed
    if isinstance(comanage_res, HTTPStatusError):
        # log who failed + status + body
        logger.error(
            "CoManage failed: user=%s status=%s body=%s",
            username,
            comanage_res.response.status_code,
            comanage_res.response.text,
        )
        raise HTTPException(
            status_code=comanage_res.response.status_code,
            detail={"source": "comanage", "error": comanage_res.response.text},
        )

    if isinstance(identity_res, HTTPStatusError):
        logger.error(
            "Identity service failed: user=%s status=%s body=%s",
            username,
            identity_res.response.status_code,
            identity_res.response.text,
        )
        raise HTTPException(
            status_code=identity_res.response.status_code,
            detail={"source": "identity", "error": identity_res.response.text},
        )

    # If you also want to catch network errors (timeouts, DNS, etc):
    if isinstance(comanage_res, Exception):
        logger.exception("CoManage exception for user=%s", username)
        raise HTTPException(
            502, detail={"source": "comanage", "error": str(comanage_res)}
        )

    if isinstance(identity_res, Exception):
        logger.exception("Identity exception for user=%s", username)
        raise HTTPException(
            502, detail={"source": "identity", "error": str(identity_res)}
        )

    return [comanage_res, identity_res]
