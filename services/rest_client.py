import httpx
from fastapi import HTTPException


class RestClient:
    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        propagate_errors: bool = False,
        timeout: float = 2.0,
    ):
        self.username = username
        self.password = password
        self.propagate_errors = propagate_errors
        self.timeout = timeout

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict = {},
        json: dict | None = None,
        data: dict | None = None,
        params: dict | list | None = None,
    ):
        client_kwargs = {}
        if self.username and self.password:
            client_kwargs["auth"] = httpx.BasicAuth(
                username=self.username, password=str(self.password)
            )

        request_headers = {"Accept": "application/json"}
        request_headers.update(headers)

        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                response = await client.request(
                    method,
                    url,
                    data=data,
                    headers=request_headers,
                    json=json,
                    params=params,
                    timeout=self.timeout,
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if self.propagate_errors:
                    # Map the external error to a FastAPI HTTPException
                    raise HTTPException(
                        status_code=exc.response.status_code,
                        detail=f"{self.__class__.__name__} API error: {exc.response.text}",
                    )
                else:
                    raise exc
            except httpx.RequestError as exc:
                if self.propagate_errors:
                    # Handle connection or timeout issues
                    raise HTTPException(
                        status_code=503,
                        detail=f"{self.__class__.__name__} API is unavailable: {exc}",
                    )
                else:
                    raise exc

            return response.json() if response.content else None
