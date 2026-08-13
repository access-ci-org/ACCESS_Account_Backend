import ssl
import time
from typing import TypeVar

import httpx
from fastapi import HTTPException

from services.logs_service import record_backend_call

_JsonShapeT = TypeVar("_JsonShapeT", dict, list)


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
        headers: dict | None = None,
        json: dict | None = None,
        data: dict | None = None,
        params: dict | list | None = None,
    ) -> dict | list | None:
        if headers is None:
            headers = {}
        client_kwargs = {}
        if self.username and self.password:
            client_kwargs["auth"] = httpx.BasicAuth(
                username=self.username, password=str(self.password)
            )

        request_headers = {"Accept": "application/json"}
        request_headers.update(headers)

        async with httpx.AsyncClient(**client_kwargs) as client:
            # Every backend call the app makes funnels through here, so this is
            # where they get timed and attached to the request that triggered
            # them. `record_backend_call` no-ops outside a request context.
            started = time.perf_counter()
            logged_url = url
            outcome: int | str = "ERR"
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
                # Log the URL httpx actually built, so `params` show up too.
                logged_url = str(response.request.url)
                outcome = response.status_code
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if self.propagate_errors:
                    # Map the external error to a FastAPI HTTPException
                    raise HTTPException(
                        status_code=exc.response.status_code,
                        detail=f"{self.__class__.__name__} API error: {exc.response.text}",
                    )
                else:
                    raise
            except (httpx.RequestError, ssl.SSLError) as exc:
                # Handle connection or timeout issues.
                # Python 3.13 raises ssl.SSLError("passed invalid argument") when the
                # remote closes the connection mid-read, rather than the SSLEOFError /
                # ConnectionResetError that older Pythons raise (which httpx wraps into
                # httpx.ReadError). Catch it here so it surfaces as a clean 503 instead
                # of propagating as an unhandled exception.
                outcome = type(exc).__name__
                if self.propagate_errors:
                    raise HTTPException(
                        status_code=503,
                        detail=f"{self.__class__.__name__} API is unavailable",
                    )
                else:
                    raise
            finally:
                record_backend_call(
                    method,
                    logged_url,
                    outcome,
                    (time.perf_counter() - started) * 1000,
                )

            return response.json() if response.content else None

    async def request_status(
        self, url: str, method: str = "GET", headers: dict | None = None
    ) -> int:
        """Make a lightweight request and return the raw HTTP status code.

        Used for connectivity health checks: unlike `request()`, this always
        returns the status code -- even for a 4xx/5xx response -- instead of
        raising or parsing a JSON body, since getting any response at all is
        what a health check cares about.
        """
        if headers is None:
            headers = {}
        client_kwargs = {}
        if self.username and self.password:
            client_kwargs["auth"] = httpx.BasicAuth(
                username=self.username, password=str(self.password)
            )

        request_headers = {"Accept": "application/json"}
        request_headers.update(headers)

        async with httpx.AsyncClient(**client_kwargs) as client:
            started = time.perf_counter()
            outcome: int | str = "ERR"
            try:
                response = await client.request(
                    method, url, headers=request_headers, timeout=self.timeout
                )
                outcome = response.status_code
            except (httpx.RequestError, ssl.SSLError) as exc:
                outcome = type(exc).__name__
                raise
            finally:
                record_backend_call(
                    method, url, outcome, (time.perf_counter() - started) * 1000
                )
            return response.status_code

    def _expect(
        self,
        result: dict | list | None,
        expected: type[_JsonShapeT],
        status_code: int = 502,
    ) -> _JsonShapeT:
        """Narrow a JSON response to the shape a caller requires, or raise.

        Different endpoints on the same API can legitimately return different
        top-level JSON shapes (e.g. a bare list for collection endpoints vs. a
        dict for single-resource endpoints), so `request()` itself stays
        shape-agnostic. Callers that need a specific shape use this to assert
        it, choosing the HTTP status code that fits their situation.
        """
        if not isinstance(result, expected):
            raise HTTPException(
                status_code=status_code,
                detail=f"Unexpected response from {self.__class__.__name__}",
            )
        return result
