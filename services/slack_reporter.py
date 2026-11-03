import asyncio
import logging
import time
from collections import deque
from collections.abc import Coroutine

import httpx

from config import SLACK_ERROR_REPORTS_PER_MINUTE, SLACK_ERROR_WEBHOOK_URL

logger = logging.getLogger("access_account_api")

POST_TIMEOUT_SECONDS = 5
WINDOW_SECONDS = 60


def escape_slack_text(text: str) -> str:
    """Escape the characters Slack treats as markup, even inside code blocks."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackReporter:
    """Post error reports to a Slack incoming webhook in the background.

    `report()` never waits on Slack, so reporting can't slow down or fail the
    request being reported. Each worker process posts at most
    `reports_per_minute` reports; the rest are counted and summarized once
    there's room again.
    """

    def __init__(self, webhook_url: str, reports_per_minute: int):
        self.webhook_url: str = webhook_url
        self.reports_per_minute: int = reports_per_minute
        self._sent_at: deque[float] = deque()
        self._suppressed: int = 0
        self._summary_scheduled: bool = False
        # Keep a reference to each task until it finishes: the event loop only
        # holds weak references, so an unreferenced task can be collected
        # mid-post.
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def report(self, text: str) -> None:
        """Queue a report. Must be called from inside the event loop."""
        if not self.enabled:
            return

        if not self._has_room():
            self._suppressed += 1
            if not self._summary_scheduled:
                self._summary_scheduled = True
                self._spawn(self._post_summary_when_room())
            return

        self._send(self._take_summary() + text)

    async def drain(self) -> None:
        """Wait for every queued post to finish."""
        while self._tasks:
            _ = await asyncio.gather(*self._tasks)

    def _has_room(self) -> bool:
        now = time.monotonic()
        while self._sent_at and now - self._sent_at[0] >= WINDOW_SECONDS:
            _ = self._sent_at.popleft()
        return len(self._sent_at) < self.reports_per_minute

    def _take_summary(self) -> str:
        if not self._suppressed:
            return ""
        count, self._suppressed = self._suppressed, 0
        errors = "error wasn't" if count == 1 else "errors weren't"
        return (
            f"{count} more {errors} posted here "
            f"(limit {self.reports_per_minute} a minute per worker); "
            "see the API log.\n"
        )

    async def _post_summary_when_room(self) -> None:
        if self._sent_at:
            wait = WINDOW_SECONDS - (time.monotonic() - self._sent_at[0])
            await asyncio.sleep(max(wait, 0))
        self._summary_scheduled = False
        # A report sent in the meantime may already have carried the summary.
        summary = self._take_summary()
        if summary:
            self._send(summary.rstrip())

    def _send(self, text: str) -> None:
        self._sent_at.append(time.monotonic())
        self._spawn(self._post(text))

    def _spawn(self, coroutine: Coroutine[object, None, None]) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _post(self, text: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=POST_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self.webhook_url, json={"text": escape_slack_text(text)}
                )
                _ = response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # httpx's messages can include the webhook URL, which is a secret,
            # so log only the status or the exception type.
            logger.warning(
                f"Slack rejected an error report: {exc.response.status_code}"
            )
        except httpx.HTTPError as exc:
            logger.warning(
                f"Could not post an error report to Slack: {type(exc).__name__}"
            )


slack_reporter = SlackReporter(
    str(SLACK_ERROR_WEBHOOK_URL), SLACK_ERROR_REPORTS_PER_MINUTE
)
