"""Tests for SlackReporter (services/slack_reporter.py) and IP masking."""

import json
import logging

import httpx
import pytest

from services import slack_reporter as slack_reporter_module
from services.logs_service import mask_ip
from services.slack_reporter import SlackReporter

WEBHOOK = "https://hooks.slack.test/services/T000/B000/secret"


# --- mask_ip ----------------------------------------------------------------
@pytest.mark.parametrize(
    "host,expected",
    [
        ("144.80.66.87", "144.*.*.87"),
        ("8.8.4.4", "8.*.*.4"),
        ("::ffff:144.80.66.87", "144.*.*.87"),
        ("2607:f8b0:4004:0c07:0000:0000:0000:1a2b", "2607:*:1a2b"),
        ("2001:db8::1", "2001:*:1"),
        ("testclient", "te*****ent"),
        (None, "-"),
    ],
)
def test_mask_ip(host, expected):
    assert mask_ip(host) == expected


# --- SlackReporter ----------------------------------------------------------
def posted_texts(route) -> list[str]:
    return [json.loads(call.request.content)["text"] for call in route.calls]


async def test_disabled_without_a_webhook(respx_mock):
    reporter = SlackReporter("", reports_per_minute=10)
    reporter.report("hello")
    await reporter.drain()
    assert not respx_mock.calls


async def test_posts_report_with_slack_markup_escaped(respx_mock):
    route = respx_mock.post(WEBHOOK).respond(200, text="ok")
    reporter = SlackReporter(WEBHOOK, reports_per_minute=10)

    reporter.report("400 <script> & more")
    await reporter.drain()

    assert posted_texts(route) == ["400 &lt;script&gt; &amp; more"]


async def test_reports_over_the_limit_are_summarized(respx_mock, monkeypatch):
    monkeypatch.setattr(slack_reporter_module, "WINDOW_SECONDS", 0.05)
    route = respx_mock.post(WEBHOOK).respond(200, text="ok")
    reporter = SlackReporter(WEBHOOK, reports_per_minute=2)

    for n in range(5):
        reporter.report(f"error {n}")
    await reporter.drain()

    texts = posted_texts(route)
    assert texts[:2] == ["error 0", "error 1"]
    assert len(texts) == 3
    assert texts[2].startswith("3 more errors weren't posted here")


@pytest.mark.parametrize(
    "response",
    [httpx.Response(404, text="no_service"), httpx.ConnectError("refused")],
)
async def test_failed_post_is_logged_without_the_webhook_url(
    respx_mock, caplog, response
):
    route = respx_mock.post(WEBHOOK)
    if isinstance(response, Exception):
        route.mock(side_effect=response)
    else:
        route.mock(return_value=response)
    reporter = SlackReporter(WEBHOOK, reports_per_minute=10)

    with caplog.at_level(logging.WARNING, logger="access_account_api"):
        reporter.report("error")
        await reporter.drain()

    messages = [r.getMessage() for r in caplog.records]
    assert any("Slack" in m for m in messages)
    assert not any("secret" in m for m in messages)
