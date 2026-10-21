"""API tests for POST /email/callback, which logs SES delivery events relayed by
SNS, and for the configuration set that routes those events to it.

Messages are signed with a throwaway RSA key whose self-signed certificate is
served from a mocked SNS SigningCertURL, so the real verification path runs.
"""

import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from config import AWS_SNS_TOPIC_ARN
from services import email_service

BASE = "/api/v1"
URL = f"{BASE}/email/callback"
CERT_URL = "https://sns.us-east-2.amazonaws.com/SimpleNotificationService-test.pem"
SUBSCRIBE_URL = (
    "https://sns.us-east-2.amazonaws.com/?Action=ConfirmSubscription"
    f"&TopicArn={AWS_SNS_TOPIC_ARN}&Token=secret-token"
)

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.test")])
_CERT_PEM = (
    x509.CertificateBuilder()
    .subject_name(_NAME)
    .issuer_name(_NAME)
    .public_key(_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(UTC) - timedelta(days=1))
    .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    .sign(_KEY, hashes.SHA256())
    .public_bytes(serialization.Encoding.PEM)
)


@pytest.fixture(autouse=True)
def signing_cert(respx_mock, monkeypatch):
    """Serve the test certificate, with an empty cert cache for each test."""
    monkeypatch.setattr(email_service, "_signing_certs", {})
    return respx_mock.get(CERT_URL).respond(200, content=_CERT_PEM)


@pytest.fixture
def email_records(caplog):
    caplog.set_level(logging.INFO, logger=email_service.logger.name)

    def _records() -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == email_service.logger.name]

    return _records


def _sign(message: dict, version: str = "2") -> dict:
    message = {
        "MessageId": "sns-msg-1",
        "Timestamp": "2026-10-20T12:00:00.000Z",
        "TopicArn": AWS_SNS_TOPIC_ARN,
        "SignatureVersion": version,
        "SigningCertURL": CERT_URL,
        **message,
    }
    fields = email_service._SNS_SIGNED_FIELDS[message["Type"]]
    string_to_sign = "".join(
        f"{name}\n{message[name]}\n" for name in fields if name in message
    )
    hash_type = hashes.SHA1() if version == "1" else hashes.SHA256()
    signature = _KEY.sign(string_to_sign.encode(), padding.PKCS1v15(), hash_type)
    return {**message, "Signature": base64.b64encode(signature).decode()}


def _post(client, message: dict):
    # SNS posts JSON with a text/plain content type.
    return client.post(
        URL,
        content=json.dumps(message),
        headers={"Content-Type": "text/plain; charset=UTF-8"},
    )


def _notification(event: dict, **extra) -> dict:
    return {"Type": "Notification", "Message": json.dumps(event), **extra}


def _subscription_confirmation(subscribe_url: str = SUBSCRIBE_URL) -> dict:
    return {
        "Type": "SubscriptionConfirmation",
        "Message": "You have chosen to subscribe to the topic.",
        "SubscribeURL": subscribe_url,
        "Token": "secret-token",
    }


DELIVERY = {
    "eventType": "Delivery",
    "mail": {"messageId": "msg-123", "destination": ["jdoe@example.org"]},
    "delivery": {"recipients": ["jdoe@example.org"], "smtpResponse": "250 2.0.0 OK"},
}


def test_delivery_event_logs_message_id_and_status(client, email_records):
    resp = _post(client, _sign(_notification(DELIVERY)))

    assert resp.status_code == 200
    [record] = email_records()
    assert record.levelno == logging.INFO
    message = record.getMessage()
    assert "SES Delivery for Message ID: msg-123" in message
    assert "smtp_response=250 2.0.0 OK" in message
    assert "jdoe@example.org" not in message


def test_bounce_event_logs_warning_with_diagnostics(client, email_records):
    event = {
        "notificationType": "Bounce",
        "mail": {"messageId": "msg-456"},
        "bounce": {
            "bounceType": "Permanent",
            "bounceSubType": "General",
            "bouncedRecipients": [
                {
                    "emailAddress": "jdoe@example.org",
                    "status": "5.1.1",
                    "diagnosticCode": "smtp; 550 jdoe@example.org unknown",
                }
            ],
        },
    }

    resp = _post(client, _sign(_notification(event)))

    assert resp.status_code == 200
    [record] = email_records()
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert "SES Bounce for Message ID: msg-456" in message
    assert "bounce_type=Permanent/General" in message
    assert "5.1.1" in message
    assert "jdoe@example.org" not in message


@pytest.mark.parametrize("version", ["1", "2"])
def test_accepts_both_signature_versions_with_subject(client, version):
    message = _sign(_notification(DELIVERY, Subject="Amazon SES Email Event"), version)
    assert _post(client, message).status_code == 200


def test_signing_cert_is_cached(client, signing_cert):
    _post(client, _sign(_notification(DELIVERY)))
    _post(client, _sign(_notification(DELIVERY)))
    assert signing_cert.call_count == 1


def test_rejects_unexpected_topic(client, signing_cert, email_records):
    message = _sign(_notification(DELIVERY, TopicArn="arn:aws:sns:x:1:other"))

    resp = _post(client, message)

    assert resp.status_code == 403
    assert email_records() == []
    assert not signing_cert.called


def test_rejects_tampered_message(client, email_records):
    message = _sign(_notification(DELIVERY))
    message["Message"] = json.dumps({**DELIVERY, "mail": {"messageId": "forged"}})

    resp = _post(client, message)

    assert resp.status_code == 403
    assert email_records() == []


@pytest.mark.parametrize(
    "changes",
    [
        {"Signature": "not base64!"},
        {"SignatureVersion": "3"},
        {"SigningCertURL": "https://evil.example.com/cert.pem"},
        {"SigningCertURL": "http://sns.us-east-2.amazonaws.com/cert.pem"},
        {"Type": "Bogus"},
    ],
)
def test_rejects_invalid_signature_fields(client, respx_mock, email_records, changes):
    evil = respx_mock.get("https://evil.example.com/cert.pem").respond(
        200, content=_CERT_PEM
    )

    resp = _post(client, {**_sign(_notification(DELIVERY)), **changes})

    assert resp.status_code == 403
    assert email_records() == []
    assert not evil.called


def test_rejects_when_cert_cannot_be_fetched(client, signing_cert):
    signing_cert.mock(side_effect=httpx.ConnectError("refused"))
    assert _post(client, _sign(_notification(DELIVERY))).status_code == 403


@pytest.mark.parametrize("body", ["not json", "[]"])
def test_rejects_malformed_bodies(client, body):
    assert client.post(URL, content=body).status_code == 400


def test_rejects_notification_with_malformed_event(client):
    message = _sign({"Type": "Notification", "Message": "not json"})
    assert _post(client, message).status_code == 400


def test_subscription_confirmation_visits_subscribe_url(client, respx_mock):
    route = respx_mock.get(SUBSCRIBE_URL).respond(200, text="<ok/>")

    resp = _post(client, _sign(_subscription_confirmation()))

    assert resp.status_code == 200
    assert route.called


def test_subscription_confirmation_refuses_non_sns_url(client, respx_mock):
    route = respx_mock.get("https://evil.example.com/").respond(200)

    message = _sign(_subscription_confirmation("https://evil.example.com/"))
    resp = _post(client, message)

    assert resp.status_code == 400
    assert not route.called


def test_subscription_confirmation_failure_returns_400(client, respx_mock):
    respx_mock.get(SUBSCRIBE_URL).mock(side_effect=httpx.ConnectError("refused"))

    resp = _post(client, _sign(_subscription_confirmation()))

    assert resp.status_code == 400


@pytest.mark.parametrize("configuration_set", ["test-configuration-set", ""])
def test_send_uses_configuration_set_when_configured(monkeypatch, configuration_set):
    send_email = MagicMock(return_value={"MessageId": "msg-123"})
    monkeypatch.setattr(email_service.ses, "send_email", send_email)
    monkeypatch.setattr(email_service, "AWS_SES_CONFIGURATION_SET", configuration_set)

    email_service.send_verification_email("jdoe@example.org", "123456")

    kwargs = send_email.call_args.kwargs
    if configuration_set:
        assert kwargs["ConfigurationSetName"] == configuration_set
    else:
        assert "ConfigurationSetName" not in kwargs
