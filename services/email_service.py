import asyncio
import base64
import binascii
import logging
import re
import time
from urllib.parse import urlsplit

import boto3
import httpx
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import (
    AWS_ACCESS_KEY,
    AWS_REGION,
    AWS_SECRET_ACCESS_KEY,
    AWS_SES_CONFIGURATION_SET,
    AWS_SES_SENDER_EMAIL,
    OTP_LIFETIME_MINUTES,
)
from services.logs_service import (
    obfuscate_email,
    obfuscate_emails_in_text,
    record_backend_call,
    record_exception,
)

logger = logging.getLogger("access_account_api.email")

# Set up Jinja env
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

template = env.get_template("email_verification_code.html.jinja")

ses = boto3.client(
    "ses",
    region_name=AWS_REGION,
    aws_access_key_id=str(AWS_ACCESS_KEY),
    aws_secret_access_key=str(AWS_SECRET_ACCESS_KEY),
)


async def ping() -> int:
    """Make a free, read-only SES request and return the HTTP status code."""
    response = await asyncio.to_thread(ses.get_send_quota)
    return response["ResponseMetadata"]["HTTPStatusCode"]


def send_verification_email(email, otp):
    # Render Jinja email template

    html_body = template.render(otp=otp, lifetime=OTP_LIFETIME_MINUTES)

    text_body = f"Your ACCESS verification code is: {otp}. This code expires in {OTP_LIFETIME_MINUTES} minutes."
    # Tagging the send with a configuration set is what routes its delivery
    # events through SNS to the /email/callback route.
    extra_args = (
        {"ConfigurationSetName": AWS_SES_CONFIGURATION_SET}
        if AWS_SES_CONFIGURATION_SET
        else {}
    )
    try:
        resp = ses.send_email(
            Source=AWS_SES_SENDER_EMAIL,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": "Your ACCESS Email Verification Code"},
                "Body": {
                    "Html": {"Data": html_body},
                    "Text": {"Data": text_body},
                },
            },
            **extra_args,
        )

        # print("SES Message ID:", resp.get("MessageId")) For testing purposes
        return resp
    except ClientError:
        record_exception(
            f"SES ClientError when sending verification email to {obfuscate_email(email)}",
            fallback=logger,
        )
        raise


# --- Delivery status callbacks ---------------------------------------------
#
# SES publishes events (Send, Delivery, Bounce, ...) for messages sent with
# AWS_SES_CONFIGURATION_SET to an SNS topic, which POSTs them to the
# /email/callback route. They are only used for debugging, so they are logged
# and not stored anywhere else.

# SNS serves subscription confirmation URLs and signing certificates from the
# regional SNS endpoint. Checking the host keeps the callback route from being
# used to make the server fetch arbitrary URLs -- or trust arbitrary certificates.
_SNS_HOST = re.compile(r"sns\.[a-z0-9-]+\.amazonaws\.com")

# Event types that mean the message did not (or not yet) reach its recipient.
_PROBLEM_EVENT_TYPES = {
    "Bounce",
    "Complaint",
    "DeliveryDelay",
    "Reject",
    "Rendering Failure",
}

# The fields SNS signs, in signing order, by message type. Optional fields
# (Subject) are skipped when absent.
_SNS_SIGNED_FIELDS = {
    "Notification": (
        "Message",
        "MessageId",
        "Subject",
        "Timestamp",
        "TopicArn",
        "Type",
    ),
    "SubscriptionConfirmation": (
        "Message",
        "MessageId",
        "SubscribeURL",
        "Timestamp",
        "Token",
        "TopicArn",
        "Type",
    ),
}
_SNS_SIGNED_FIELDS["UnsubscribeConfirmation"] = _SNS_SIGNED_FIELDS[
    "SubscriptionConfirmation"
]

_SNS_SIGNATURE_HASHES = {"1": hashes.SHA1, "2": hashes.SHA256}

# SNS rotates its signing certificate rarely, so cache it by URL rather than
# fetching it for every message.
_signing_certs: dict[str, rsa.RSAPublicKey] = {}


async def _sns_get(url: str) -> httpx.Response:
    """GET a URL on the SNS endpoint, refusing any other host."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not _SNS_HOST.fullmatch(parts.hostname or ""):
        raise ValueError(f"Unexpected SNS URL host: {parts.hostname}")

    started = time.perf_counter()
    outcome: int | str = "ERR"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
        outcome = response.status_code
        response.raise_for_status()
        return response
    finally:
        # A SubscribeURL carries the subscription token, so log only the endpoint.
        record_backend_call(
            "GET",
            f"{parts.scheme}://{parts.hostname}{parts.path}",
            outcome,
            (time.perf_counter() - started) * 1000,
        )


async def _signing_key(cert_url: str) -> rsa.RSAPublicKey:
    if cert_url not in _signing_certs:
        response = await _sns_get(cert_url)
        key = x509.load_pem_x509_certificate(response.content).public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("SNS signing certificate does not hold an RSA key")
        _signing_certs[cert_url] = key
    return _signing_certs[cert_url]


async def verify_sns_message(message: dict) -> None:
    """Verify an SNS message's signature, raising ValueError if it is invalid.

    See https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
    """
    fields = _SNS_SIGNED_FIELDS.get(message.get("Type", ""))
    hash_type = _SNS_SIGNATURE_HASHES.get(message.get("SignatureVersion", ""))
    if fields is None or hash_type is None:
        raise ValueError(
            f"Unsupported SNS message type {message.get('Type')} "
            f"or signature version {message.get('SignatureVersion')}"
        )

    string_to_sign = "".join(
        f"{name}\n{message[name]}\n" for name in fields if name in message
    )
    try:
        signature = base64.b64decode(message.get("Signature", ""), validate=True)
    except binascii.Error as exc:
        raise ValueError("SNS signature is not valid base64") from exc

    key = await _signing_key(str(message.get("SigningCertURL")))
    try:
        key.verify(signature, string_to_sign.encode(), padding.PKCS1v15(), hash_type())
    except InvalidSignature as exc:
        raise ValueError("SNS signature does not match") from exc


async def confirm_sns_subscription(subscribe_url: str) -> None:
    """Confirm a new SNS subscription by visiting its SubscribeURL."""
    await _sns_get(subscribe_url)


def _recipients(entries: list) -> str:
    """Render SES recipient entries -- plain addresses or dicts -- for the log.

    Addresses are left as-is here; `log_ses_event` masks the whole line.
    """
    rendered = []
    for entry in entries:
        if isinstance(entry, dict):
            detail = " ".join(
                str(entry[key])
                for key in ("status", "action", "diagnosticCode")
                if entry.get(key)
            )
            address = entry.get("emailAddress") or "-"
            rendered.append(f"{address} ({detail})" if detail else address)
        else:
            rendered.append(str(entry))
    return ", ".join(rendered)


def log_ses_event(event: dict) -> None:
    """Log the message ID and status details from an SES event notification."""
    # Configuration-set event publishing uses "eventType"; identity feedback
    # notifications use "notificationType". Accept either.
    event_type = event.get("eventType") or event.get("notificationType") or "Unknown"
    mail = event.get("mail") or {}

    details: list[str] = []
    if delivery := event.get("delivery"):
        details.append(f"recipients={_recipients(delivery.get('recipients', []))}")
        details.append(f"smtp_response={delivery.get('smtpResponse')}")
    elif bounce := event.get("bounce"):
        details.append(
            f"bounce_type={bounce.get('bounceType')}/{bounce.get('bounceSubType')}"
        )
        details.append(f"recipients={_recipients(bounce.get('bouncedRecipients', []))}")
    elif complaint := event.get("complaint"):
        details.append(f"feedback_type={complaint.get('complaintFeedbackType')}")
        details.append(
            f"recipients={_recipients(complaint.get('complainedRecipients', []))}"
        )
    elif delay := event.get("deliveryDelay"):
        details.append(f"delay_type={delay.get('delayType')}")
        details.append(f"recipients={_recipients(delay.get('delayedRecipients', []))}")
    elif reject := event.get("reject"):
        details.append(f"reason={reject.get('reason')}")
    elif failure := event.get("failure"):
        details.append(f"error={failure.get('errorMessage')}")
    else:
        details.append(f"recipients={_recipients(mail.get('destination', []))}")

    level = logging.WARNING if event_type in _PROBLEM_EVENT_TYPES else logging.INFO
    # Recipients, SMTP responses and diagnostic codes can all contain addresses.
    logger.log(
        level,
        obfuscate_emails_in_text(
            f"SES {event_type} for Message ID: {mail.get('messageId')}, "
            + ", ".join(details)
        ),
    )
