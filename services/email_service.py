import logging

import boto3
from botocore.exceptions import ClientError
from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import (
    AWS_ACCESS_KEY,
    AWS_REGION,
    AWS_SECRET_ACCESS_KEY,
    AWS_SES_SENDER_EMAIL,
    OTP_LIFETIME_MINUTES,
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


def send_verification_email(email, otp):
    # Render Jinja email template

    html_body = template.render(otp=otp, lifetime=OTP_LIFETIME_MINUTES)

    text_body = f"Your ACCESS verification code is: {otp}. This code expires in {OTP_LIFETIME_MINUTES} minutes."
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
        )

        # print("SES Message ID:", resp.get("MessageId")) For testing purposes
        return resp
    except ClientError as e:
        logger.exception(f"SES ClientError when sending verification email to {email}")
        raise e
