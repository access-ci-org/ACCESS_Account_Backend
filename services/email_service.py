import boto3
from config import AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY

ses = boto3.client(
    "ses",
    region_name=AWS_REGION,
    aws_access_key_id=str(AWS_ACCESS_KEY),
    aws_secret_access_key=str(AWS_SECRET_ACCESS_KEY),
)

def send_otp_email_inline(email, otp):
    html = f"""
      <html>
      <body>
        <p>Your ACCESS OTP is:</p>
        <h2>{otp}</h2>
      </body>
      </html>
    """

    return ses.send_email(
        Source="support@access-ci.atlassian.net",
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your ACCESS OTP"},
            "Body": {
                "Html": {"Data": html},
                "Text": {"Data": f"Your ACCESS OTP is {otp}"},
            },
        },
    )
