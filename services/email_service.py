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
      <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8" />
                <title>ACCESS One-Time Password</title>
            </head>
            <body style="margin:0; padding:0; background-color:#f5f7fa; font-family:Arial, sans-serif; color:#2d2d2d;">

                <table width="100%" border="0" cellspacing="0" cellpadding="0" style="padding: 40px 0;">
                <tr>
                    <td align="center">

                    <!-- Container -->
                    <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color:#ffffff; border-radius:8px; padding: 40px; box-shadow:0 2px 8px rgba(0,0,0,0.05);">
                        <tr>
                        <td>

                            <!-- Header -->
                            <h1 style="margin:0; font-size:24px; font-weight:700; color:#003b5c; text-align:center;">
                            ACCESS Verification Code
                            </h1>

                            <p style="font-size:16px; margin-top:24px; line-height:1.5;">
                            Hello,
                            </p>

                            <p style="font-size:16px; margin:16px 0; line-height:1.5; text-align:center;">
                            Use the following one-time password (OTP) to continue signing in to your ACCESS Account.
                            </p>
                            
                            <div style="text-align:center; margin-top:16px;">
                                <!-- OTP Box -->
                                <div style="
                                    margin: 30px 0;
                                    padding: 16px;
                                    background-color:#f0f4f8;
                                    border-radius:6px;
                                    display:inline-block;
                                    font-size:32px;
                                    font-weight:700;
                                    letter-spacing:8px;
                                    color:#003b5c;
                                ">
                                    {otp}
                                </div>
                            </div>

                            <!-- Footer -->
                            <p style="font-size:14px; margin-top:24px; line-height:1.4; color:#555;">
                            If you did not request this code, you can safely ignore this email.
                            </p>

                            <p style="font-size:14px; margin-top:16px; line-height:1.4; color:#777;">
                            — ACCESS Support Team
                            </p>

                        </td>
                        </tr>
                    </table>

                    </td>
                </tr>
                </table>

            </body>
        </html>
        """

    resp = ses.send_email(
        Source="allocations@access-ci.org",
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your ACCESS OTP"},
            "Body": {
                "Html": {"Data": html},
                "Text": {"Data": f"Your ACCESS OTP is {otp}"},
            },
        },
    )

    #print("SES Message ID:", resp.get("MessageId")) For testing purposes
    return resp

