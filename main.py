import string
from asyncio import gather
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi_utilities import repeat_every
from httpx import HTTPStatusError
from sqlalchemy import delete

from auth import (
    TokenPayload,
    create_access_token,
    decode_token,
    require_otp,
    require_otp_or_login,
    require_own_username_access,
    require_username_access,
)
from config import (
    CORS_ORIGINS,
    DEBUG,
    EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS,
    FRONTEND_URL,
    IDP_BY_DOMAIN_CACHE_REFRESH_INTERVAL_SECONDS,
    OTP_LIFETIME_MINUTES,
)
from database import OTPEntry, get_session, init_db
from models import (
    AcademicStatus,
    AcademicStatusResponse,
    AccountResponse,
    AddSSHKeyRequest,
    CountriesResponse,
    CreateAccountRequest,
    DegreesResponse,
    DomainResponse,
    IdentitiesResponse,
    Identity,
    JWTResponse,
    LoginRequest,
    SendOTPRequest,
    SSHKey,
    SSHKeysResponse,
    TermsAndConditionsResponse,
    UpdateAccountRequest,
    UpdatePasswordRequest,
    VerifyOTPRequest,
)
from services.account_service import (
    comanage_client,
    get_account_data,
    identity_client,
    safe_get,
)
from services.cilogon_client import CILogonClient
from services.email_service import send_verification_email, ses
from services.idp_service import build_idp_domain_mapping
from services.logs_service import logger
from services.otp_service import (
    generate_otp,
    store_otp,
    verify_stored_otp,
)
from services.ssh_key_service import calculate_ssh_fingerprint_sha256

# IDP by Domain
IDP_BY_DOMAIN: dict[str, dict[str, str]] = {}


# cron job to clean up expired OTPs
@repeat_every(seconds=EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS)  # runs every minute
def clear_expired_otps():
    # logger.info("Running expired OTP cleanup task")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=OTP_LIFETIME_MINUTES)

    with get_session() as session:
        # Bulk delete expired OTP entries
        stmt = delete(OTPEntry).where(OTPEntry.created_at < cutoff)

        result = session.exec(stmt)
        session.commit()

        rows_deleted = result.rowcount or 0
    # logger.info(f"Expired OTP cleanup task completed, removed {rows_deleted} entries")


@repeat_every(seconds=IDP_BY_DOMAIN_CACHE_REFRESH_INTERVAL_SECONDS, wait_first=True)
async def refresh_idp_domain_mapping():
    global IDP_BY_DOMAIN
    try:
        if DEBUG:
            logger.info("Refreshing IdP domain mapping...")

        new_map = await build_idp_domain_mapping()
        IDP_BY_DOMAIN = new_map
        if DEBUG:
            logger.info(f"Refreshed IdP domain mapping entries: {len(IDP_BY_DOMAIN)}")

    except Exception as e:
        logger.exception(f"Failed to refresh IdP domain mapping: {e}")


# Initialize the OTP database
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up... Initializing database.")
    init_db()
    print("Database initialized.")
    await clear_expired_otps()  # Initial cleanup on startup

    global IDP_BY_DOMAIN
    try:
        print("Fetching IdP metadata...")
        IDP_BY_DOMAIN = await build_idp_domain_mapping()
        logger.info(f"Loaded IdP domain mapping entries: {len(IDP_BY_DOMAIN)}")
    except Exception as e:
        logger.exception(f"Failed to load IdP domain mapping: {e}")
        IDP_BY_DOMAIN = {}
    yield


app = FastAPI(
    title="ACCESS Account API",
    description="API for ACCESS CI accounts and registration",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create router with /api/v1 prefix
router = APIRouter(prefix="/api/v1")


# Auth Routes
@router.post(
    "/auth/send-otp",
    tags=["Authentication"],
    summary="Send OTP to email",
    description="Send a one-time password (OTP) to the specified email, if it exists. "
    "In order to avoid revealing whether the email has an associated account, "
    "we send the OTP regardless of whether the domain is allowed by ACCESS. "
    "Prohibited domains will be flagged after the user enters the OTP.",
    responses={
        200: {"description": "The OTP was sent"},
        400: {
            "description": "The OTP could not be sent (e.g., due to a malformed email address)"
        },
    },
)
async def send_otp(request: SendOTPRequest):
    email = request.email.lower().strip()

    if "@" not in email:
        logger.warning(f"Rejected OTP request due to invalid email format: {email}")
        raise HTTPException(400, "Invalid email")

    otp = generate_otp()
    store_otp(email, otp)

    if DEBUG:
        logger.info(f"OTP for {email}: {otp}")
    else:
        try:
            resp = send_verification_email(email, otp)
            message_id = resp.get("MessageId")

        except ses.exceptions.MessageRejected:
            logger.error(f"SES MessageRejected for email={email}")
            raise HTTPException(400, "Email was rejected by SES")

        except ses.exceptions.MailFromDomainNotVerifiedException:
            logger.error(f"SES MailFromDomainNotVerifiedException for email={email}")
            raise HTTPException(400, "Sender domain is not verified in SES")

        except ses.exceptions.ConfigurationSetDoesNotExistException:
            logger.error(f"SES ConfigurationSetDoesNotExistException for email={email}")
            raise HTTPException(400, "SES configuration set does not exist")

        except ses.exceptions.ConfigurationSetSendingPausedException:
            logger.error(
                f"SES ConfigurationSetSendingPausedException for email={email}"
            )
            raise HTTPException(400, "SES configuration set sending is paused")

        except ses.exceptions.AccountSendingPausedException:
            logger.error(f"SES AccountSendingPausedException for email={email}")
            raise HTTPException(400, "SES account sending is paused")

        except ses.exceptions.InvalidParameterValue:
            logger.error(f"SES InvalidParameterValue for email={email}")
            raise HTTPException(400, "Invalid email or SES parameter value")

        except ClientError as e:
            code = e.response["Error"]["Code"]
            logger.exception(f"Unexpected SES error for email={email}: {code}")
            raise HTTPException(400, f"Email send failed: {code}")

        logger.info(
            f"Verification email sent successfully: {email}, Message ID: {message_id}"
        )

    return {"success": True}


@router.post(
    "/auth/verify-otp",
    response_model=JWTResponse,
    tags=["Authentication"],
    summary="Verify OTP",
    description="Verify an OTP provided by the user.",
    responses={
        200: {"description": "The OTP is valid. Returns a JWT of type 'otp'"},
        400: {"description": "The request body is malformed"},
        403: {"description": "The OTP is invalid"},
    },
)
async def verify_otp(request: VerifyOTPRequest):
    """Verify an OTP provided by the user."""
    # Validate format
    email = request.email.lower().strip()
    otp = request.otp.strip()

    if "@" not in email:
        logger.warning(
            f"Rejected OTP verification due to invalid email format: {email}"
        )
        raise HTTPException(400, "Invalid email")

    if len(otp) != 6 or not all(
        c in (string.ascii_lowercase + string.digits) for c in otp
    ):
        logger.warning(
            f"Rejected OTP verification due to invalid OTP format: {otp} for email: {email}"
        )
        raise HTTPException(400, "Invalid OTP format")

    # Verify against stored OTP
    verify_stored_otp(email, otp)

    # Look up the email address to see if it has an existing account.
    username = await comanage_client.get_access_id_for_email(email)

    # Create a JWT token of type "otp"
    token = create_access_token(sub=request.email, token_type="otp", username=username)

    logger.info(f"OTP verified successfully for email={email}")
    return JWTResponse(jwt=token)


@router.post(
    "/auth/login",
    tags=["Authentication"],
    summary="Start CILogon authentication",
    description="Start the CILogon authentication flow. "
    "The preferred IDP can be included in the request body. "
    "Otherwise, the user is prompted to select an IDP by CILogon.",
    responses={
        307: {"description": "Redirect to the CILogon URL to start the login process"},
        400: {
            "description": "The redirect could not be sent (e.g., due to a malformed email address)"
        },
    },
    response_class=RedirectResponse,
)
async def start_login(
    request: Request,
    login_request: LoginRequest | None = None,
    token_type: str | None = None,
):
    """Start the CILogon OIDC authentication flow."""
    return CILogonClient().get_oidc_start_url(
        request, idp=login_request.idp if login_request else None, token_type=token_type
    )


@router.get(
    "/auth/login",
    tags=["Authentication"],
    summary="Complete CILogon authentication",
    description="Receive the CILogon token after a successful login, and redirect to the front end URL.",
    responses={
        307: {
            "description": "Redirect to the account frontend URL with query string parameters: "
            "jwt (a JWT of type 'login'), first_name (the given_name OIDC claim), "
            "and last_name (the family_name OIDC claim)"
        },
    },
    response_class=RedirectResponse,
)
async def complete_login(code: str, request: Request, token_type: str | None = None):
    """Receive the CILogon token after a successful login."""
    cilogon = CILogonClient()
    access_token = await cilogon.get_access_token(request, code)
    user_info = await cilogon.get_user_info(access_token)

    # Create a JWT token of type "login"
    user = user_info.get("preferred_username", "user")

    if token_type == "cilogon":
        jwt = access_token
    else:
        jwt = create_access_token(
            sub=user_info["sub"],
            token_type="login",
            username=user,
        )

    # Build redirect URL with query parameters
    query_params = {
        "jwt": jwt,
        "first_name": user_info["given_name"],
        "last_name": user_info["family_name"],
    }
    if token_type:
        query_params["token_type"] = token_type

    return f"{FRONTEND_URL}?{urlencode(query_params)}"


# Account Routes
@router.post(
    "/account",
    tags=["Account"],
    summary="Create new account",
    description="Create a new account.",
    responses={
        200: {"description": "The account was created"},
        400: {
            "description": "The input failed validation (e.g., the organization does not match "
            "the e-mail domain or an account for that email address already exists)"
        },
        403: {"description": "The JWT is invalid"},
    },
)
async def create_account(
    account_request: CreateAccountRequest,
    request: Request,
    token: TokenPayload = Depends(require_otp),
    cilogon_token: str | None = None,
):
    """Create a new ACCESS account."""
    email = token.sub.lower().strip()
    try:
        domain = email.split("@")[1]
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address",
        )

    # Perform preliminary checks in parallel
    [_existing_access_id, active_tandc, organization_name] = await gather(
        comanage_client.check_account_does_not_exist(email),
        comanage_client.check_active_tandc_exists(),
        identity_client.check_organization_matches_domain(
            account_request.organization_id, domain
        ),
    )

    # Create a new CoPerson record
    co_person_response = await comanage_client.create_new_user(
        firstname=account_request.first_name,
        lastname=account_request.last_name,
        organization=organization_name,
        email=email,
    )

    # Extract the ACCESS ID from the response
    if (
        len(co_person_response) == 1
        and co_person_response[0].get("type", None) == "accessid"
    ):
        access_id = co_person_response[0]["identifier"]
    else:
        logger.error(f"Could not retrieve ACCESS ID for newly created user {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to retrieve ACCESS ID",
        )

    # Get the CoPerson ID for the new user
    co_person_id = await comanage_client.get_co_person_id_for_email(email)

    # Create an OrgIdentity record
    linked_identity = comanage_client.create_linked_identity(
        co_person_id, access_id, cilogon_token
    )

    # Create a terms and conditions agreement
    tandc_agreement = comanage_client.create_new_tandc_agreement(
        co_tandc_id=active_tandc["Id"],
        co_person_id=int(co_person_id),
    )

    # Create or update the person record in the identity service
    identity_person = identity_client.create_person(
        access_id, **dict(account_request), email=email, update_if_exists=True
    )

    # Await parallel updates
    await gather(linked_identity, tandc_agreement, identity_person)

    return {"success": True, "access_id": access_id}


@router.get(
    "/account/{username}",
    tags=["Account"],
    summary="Get account profile",
    description="Get the profile for the given account.",
    responses={
        200: {"description": "Return the profile information for the user"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
    response_model=AccountResponse,
)
async def get_account(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    [comanage_user, identity_person] = await get_account_data(username)

    # Comanage (preferred) values
    primary_name = comanage_user.get_primary_name()
    comanage_first = primary_name.get("given")
    comanage_last = primary_name.get("family")
    comanage_tz = safe_get(comanage_user, "CoPerson", "timezone")
    primary_email = comanage_user.get_primary_email()

    # Identity Service values
    organization_id = identity_person.get("organizationId")
    academic_status_id = identity_person.get("nsfStatusCodeId")
    residence_country_id = identity_person.get("countryId")
    citizenship_country_ids = [
        c["countryId"]
        for c in (identity_person.get("citizenships") or [])
        if isinstance(c, dict) and "countryId" in c
    ]

    return {
        "username": username,
        "first_name": comanage_first,
        "last_name": comanage_last,
        "email": primary_email,
        "time_zone": comanage_tz,
        "organization_id": organization_id,
        "academic_status_id": academic_status_id,
        "residence_country_id": residence_country_id,
        "citizenship_country_ids": citizenship_country_ids,
    }


@router.post(
    "/account/{username}",
    tags=["Account"],
    summary="Update account profile",
    description="Update the profile information for an account. "
    "If email is different from the email in the Authorization header, "
    "a valid emailJWT of type 'otp' must be provided to prove that the user owns the new email address.",
    responses={
        200: {"description": "The account profile was updated"},
        400: {
            "description": "The input failed validation (e.g., the organization does not match the e-mail domain)"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to update the account"
        },
    },
)
async def update_account(
    username: str,
    account_request: UpdateAccountRequest,
    token: TokenPayload = Depends(require_username_access),
):
    [comanage_user, identity_person] = await get_account_data(username)

    prev_email = comanage_user.get_primary_email()
    prev_organization_id = identity_person["organizationId"]

    email = account_request.email or prev_email
    organization_id = account_request.organization_id or prev_organization_id

    # If the email address has changed, check that we have a valid OTP token
    # proving that the user owns the new email address.
    if email != prev_email:
        error_message = "Invalid email OTP token"
        error_status = status.HTTP_400_BAD_REQUEST
        email_token = decode_token(
            account_request.email_otp_token,
            error_message=error_message,
            error_status=error_status,
        )
        if email_token.type != "otp" or email_token.sub != email:
            raise HTTPException(
                status_code=error_status,
                detail=error_message,
            )

    # If either the email or organization ID has changed, check that
    # the email maches the organization.
    organization_name = None
    if email != prev_email or organization_id != prev_organization_id:
        domain = email.strip().split("@")[1]
        organization_name = await identity_client.check_organization_matches_domain(
            organization_id, domain
        )

    registry_update = comanage_client.update_user(
        username,
        first_name=account_request.first_name,
        last_name=account_request.last_name,
        email=account_request.email,
        organization=organization_name,
        time_zone=account_request.time_zone,
        user=comanage_user,
    )

    identity_update = identity_client.update_person(
        username,
        first_name=account_request.first_name,
        last_name=account_request.last_name,
        email=account_request.email,
        organization_id=organization_id,
        academic_status_id=account_request.academic_status_id,
        residence_country_id=account_request.residence_country_id,
        citizenship_country_ids=account_request.citizenship_country_ids,
        degrees=[d.model_dump() for d in account_request.degrees]
        if account_request.degrees
        else None,
    )

    await gather(registry_update, identity_update)
    return {"success": True}


@router.post(
    "/account/{username}/password",
    tags=["Account"],
    summary="Set or update password",
    description="Set or update the password for the account in the ACCESS IDP.",
    responses={
        200: {"description": "The password was updated"},
        400: {
            "description": "The password does not conform to the ACCESS password policy"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to update the password"
        },
    },
)
async def update_password(
    username: str,
    request: UpdatePasswordRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement password update logic
    pass


# Identity Routes
@router.get(
    "/account/{username}/identity",
    tags=["Identity"],
    summary="Get linked identities",
    description="Get a list of identities associated with this account.",
    responses={
        200: {
            "description": "Return the list of linked identities and associated IDPs"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
)
async def get_identities(
    username: str,
    token: TokenPayload = Depends(require_username_access),
) -> IdentitiesResponse:
    try:
        comanage_user = await comanage_client.get_user_info(username)
    except HTTPStatusError as err:
        raise HTTPException(err.response.status_code, err.response.text)

    # Pass all Identifier records with {type, identifier}
    identities: list[Identity] = []

    # Extract identities from OrgIdentity records
    for org_identity in comanage_user.get("OrgIdentity", []):
        identifiers_records = org_identity.get("Identifier") or []

        identifiers = []
        for identity in identifiers_records:
            identifiers.append(
                {
                    "type": identity.get("type"),
                    "identifier": identity.get("identifier"),
                    "login": identity.get("login"),
                }
            )

        # Append the Identity object
        identities.append(
            Identity(
                identity_id=org_identity["meta"]["id"],
                organization=org_identity.get("o"),
                identifiers=identifiers,
            )
        )

    return IdentitiesResponse(identities=identities)


@router.post(
    "/account/{username}/identity",
    tags=["Identity"],
    summary="Link new identity",
    description="Start the process of linking a new identity. "
    "Redirects to CILogon to start the linking flow.",
    responses={
        307: {
            "description": "Redirect to CILogon to start the linking flow. "
            "At the end of the flow, CILogon redirects back to /auth/login with the OIDC token"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
    },
)
async def link_identity(
    username: str,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement identity linking flow
    pass


@router.delete(
    "/account/{username}/identity/{identity_id}",
    tags=["Identity"],
    summary="Delete linked identity",
    description="Delete a linked identity.",
    responses={
        200: {"description": "The linked identity was deleted"},
        400: {
            "description": "The specified identity cannot be deleted "
            "(e.g., it is the last one associated with this account)"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
        404: {"description": "The requested identity does not exist"},
    },
)
async def delete_identity(
    username: str,
    identity_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement identity deletion logic
    pass


# SSH Key Routes
@router.get(
    "/account/{username}/ssh-key",
    tags=["SSH Keys"],
    summary="Get SSH keys",
    description="Get a list of SSH keys associated with this account.",
    responses={
        200: {"description": "Return the list of linked SSH keys"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
)
async def get_ssh_keys(
    username: str,
    token: TokenPayload = Depends(require_username_access),
) -> SSHKeysResponse:
    try:
        comanage_user = await comanage_client.get_user_info(username)
    except HTTPStatusError as err:
        raise HTTPException(err.response.status_code, err.response.text)

    ssh_keys = []
    for ssh_key in comanage_user.get("SshKey", []):
        # Skip deleted keys
        if ssh_key.get("meta", {}).get("deleted"):
            continue

        ssh_keys.append(
            SSHKey(
                key_id=ssh_key["meta"]["id"],
                hash=calculate_ssh_fingerprint_sha256(ssh_key.get("skey")),
                created=ssh_key["meta"]["created"],
            )
        )

    return SSHKeysResponse(ssh_keys=ssh_keys)


@router.post(
    "/account/{username}/ssh-key",
    tags=["SSH Keys"],
    summary="Add SSH key",
    description="Add a new SSH key to the account.",
    responses={
        200: {"description": "The key was added successfully"},
        400: {
            "description": "The provided key is not valid or is already associated with another account"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
    },
)
async def add_ssh_key(
    username: str,
    request: AddSSHKeyRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    # Get public key
    public_key = request.public_key.strip()
    if not public_key:
        raise HTTPException(
            400,
            "The provided key is not valid.",
        )

    # Call the CoManage API to add the key
    await comanage_client.add_ssh_key_for_user(username, public_key)
    return {"success": True}


@router.delete(
    "/account/{username}/ssh-key/{key_id}",
    tags=["SSH Keys"],
    summary="Delete SSH key",
    description="Delete an SSH key.",
    responses={
        200: {"description": "The linked SSH key was deleted"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
        404: {"description": "The requested key does not exist"},
    },
)
async def delete_ssh_key(
    username: str,
    key_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    # Call the CoManage API to delete the key
    await comanage_client.delete_ssh_key_for_user(username, key_id)
    return {"success": True}


# Reference Data Routes


@router.get(
    "/academic-status",
    response_model=AcademicStatusResponse,
    tags=["Reference Data"],
    summary="Get academic statuses",
    description="Get a list of all possible academic statuses.",
    responses={
        200: {"description": "Return a list of possible academic statuses"},
        403: {"description": "The JWT is invalid"},
    },
)
async def get_academic_statuses(
    token: TokenPayload = Depends(require_otp_or_login),
) -> AcademicStatusResponse:
    raw = await identity_client.get_academic_statuses()

    transformed = [
        AcademicStatus(
            academicStatusId=item["nsfStatusCodeId"],
            name=item["nsfStatusCodeName"],
        )
        for item in raw
    ]

    return AcademicStatusResponse(academicStatuses=transformed)


@router.get(
    "/country",
    tags=["Reference Data"],
    summary="Get countries",
    description="Get a list of all possible countries.",
    response_model=CountriesResponse,
    responses={
        200: {"description": "Return a list of possible countries"},
        403: {"description": "The JWT is invalid"},
    },
)
async def get_countries(
    token: TokenPayload = Depends(require_otp_or_login),
) -> CountriesResponse:
    # Call the Identity Service client to get the countries
    data = await identity_client.get_countries()

    # Convert the raw data from the service into Country model objects
    return {
        "countries": [
            {
                "countryId": item["countryId"],
                "name": item["countryName"],
            }
            for item in data
        ]
    }


@router.get(
    "/degree",
    tags=["Reference Data"],
    summary="Get degrees",
    description="Get a list of all possible academic degrees.",
    response_model=DegreesResponse,
    responses={
        200: {"description": "Return a list of possible degrees"},
        403: {"description": "The JWT is invalid"},
    },
)
async def get_degrees(
    token: TokenPayload = Depends(require_otp_or_login),
) -> DegreesResponse:
    degrees = await identity_client.get_degrees()
    return {
        "degrees": [
            {
                "degree_id": item["degreeId"],
                "name": item["description"],
            }
            for item in degrees
        ]
    }


@router.get(
    "/domain/{domain}",
    tags=["Reference Data"],
    summary="Get domain information",
    description="Get information about an email domain, including whether it meets ACCESS eligibility criteria, "
    "and associated organizations and IDPs, if any.",
    response_model=DomainResponse,
    responses={
        200: {
            "description": "Return lists of associated organizations and IDPs for the domain"
        },
        403: {"description": "The JWT is invalid"},
        404: {"description": "The domain is not known to ACCESS/CILogon"},
    },
)
async def get_domain_info(
    domain: str,
    token: TokenPayload = Depends(require_otp_or_login),
) -> DomainResponse:
    domain_clean = domain.strip().lower()
    # Call the Identity Service client to get the domain information
    try:
        organizations = await identity_client.get_organizations_by_domain(domain_clean)
    except HTTPStatusError as err:
        # bubble up upstream status code + message
        raise HTTPException(
            status_code=err.response.status_code,
            detail=f"Identity service error: {err.response.text}",
        )

    idps = []
    match = IDP_BY_DOMAIN.get(domain_clean)
    if match:
        idps.append(
            {"displayName": match["display_name"], "entityId": match["entity_id"]}
        )
    # Include the full organization dictionaries from XRAS
    return {
        "domain": domain_clean,
        "organizations": organizations,
        "idps": idps,
    }


@router.get(
    "/terms-and-conditions",
    tags=["Reference Data"],
    summary="Get active terms and conditions",
    description="Get the active terms and conditions for ACCESS.",
    response_model=TermsAndConditionsResponse,
    responses={
        200: {"description": "Return the active terms and conditions"},
        403: {"description": "The JWT is invalid"},
        404: {"description": "No active terms and conditions found"},
    },
)
async def get_terms_and_conditions(
    token: TokenPayload = Depends(require_otp_or_login),
) -> TermsAndConditionsResponse:
    # Call the CoManage Registry client to get active terms and conditions
    tandc = await comanage_client.get_active_tandc()

    if not tandc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active terms and conditions found",
        )

    return TermsAndConditionsResponse(
        id=tandc["Id"],
        description=tandc["Description"],
        url=tandc["Url"],
        body=tandc["Body"],
    )


# Include router in the app
app.include_router(router)


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
