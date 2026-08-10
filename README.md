# ACCESS Account API

API for ACCESS CI accounts and registration.

## Getting Started

### Prerequisites

- Python 3.13 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Installation

1. Clone the repository:
```bash
git clone git@github.com:access-ci-org/ACCESS_Account_Backend.git
cd ACCESS_Account_Backend
```

2. Install dependencies using uv:
```bash
uv sync
```

### Configuration

The API requires several environment variables to be set. Create a `.env` file in the project root:

```bash
# Required: JWT secret key for signing tokens
# Generate a secure random string (e.g., using: openssl rand -hex 32)
JWT_SECRET_KEY=your-secure-secret-key-here

# Optional: JWT configuration (defaults shown)
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_ISSUER=https://account.access-ci.org
JWT_AUDIENCE=https://account.access-ci.org

# Optional: Application configuration
CORS_ORIGINS=http://localhost:3000,https://access-ci-org.github.io
DEBUG=false
FRONTEND_URL=http://localhost:3000

# Optional: comma-separated ACCESS usernames granted administrative access
# (e.g., to read or update any user's profile)
ADMIN_USERNAMES=

# Optional: backing store for rate limiting (defaults to in-memory, which is
# not shared across multiple worker processes)
RATE_LIMIT_STORAGE_URL=memory://
```

**Important:** The `JWT_SECRET_KEY` is required and must be set. The application will fail to start without it.

### Running the Development Server

Start the development server:

```bash
uv run python main.py
```

The API will be available at `http://localhost:8000`.

### API Documentation

Once the server is running, you can access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

All API routes are prefixed with `/api/v1`.

## Authentication

Users can authenticate to the Account API using two methods, which provide different levels of privilege:
- By providing a one-time password (OTP) sent to their email address. This type of authentication proves their ownership of the email address but does not assert ownership of an ACCESS account (or even that an associated ACCESS account exists).
- By completing the CILogon OAuth flow. This type of authentication proves the user's identity and their ownership of the associated ACCESS account, if any.

The /auth/* routes described below return a JSON Web Token (JWT) with the following claims (in addition to the standard claims like iss, exp, etc.):
 - `sub`: The e-mail address.
 - `typ`: The authentication type (one of `otp` or `login`).
 - `uid`: The ACCESS username, if there is one associated with the email address.

The other routes authenticate using one or both of these JWT types via the Authorization header.

## Routes

### GET `/health`
Make parallel connectivity checks against CoManage Registry, CILogon, the Identity Service, and AWS SES, and report whether each is reachable. Always returns HTTP 200; inspect the response body for per-service status. Does not require authentication.

#### Response Types

##### HTTP 200
```json
{
	"comanageRegistry": {"reachable": true, "statusCode": 200, "detail": null},
	"cilogon": {"reachable": true, "statusCode": 200, "detail": null},
	"identityService": {"reachable": true, "statusCode": 200, "detail": null},
	"awsSes": {"reachable": true, "statusCode": 200, "detail": null}
}
```

### POST `/auth/send-otp`
Send a one-time password (OTP) to the specified email, if it exists. In order to avoid revealing whether the email has an associated account, we should send the OTP regardless of whether the domain is allowed by ACCESS. Prohibited domains will be flagged after the user enters the OTP.

This route is rate-limited to 1000 requests/day per IP address and 4 requests/hour per email address.

#### Request Body
```json
{
	"email": "user@example.edu"
}
```

#### Response Types

##### HTTP 200
The OTP was sent.

##### HTTP 400
The OTP could not be sent (e.g., due to a malformed email address).

##### HTTP 429
The rate limit was exceeded (by IP address or by email address).

### POST `/auth/verify-otp`
Verify an OTP provided by the user.

#### Request Body
```json
{
	"email": "user@example.edu",
	"otp": "abc123"
}
```

#### Response Types

##### HTTP 200
The OTP is valid. Return a JWT of type `otp`.

```json
{
	"jwt": "<jwt>"
}
```

##### HTTP 400
The request body is malformed.

##### HTTP 403
The OTP is invalid.

### GET `/auth/info`
Get the CILogon OIDC client IDs and authorization URL.

#### Response Types

##### HTTP 200
Return the OIDC client IDs and authorization URL.

```json
{
	"authorization_url": "<authorization_url>",
	"client_ids": {
		"login": "<login_client_id>",
		"link": "<link_client_id>"
	}
}
```

### POST `/auth/oauth2/token`
Exchange an authorization code for OIDC tokens, or refresh existing tokens using a refresh token.

#### Request Body
```json
{
	"client_id": "<cilogon_client_id>",
	"grant_type": "authorization_code",
	"redirect_uri": "https://example.com/callback",
	"code": "<authorization_code>"
}
```

For token refresh, use `grant_type: "refresh_token"` and provide `refresh_token` instead of `code`. `redirect_uri` is still required by the request schema even when refreshing.

#### Response Types

##### HTTP 200
Return the OIDC tokens. `isAdmin` is only populated (and only meaningful) for the login client, based on whether the CILogon username is in `ADMIN_USERNAMES`.

```json
{
	"accessToken": "<access_token>",
	"idToken": "<id_token>",
	"refreshToken": "<refresh_token>",
	"isAdmin": false
}
```

### POST `/auth/password-reset`
Request a password reset for an unauthenticated user.

#### Request Headers
- `Authorization`: containing a JWT of type `otp`.

#### Request Body
```json
{
	"password": "New Password"
}
```

#### Response Types

##### HTTP 200
The password was updated.

```json
{
	"success": true
}
```

##### HTTP 400
The password does not conform to the ACCESS password policy

##### HTTP 403
The JWT is invalid

##### HTTP 404
No account was found for the provided email address

### POST `/account`
Create a new account. The email address is taken from the `sub` claim of the OTP JWT, not from the request body.

#### Request Headers
- `Authorization`: containing a JWT of type `otp`.

#### Request Body
`cilogonToken` is optional; if provided (a CILogon access token from another IdP obtained outside this OTP flow), a second linked identity is created for that IdP in addition to the ACCESS IdP identity.

```json
{
	"firstName": "Jane",
	"lastName": "Doe",
	"organizationId": 123,
	"academicStatusId": 101,
	"residenceCountryId": 201,
	"citizenshipCountryIds": [201],
	"department": "Computer Science",
	"cilogonToken": ""
}
```

#### Response Types

##### HTTP 200
The account was created. Returns the newly created ACCESS ID.

```json
{
	"success": true,
	"access_id": "jdoe"
}
```

##### HTTP 400
The input failed validation (e.g., the organization does not match the e-mail domain, the academic status ID is invalid, or an account for that email address already exists). Return an error message indicating the problem.

```json
{
	"detail": "Organization does not match email domain."
}
```

##### HTTP 403
The JWT is invalid or is not of type `otp`.

### GET `/account/<username>`
Get the profile for the given account. Data is merged from CoManage Registry (name, email addresses, time zone) and the Identity Service (organization, academic status, country/citizenship, degrees, department).

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Response Types

##### HTTP 200
Return the profile information for the user.

```json
{
	"username": "jdoe",
	"firstName": "Jane",
	"lastName": "Doe",
	"emails": [
		{"email": "jdoe@example.edu", "primary": true},
		{"email": "jdoe2@other.edu", "primary": false}
	],
	"timeZone": "America/New_York",
	"organizationId": 123,
	"academicStatusId": 101,
	"residenceCountryId": 201,
	"citizenshipCountryIds": [201],
	"degrees": [
		{"degreeId": 1, "degreeField": "Computer Science"}
	],
	"department": "Computer Science"
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to access the account.

##### HTTP 404
The requested user does not exist, or does not have a primary name on record.

### POST `/account/<username>`
Update the profile information for an account. All fields are optional; omitted fields are left unchanged. Fields set to `null`/omitted are not modified, but fields that are provided always replace the existing value (there is no partial update of a list field like `emails`, `citizenshipCountryIds`, or `degrees`).

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Request Body
If an `emails` list is provided, it fully replaces the account's email addresses and exactly one entry must be marked `primary`. Any address in the list that is not already on the account's CoManage record must include a valid `otpToken` (a JWT of type `otp` whose `sub` matches that email address) proving ownership; this applies to new primary and new recovery addresses alike. The domain of the resulting primary email must match `organizationId`.

```json
{
	"firstName": "Jane",
	"lastName": "Doe",
	"emails": [
		{"email": "jdoe@example.edu", "primary": true},
		{"email": "jdoe2@other.edu", "primary": false, "otpToken": "<jwt_for_jdoe2>"}
	],
	"organizationId": 123,
	"academicStatusId": 101,
	"residenceCountryId": 201,
	"citizenshipCountryIds": [201],
	"degrees": [
		{"degreeId": 1, "degreeField": "Computer Science"}
	],
	"timeZone": "America/New_York",
	"department": "Computer Science"
}
```

The request schema also accepts a `programRole` field, but the handler does not currently apply it to either backing store.

#### Response Types

##### HTTP 200
The account profile was updated.

##### HTTP 400
The input failed validation (e.g., not exactly one primary email, a missing/invalid `otpToken` for a new email address, an invalid academic status ID, or the primary email's domain does not match the organization). Return a message describing the problem.

```json
{
	"detail": "Exactly one email address must be marked as primary."
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to update the account.

### POST `/account/<username>/password`
Set or update the password for the account in the ACCESS IDP.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Request Body
```json
{
	"password": "my N3w very $ecure passw0rd!"
}
```

#### Response Types

##### HTTP 200
The password was updated.

##### HTTP 400
The password does not conform to the ACCESS password policy. Return a message describing the problem.

```json
{
	"detail": "The password does not conform to the ACCESS password policy."
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to update the password.

##### HTTP 404
The account or password record was not found.

##### HTTP 502
The password update failed in CoManage Registry.

### GET `/account/<username>/identity`
Get a list of identities associated with this account. Each identity corresponds to an `OrgIdentity` record in CoManage (one per linked IdP, including the ACCESS IdP itself) and includes its raw `Identifier` records.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Response Types

##### HTTP 200
Return the list of linked identities.

```json
{
	"identities": [
		{
			"identityId": 15,
			"organization": "Example University",
			"identifiers": [
				{"type": "eppn", "identifier": "jdoe15@example.edu", "login": true}
			]
		}
	]
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to access the account.

##### HTTP 404
The requested user does not exist.

### POST `/account/<username>/identity`
Link a new identity to the account using a CILogon access token obtained from the link client (via `POST /auth/oauth2/token` with the link client ID).

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Request Body
```json
{
	"cilogonToken": "<cilogon_access_token>"
}
```

#### Response Types

##### HTTP 200
The identity was linked.

```json
{
	"success": true
}
```

##### HTTP 400
The requested username does not exist.

##### HTTP 403
The JWT is invalid or the user does not have permission to modify the account.

### DELETE `/account/<username>/identity/<identity_id>`
Delete a linked identity, including its `Identifier` records on both the `OrgIdentity` and the parent `CoPerson`, then unlink and delete the `OrgIdentity` itself.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Response Types

##### HTTP 200
The linked identity was deleted.

```json
{
	"success": true
}
```

##### HTTP 400
The specified identity cannot be deleted (the ACCESS IdP identity, i.e. an identifier of type `eppn` ending in `@access-ci.org`, can never be deleted) or the requested username does not exist. Return a message describing the problem.

```json
{
	"detail": "The ACCESS identity cannot be deleted"
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to modify the account.

##### HTTP 404
The requested identity does not exist.

### GET `/account/<username>/ssh-key`
Get a list of SSH keys associated with this account.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Response Types

##### HTTP 200
Return the list of linked SSH keys.

```json
{
	"sshKeys": [
		{
			"keyId": 15,
			"hash": "<ssh_key_hash>",
			"created": "2025-07-01T10:00:00"
		}
	]
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to access the account.

##### HTTP 404
The requested user does not exist.

### POST `/account/<username>/ssh-key`
Add a new SSH key to the account.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Request Body
```json
{
	"publicKey": "<my_public_key>"
}
```

#### Response Types

##### HTTP 200
The key was added successfully.

##### HTTP 400
The provided key is not valid (e.g., empty) or is already associated with another account. Return a message describing the problem.

```json
{
	"detail": "The provided key is not valid."
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to modify the account.

### DELETE `/account/<username>/ssh-key/<key_id>`
Delete an SSH key.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Response Types

##### HTTP 200
The linked SSH key was deleted.

##### HTTP 403
The JWT is invalid or the user does not have permission to modify the account.

##### HTTP 404
The requested key does not exist.

### GET `/academic-status`
Get a list of all possible academic statuses.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return a list of possible academic statuses.

```json
{
	"academicStatuses": [
		{
			"academicStatusId": 101,
			"name": "Graduate Student"
		}
	]
}
```

##### HTTP 403
The JWT is invalid.

### GET `/country`
Get a list of all possible countries.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return a list of possible countries.

```json
{
	"countries": [
		{
			"countryId": 201,
			"name": "United States"
		}
	]
}
```

##### HTTP 403
The JWT is invalid.

### GET `/degree`
Get a list of all possible academic degrees.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return a list of possible academic degrees.

```json
{
	"degrees": [
		{
			"degreeId": 1,
			"name": "Bachelor's"
		}
	]
}
```

##### HTTP 403
The JWT is invalid.

### GET `/domain/<domain>`
Get information about an email domain, including whether it meets ACCESS eligibility criteria, and associated organizations and IDPs, if any.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return lists of associated organizations and IdPs for the domain. `organizations` is the full XRAS organization record for each match; `idps` is omitted for organizations that set `ignoreIdp`.

```json
{
	"domain": "example.edu",
	"organizations": [
		{
			"organizationId": 123,
			"orgTypeId": 1,
			"organizationAbbrev": "EXU",
			"organizationName": "Example University",
			"organizationUrl": "https://example.edu",
			"organizationPhone": null,
			"nsfOrgCode": null,
			"isReconciled": true,
			"amieName": null,
			"countryId": 201,
			"stateId": null,
			"latitude": null,
			"longitude": null,
			"isMsi": false,
			"isActive": true,
			"isEligible": true,
			"carnegieCategories": [],
			"state": null,
			"country": "United States",
			"orgType": "Academic",
			"ignoreIdp": false
		}
	],
	"idps": [
		{"displayName": "Example University", "entityId": "urn:mace:example.edu"}
	]
}
```

##### HTTP 403
The JWT is invalid.

##### HTTP 404
The domain is not known to ACCESS/CILogon.

### GET `/terms-and-conditions`
Get the active terms and conditions for ACCESS.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return the active terms and conditions.

```json
{
	"id": 1,
	"description": "ACCESS Terms and Conditions",
	"url": "https://access-ci.org/terms",
	"body": "Full text of the terms and conditions..."
}
```

##### HTTP 403
The JWT is invalid.

##### HTTP 404
No active terms and conditions found.
