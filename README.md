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

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
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

### POST `/auth/send-otp`
Send a one-time password (OTP) to the specified email, if it exists. In order to avoid revealing whether the email has an associated account, we should send the OTP regardless of whether the domain is allowed by ACCESS. Prohibited domains will be flagged after the user enters the OTP.

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

### POST `/auth/login`
Start the CILogon authentication flow.

#### Request Body
The preferred IDP can be included in the request body. Otherwise, the user is prompted to select an IDP by CILogon.

```json
{
	"idp": "<optional IDP identifier>"
}
```

#### Response Types

##### HTTP 307
Redirect to the CILogon URL to start the login process.

##### HTTP 400
The redirect could not be sent (e.g., due to a malformed email address).

### GET `/auth/login`
Receive the CILogon token after a successful login, and redirect to the front end URL.

#### Query Parameters
- `token`: The token from CILogon

#### Response Types

##### HTTP 307
Redirect to the account frontend URL with these query string parameters:
- `jwt`: a JWT of type `login`
- `first_name`: the given_name OIDC claim, if provided by the IDP.
- `last_name`: the family_name OIDC claim, if provided by the IDP.

### POST `/account`
Create a new account.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Request Body
```json
{
	"firstName": "Jane",
	"lastName": "Doe",
	"organizationId": 123
}
```

#### Response Types

##### HTTP 200
The account was created.

##### HTTP 400
The input failed validation (e.g., the organization does not match the e-mail domain or an account for that email address already exists). Return an error message indicating the problem.

```json
{
	"error": "Organization does not match email domain."
}
```

##### HTTP 403
The JWT is invalid.

### GET `/account/<username>`
Get the profile for the given account.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Response Types

##### HTTP 200
Return the profile information for the user.

```json
{
	"username": "jdoe",
	"email": "jdoe@example.edu",
	"firstName": "Jane",
	"lastName": "Doe",
	"organizationId": 123
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to access the account.

##### HTTP 404
The requested user does not exist.

### POST `/account/<username>`
Update the profile information for an account.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Request Body
If email is different from the email in the Authorization header (i.e., the user is changing their email address), a valid `emailJWT` of type `otp` must be provided to prove that the user owns the new email address. The new email domain must also match organizationId.

```json
{
	"firstName": "Jane",
	"lastName": "Doe",
	"email": "jdoe2@other.edu",
	"emailJWT": "<jwt_for_jdoe2>",
	"organizationId": 123
}
```

#### Response Types

##### HTTP 200
The account profile was updated.

##### HTTP 400
The input failed validation (e.g., the organization does not match the e-mail domain). Return an error message indicating the problem.

```json
{
	"error": "Country of residence is not the United States."
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
	"error": "Passwords must be at least 12 characters."
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to update the password.

### GET `/account/<username>/identity`
Get a list of identities associated with this account.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username, or be an administrative user.

#### Response Types

##### HTTP 200
Return the list of linked identities and associated IDPs.

```json
{
	"identities": [
		{
			"identityId": 15,
			"username": "jdoe15",
			"idp": {}
		}
	]
}
```

##### HTTP 403
The JWT is invalid or the user does not have permission to access the account.

##### HTTP 404
The requested user does not exist.

### POST `/account/<username>/identity`
Start the process of linking a new identity.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Response Types

##### HTTP 307
Redirect to CILogon to start the linking flow. At the end of the flow, CILogon redirects back to `/auth/login` with the OIDC token, indicating that the API should link the new identity to the account.

##### HTTP 403
The JWT is invalid or the user does not have permission to modify the account.

### DELETE `/account/<username>/identity/<identity_id>`
Delete a linked identity.

#### Request Headers
- `Authorization`: containing a JWT of type `login`. The uid claim must match the requested username.

#### Response Types

##### HTTP 200
The linked identity was deleted.

##### HTTP 400
The specified identity cannot be deleted (e.g., it is the last one associated with this account). Return a message describing the problem.

```json
{
	"error": "Each account must have at least one identity."
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
The provided key is not valid or is already associated with another account. Return a message describing the problem.

```json
{
	"error": "Invalid public key."
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

### GET `/domain/<domain>`
Get information about an email domain, including whether it meets ACCESS eligibility criteria, and associated organizations and IDPs, if any.

#### Request Headers
- `Authorization`: containing a JWT of type `otp` or `login`.

#### Response Types

##### HTTP 200
Return lists or associated organizations and idps for the domain.

```json
{
	"domain": "example.edu",
	"organizations": [],
	"idps": []
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
