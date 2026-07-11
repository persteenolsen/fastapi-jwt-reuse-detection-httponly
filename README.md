# 🔐 JWT Authentication API (FastAPI + PostgreSQL)

A REST API built with FastAPI demonstrating secure user authentication using JWT access tokens, refresh token rotation, refresh token reuse detection, and HttpOnly cookie-based authentication.

The project supports two authentication scenarios:

- Swagger / OpenAPI OAuth2 authentication using bearer tokens
- Vue 3 SPA authentication using HttpOnly cookies

The project uses:

- JWT access tokens
- HttpOnly cookies for browser authentication
- Refresh token rotation
- Refresh token reuse detection
- PostgreSQL refresh token tracking
- Swagger OAuth2 login support
- Vue 3 frontend integration

This project was built to explore modern backend architecture, authentication security patterns, database design, token lifecycle management, browser security, and integration testing using Python.

**Last updated:** 11-07-2026

---

# ✨ Features

- User registration and authentication
- JWT-based short-lived access tokens
- Swagger OAuth2 login support using `/token`
- Vue SPA authentication using HttpOnly cookies
- Access token stored in HttpOnly cookie
- Refresh token stored in HttpOnly cookie
- Automatic browser cookie authentication
- No JWT storage in localStorage or JavaScript memory
- Refresh token rotation
- Refresh token reuse detection
- Token family revocation after detected reuse
- Refresh tokens stored as SHA-256 hashes
- Unique refresh token identity using JWT `jti`
- Refresh token replacement tracking using `replaced_by_jti`
- Refresh token parent tracking using `parent_jti`
- Single session logout
- Logout all sessions
- Cookie cleanup during logout
- Expired and revoked refresh token cleanup
- Admin refresh token purge endpoint
- Protected API routes
- PostgreSQL database integration
- Database migrations with Alembic
- Swagger / OpenAPI documentation
- Layered backend architecture
- Manual JWT validation tests
- Manual authentication integration tests
- Vue 3 authentication client integration

---

# 🧰 Tech Stack

- Python 3.12
- FastAPI
- PostgreSQL
- SQLAlchemy
- Alembic
- PyJWT
- Pydantic
- Requests
- Vue 3
- Pinia
- Vue Router

---

# 🏗️ Project Architecture

The project follows a layered architecture to separate responsibilities:

## routes

Responsible for:

- API endpoints
- HTTP request handling
- Cookie creation and deletion
- Authentication routes

## services

Responsible for:

- Authentication logic
- Password validation
- JWT creation
- Refresh token lifecycle management
- Token rotation
- Token reuse detection

## models

Responsible for:

- SQLAlchemy database models
- Refresh token database tracking

## schemas

Responsible for:

- Pydantic request models
- Response validation

## security

Responsible for:

- Password hashing
- JWT creation
- JWT validation

## db

Responsible for:

- Database configuration
- Database sessions

## tests

Contains:

- JWT validation tests
- Authentication integration tests

The architecture is intentionally kept simple and focused on secure authentication flows.

---

# 🔐 Authentication Flow

The system supports two authentication clients.

---

# Swagger Authentication

Swagger uses the standard OAuth2 password flow.

Endpoint:

POST `/token`

Swagger receives:

- Access token
- Token type

Swagger sends future requests using:

Authorization: Bearer `<access_token>`

This flow is useful for:

- API testing
- Backend development
- External API clients

---

# Vue SPA Authentication

The Vue frontend uses cookie-based authentication.

Login endpoint:

POST `/login-cookie`

The server:

1. Validates username and password.
2. Creates an access token.
3. Creates a refresh token.
4. Stores refresh token metadata in PostgreSQL.
5. Returns authentication cookies.

The browser stores:

- `access_token` cookie
- `refresh_token` cookie

The Vue application cannot read these cookies using JavaScript.

---

# 🍪 HttpOnly Cookie Authentication

Authentication cookies are configured for browser security.

Cookie properties:

- HttpOnly
- Secure in production
- SameSite protection

Cookies:

- `access_token`
- `refresh_token`

Benefits:

- JavaScript cannot directly access authentication tokens.
- Tokens are protected from common XSS token theft scenarios.
- Browser automatically manages authentication state.
- Vue does not need to store JWT tokens.

Authentication can be performed through:

1. Swagger Authorization header
2. HttpOnly access token cookie

---

# 🔄 Refresh Token Rotation

When the access token expires:

Client sends:

POST `/refresh-token-spa`

The refresh token is automatically sent by the browser cookie mechanism.

The server validates:

- JWT signature
- Token type
- JWT expiration
- Database token record
- Revocation status

If the refresh token is valid:

1. A new access token is created.
2. A new refresh token is created.
3. The old refresh token is revoked.
4. The old token stores the replacement token reference.
5. The new token stores the parent token reference.
6. New cookies are issued.

Example:

Refresh Token A

↓

Refresh request

↓

Refresh Token A:

- revoked_at = timestamp
- replaced_by_jti = Token B

Refresh Token B:

- revoked_at = NULL
- parent_jti = Token A

This creates a traceable refresh token chain.

---

# 🛡️ Refresh Token Reuse Detection

The system detects replay attempts using previously rotated refresh tokens.

Example:

1. User logs in.
2. Server creates Refresh Token A.
3. User refreshes successfully.
4. Server creates Refresh Token B.
5. Refresh Token A becomes revoked.
6. Someone attempts to use Refresh Token A again.

The server detects:

- Token exists in database
- Token is already revoked
- Token has been replaced

The request is rejected:

401 Unauthorized

The system then revokes active refresh tokens belonging to the affected token family/user.

This protects against replay attacks using stolen refresh tokens.

---

# ⚙️ Setup Instructions

## 1. Clone Repository

    git clone <your-repository-url>

    cd <your-project-folder>

---

## 2. Create Virtual Environment

Create:

    python -m venv .venv

Activate:

Windows PowerShell:

    .venv\Scripts\activate

---

## 3. Install Dependencies

    pip install -r requirements.txt

---

## 4. Configure Environment Variables

Create a `.env` file:

    DATABASE_URL=your_postgres_connection

    SECRET_KEY=your_secret_key

    ALGORITHM=HS256

    ACCESS_TOKEN_EXPIRE_MINUTES=2

    REFRESH_TOKEN_EXPIRE_MINUTES=5

---

## 5. Run Database Migration

Create database tables:

    alembic upgrade head

---

# 🛠️ Creating New Migrations

After changing SQLAlchemy models:

Create migration:

    alembic revision --autogenerate -m "describe your change"

Apply migration:

    alembic upgrade head

---

# 🌐 Vue 3 Frontend

A companion Vue 3 frontend is available:

https://github.com/persteenolsen/vue-fastapi-jwt-reuse-detection-httponly-client

Features:

- Login using HttpOnly cookies
- Cookie-based authentication
- Automatic refresh handling
- Protected routes
- Vue Router integration
- Authentication testing

The frontend does not store JWT tokens in localStorage.

---

# 🧪 Manual Tests

The project contains two manual test suites.

---

# JWT Validation Tests

Tests JWT creation and validation without API calls.

Run:

    python -m tests.test_auth_manual

Tests:

- Valid access token
- Wrong token type rejection
- Refresh token validation
- Refresh token `jti` validation
- Expired token rejection
- Invalid signature rejection
- Invalid token rejection
- Missing token rejection

---

# Integration Authentication Tests

Tests the complete cookie authentication lifecycle.

Run:

    python -m tests.test_integration_auth

Tests:

- Cookie login flow
- HttpOnly cookie creation
- Refresh token rotation
- Refresh token reuse detection
- Logout flow
- Refresh after logout rejection
- Cleanup endpoint

---

# 📡 API Endpoints

## Public

## Swagger Login

POST `/token`

Used by Swagger OAuth2 authentication.

Returns:

- Access token
- Token type

---

## Vue Cookie Login

POST `/login-cookie`

Creates authentication cookies.

Sets:

- HttpOnly access token cookie
- HttpOnly refresh token cookie

---

## Refresh Authentication

POST `/refresh-token-spa`

Uses refresh token cookie.

Features:

- JWT validation
- Database validation
- Refresh token rotation
- Reuse detection
- Token family revocation

---

## Protected

GET `/users/me`

Returns current authenticated user.

---

GET `/protected-route`

Protected authentication test endpoint.

---

GET `/get-all-users`

Returns users.

---

## Logout

POST `/logout`

Actions:

- Revokes refresh token
- Clears authentication cookies

---

## Logout All

POST `/logout-all`

Revokes all active refresh tokens for the user.

---

## Admin

POST `/cleanup-tokens`

Removes expired and old revoked refresh tokens.

---

POST `/admin/purge-refresh-tokens`

Deletes all refresh tokens.

---

# 🛡️ Security Notes

- Passwords are securely hashed
- Access tokens are short-lived
- Refresh tokens are never exposed to JavaScript
- Authentication uses HttpOnly cookies
- Refresh tokens are rotated after successful refresh
- Old refresh tokens cannot be reused
- Refresh token reuse is detected
- Refresh tokens are stored as SHA-256 hashes
- JWT identity is tracked using `jti`
- Token replacement relationships are stored
- Token parent relationships are stored
- Database validation is performed during refresh operations
- Swagger authentication remains available through OAuth2 bearer tokens
- CORS is configured for credential-based cookie authentication

---

# 🚀 Future Improvements

- Add refresh token reuse detection alerts
- Add rate limiting
- Add pytest-based automated suite
- Add CI/CD pipeline
- Add Redis session tracking
- Add multi-device session management
- Add refresh token family identifiers
- Add dedicated CSRF protection strategy
- Add production HTTPS deployment examples

---

# 🎯 Learning Goals

- JWT authentication
- HttpOnly cookie authentication
- Refresh token rotation
- Refresh token reuse detection
- Secure token lifecycle management
- Browser authentication security
- FastAPI backend architecture
- PostgreSQL database design
- Alembic migrations
- Vue 3 frontend integration
- Authentication testing strategies
- Real-world security patterns

---

# 👨‍💻 Author

Built by Per Olsen

Backend-focused portfolio project exploring authentication systems, secure token handling, browser authentication, and scalable API design.