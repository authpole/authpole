# ⚡ Auth Pole - Mediator IDP & SPIFFE M2M Server

**Auth Pole** is a high-performance, multi-tenant Go mediator Identity Provider (IDP) and **SPIFFE M2M Provider** server. It acts as a federated authentication proxy between client applications (Service Providers / Relying Parties), upstream identity providers (Google, GitHub, Okta, SAML, or custom OIDC/OAuth2 IDPs), and machine workloads (SPIFFE SVID issuer).

Unlike Keycloak, **Auth Pole does not store or manage user credentials/user databases**. It standardizes identity claims across upstream IDPs, issues Auth Pole signed JWTs and SPIFFE SVIDs, and provides ultra-fast zero-database access path validation.

---

## 🌟 Key Benefits & Capabilities

- **Mediator Proxy IDP**: Implements standard OIDC (`/.well-known/openid-configuration`, `/oauth/v2/authorize`, `/oauth/v2/token`, `/oauth/v2/userinfo`) and federates upstream identity context without maintaining internal user passwords.
- **Machine-to-Machine (M2M) & SPIFFE Provider**:
  - Acts as a SPIFFE Identity Provider issuing standard SVIDs (`spiffe://<domain>/ns/<organization>/sa/<workload>`).
  - Workloads authenticate using long-expiry SPIFFE client certificates to request short-lived (15-min) SPIFFE JWT-SVID tokens (`/api/v1/spiffe/svid`) with fine-grained scopes.
  - Authorizing machines query `/.well-known/spiffe/bundle` to refresh CA certificates and public signing keys to validate machine requests offline.
- **Zero-Latency Access Path**: In-memory thread-safe caching (`pkg/cache`) ensures JWT token verification requests (`/api/v1/auth/validate`) execute in sub-millisecond time with zero DB or S3 reads.
- **S3 Storage with CAS Concurrency Control**: Minimal configuration, certificates, trust settings, and console RBAC are persisted in S3 (or S3-compatible emulator) with Compare-And-Swap (CAS) optimistic locking using `ETag`/`VersionID` headers.
- **Optimized Horizontal Scale & Sharding**: Partitioned by `OrganizationID:AppID` hash (excluding KeyID), ensuring that all signing keys and certs required for an application are co-located on minimal server memory nodes across a cluster.
- **Decoupled Admin Console UI**: Standalone static web application (`web/admin/`) designed to be hosted on a separate domain (e.g., `admin.authpole.io`), communicating via CORS REST APIs with real-time CAS conflict detection modals.

---

## 🚀 Quickstart

### 1. Build & Run Auth Pole Server

```bash
# Clone and build the Go binary
go build -o authpole ./cmd/server

# Start the Auth Pole server (uses built-in S3 emulator for local dev)
./authpole -port=8080 -data-dir=./data
```

Server endpoints will be active at:
- **OIDC Discovery**: `http://localhost:8080/.well-known/openid-configuration`
- **JWKS Download**: `http://localhost:8080/.well-known/jwks.json?organization=default`
- **SPIFFE SVID Endpoint**: `http://localhost:8080/api/v1/spiffe/svid`
- **SPIFFE Trust Bundle**: `http://localhost:8080/.well-known/spiffe/bundle`
- **Access Path Validation**: `http://localhost:8080/api/v1/auth/validate`
- **Admin REST API**: `http://localhost:8080/api/v1/organizations`

### 2. Global Platform Admin OAuth Credentials (Environment Variables)

System-level Google & GitHub OAuth client credentials used for signing into the Platform Admin Console are configured globally via environment variables (or AWS Secrets Manager):

```bash
export AUTHPOLE_GOOGLE_CLIENT_ID="123456789-abc.apps.googleusercontent.com"
export AUTHPOLE_GOOGLE_CLIENT_SECRET="your_google_client_secret"

export AUTHPOLE_GITHUB_CLIENT_ID="your_github_client_id"
export AUTHPOLE_GITHUB_CLIENT_SECRET="your_github_client_secret"
```

---

### 3. Launch Standalone Admin Console (`admin.*`)

The Admin Console is located in `web/admin/` as a static SPA. Serve it using any static file server:

```bash
# Serve the admin console UI
npx serve web/admin -p 3000
```
Open `http://localhost:3000` in your browser. Configure the **Auth Pole API Host** to `http://localhost:8080`.

---

## 🤖 SPIFFE M2M Workload Authentication & Cert Refresh

### 1. Workload Exchanges Long-Expiry Cert for Short-Lived SVID

```http
POST /api/v1/spiffe/svid HTTP/1.1
Host: localhost:8080
X-Organization-ID: default
X-SPIFFE-Client-Cert: -----BEGIN CERTIFICATE-----\n...
Content-Type: application/json

{
  "workload_id": "payment_service",
  "audience": "spiffe://authpole.local/ns/default",
  "requested_scopes": ["read:transactions", "write:payments"]
}
```

**Response**:

```json
{
  "svid": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiMTIzIn0...",
  "spiffe_id": "spiffe://authpole.local/ns/default/sa/payment-service",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:transactions write:payments",
  "organization_id": "default"
}
```

### 2. Authorizing Machine Refreshes Trust Bundle

```http
GET /.well-known/spiffe/bundle?organization=default HTTP/1.1
Host: localhost:8080
```

**Response**:

```json
{
  "spiffe_id": "spiffe://authpole.local/ns/default/sa/trust-bundle",
  "organization_id": "default",
  "domain": "authpole.local",
  "keys": {
    "keys": [
      { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "ab123", ... }
    ]
  },
  "version": "tb_1785632190"
}
```

---

## 🔒 Compare-And-Swap (CAS) Optimistic Locking

All persistent updates sent to Auth Pole require the current object version:

```http
POST /api/v1/admin/spiffe/workloads HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-Organization-ID: default
X-Expected-Version: v1_ab12cd34

{
  "id": "payment_service",
  "name": "Payment Processing Service",
  "spiffe_id": "spiffe://authpole.local/ns/default/sa/payment-service",
  "allowed_scopes": ["read:transactions"],
  "version": "v1_ab12cd34"
}
```

If another session updated the object in S3, Auth Pole responds with `409 Conflict`:

```json
{
  "error": "cas_conflict",
  "message": "cas conflict: current version \"v2_99ef\" != expected version \"v1_ab12cd34\""
}
```

The Admin Console UI automatically catches `409 Conflict` and prompts the user to refresh the latest data.

---

## 🧪 Unit & Integration Testing

Run the test suite with race detector enabled:

```bash
go test -v -race ./...
```
