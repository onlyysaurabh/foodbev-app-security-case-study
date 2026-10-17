# 04 — Long-Lived Bearer JWTs and Lack of Dual-Factor Session Binding

**Severity:** Medium · **CVSS v3.1:** 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
**CWE:** CWE-613 (Insufficient Session Expiration), CWE-287 (Improper Authentication)
**OWASP Categories:** OWASP MASVS-AUTH, API2:2023 Broken Authentication

> **Anonymized, educational case study.** No real tokens, signing keys, user identifiers, or live domains are included. All snippets and token structures are synthetic illustrations based on verified live-traffic telemetry.

---

## 1. Executive Summary

During the mobile API security evaluation, researchers analyzed the authentication and session management architecture governing customer accounts. Authentication relies on an HMAC-SHA256 (HS256) JSON Web Token (JWT) supplied via the standard `Authorization: Bearer <token>` HTTP header.

Analysis revealed that issued tokens possess an extraordinary validity lifespan of **approximately two years (730 days)** without automated token rotation or refresh mechanisms. Concurrently, while the mobile client transmits two opaque session cookies alongside the Bearer token, comprehensive tampering tests demonstrated that the backend completely ignores these cookies. The Bearer JWT is the **sole authentication factor**.

Consequently, any Bearer token leaked via device backups, application logging, reverse proxies, or network interception grants an attacker persistent, unrevocable account takeover lasting up to two years.

---

## 2. Token Structure & Lifespan Analysis

Network captures of authenticated traffic (e.g., retrieving customer profiles, viewing order histories, or applying promotional coupons) revealed the following JWT payload structure:

```json
// JWT Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// JWT Claims
{
  "jti": "1E366EB6-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "uid": "10492",
  "exp": 1853020800,
  "iss": "https://app.foodbev.invalid/",
  "aud": "https://app.foodbev.invalid/"
}
```

### Claims Decomposition
- `jti`: A unique UUIDv4 identifying the token instance.
- `uid`: The integer customer identification number (`CustomerId 10492`), mapping directly to the user's database record.
- `exp`: Epoch timestamp `1853020800`, corresponding to **September 20, 2028**.
- **Lifespan Calculation:** When captured during testing, the token held an active lifespan of **730 days (24 months)**.
- **Absence of Refresh Flows:** Across extensive user interactions, no token refresh endpoint (`/refresh`), token rotation, or sliding-window expiration events were observed. The single Bearer token was reused statically across all application sessions.

---

## 3. The Token Forgery & Tampering Matrix

A rigorous testing matrix comprising 13 distinct variants was executed against the authenticated customer profile endpoint (`GET /api/app/GetCustomerProfile?storeCode=STORE-124`) to evaluate signature enforcement, claim validation, and session binding.

| Test ID | Token Variant / Mutation | Cookie State | Observed Server Response | Security Conclusion |
| :--- | :--- | :--- | :--- | :--- |
| **T01** | Baseline valid token | Valid cookies | HTTP 200 OK (`CustomerId: 10492`) | Positive control baseline. |
| **T02** | No `Authorization` header | Valid cookies | HTTP 401 Unauthorized | Cookies alone cannot authenticate. |
| **T03** | Malformed / Garbage token | Valid cookies | HTTP 401 Unauthorized | Rejects unparseable tokens. |
| **T04** | `alg: "none"` (Empty signature) | Valid cookies | HTTP 401 Unauthorized | Protected against `alg:none` bypass. |
| **T05** | `alg: "none"` (Dummy signature) | Valid cookies | HTTP 401 Unauthorized | Protected against `alg:none` bypass. |
| **T06** | Modified claim: `uid: 10493` | Valid cookies | HTTP 401 Unauthorized | Signature verifies payload integrity. |
| **T07** | Modified claim: `uid: 1` (Admin) | Valid cookies | HTTP 401 Unauthorized | Horizontal/vertical escalation rejected. |
| **T08** | Modified claim: `exp: 1000000000` | Valid cookies | HTTP 401 Unauthorized | Signature invalidated by claim edit. |
| **T09** | Modified claim: `jti` replaced | Valid cookies | HTTP 401 Unauthorized | Signature invalidated by claim edit. |
| **T10** | Single-byte flip in signature | Valid cookies | HTTP 401 Unauthorized | Cryptographic signature enforced. |
| **T11** | Modified `iss` / `aud` claims | Valid cookies | HTTP 401 Unauthorized | Signature invalidated by claim edit. |
| **T12** | Valid Bearer JWT | **Cookies Removed** | **HTTP 200 OK (`CustomerId: 10492`)** | **Cookies are purely decorative!** |
| **T13** | Valid Bearer JWT | **Garbage Cookies** | **HTTP 200 OK (`CustomerId: 10492`)** | **Cookies are completely ignored!** |

---

## 4. Analysis of Behavioral Findings

### 1. Robust Cryptographic Signature Verification
Tests T04 through T11 confirmed that the backend's JWT middleware correctly enforces cryptographic HMAC-SHA256 signature verification:
- The server does not support `alg: none` downgrades.
- The JWT header contains no `kid`, `jku`, or `x5u` headers, eliminating common key-confusion or remote JWKS injection vectors.
- A targeted offline dictionary attack using 265 app-specific, brand, and standard dictionary secrets against the captured signature yielded zero matches, confirming that the HMAC secret is sufficiently complex and not trivially guessable.

### 2. Decorative Cookie Vulnerability
In addition to the Bearer token, the mobile client consistently transmitted two opaque cookies:
- `sessionUserData = "a1b2c3d4..."` (16-byte hex blob)
- `sessionMobileData = "e5f6g7h8..."` (16-byte hex blob)

However, tests **T12 and T13** definitively proved that stripping these cookies entirely or replacing them with arbitrary strings had zero effect on authentication. The backend API solely inspects the `Authorization: Bearer` header. The cookies serve no binding or dual-factor session role.

### 3. The 2-Year Exposure Window
Because the Bearer token is the single factor and lives for 24 months:
- If a user connects via an untrusted Wi-Fi hotspot lacking certificate pinning, an intercepted token provides two years of uninterrupted access.
- If a device is backed up, inspected via Android Debug Bridge (`adb backup` / logcat), or decommissioned, the token remains fully active.
- There is no observed server-side revocation mechanism: logging out on the client app simply discards the token locally while the token itself remains completely valid on the backend.

---

## 5. Technical Root Cause Analysis

The flaw stems from ASP.NET JWT Bearer middleware configured with static, extended lifetimes and an absence of a dual-token access/refresh lifecycle.

### Insecure JWT Configuration (Illustrative C# / ASP.NET)

```csharp
// INSECURE STARTUP CONFIGURATION
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"])),
            ValidateIssuer = true,
            ValidIssuer = "https://app.foodbev.invalid/",
            ValidateAudience = true,
            ValidAudience = "https://app.foodbev.invalid/",
            
            // ANTI-PATTERN: Blindly trust long exp claim without server-side revocation check
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };
        // Lacks OnTokenValidated event to check user token version or revocation list!
    });
```

---

## 6. Remediation & Fixed Pattern

Modern mobile API architectures must decouple short-lived authorization from long-term session persistence:

```
┌────────────────────────────────────────────────────────┐
│                   Mobile Client                        │
└──────────────┬─────────────────────────┬───────────────┘
               │                         │
     Short-Lived Access (15m)    Long-Lived Refresh (30d)
     (In-Memory Only)            (Encrypted Android Keystore)
               │                         │
               ▼                         ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│     Protected API Gateway    │ │  Auth / Refresh API   │
│   • Validates 15-min JWT     │ │  • Rotates Refresh    │
│   • Checks Token Version     │ │  • Detects Token Reuse│
└──────────────────────────────┘ └───────────────────────┘
```

1. **Short Access Token Lifespan:** Reduce the validity period of access tokens to **15 minutes**.
2. **Rotating Refresh Tokens:** Issue cryptographically random, single-use refresh tokens stored securely in Android Keystore / `EncryptedSharedPreferences`. Each refresh request issues a new access token and a new refresh token while invalidating the old one.
3. **Automatic Reuse Detection:** If an invalidated refresh token is ever presented, the backend must assume a breach and revoke the entire refresh token family for that user.
4. **Server-Side Revocation (Token Versioning):** Store an integer `token_version` on the user's database record. Include this version in the JWT claims. Whenever a user logs out, changes passwords, or reports a lost device, increment `token_version` in the database to instantly invalidate all outstanding tokens.

### Fixed ASP.NET JWT Validation & Revocation Event

```csharp
// SECURE JWT CONFIGURATION WITH ACTIVE REVOCATION
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"])),
            ValidateIssuer = true,
            ValidIssuer = "https://app.foodbev.invalid/",
            ValidateAudience = true,
            ValidAudience = "https://app.foodbev.invalid/",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // Strict clock validation
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
                var userIdClaim = context.Principal.FindFirst("uid")?.Value;
                var tokenVersionClaim = context.Principal.FindFirst("ver")?.Value;

                if (!int.TryParse(userIdClaim, out int userId) || !int.TryParse(tokenVersionClaim, out int tokenVersion))
                {
                    context.Fail("Invalid token claims.");
                    return;
                }

                // Verify token version against live database user record
                var user = await db.Users.FindAsync(userId);
                if (user == null || user.TokenVersion != tokenVersion)
                {
                    context.Fail("Token has been revoked or session expired.");
                }
            }
        };
    });
```

---

## 7. Verification & Defender Playbook

### Token Expiration Audit
Inspect captured tokens using JWT decoding tools:
```bash
# Decode JWT payload and compute lifespan in days
echo "<BEARER_JWT>" | cut -d. -f2 | base64 -d 2>/dev/null | jq '
  {
    issued_at: (.iat // "Not set"),
    expires_at: .exp,
    lifespan_days: ((.exp - (.iat // 1726900000)) / 86400)
  }'

# Target: Lifespan must be <= 0.01 days (15 minutes). Any value > 1 day must be flagged as High Risk.
```

### Cookie Independence Test
```bash
# Test profile endpoint with Bearer token but without cookies
curl -s -o /dev/null -w "%{http_code}\n" \
  https://app.foodbev.invalid/api/app/GetCustomerProfile \
  -H "Authorization: Bearer <VALID_JWT>"

# Assert: If this returns 200 OK, the application relies solely on the bearer token.
```
