# 06 — Sensitive Identifiers in Query Strings, Verbose Exceptions, and Catalog Reconnaissance Exposure

**Severity:** Low / Informational · **CVSS v3.1:** 4.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
**CWE:** CWE-200 (Exposure of Sensitive Information), CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-359 (Exposure of Private Personal Information)
**OWASP Categories:** OWASP MASVS-CODE, OWASP MASVS-STORAGE

> **Anonymized, educational case study.** No real phone numbers, database connection strings, or corporate staging URLs are included. All snippets, error traces, and endpoints are synthetic illustrations based on verified live-traffic telemetry.

---

## 1. Executive Summary

During the reconnaissance and static analysis phases of the mobile platform evaluation, several low-severity and informational flaws were identified. While individually non-critical, in aggregate these weaknesses significantly facilitate attacker reconnaissance, backend technology fingerprinting, and customer privacy leakage.

Key findings include:
1. Customer phone numbers transmitted within unauthenticated `GET` query strings, exposing Personally Identifiable Information (PII) to intermediary network logs and caching proxies.
2. Verbose backend exceptions disclosing database engine specifics (Microsoft SQL Server `OFFSET` clauses and `uniqueidentifier` types), .NET framework stack traces (`NullReferenceException`), and internal model-binding schemas.
3. An excessively broad unauthenticated catalog surface enabling cross-store data scraping and reconnaissance.
4. Production-mirrored UAT staging infrastructure hosting publicly accessible administrative login interfaces, alongside insecure Android manifest network permissions (`usesCleartextTraffic=true`).

---

## 2. Customer Phone Numbers in Unauthenticated Query Strings

Multiple promotional and banner discovery endpoints require or accept the customer's mobile telephone number directly within `GET` query parameters:

```http
GET /api/app/Get_CouponCodeListDynamic?MobileNo=9999999999&storeCode=STORE-124 HTTP/1.1
Host: app.foodbev.invalid

GET /api/app/GetNewBannerList?storeCode=STORE-124&pageId=2&mobileNo=9999999999 HTTP/1.1
Host: app.foodbev.invalid
```

### Behavioral Analysis
- **Decorative Nature:** Live fuzzing demonstrated that the `MobileNo` / `mobileNo` parameter is functionally decorative. Submitting a fictitious, randomized number or omitting the parameter returned the exact same public coupon list and banner promotional images.
- **Privacy Impact:** Despite being decorative on the backend, transmitting user mobile numbers in URL query strings violates basic privacy standards:
  - **Access Log Retention:** Query strings are recorded in plaintext across reverse proxies (IIS/Nginx), API gateways, content delivery networks (CDNs), and corporate web application firewalls (WAFs).
  - **Browser & Device Caching:** Mobile OS webviews, proxy debuggers (e.g., HTTP Toolkit, Charles), and local system logs record full URLs indefinitely.
  - **Referer Leakage:** If banners or external links are rendered, the `Referer` HTTP header can leak customer mobile numbers to third-party ad networks or analytics services.

---

## 3. Verbose Exception Disclosures & Database Stack Leaks

The backend application frequently returns unhandled .NET exceptions, database syntax errors, and RFC 9110 model validation details when supplied with missing or malformed inputs:

### 1. SQL Server `uniqueidentifier` Conversion Error
When an invalid key type is submitted to the order bill endpoint (`GET /api/app/Get_Order_Bill_Detail?OrderId=1` or `OrderId=invalid-text`), the server returns HTTP 400 Bad Request with:
```json
{
  "success": false,
  "message": "Conversion failed when converting from a character string to uniqueidentifier."
}
```
**Impact:** Confirms the backend database is Microsoft SQL Server and informs the attacker that the primary key column is a GUID (`uniqueidentifier`).

### 2. SQL Server OFFSET Clause Disclosure
When the order pagination endpoint (`GET /api/app/Get_CustomerBy_AllOrder_List_Pagination`) is called without required pagination parameters (`PageNumber` and `PageSize`), the backend returns:
```json
{
  "success": false,
  "message": "The offset specified in a OFFSET clause may not be negative."
}
```
**Impact:** Discloses internal SQL Server query construction (confirming queries utilize `ORDER BY ... OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY`). While strong framework model-binding prevented SQL injection via string parameters (non-integers were rejected by ASP.NET before query execution), the error leaks internal database query syntax.

### 3. ASP.NET NullReferenceException Leakage
Submitting an empty JSON object to subscription endpoints (`POST /api/app/Get_Order_SubscriptionCardItem_applyV1 {}`) yields:
```json
{
  "success": false,
  "message": "Object reference not set to an instance of an object."
}
```
**Impact:** Discloses unhandled .NET `System.NullReferenceException` faults, indicating an absence of defensive null-safety guards.

### 4. OTP Endpoint Schema Enumeration
Sending an empty body to the OTP verification endpoint (`POST /api/app/VerifyOTP {}`) returns an RFC 9110 validation structure:
```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "errors": {
    "otp": ["The otp field is required."],
    "fcmToken": ["The fcmToken field is required."],
    "appPlatform": ["The appPlatform field is required."]
  },
  "traceId": "00-4b2a8d3e91f04c6a9b4d8a1e2f3c4b5a-6a7b8c9d0e1f2a3b-00"
}
```
**Impact:** Discloses the exact internal variable names expected by authentication microservices without requiring decompilation of the mobile client.

---

## 4. Over-Exposed Public Catalog & Staging Reconnaissance

### Cross-Store Menu & Store Directory Harvesting
The platform exposes broad unauthenticated read access across its retail network:
- `GET /api/app/GetStoreList`: Returns the full directory of all retail locations, including exact GPS coordinates, manager contact phone numbers, GSTIN tax registration numbers, and FSSAI food hygiene license numbers.
- `GET /api/app/GetCategoryList/{storeCode}`: Passing arbitrary store identifiers (e.g., `/GetCategoryList/STORE-109`) allows remote attackers to pull item catalogs, pricing variations, and localized stock availability across regional stores without authentication or geo-fencing.

### Staging / UAT Surface Exposure
Reconnaissance identified an active user acceptance testing (UAT) domain (`app.uat.foodbev.invalid`):
- **Full API Mirror:** The UAT domain mirrored the exact route map of production.
- **Administrative Portal:** Accessing the root path (`https://app.uat.foodbev.invalid/`) returned an active ASP.NET MVC administrative portal: **"Admin User Login"** (`POST /admin/validateLogin`).
- **Data Cross-Pollination:** Corporate banners served on production referenced asset URLs hosted on the UAT domain (`app.uat.foodbev.invalid/uploads/Corporate/...`), revealing mixed environment dependencies.

### Android Application Configuration Issues
Static analysis of `AndroidManifest.xml` and decompiled resources revealed:
- `android:usesCleartextTraffic="true"`: Cleartext HTTP traffic was enabled across the entire application without a restrictive `networkSecurityConfig.xml` file.
- Embedded Third-Party Keys: Client resources (`res/values/strings.xml`) contained Google API keys (`AIzaSy...`). While standard for maps SDKs, lack of API restrictions allows key quota exhaustion.

---

## 5. Technical Root Cause Analysis

### Vulnerable Global Exception Handling (Illustrative C#)

```csharp
// ANTI-PATTERN: Direct Exception Exposure in Controller
[HttpPost("VerifyOTP")]
public async Task<IActionResult> VerifyOTP([FromBody] OtpVerificationRequest request)
{
    try
    {
        // Business logic...
        return Ok(new { success = true });
    }
    catch (Exception ex)
    {
        // ANTI-PATTERN: Echoing internal exception details to client
        return BadRequest(new { success = false, message = ex.Message });
    }
}
```

---

## 6. Remediation & Hardening Roadmap

1. **Remove PII from URLs:** Deprecate `MobileNo` and `mobileNo` query parameters on all `GET` endpoints. Extract customer identity exclusively from validated claims within the `Authorization: Bearer` JWT token.
2. **Global Exception Handling Middleware:** Implement centralized exception handling in ASP.NET that logs raw exception details and stack traces to internal logging infrastructure while returning generic, opaque error payloads with correlation IDs (`traceId`) to the client.
3. **Network Security Configuration:** Set `android:usesCleartextTraffic="false"` in `AndroidManifest.xml` and enforce strict TLS 1.3 requirements via an explicit `network_security_config.xml`.
4. **Isolate Staging & Admin Portals:** Place staging infrastructure (`uat.*`) and administrative panels (`/admin/*`) behind corporate VPNs or IP allowlists, completely segregating test databases from production endpoints.

### Fixed ASP.NET Global Exception Handler

```csharp
// SECURE GLOBAL EXCEPTION HANDLING MIDDLEWARE
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            var traceId = Activity.Current?.Id ?? context.TraceIdentifier;
            
            // Log full exception details internally with trace context
            _logger.LogError(ex, "Unhandled exception occurred. TraceId: {TraceId}", traceId);

            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            context.Response.ContentType = "application/json";

            // Return sanitized, opaque response to client
            var response = new
            {
                success = false,
                message = "An unexpected error occurred. Please contact support.",
                traceId = traceId
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}
```

---

## 7. Verification & Defender Playbook

### Error Disclosure Fuzzing (Bash)
```bash
# Test for raw exception disclosure on malformed input
curl -s -X POST https://app.foodbev.invalid/api/app/Get_Order_SubscriptionCardItem_applyV1 \
  -H "Content-Type: application/json" -d "{}" | grep -Ei "exception|nullreference|syntax|uniqueidentifier"

# Assert: The response must return generic error messages without stack or type traces.
```

### URL Parameter Audit
```bash
# Search mobile traffic captures for sensitive identifiers in query parameters
grep -E "\?(.*)(mobile|phone|email|token|ssn)=" traffic/captures/*.har
```
