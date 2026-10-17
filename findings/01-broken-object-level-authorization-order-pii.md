# 01 — Broken Object-Level Authorization (BOLA / IDOR) on Order-Detail APIs Discloses Full Customer PII

**Severity:** High · **CVSS v3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-200 (Exposure of Sensitive Information), CWE-209 (Generation of Error Message Containing Sensitive Information)
**OWASP Categories:** API1:2023 Broken Object Level Authorization, OWASP MASVS-AUTH

> **Anonymized, educational case study.** No real hostnames, live credentials, customer identifiers, or active endpoints are included. All snippets, endpoints, and identifiers are synthetic illustrations based on verified real-world findings.

---

## 1. Executive Summary

During a black-box security assessment of a mobile food and beverage ordering platform, multiple backend order-detail endpoints were discovered to serve complete customer order records **without requiring any authentication**. An anonymous remote caller providing only a target order GUID (`OrderId`) receives the exact same sensitive order record, byte-for-byte, as the authenticated customer who placed the order.

The exposed data includes the customer's full name, mobile telephone number, full physical delivery address, detailed itemized cart contents with customized variant options, applied promotional codes, financial and tax breakdowns, and an unexpired, signed URL to the customer's live tax invoice. The invoice itself is anonymously fetchable and exposes additional personal data.

Furthermore, a separate sequential order-status endpoint permits authenticated users to enumerate integer order numbers, leaking the corresponding internal `OrderId` GUIDs and bridging the gap between unguessable GUIDs and automated mass data harvesting.

---

## 2. Affected Endpoints

All endpoints operate under the primary API namespace (`/api/app/`):

| Method | Endpoint Path | Authentication Required | Observed Anonymous Response |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/app/Get_Order_Bill_Detail?OrderId={guid}` | **None** (Static headers only) | HTTP 200 OK — Full order record (`data[1]`), byte-identical to owner |
| `GET` | `/api/app/Get_Order_Bill_Detail_By_OrderId?orderId={guid}` | **None** (Static headers only) | HTTP 200 OK — Full order record with extended PII and signed invoice |
| `GET` | `/api/app/GetReOrderList?OrderId={guid}` | **None** (Static headers only) | HTTP 200 OK — Complete re-cart structure byte-identical to owner |
| `GET` | External Signed Invoice URL (`apps.invoice-service.invalid/...&_sign=`) | **None** (Publicly fetchable) | HTTP 200 OK (`text/html`, ~6.5 KB) — Rendered tax invoice with PII |
| `GET` | `/api/app/GetOrderStatus?orderNo={int}` | Authenticated (Any valid Bearer) | HTTP 200 OK — Exposes store coordinates and internal `OrderId` GUID |

---

## 3. Empirical Proof of Anonymous Access

To establish that the authorization control was completely non-existent rather than merely flawed in scope, the assessment utilized **positive controls on the researcher's own account only**. Six real orders were placed on the platform using the researcher's own credentials. Zero third-party customer records were accessed.

When querying `/api/app/Get_Order_Bill_Detail?OrderId=<OWN_ORDER_GUID>`:
1. **Authenticated Baseline (Owner):** The request was sent with the owner's valid HS256 Bearer JWT and session cookies. The API returned HTTP 200 OK with the full order JSON payload.
2. **Anonymous Replay:** The exact same request was repeated with the `Authorization` header completely removed and all session cookies stripped, sending only the static application identification headers (`domainname` and `authcode`).
3. **Cryptographic Parity:** The SHA-256 hash of the response body returned to the anonymous caller was **identical** to the SHA-256 hash of the response returned to the authenticated owner:
   $$\text{SHA256}(\text{Response}_{\text{Authenticated}}) == \text{SHA256}(\text{Response}_{\text{Anonymous}})$$

The authorization filter did not perform any check on the caller's identity; the `Authorization` header was ignored dead weight on these endpoints.

---

## 4. Granular Inventory of Disclosed PII

The data returned by `Get_Order_Bill_Detail` and `Get_Order_Bill_Detail_By_OrderId` constitutes a complete breach of customer privacy:

### Customer Identity & Contact Data
- **CustomerName:** Full legal name of the user.
- **MobileNo:** Customer's registered 10-digit mobile telephone number.
- **CustAddress:** Detailed physical delivery street address, building/flat details, and landmark.
- **CustomerSubscriptionId:** Internal UUID identifying the customer's subscription profile.

### Physical Store & Geolocation Metadata
- **StoreCode & StoreName:** Physical store identification.
- **Store Address:** Full address, city, state, and postal ZIP code of the fulfillment outlet.
- **ContactNo:** Direct phone number of the retail store.
- **GSTIN & FSSAI:** Legal tax identification and food safety registration numbers.
- **Store Coordinates:** Granular latitude and longitude coordinates.

### Order Contents & Pricing Details
- **Item Breakdown:** `ItemId`, `CategoryId`, `ItemRefId`, `ItemName`, `ItemUrl` (image CDN link).
- **Variant Selections:** Specific custom options (`OptionNames`, e.g., milk type, flavor syrups, add-ons).
- **Pricing Breakdown:** `Qty`, `UnitPrice`, `ItemPrice`, `ItemActualPrice`, `TotalItemPrice`, `ItemSubTotal`.
- **Financial Metadata:** `CartAmount`, `Discount`, `TotalAmount`, `GSTPercentageAmount`, `TotalGST`, `TIPAmount`, `PaymentMethod`.
- **Fulfillment:** `DeliveryType` (Takeout/Delivery), `DeliveryCharge`, `OrderDate`, `OrderEventStatus`, `OrderStatusNo`.

### Promotional & Sensitive Identifiers
- **CouponCode:** The exact coupon code redeemed on the order. This leaks single-use or confidential campaign promo codes that had previously been applied.
- **POSInvoiceNumber:** Point-of-sale invoice number sequence (e.g., `STORE/26-27/13728`).
- **InvoiceUrl:** A signed URL allowing anyone holding it to view the live invoice.
- **FinalShareOrderDetail:** Marketing share text and dynamic short-link.

---

## 5. Anonymous Invoice Exfiltration

The `InvoiceUrl` field returned by `Get_Order_Bill_Detail_By_OrderId` points to an external cloud-hosted point-of-sale document:

```http
https://apps.invoice-service.invalid/be/order?id=200102&uuid=3c285e2b-xxxx-xxxx-xxxx-xxxxxxxxxxxx&_sign=a9f1b8c7...
```

Investigation revealed:
1. **No Session Requirement:** An anonymous `GET` request to this signed URL returns HTTP 200 OK (`Content-Type: text/html; charset=utf-8`, 6,585 bytes).
2. **PII in Rendered Document:** The rendered HTML document contains the customer's full name, masked phone number, order date, order number, store location, and itemized billing breakdown.
3. **Flawed Cryptographic Scoping:** While the URL relies on a cryptographic HMAC parameter (`_sign`) to prevent URL tampering, the signature parameter is **directly handed out to unauthenticated callers** by the vulnerable order-detail endpoint. The signature provides zero access control against anyone querying the API.

---

## 6. The Three-State Anonymous GUID Validation Oracle

Testing revealed that the `/api/app/Get_Order_Bill_Detail` endpoint exposes a three-state oracle that allows an unauthenticated attacker to validate whether candidate GUIDs exist:

```
┌───────────────────────────────────────┐
│     Client Request (Anonymous)        │
│   GET /Get_Order_Bill_Detail?OrderId= │
└──────────────────┬────────────────────┘
                   │
      ┌────────────┴────────────┐
      ▼                         ▼
[Malformed Input]       [Valid UUIDv4 Shape]
(e.g., OrderId=1)               │
      │                         │
      ▼                         ├────────────────────────┐
HTTP 400 Bad Request            ▼                        ▼
"Conversion failed to     [Non-Existent GUID]    [Existing Order GUID]
 uniqueidentifier"              │                        │
                                ▼                        ▼
                        HTTP 200 OK              HTTP 200 OK
                        {"success": true,        {"success": true,
                         "data": []}              "data": [OrderRecord]}
                        (Empty Array)            (Populated Array)
```

1. **State 1: Type Validation Error (HTTP 400 Bad Request):**
   Passing an integer or non-GUID string (e.g., `OrderId=1`) yields:
   ```json
   {
     "success": false,
     "message": "Conversion failed when converting from a character string to uniqueidentifier."
   }
   ```
   This confirms the database engine (Microsoft SQL Server) and the underlying column type (`uniqueidentifier`).
2. **State 2: Non-Existent Identifier (HTTP 200 OK):**
   Passing a well-formed UUIDv4 that does not exist in the database (e.g., the nil GUID `00000000-0000-0000-0000-000000000000` or a randomly generated UUID) returns:
   ```json
   {
     "success": true,
     "data": []
   }
   ```
3. **State 3: Existing Order Hit (HTTP 200 OK):**
   Passing an active customer `OrderId` returns HTTP 200 with `data` populated with the complete order record.

This oracle enables attackers holding candidate lists (from logs, cache leaks, or third-party breaches) to verify order validity without credentials.

---

## 7. The Sequential Order Enumeration Bridge

While UUIDv4 identifiers are computationally infeasible to brute-force randomly ($2^{122}$ search space), the application implements an integer-based order sequence endpoint that bridges the gap:

```http
GET /api/app/GetOrderStatus?orderNo=200101 HTTP/1.1
Host: app.foodbev.invalid
Authorization: Bearer <ANY_AUTHENTICATED_USER_JWT>
```

Behavior observed across sequential integer values:
- **Sequential Integer Keys:** Order numbers increment sequentially (`200101`, `200102`, `200103`...).
- **Authenticated Access:** The endpoint requires a valid customer Bearer JWT (it rejects anonymous requests with HTTP 401 Unauthorized).
- **Internal Identifier Exposure:** When querying an active order, the response returns internal routing and database identifiers:
  ```json
  {
    "success": true,
    "data": [
      {
        "OrderNo": 200101,
        "OrderId": "12f03d02-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "StoreCode": "STORE-124",
        "StoreName": "City Kiosk",
        "Latitude": 28.6139,
        "Longitude": 77.2090,
        "OrderStatus": "Collected",
        "TotalQty": 1
      }
    ]
  }
  ```
- **The Exploit Chain & Tenant Isolation Analysis:**
  1. An attacker obtains a standard customer account to acquire a valid Bearer JWT.
  2. The attacker queries `GetOrderStatus` with known or candidate integer order numbers to retrieve corresponding `OrderId` GUIDs. *(Note: During testing with researcher-controlled orders, querying active positive controls confirmed that internal `OrderId` GUIDs are returned. While historical non-owned order queries returned empty `data: []` arrays on this tenant, any misconfiguration or unpartitioned order state bridging integer lookups across customers exposes candidate GUIDs).*
  3. The attacker takes candidate `OrderId` GUIDs and queries `Get_Order_Bill_Detail_By_OrderId` **anonymously** (completely unauthenticated) to exfiltrate the full customer PII, order contents, and signed invoice.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker (Low-Privilege User)
    participant StatusAPI as /GetOrderStatus (Gated)
    participant BillAPI as /Get_Order_Bill_Detail (Unauthenticated)
    participant InvoiceCDN as External Invoice Service

    Attacker->>StatusAPI: GET ?orderNo=200101 (Bearer Token)
    Note over StatusAPI: Internal handle exposure;<br/>Leaks internal OrderId GUID
    StatusAPI-->>Attacker: 200 OK: Leaks internal OrderId GUID
    
    Attacker->>BillAPI: GET ?OrderId=<HARVESTED_GUID> (No Auth Header)
    Note over BillAPI: Completely unauthenticated!<br/>Direct database object fetch
    BillAPI-->>Attacker: 200 OK: Full Customer PII + Signed Invoice URL
    
    Attacker->>InvoiceCDN: GET <Signed Invoice URL> (No Auth)
    InvoiceCDN-->>Attacker: 200 OK: HTML Tax Receipt with Name & Phone
```

---

## 8. Root Cause Analysis

The flaw originates from an absence of authorization filters on public controller actions, combined with direct query lookups that omit customer tenancy checks.

### Vulnerable ASP.NET Controller Pattern (Illustrative)

```csharp
// VULNERABLE CONTROLLER IMPLEMENTATION
[ApiController]
[Route("api/app")]
public class OrderController : ControllerBase
{
    private readonly ApplicationDbContext _db;

    public OrderController(ApplicationDbContext db)
    {
        _db = db;
    }

    // MISSING [Authorize] attribute completely!
    [HttpGet("Get_Order_Bill_Detail_By_OrderId")]
    public async Task<IActionResult> GetOrderBillDetailByOrderId([FromQuery] Guid orderId)
    {
        // Direct database lookup using caller-supplied GUID with no user binding
        var order = await _db.Orders
            .Include(o => o.LineItems)
            .Include(o => o.Store)
            .FirstOrDefaultAsync(o => o.OrderId == orderId);

        if (order == null)
        {
            // Leaks existence oracle (200 with empty array)
            return Ok(new { success = true, data = Array.Empty<object>() });
        }

        // Returns full sensitive PII to any anonymous caller
        return Ok(new { success = true, data = new[] { order } });
    }
}
```

---

## 9. Remediation & Fixed Pattern

To properly secure the order architecture:
1. **Enforce Mandatory Authentication:** Apply `[Authorize]` attributes to all order-related controllers and actions.
2. **Enforce Tenancy / Ownership Verification:** Extract the caller's unique customer ID (`uid`) from the verified JWT claims and ensure the requested order belongs to that customer.
3. **Eliminate the Existence Oracle:** Return a uniform HTTP 404 Not Found response whenever an order does not exist or does not belong to the caller.
4. **Scope and Expire Invoice URLs:** Sign invoice URLs with short expirations (e.g., 15 minutes) bound to the owner's session, or route invoice downloads through an authenticated proxy endpoint.

### Fixed ASP.NET Controller Implementation

```csharp
// SECURE CONTROLLER IMPLEMENTATION
[Authorize] // Enforce JWT Bearer authentication globally
[ApiController]
[Route("api/app")]
public class OrderController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IInvoiceSigningService _invoiceSigner;

    public OrderController(ApplicationDbContext db, IInvoiceSigningService invoiceSigner)
    {
        _db = db;
        _invoiceSigner = invoiceSigner;
    }

    [HttpGet("Get_Order_Bill_Detail_By_OrderId")]
    public async Task<IActionResult> GetOrderBillDetailByOrderId([FromQuery] Guid orderId)
    {
        // 1. Extract authenticated caller identity from verified claims
        var callerIdClaim = User.FindFirst("uid")?.Value;
        if (!int.TryParse(callerIdClaim, out int callerId))
        {
            return Unauthorized(new { success = false, message = "Invalid caller claims." });
        }

        // 2. Query order strictly filtered by BOTH OrderId AND CustomerId (Tenancy Check)
        var order = await _db.Orders
            .Include(o => o.LineItems)
            .Include(o => o.Store)
            .FirstOrDefaultAsync(o => o.OrderId == orderId && o.CustomerId == callerId);

        // 3. Return uniform 404 for non-existent OR unauthorized orders (No Oracle)
        if (order == null)
        {
            return NotFound(new { success = false, message = "Order not found." });
        }

        // 4. Generate time-limited, session-bound invoice URL
        order.InvoiceUrl = _invoiceSigner.GenerateScopedUrl(
            orderId: order.OrderId, 
            customerId: callerId, 
            validity: TimeSpan.FromMinutes(15)
        );

        return Ok(new { success = true, data = new[] { order } });
    }
}
```

---

## 10. Verification & Detection Playbook (Defenders)

### Automated Regression Unit Test
```csharp
[Fact]
public async Task GetOrderBillDetail_WhenCalledByUnauthorizedUser_ReturnsNotFound()
{
    // Arrange: User B attempts to access User A's order
    var userAOrder = await CreateTestOrderAsync(customerId: 101);
    var client = Factory.CreateAuthenticatedClient(customerId: 102);

    // Act
    var response = await client.GetAsync($"/api/app/Get_Order_Bill_Detail_By_OrderId?orderId={userAOrder.OrderId}");

    // Assert: Must return 404, never 200 and never 400
    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
}
```

### Log Hunting & SIEM Alerting
- Monitor API gateway logs for requests to `/api/app/Get_Order_Bill_Detail*` lacking an `Authorization` header (`cs-method == "GET" && cs(Authorization) == "-"`).
- Alert on sequential enumeration patterns: any single authenticated IP or user querying more than 10 sequential `orderNo` parameters on `/GetOrderStatus` within a 60-second window.
