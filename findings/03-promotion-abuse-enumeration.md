# 03 — Hidden Campaign Voucher Enumeration, 3-State Error Oracle, and Unrestricted Reuse

**Severity:** High · **CVSS v3.1:** 7.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`)
**CWE:** CWE-807 (Reliance on Untrusted Inputs), CWE-837 (Improper Enforcement of Single-Use or Quota), CWE-200 (Exposure of Sensitive Information)
**OWASP Categories:** Business Logic Abuse, API4:2023 Unrestricted Resource Consumption

> **Anonymized, educational case study.** No real voucher codes, merchant brand names, or active endpoints are included. All snippets, regular expressions, and responses are synthetic illustrations derived from live research telemetry.

---

## 1. Executive Summary

During an assessment of the mobile promotional ecosystem, researchers uncovered a cluster of interrelated vulnerabilities in voucher code generation, validation, and lifecycle management. The backend system accepted unadvertised, high-value `CampaignMode` discount vouchers that granted ~78% flat-rate discounts (₹247 off a ₹318 basket), completely absent from the public coupon catalog.

These campaign vouchers were generated using a highly predictable, low-entropy format (`cp` + 4 lowercase letters + `app`), matched case-insensitively, and were validated by an endpoint that presented a **three-state error oracle**. This oracle allowed unauthenticated or authenticated attackers to definitively differentiate valid unused vouchers from exhausted vouchers and non-existent codes.

Because the promotional endpoint enforced zero rate limiting, an automated parallel sweep successfully enumerated and cataloged over **334 valid, redeemable vouchers** representing substantial commercial value. Furthermore, coupons suffered from validation-layer reuse and a split-brain architecture where independent validation endpoints contradicted one another.

---

## 2. Hidden Campaign Vouchers vs. Public Catalog

The platform exposes a public promotional endpoint designed to inform mobile users of active discounts:

```http
GET /api/app/Get_CouponCodeListDynamic?MobileNo=9999999999&storeCode=STORE-124 HTTP/1.1
Host: app.foodbev.invalid
```

### Public Catalog Limitations
The public list returned only three restrictive, low-tier promotional vouchers:
- `BEANS10`: 10% discount on carts exceeding ₹399.
- `GRIND15`: 15% discount on carts exceeding ₹699.
- `DECAF20`: 20% discount on carts exceeding ₹999.

Additionally, catalog rule fields returned in the JSON payload were unpopulated (`minimumItem: 0`, `startDate: 0001-01-01`, `endDate: 0001-01-01`), meaning thresholds were embedded solely in human-readable description strings rather than machine-readable metadata.

### The Hidden Campaign Discovery
When a non-listed campaign voucher (e.g., `cpYzsYapp`) was submitted to the validation endpoint (`POST /api/app/Get_Order_CouponCodeItem_apply_DyNamic`), the server accepted it unconditionally:
- **Campaign Type:** Identified as `couponForUsed: "CampaignMode"` (internal campaign voucher).
- **Discount Value:** Flat **₹247** discount applied to a ₹318 cart (a **77.7% discount**), requiring only ₹71 in out-of-pocket payable amount.
- **Cart Threshold Bypass:** The cart did not satisfy any of the public minimum spend thresholds (₹399+), confirming that campaign codes bypassed standard promotional rules.

---

## 3. Low-Entropy Pattern & Namespace Reduction

Static reverse engineering of the Android client APK (decompiled via JADX and Apktool, and decompiled Hermes JavaScript bytecode bundles) confirmed that **no voucher codes were hardcoded within the client application**. Codes were exclusively generated and verified on the server.

However, syntactic analysis of discovered vouchers revealed a fixed, low-entropy structure:

$$\mathbf{Format:} \quad \texttt{cp} + [a\text{-}z]{4} + \texttt{app}$$

```
Position:  [ 0 ][ 1 ] [ 2 ][ 3 ][ 4 ][ 5 ] [ 6 ][ 7 ][ 8 ]
Content:   |  c    p  | |     4 Letters    | |  a    p    p  |
           └────┬─────┘ └────────┬────────┘ └────┬────────┘
             Static          Variable          Static
             Prefix         Keyspace           Suffix
```

### Namespace Math
1. **Total String Length:** Exactly 9 characters.
2. **Static Affixes:** 5 fixed characters (`cp...app`).
3. **Variable Core:** Exactly 4 alphabetic characters ($[a\text{-}z]$).
4. **Case-Insensitivity:** Testing proved the backend normalizes codes via `.ToLower()` or SQL `COLLATE` case-insensitivity (`CPYZSYAPP` $\equiv$ `cpyzsyapp`).
5. **Total Search Space:**
   $$\text{Keyspace} = 26^4 = 456,976 \text{ combinations}$$

At a conservative sequential request pace of 1.5 seconds per attempt, the entire keyspace requires approximately 7.9 days. With a lightweight parallel pool of 15 asynchronous workers, the entire universe of campaign vouchers could be systematically enumerated in **under 12 hours**.

---

## 4. The Three-State Error Oracle

The coupon application endpoint responds with three distinct JSON payload schemas that create an information disclosure oracle:

```
┌────────────────────────────────────────────────────────┐
│                   Incoming Request                     │
│    POST /api/app/Get_Order_CouponCodeItem_apply_DyNamic│
└───────────────────────────┬────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
       [Code Exists]               [Code Does Not Exist]
            │                               │
    ┌───────┴───────┐                       ▼
    ▼               ▼                  STATE 3: NON-EXISTENT
[Not Used]     [Already Used]          • HTTP 200 OK
    │               │                  • success: false
    ▼               ▼                  • message: "" (Empty)
 STATE 1:       STATE 2:               • obj_CouponCode: null
 ACTIVE         EXHAUSTED
 • 200 OK       • 200 OK
 • success:true • success:false
 • disc: ₹247   • message: "already used"
 • obj populated• obj populated
```

### State 1: Active, Redeemable Voucher
```json
{
  "success": true,
  "message": "Coupon code redemption is successful",
  "obj_CouponCode": {
    "couponId": 85158,
    "couponRefId": "3B333FA4-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "couponCode": "cpyzsyapp",
    "couponForUsed": "CampaignMode",
    "totalCartPriceStr": "318",
    "totalDiscountPriceStr": "247",
    "finalPayableAmount": "71"
  }
}
```

### State 2: Valid but Exhausted / Redeemed Voucher
```json
{
  "success": false,
  "message": "Coupon already used",
  "obj_CouponCode": {
    "couponId": 85158,
    "couponRefId": "3B333FA4-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "couponCode": "cpyzsyapp",
    "couponForUsed": "CampaignMode",
    "totalCartPriceStr": "318",
    "totalDiscountPriceStr": "0",
    "finalPayableAmount": "318"
  }
}
```

### State 3: Non-Existent / Invalid Code
```json
{
  "success": false,
  "message": "",
  "obj_CouponCode": null
}
```

### Oracle Security Implications
- State 3 returns an empty string `message: ""` and a `null` object.
- State 2 returns `message: "Coupon already used"` along with the full `obj_CouponCode` metadata record.
- **Attacker Advantage:** The oracle allows an attacker to quickly discard invalid combinations and immediately detect whether a campaign code exists in the database, even if other customers have already redeemed it.

---

## 5. Automated Enumeration of 334+ Live Vouchers

To verify the feasibility of automated harvesting, researchers built a controlled Python sweep harness using family neighborhood clustering and pseudo-random seed sampling (`coupon-sweep.py`).

### Empirical Results
- Over the course of testing, **330+ valid, unused campaign vouchers** were enumerated across campaign identifier clusters (`couponId: 85158` through `85163`).
- Examples of discovered active siblings (anonymized):
  - `cpzkwuapp` (`couponId: 85162`, `couponRefId: FED88BB3-...`)
  - `cpazqtapp` (`couponId: 85163`, `couponRefId: 11F94D19-...`)
  - `cpbwsrapp` (`couponId: 85159`, `couponRefId: 30473F51-...`)
  - `cpdfxrapp` (`couponId: 85161`, `couponRefId: 98BC8B21-...`)
  - `cpdtcbapp` (`couponId: 85163`, `couponRefId: 0822A444-...`)
- **Bulk Invalidation Signal:** During testing, a scheduled full recheck round revealed that all previously valid vouchers suddenly transitioned from State 1 directly to State 3 (returning empty-invalid). This confirmed that backend administrators performed a bulk deletion/invalidation of the campaign table.

---

## 6. Split-Brain Validation & Validation-Layer Reuse

### Split-Brain Architecture
Static analysis identified a separate standalone coupon validation endpoint:

```http
GET /api/app/ValidateSubCouponGST_V1?couponCode=cpYzsYapp HTTP/1.1
Host: app.foodbev.invalid
Authorization: Bearer <CUSTOMER_JWT>
```

When supplied with valid, active campaign vouchers that successfully redeemed ₹247 off on the apply endpoint, `ValidateSubCouponGST_V1` responded with:
```json
{
  "success": false,
  "ValidCouponCode": false,
  "DiscountValue": 0,
  "message": "Coupon code is not available"
}
```
This demonstrated an architectural split-brain: the application maintained divergent validation logic where pre-validation checked an isolated subscription table, while the actual checkout apply endpoint accepted general campaign vouchers.

### Validation-Layer Reuse
In a single testing session, the same campaign voucher was applied **over 25 consecutive times** across multiple simulated carts. In every response, usage counters remained permanently zero:
```json
{
  "availableQty": 0,
  "orderTimeUsedQty": 0,
  "finalAvailableQty": 0,
  "noOfCustomerOrderThisCouponUsed": 0
}
```
Validation requests did not decrement or reserve the voucher. Vouchers were only flagged as consumed (`"Coupon already used"`) upon completed order generation. This opens a window for race conditions where an attacker can concurrently submit multiple orders using a single voucher.

---

## 7. Technical Root Cause Analysis

The vulnerability stems from predictable identifier generation, missing API rate limits, non-atomic database state updates, and disparate error handlers.

### Vulnerable Server Implementation (Illustrative Python / Flask)

```python
# VULNERABLE VOUCHER VALIDATION LOGIC
@app.route("/api/app/Get_Order_CouponCodeItem_apply_DyNamic", methods=["POST"])
def apply_coupon():
    data = request.get_json()
    code_input = data.get("CouponCode", "").strip()

    # Case-insensitive lookup over low-entropy namespace
    coupon = db.coupons.find_one({"code_lower": code_input.lower()})

    # ORACLE LEAK: State 3 (Non-existent)
    if not coupon:
        return jsonify({"success": False, "message": "", "obj_CouponCode": None}), 200

    # ORACLE LEAK: State 2 (Exhausted)
    if coupon.get("is_redeemed", False):
        return jsonify({
            "success": False, 
            "message": "Coupon already used", 
            "obj_CouponCode": coupon
        }), 200

    # State 1 (Active)
    # Flaw: Does not atomically reserve or decrement the coupon at validation!
    return jsonify({
        "success": True,
        "message": "Coupon code redemption is successful",
        "obj_CouponCode": coupon
    }), 200
```

---

## 8. Remediation & Fixed Pattern

1. **High-Entropy Cryptographic Codes:** Discontinue structured, short alphanumeric prefixes and suffixes. Generate promo codes using cryptographically secure random number generators with at least 128 bits of entropy (e.g., 16 random alphanumeric characters, case-sensitive: $62^{16} \approx 4.7 \times 10^{28}$).
2. **Uniform Error Responses:** Eliminate distinguishing messages and payload shapes. Return an identical generic failure message and null data payload for any code that cannot be applied.
3. **Strict Sliding-Window Rate Limiting:** Enforce a strict rate limit on coupon validation endpoints (e.g., maximum 5 attempts per user/IP per minute) with exponential backoff and captcha challenge on failure.
4. **Single Source of Promotional Truth:** Unify promotional validation across all endpoints so that listing, validation, and order generation share identical business rules.
5. **Atomic Claim & Reservation:** When a voucher is validated during checkout, hold an atomic reservation with a short TTL (e.g., 5 minutes) to prevent concurrent multi-device redemption races.

### Fixed Server Implementation (Illustrative Python)

```python
# SECURE VOUCHER ENGINE IMPLEMENTATION
import time
from flask import request, jsonify

@app.route("/api/app/Get_Order_CouponCodeItem_apply_DyNamic", methods=["POST"])
@require_authentication # Enforce user JWT
def apply_coupon_secure():
    user_id = g.current_user_id
    ip_address = request.remote_addr

    # 1. Enforce strict sliding-window rate limit per user and IP
    rate_key = f"rl:coupon:{user_id}:{ip_address}"
    if not rate_limiter.allow_request(rate_key, max_attempts=5, window_seconds=60):
        return jsonify({
            "success": False, 
            "message": "Too many coupon attempts. Please try again later."
        }), 429

    data = request.get_json()
    code_input = data.get("CouponCode", "").strip()

    # 2. Case-sensitive exact match lookup
    coupon = db.coupons.find_one({"code": code_input, "is_active": True})

    # 3. Uniform error response: Never differentiate non-existent vs. exhausted
    if not coupon or coupon.get("remaining_uses", 0) <= 0:
        return jsonify({
            "success": False,
            "message": "Invalid or inapplicable promotional code.",
            "obj_CouponCode": None
        }), 200

    # 4. Check user-specific redemption eligibility
    has_user_redeemed = db.redemptions.find_one({"coupon_id": coupon["_id"], "user_id": user_id})
    if has_user_redeemed:
        return jsonify({
            "success": False,
            "message": "Invalid or inapplicable promotional code.",
            "obj_CouponCode": None
        }), 200

    # 5. Success response with sanitized fields only
    return jsonify({
        "success": True,
        "message": "Promotional code applied successfully.",
        "obj_CouponCode": {
            "discount_amount": coupon["flat_amount"],
            "coupon_type": coupon["type"]
        }
    }), 200
```

---

## 9. Verification & Defender Playbook

### Testing for Error Oracles (Curl)
```bash
# Test Non-Existent Code
curl -s -X POST https://app.foodbev.invalid/api/app/Get_Order_CouponCodeItem_apply_DyNamic \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"CouponCode": "INVALIDZZZZ999", "TotalAmount": 300}' | jq .

# Test Exhausted Code
curl -s -X POST https://app.foodbev.invalid/api/app/Get_Order_CouponCodeItem_apply_DyNamic \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"CouponCode": "EXHAUSTEDCODE123", "TotalAmount": 300}' | jq .

# Assert: The responses must be byte-for-byte identical in status, message, and schema.
```

### SIEM Detection & Anomaly Alerts
- Configure alerting on any single IP or user account generating more than 10 coupon validation requests in a 5-minute interval.
- Alert on spikes in coupon validation failure rates (> 30% failure rate across a 10-minute rolling window).
