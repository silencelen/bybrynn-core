# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Four (4) critical vertical privilege escalation vulnerabilities and one (1) critical context-based workflow bypass were identified. All findings represent complete absence of authorization controls, allowing anonymous users to perform administrative operations.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue. It is intended to be read alongside the JSON deliverable.

**Critical Finding Summary:**
- ✅ OAuth authentication implemented for GET /submissions
- ❌ Authorization **completely absent** for all privileged operations
- ❌ POST method explicitly bypasses OAuth authentication
- ❌ No role-based access control system exists
- ❌ No session persistence after OAuth completion
- ❌ Debug/admin files exposed without protection

**Scope:** This analysis covers all authorization vectors identified in the reconnaissance phase, focusing on vertical privilege escalation (anonymous → admin) and context-based workflow bypasses. No horizontal escalation vectors exist due to single-user architecture.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Missing Function-Level Access Control (Vertical)

**Description:** Multiple administrative endpoints and operations have ZERO authorization guards, allowing anonymous users to perform privileged operations including file uploads, database modification, code injection, and credential exposure.

**Root Cause:** The application implements OAuth authentication but completely fails to:
1. Store authentication state in session after OAuth completion
2. Validate authentication state before privileged operations
3. Implement any role-based access control

**Implication:** Any anonymous internet user can:
- Upload artwork files to the server
- Modify the JSON database (entries.json)
- Inject PHP code into executable files (index.php)
- Access OAuth client credentials (env.php)
- View complete PHP configuration (info.php)
- Read session IDs and cookies from debug logs (admin_debug.log)

**Representative Vulnerabilities:**
- AUTHZ-VULN-01: POST /submissions - Anonymous artwork submission with RCE
- AUTHZ-VULN-02: GET /env.php - OAuth credential exposure
- AUTHZ-VULN-03: GET /info.php - phpinfo() disclosure
- AUTHZ-VULN-04: GET /admin_debug.log - Session hijacking via log exposure

**Attack Surface:** 5 unprotected privileged endpoints/operations

---

### Pattern 2: Authentication Bypass via HTTP Method Exclusion (Context)

**Description:** The OAuth authentication flow is explicitly disabled for POST requests through a conditional check that excludes POST from authentication logic, creating a complete workflow bypass.

**Technical Detail:**
```php
// submissions.php:27
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // OAuth flow here (lines 28-77)
    // User authentication and token retrieval
}

// submissions.php:121
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // NO authentication check
    // Direct processing of privileged operations
}
```

**Implication:** The intended authentication workflow (GET → OAuth → POST) can be completely bypassed by sending POST requests directly, skipping the GET step entirely.

**Representative Vulnerability:**
- AUTHZ-VULN-05: OAuth workflow bypass - POST without authentication

**Attack Surface:** 1 workflow bypass enabling all vertical escalation attacks

---

### Pattern 3: Missing State Persistence After Authentication

**Description:** Even when OAuth authentication completes successfully (GET request flow), no authentication state is stored in the session. The retrieved user identity is discarded immediately after OAuth completes.

**Technical Detail:**
```php
// submissions.php:73-76 - User info retrieved but never stored
$owner = $provider->getResourceOwner($token);
// $owner contains: email, name, ID
// BUT: No session variable set, no database record created
// Token and user info immediately lost when script ends
```

**Implication:** Even if an attacker completed the OAuth flow legitimately, subsequent requests have no way to verify authentication occurred because no persistent state exists.

**Representative Vulnerability:**
- AUTHZ-VULN-05: No session state after OAuth completion

**Attack Surface:** Broken authentication persistence affecting all privileged operations

---

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture

**Configuration (submissions.php:3-10):**
- **Cookie Name:** PHPSESSID (PHP default)
- **Lifetime:** 0 (session cookie, expires on browser close)
- **Path:** `/`
- **Domain:** `.bybrynn.com` (shared across subdomains)
- **Secure:** true (HTTPS only)
- **HttpOnly:** true (no JavaScript access)
- **SameSite:** Lax (CSRF protection)

**Critical Finding:** Session configuration is properly hardened, but session is **never used for authentication state**. After OAuth completes, session contains only the expired `oauth2state` CSRF token (which is immediately unset), resulting in an empty session.

**Exploitation Strategy:** No session manipulation needed - attacks work without any session or authentication tokens.

---

### Role/Permission Model

**Intended Model:**
- **Anonymous (Level 0):** Read-only access to public portfolio
- **Artist/Admin (Level 10):** Full access to submission portal

**Actual Implementation:**
- **Anonymous (Level 0):** Complete access to all functionality
- **No role system exists:** No role assignment, no role checks, no permission validation

**Critical Finding:** The application has no concept of roles, privileges, or authorization boundaries. The only distinction is authentication (OAuth completed vs not completed), but this distinction is never enforced.

**Exploitation Strategy:** No privilege escalation techniques needed - anonymous users already have full access. Simply use administrative functions directly without authentication.

---

### Resource Access Patterns

**Data Storage:**
- **Type:** JSON flat files (no SQL database)
- **Primary Database:** `/art/entries.json` (publicly readable)
- **Images:** `/art/images/*.webp` (publicly accessible)
- **PHP Code:** `/art/index.php` (executable, modified by submissions)

**File Upload Flow:**
1. POST request to `/submissions.php` with multipart form data
2. MIME type check: `$_FILES['highres']['type'] === 'image/webp'` (client-controlled)
3. Move uploaded file to `/art/images/{slug}.webp`
4. Generate entry in entries.json
5. Inject gallery item into index.php

**Critical Finding:** All file operations occur without authentication checks. The only validation is a weak client-provided MIME type check.

**Exploitation Strategy:** Use standard HTTP POST with multipart form data. No authentication headers needed. Set Content-Type header to bypass MIME check.

---

### OAuth Integration Architecture

**Provider:** Microsoft Azure AD
- **Tenant ID:** cd47551c-33c7-4b7f-87a9-df19f9169121
- **Client ID:** From environment variable `MICROSOFT_OAUTH_CLIENT_ID`
- **Client Secret:** From environment variable `MICROSOFT_OAUTH_CLIENT_SECRET`
- **Redirect URI:** https://bybrynn.com/submissions
- **Scope:** User.Read

**OAuth Flow Endpoints:**
- **Authorization:** `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize`
- **Token Exchange:** `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`
- **User Info:** `https://graph.microsoft.com/oidc/userinfo`

**Critical Finding:** OAuth implementation is technically correct (state validation works) but strategically useless because:
1. Only applies to GET requests
2. Retrieved user identity is never stored
3. POST operations don't check authentication
4. Client credentials exposed via /env.php

**Exploitation Strategy:**
- **Option 1:** Bypass OAuth entirely by sending POST directly
- **Option 2:** Steal client credentials from /env.php to impersonate application

---

### Debug/Logging Infrastructure

**Debug Log Location:** `/admin_debug.log`

**Logged Data (submissions.php:14-21):**
- Session ID: `session_id()`
- All Cookies: `$_COOKIE` array
- All GET Parameters: `$_GET` array (includes OAuth codes)
- Session Contents: `$_SESSION` array (includes oauth2state token)
- Timestamps: ISO 8601 format

**Critical Finding:** Debug logging is enabled in production and logs highly sensitive authentication artifacts. Log file is web-accessible with no authorization guards.

**Exploitation Strategy:** Access `/admin_debug.log` to retrieve session IDs for session hijacking or OAuth codes for token theft. No authentication needed.

---

## 4. Vectors Analyzed and Confirmed Secure

These authorization checks were traced and confirmed to have robust, properly-placed guards. They are **low-priority** for further testing.

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|--------------|-------------------|----------------------|-------------|
| `GET /art/index.php` | N/A (public endpoint) | Intentionally public gallery listing | SAFE (by design) |
| `GET /art/entries.json` | N/A (public endpoint) | Intentionally public artwork metadata | SAFE (by design) |
| `GET /art/page.html` | N/A (public endpoint) | Intentionally public artwork detail page | SAFE (by design) |
| `GET /photography/index.html` | N/A (public endpoint) | Intentionally public portfolio | SAFE (by design) |
| `GET /shop/index.html` | N/A (public endpoint) | Intentionally public e-commerce listing | SAFE (by design) |
| `GET /about/index.html` | N/A (public endpoint) | Intentionally public biography | SAFE (by design) |
| `GET /commissions/index.html` | N/A (public endpoint) | Intentionally public commission info | SAFE (by design) |
| OAuth State Validation | submissions.php:60-63 | CSRF token properly validated before token exchange | SAFE |

**Note:** Public endpoints are secure by design - they are intentionally accessible without authentication. The OAuth state validation is the **only** working authorization control in the entire application, but it only protects against OAuth CSRF attacks, not against unauthorized access to privileged operations.

---

## 5. Analysis Constraints and Blind Spots

### Unanalyzed Components

**Web Server Configuration:**
- Source code analysis did not include Apache/Nginx configuration files
- Cannot confirm if server-level access controls exist for .log, .env, or .php files
- Assume default configuration (no additional restrictions)

**Deployed Environment Variables:**
- Cannot access actual values of `MICROSOFT_OAUTH_CLIENT_ID` and `MICROSOFT_OAUTH_CLIENT_SECRET`
- Analysis based on code references to these variables
- Credentials may be exposed via /env.php if environment variables are set

**Runtime Session State:**
- Analysis based on code, not runtime observation
- Cannot confirm actual session contents after OAuth completion
- Static analysis confirms no code sets authentication state

### Assumptions Made

1. **Web Server Serves All Files:** Assumed all files in `/repos/bybrynn-core/` are within the web root and accessible via HTTP unless explicitly blocked.

2. **No Additional Middleware:** Assumed no reverse proxy, WAF, or API gateway adds authentication/authorization layers not visible in source code.

3. **Default PHP Configuration:** Assumed no custom PHP configuration limits script execution or file access beyond what's in the code.

4. **Production Environment:** Analysis assumes debug logging (admin_debug.log) exists in production. If this is development-only, AUTHZ-VULN-04 may not be exploitable in production.

5. **HTTPS Certificate Issues:** Reconnaissance noted expired SSL certificate. Analysis assumes HTTPS is still functional for exploitation purposes.

---

**Report Generated:** 2026-02-12
**Analyst:** Authorization Analysis Specialist
**Target:** https://bybrynn.com
**Scope:** Externally exploitable authorization vulnerabilities
**Methodology:** White-box source code analysis with authorization guard tracing
