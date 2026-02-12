# SSRF Analysis Report

## 1. Executive Summary
- **Analysis Status:** Complete
- **Key Outcome:** No exploitable SSRF vulnerabilities were identified in the bybrynn.com application. The application does not accept user-controlled URLs for server-side HTTP requests.
- **Purpose of this Document:** This report provides the strategic context on the application's outbound request mechanisms, absence of SSRF attack vectors, and key architectural details that make the application resilient to SSRF attacks.

### Key Findings

- **Guzzle Usage:** Indirect only (via OAuth library dependencies)
- **User Input Control:** NO user input influences HTTP request destinations
- **SSRF Risk Level:** NONE (currently secure)
- **Hardcoded URLs:** All OAuth endpoints are hardcoded
- **Configuration Security:** OAuth client configuration is static

### Risk Assessment

**Overall SSRF Risk: NONE**

The application does not contain exploitable SSRF vulnerabilities because all outbound HTTP requests use hardcoded, trusted URLs for Microsoft OAuth authentication. No user-controllable parameters reach the Guzzle HTTP client.

---

## 1. Guzzle HTTP Client Usage Inventory

### 1.1 Application Code Analysis

**Search Methodology:**
- Searched for direct Guzzle instantiations: `new \GuzzleHttp\Client()`
- Searched for HTTP method calls: `->get()`, `->post()`, `->request()`
- Searched for `use GuzzleHttp\` statements
- Examined all application PHP files (non-vendor)

**Application Files Examined:**
1. `/repos/bybrynn-core/submissions.php` (256 lines) - Main OAuth handler
2. `/repos/bybrynn-core/thumb.php` (67 lines) - Thumbnail generation
3. `/repos/bybrynn-core/env.php` (5 lines) - Environment variable exposure
4. `/repos/bybrynn-core/info.php` (3 lines) - phpinfo() disclosure
5. `/repos/bybrynn-core/art/index.php` (195 lines) - Gallery listing

### 1.2 Direct Guzzle Usage

**Finding:** The application code contains **ZERO direct instantiations** of Guzzle HTTP client.

**Evidence:**
```bash
# Search results for "new \GuzzleHttp\Client" in application code
grep -r "new.*Client\(" /repos/bybrynn-core/*.php
# Result: No matches in application code (only in vendor/)
```

**Conclusion:** The application does not directly use `GuzzleHttp\Client` anywhere in custom code.

### 1.3 Indirect Guzzle Usage via Dependencies

**Guzzle is used indirectly through:**

#### OAuth2 Client Library

**Package:** `league/oauth2-client` (version ^2.8)
**File:** `/repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php`
**Lines:** 17-18, 148-155

```php
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface as HttpClientInterface;

// Constructor creates Guzzle client
if (empty($collaborators['httpClient'])) {
    $client_options = $this->getAllowedClientOptions($options);
    
    $collaborators['httpClient'] = new HttpClient(
        array_intersect_key($options, array_flip($client_options))
    );
}
$this->setHttpClient($collaborators['httpClient']);
```

**Purpose:** OAuth token exchange and user info retrieval from Microsoft

#### Microsoft OAuth Provider

**Package:** `stevenmaguire/oauth2-microsoft` (version ^2.2)
**File:** `/repos/bybrynn-core/vendor/stevenmaguire/oauth2-microsoft/src/Provider/Microsoft.php`

Uses parent class (`AbstractProvider`) Guzzle implementation.

---

## 2. HTTP Request Destinations Analysis

### 2.1 OAuth Endpoint Configuration

**Location:** `/repos/bybrynn-core/submissions.php`, Lines 37-44

```php
$provider = new Microsoft([
    'clientId'                => $clientId,
    'clientSecret'            => $clientSecret,
    'redirectUri'             => $redirectUri,
    'urlAuthorize'            => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/authorize",
    'urlAccessToken'          => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token",
    'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
]);
```

**Analysis:**

| Parameter | Value | User Controlled? | SSRF Risk |
|-----------|-------|------------------|-----------|
| `clientId` | `getenv('MICROSOFT_OAUTH_CLIENT_ID')` | ❌ NO (server env) | NONE |
| `clientSecret` | `getenv('MICROSOFT_OAUTH_CLIENT_SECRET')` | ❌ NO (server env) | NONE |
| `redirectUri` | `'https://bybrynn.com/submissions'` | ❌ NO (hardcoded) | NONE |
| `urlAuthorize` | `https://login.microsoftonline.com/...` | ❌ NO (hardcoded) | NONE |
| `urlAccessToken` | `https://login.microsoftonline.com/...` | ❌ NO (hardcoded) | NONE |
| `urlResourceOwnerDetails` | `https://graph.microsoft.com/oidc/userinfo` | ❌ NO (hardcoded) | NONE |

**Tenant ID:**
```php
$tenantId = 'cd47551c-33c7-4b7f-87a9-df19f9169121'; // Hardcoded
```

- ❌ NOT user-controllable
- ✅ Hardcoded in application code
- ✅ Specific to bybrynn's Azure AD tenant

### 2.2 HTTP Requests Made by OAuth Flow

The OAuth library makes the following HTTP requests via Guzzle:

#### Request 1: Authorization URL (No Outbound Request)
```php
// User is redirected to Microsoft - no server-side HTTP request
header('Location: ' . $authUrl);
```
**SSRF Risk:** NONE (client-side redirect)

#### Request 2: Access Token Exchange

**Endpoint:** `https://login.microsoftonline.com/cd47551c-33c7-4b7f-87a9-df19f9169121/oauth2/v2.0/token`

**Method:** POST

**Triggered By:** `/repos/bybrynn-core/submissions.php`, Line 66
```php
$token = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code'],
]);
```

**User Input:**
- `$_GET['code']` - Authorization code from Microsoft OAuth callback

**Analysis:**
- ✅ Authorization code is sent in POST body, NOT in URL
- ✅ Destination URL is hardcoded
- ✅ User cannot modify the destination
- ❌ Authorization code does NOT control WHERE the request goes

**SSRF Risk:** NONE

#### Request 3: Resource Owner Details

**Endpoint:** `https://graph.microsoft.com/oidc/userinfo`

**Method:** GET

**Triggered By:** `/repos/bybrynn-core/submissions.php`, Line 74
```php
$owner = $provider->getResourceOwner($token);
```

**Implementation:** `/repos/bybrynn-core/vendor/stevenmaguire/oauth2-microsoft/src/Provider/Microsoft.php`, Lines 106-111

```php
public function getResourceOwnerDetailsUrl(AccessToken $token)
{
    $uri = new Uri($this->urlResourceOwnerDetails);
    
    return (string) Uri::withQueryValue($uri, 'access_token', (string) $token);
}
```

**Analysis:**
- ✅ Base URL (`$this->urlResourceOwnerDetails`) is hardcoded: `https://graph.microsoft.com/oidc/userinfo`
- ✅ User access token is appended as query parameter, NOT as URL path/host
- ✅ User cannot control destination URL

**SSRF Risk:** NONE

---

## 3. Guzzle Configuration Analysis

### 3.1 Allowed Client Options

**Location:** `/repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php`, Lines 171-181

```php
protected function getAllowedClientOptions(array $options)
{
    $client_options = ['timeout', 'proxy'];

    // Only allow turning off ssl verification if it's for a proxy
    if (!empty($options['proxy'])) {
        $client_options[] = 'verify';
    }

    return $client_options;
}
```

**Allowed Configuration Options:**
1. `timeout` - Request timeout
2. `proxy` - HTTP proxy server
3. `verify` - SSL certificate verification (only if proxy is set)

### 3.2 User Control Over Configuration

**Application Code Analysis:**
```php
// submissions.php - Microsoft provider instantiation
$provider = new Microsoft([
    'clientId'                => $clientId,
    'clientSecret'            => $clientSecret,
    'redirectUri'             => $redirectUri,
    'urlAuthorize'            => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/authorize",
    'urlAccessToken'          => "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token",
    'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
]);
```

**Analysis:**

| Configuration Option | User Input? | SSRF Risk |
|---------------------|-------------|-----------|
| `timeout` | ❌ NOT provided | NONE |
| `proxy` | ❌ NOT provided | NONE |
| `verify` | ❌ NOT provided | NONE |
| `base_uri` | ❌ NOT used | NONE |

**Finding:** NO Guzzle configuration options are influenced by user input.

### 3.3 Proxy Configuration

**Current State:** No proxy configuration is set in application code.

**Potential SSRF Vector (NOT PRESENT):**

If user input could control the `proxy` option, it would be exploitable:
```php
// HYPOTHETICAL VULNERABILITY (NOT PRESENT IN THIS APPLICATION)
$provider = new Microsoft([
    // ... other options ...
    'proxy' => $_POST['proxy_url'], // ⚠️ User-controlled - would be SSRF
]);
```

**Actual Implementation:** ✅ SECURE - Proxy is NOT configured and NOT user-controllable.

---

## 4. User Input Flow Analysis

### 4.1 User Input Sources

All user input in the application:

**GET Parameters:**
1. `$_GET['error']` - OAuth error from Microsoft (Line 46)
2. `$_GET['error_description']` - OAuth error description (Line 47)
3. `$_GET['state']` - OAuth state token (Line 60)
4. `$_GET['code']` - OAuth authorization code (Line 67)

**POST Parameters:**
1. `$_POST['title']` - Artwork title (Line 124)
2. `$_POST['medium']` - Artwork medium (Line 125)
3. `$_POST['dimensions']` - Artwork dimensions (Line 126)
4. `$_POST['year']` - Year finished (Line 127)
5. `$_POST['description']` - Artwork description (Line 128)
6. `$_POST['date']` - Current date (Line 129)

**File Uploads:**
1. `$_FILES['highres']` - High-resolution image
2. `$_FILES['secondary']` - Secondary/framed image

### 4.2 User Input to HTTP Request Mapping

**Question:** Does any user input reach Guzzle HTTP client?

| User Input | Reaches Guzzle? | How? | SSRF Risk |
|------------|-----------------|------|-----------|
| `$_GET['code']` | ✅ YES | Sent in POST body to token endpoint | ❌ NONE (data only, not URL) |
| `$_GET['state']` | ❌ NO | Validated locally, not sent to external service | NONE |
| `$_GET['error']` | ❌ NO | Displayed to user only | NONE |
| `$_POST['*']` | ❌ NO | Never reaches OAuth/Guzzle code | NONE |
| `$_FILES['*']` | ❌ NO | Local file handling only | NONE |

**Critical Finding:** 

While `$_GET['code']` (authorization code from Microsoft) is sent to the token endpoint, it is sent as **POST data**, NOT as part of the URL. The destination URL remains hardcoded:

```php
// Where the code goes (line 66-68):
$token = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code'], // Sent as POST body parameter
]);

// Actual HTTP request made by Guzzle:
POST https://login.microsoftonline.com/cd47551c-33c7-4b7f-87a9-df19f9169121/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<user_provided_code>&redirect_uri=https://bybrynn.com/submissions&client_id=...&client_secret=...
```

**SSRF Risk:** NONE - The user controls the `code` parameter VALUE but NOT the request DESTINATION.

---

## 5. Wrapper Functions and Abstractions

### 5.1 OAuth Library as HTTP Wrapper

The OAuth library acts as a wrapper around Guzzle, but all usage is secure:

**Wrapper Methods:**

#### `getAccessToken()`
**File:** `AbstractProvider.php`
**Purpose:** Exchange authorization code for access token

```php
public function getAccessToken($grant, array $options = [])
{
    $grant = $this->verifyGrant($grant);

    $params = [
        'client_id'     => $this->clientId,
        'client_secret' => $this->clientSecret,
        'redirect_uri'  => $this->redirectUri,
    ];

    $params   = $grant->prepareRequestParameters($params, $options);
    $request  = $this->getAccessTokenRequest($params);
    $response = $this->getParsedResponse($request);
    // ...
}
```

**SSRF Analysis:**
- ✅ Destination URL: `$this->getBaseAccessTokenUrl()` - hardcoded by provider
- ✅ No user input controls URL

#### `getResourceOwner()`
**Purpose:** Fetch user information from Microsoft Graph

```php
public function getResourceOwner(AccessToken $token)
{
    $response = $this->fetchResourceOwnerDetails($token);

    return $this->createResourceOwner($response, $token);
}

protected function fetchResourceOwnerDetails(AccessToken $token)
{
    $url = $this->getResourceOwnerDetailsUrl($token);

    $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);

    $response = $this->getParsedResponse($request);
    // ...
}
```

**SSRF Analysis:**
- ✅ URL constructed by `getResourceOwnerDetailsUrl()` - uses hardcoded base URL
- ✅ Access token appended as query parameter, NOT as host/path
- ✅ No user input controls URL

### 5.2 Custom Wrapper Functions

**Finding:** The application does NOT implement any custom wrapper functions around Guzzle or HTTP requests.

All HTTP functionality is provided by third-party OAuth libraries.

---

## 6. SSRF Attack Vector Analysis

### 6.1 Classic SSRF Attack Patterns

#### Pattern 1: URL Parameter Injection

**Vulnerable Pattern (NOT PRESENT):**
```php
// HYPOTHETICAL - NOT IN THIS APPLICATION
$url = $_GET['callback_url'];
$client = new \GuzzleHttp\Client();
$response = $client->get($url); // ⚠️ SSRF vulnerability
```

**Actual Implementation:** ✅ SECURE
```php
// submissions.php - NO user-controlled URLs
$provider = new Microsoft([/* hardcoded URLs */]);
$token = $provider->getAccessToken('authorization_code', [
    'code' => $_GET['code'], // Code is data, not URL
]);
```

#### Pattern 2: Base URI Manipulation

**Vulnerable Pattern (NOT PRESENT):**
```php
// HYPOTHETICAL - NOT IN THIS APPLICATION
$client = new \GuzzleHttp\Client([
    'base_uri' => $_POST['api_endpoint'], // ⚠️ SSRF vulnerability
]);
$response = $client->get('/users');
```

**Actual Implementation:** ✅ SECURE - No base_uri configuration provided to Guzzle.

#### Pattern 3: Proxy Manipulation

**Vulnerable Pattern (NOT PRESENT):**
```php
// HYPOTHETICAL - NOT IN THIS APPLICATION
$provider = new Microsoft([
    // ...
    'proxy' => $_SERVER['HTTP_X_PROXY'], // ⚠️ SSRF via header
]);
```

**Actual Implementation:** ✅ SECURE - No proxy configuration in application code.

#### Pattern 4: OAuth Redirect URI Manipulation

**Vulnerable Pattern (NOT PRESENT):**
```php
// HYPOTHETICAL - NOT IN THIS APPLICATION
$provider = new Microsoft([
    'redirectUri' => $_GET['redirect'], // ⚠️ Open redirect / SSRF
]);
```

**Actual Implementation:** ✅ SECURE
```php
// submissions.php Line 31
$redirectUri = 'https://bybrynn.com/submissions'; // Hardcoded
```

### 6.2 Cloud Metadata Service Access

#### AWS EC2 Instance Metadata

**Target:** `http://169.254.169.254/latest/meta-data/`

**Attack Vector (NOT EXPLOITABLE):**

If SSRF existed, attacker could attempt:
```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

To retrieve AWS IAM credentials.

**Current Risk:** NONE - No SSRF vulnerability exists to exploit this.

#### Azure Instance Metadata

**Target:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

**Attack Vector (NOT EXPLOITABLE):**

Headers required:
```
Metadata: true
```

**Current Risk:** NONE - No SSRF capability.

#### Google Cloud Metadata

**Target:** `http://metadata.google.internal/computeMetadata/v1/`

**Current Risk:** NONE

### 6.3 Internal Service Discovery

**Potential Targets if SSRF existed:**

| Service | Default Port | Internal URL Pattern |
|---------|--------------|---------------------|
| Redis | 6379 | `redis://127.0.0.1:6379` |
| MySQL | 3306 | `mysql://127.0.0.1:3306` |
| PostgreSQL | 5432 | `postgresql://127.0.0.1:5432` |
| Memcached | 11211 | `http://127.0.0.1:11211` |
| Elasticsearch | 9200 | `http://127.0.0.1:9200` |
| MongoDB | 27017 | `mongodb://127.0.0.1:27017` |

**Current Risk:** NONE - No SSRF vector exists.

### 6.4 DNS Rebinding Attack

**Attack Pattern:**

1. Attacker registers domain `evil.com`
2. DNS initially resolves to public IP (e.g., 1.2.3.4)
3. Application makes request to `http://evil.com`
4. DNS record updated to internal IP (e.g., 169.254.169.254)
5. Application retries or follows redirect to internal service

**Mitigation in Guzzle:**
- Guzzle does not automatically retry on DNS changes
- Each request resolves DNS independently

**Current Risk:** NONE - No URL-based requests from user input.

---

## 7. OAuth-Specific SSRF Considerations

### 7.1 OAuth Endpoint Configuration

The Microsoft OAuth provider allows custom endpoint URLs to be specified:

```php
new Microsoft([
    'urlAuthorize'            => 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
    'urlAccessToken'          => 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
    'urlResourceOwnerDetails' => 'https://graph.microsoft.com/oidc/userinfo',
]);
```

**Potential SSRF Vector:** If these URLs were user-controllable, attacker could set:
```php
'urlAccessToken' => 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
```

**Actual Implementation:** ✅ SECURE - All URLs are hardcoded in submissions.php.

### 7.2 OAuth Redirect URI Validation

**Implementation:** Line 31
```php
$redirectUri = 'https://bybrynn.com/submissions';
```

**Security Analysis:**
- ✅ Redirect URI is hardcoded
- ✅ Must match Azure AD app registration
- ✅ Cannot be manipulated by user
- ✅ Microsoft validates redirect URI server-side

**Open Redirect Risk:** NONE

### 7.3 OAuth State Parameter

**Implementation:** Lines 55, 60
```php
$_SESSION['oauth2state'] = $provider->getState();
// ...
if (empty($_GET['state']) || ($_GET['state'] !== ($_SESSION['oauth2state'] ?? null))) {
    unset($_SESSION['oauth2state']);
    exit('Invalid OAuth state');
}
```

**Security Analysis:**
- ✅ State generated server-side (random)
- ✅ Validated against session
- ✅ Not used in HTTP requests
- ✅ CSRF protection only

**SSRF Risk:** NONE

---

## 8. File Operations and Local Resource Access

### 8.1 file_get_contents() Usage

**Location 1:** `/repos/bybrynn-core/submissions.php`, Line 165
```php
$raw = file_get_contents($entriesFile);
```

**Analysis:**
- `$entriesFile` = `__DIR__ . '/art/entries.json'` (Line 97)
- ✅ Path is hardcoded with `__DIR__`
- ✅ No user input influences path
- ✅ Local file only

**SSRF Risk:** NONE

**Location 2:** `/repos/bybrynn-core/submissions.php`, Line 226
```php
$html = file_get_contents($indexFile);
```

**Analysis:**
- `$indexFile` = `__DIR__ . '/art/index.php'` (Line 98)
- ✅ Path is hardcoded
- ✅ Local file only

**SSRF Risk:** NONE

### 8.2 URL Wrappers

**PHP URL Wrappers Enabled by Default:**
- `file://` - Local files
- `http://` - HTTP requests
- `https://` - HTTPS requests
- `ftp://` - FTP
- `php://` - PHP input/output streams
- `data://` - Data URIs

**Current Usage:**

```php
// All file_get_contents() calls use local paths only
file_get_contents(__DIR__ . '/art/entries.json');  // Local file path
file_get_contents(__DIR__ . '/art/index.php');     // Local file path
```

**Analysis:**
- ✅ No URL schemes used (file://, http://, etc.)
- ✅ All paths are local filesystem paths
- ✅ No user input reaches file_get_contents()

**SSRF Risk:** NONE

### 8.3 cURL Usage

**Search Results:**
```bash
grep -r "curl_init\|curl_exec" /repos/bybrynn-core/*.php
# Result: No matches in application code
```

**Finding:** Application code does NOT directly use cURL functions.

**Indirect Usage:** Guzzle uses cURL via `CurlHandler.php` in vendor directory, but only for hardcoded OAuth URLs.

---

## 9. Third-Party Dependencies SSRF Review

### 9.1 league/oauth2-client Security

**Package Version:** ^2.8

**Known SSRF Issues:**
- No known SSRF vulnerabilities in version 2.8+
- Library design prevents URL injection by design
- All URLs come from provider configuration, not user input

**Security Mechanism:**
```php
// AbstractProvider.php - URL is from provider method, not parameter
$url = $this->getBaseAccessTokenUrl($params);
```

### 9.2 stevenmaguire/oauth2-microsoft Security

**Package Version:** ^2.2

**Hardcoded Endpoints:**
```php
protected $urlAuthorize = 'https://login.live.com/oauth20_authorize.srf';
protected $urlAccessToken = 'https://login.live.com/oauth20_token.srf';
protected $urlResourceOwnerDetails = 'https://apis.live.net/v5.0/me';
```

**Override Capability:**
- Application DOES override these with hardcoded Azure AD URLs
- Overrides are in application code (submissions.php), NOT from user input

**SSRF Risk:** NONE

### 9.3 GuzzleHttp/Guzzle Security

**Guzzle Version:** (transitive dependency, version not specified in application)

**Known SSRF Issues:**
- CVE-2022-31042: SSRF via HTTP redirect to Unix socket
- CVE-2022-31043: Header injection
- CVE-2022-31090: Cross-domain cookie leakage

**Applicability:**
- ❓ Unknown Guzzle version (should run `composer show guzzlehttp/guzzle`)
- ✅ Application does not allow user-controlled redirects
- ✅ Application does not allow user-controlled headers
- ✅ Application does not use cookies for authentication (uses OAuth tokens)

**Recommendation:** Update Guzzle to latest version to patch known issues.

---

## 10. Defense-in-Depth Recommendations

Even though no SSRF vulnerabilities currently exist, the following measures are recommended:

### 10.1 URL Allowlisting

If URL-based features are added in the future:

```php
/**
 * Validate that a URL is in the allowlist
 */
function is_url_allowed(string $url): bool {
    $allowed_hosts = [
        'login.microsoftonline.com',
        'graph.microsoft.com',
        'login.live.com',
        'apis.live.net',
    ];
    
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) {
        return false;
    }
    
    return in_array($parsed['host'], $allowed_hosts, true);
}
```

### 10.2 Block Private IP Ranges

Prevent requests to internal networks:

```php
/**
 * Check if an IP address is private/internal
 */
function is_private_ip(string $ip): bool {
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}

/**
 * Validate URL does not resolve to private IP
 */
function validate_url_not_private(string $url): bool {
    $parsed = parse_url($url);
    if (!isset($parsed['host'])) {
        return false;
    }
    
    $ip = gethostbyname($parsed['host']);
    
    return !is_private_ip($ip);
}
```

### 10.3 Guzzle Configuration Hardening

If additional Guzzle clients are added:

```php
$client = new \GuzzleHttp\Client([
    'timeout' => 10,              // Prevent slow loris
    'connect_timeout' => 5,       // Prevent connection delays
    'allow_redirects' => false,   // Disable redirects to prevent bypasses
    'verify' => true,             // Always verify SSL
    'protocols' => ['https'],     // Only allow HTTPS
]);
```

### 10.4 Dependency Updates

**Recommended Actions:**

1. **Check Guzzle Version:**
   ```bash
   composer show guzzlehttp/guzzle
   ```

2. **Update Dependencies:**
   ```bash
   composer update guzzlehttp/guzzle
   composer update league/oauth2-client
   composer update stevenmaguire/oauth2-microsoft
   ```

3. **Run Security Audit:**
   ```bash
   composer audit
   ```

### 10.5 Network-Level Controls

**Firewall Rules:**

Block outbound connections to:
- `169.254.169.254/32` (AWS/Azure metadata)
- `10.0.0.0/8` (Private Class A)
- `172.16.0.0/12` (Private Class B)
- `192.168.0.0/16` (Private Class C)
- `127.0.0.0/8` (Loopback)
- `0.0.0.0/8` (This network)

Except from application server to:
- `login.microsoftonline.com`
- `graph.microsoft.com`

### 10.6 Monitoring and Logging

Log all outbound HTTP requests:

```php
// Guzzle middleware for logging
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;

$stack = HandlerStack::create();
$stack->push(Middleware::log(
    $logger,
    new \GuzzleHttp\MessageFormatter('{method} {uri} - {code}')
));

$client = new \GuzzleHttp\Client([
    'handler' => $stack,
]);
```

Monitor for:
- Requests to internal IPs
- Requests to cloud metadata services
- Unusual OAuth endpoints
- High volume of outbound requests

---

## 11. Conclusion

### 11.1 Current Security Posture

**SSRF Risk Assessment: SECURE**

The bybrynn-core application is **NOT vulnerable to SSRF attacks** in its current implementation because:

1. ✅ **No Direct Guzzle Usage:** Application code does not directly instantiate or use Guzzle HTTP client
2. ✅ **Hardcoded Endpoints:** All OAuth URLs are hardcoded and cannot be manipulated
3. ✅ **No User-Controlled URLs:** No user input influences HTTP request destinations
4. ✅ **Secure Configuration:** No user-controllable Guzzle configuration options (proxy, base_uri, etc.)
5. ✅ **Input Isolation:** User inputs (POST/GET parameters) are isolated from HTTP client logic
6. ✅ **Trusted Dependencies:** OAuth libraries use secure patterns that prevent URL injection

### 11.2 Summary of Findings

| Finding | Status | Risk |
|---------|--------|------|
| Direct Guzzle instantiation in app code | ❌ NOT FOUND | NONE |
| User-controlled HTTP URLs | ❌ NOT FOUND | NONE |
| User-controlled proxy configuration | ❌ NOT FOUND | NONE |
| User-controlled OAuth endpoints | ❌ NOT FOUND | NONE |
| URL parameter injection | ❌ NOT FOUND | NONE |
| file_get_contents() with URLs | ❌ NOT FOUND | NONE |
| Indirect Guzzle usage (OAuth) | ✅ FOUND | NONE (secure) |

### 11.3 Vulnerabilities Identified

**SSRF Vulnerabilities Found:** 0

**Related Security Issues:**
- While not SSRF, the application has other critical vulnerabilities (see CODE_ANALYSIS.md):
  - OAuth credential exposure (env.php)
  - Authentication bypass (submissions.php)
  - Remote code execution (code injection)

### 11.4 Recommendations

#### Immediate Actions (P0)
- ✅ No SSRF-related urgent actions required
- ⚠️ Focus on other critical vulnerabilities (RCE, auth bypass)

#### Short-term Actions (P1)
1. Run `composer audit` to check for known vulnerabilities in dependencies
2. Update Guzzle and OAuth libraries to latest versions
3. Document that URL-based features should not be added without SSRF review

#### Medium-term Actions (P2)
1. Implement URL allowlisting function (even if not currently needed)
2. Add network-level controls to block private IP ranges
3. Implement outbound request logging

#### Long-term Actions (P3)
1. Regular dependency updates (monthly)
2. Security review process for any new HTTP client usage
3. Automated SSRF testing in CI/CD pipeline

### 11.5 Future Considerations

**If the application is extended with new features, SSRF review is required for:**

1. **Webhook functionality** - User-provided callback URLs
2. **Image fetching from URLs** - User-provided image URLs
3. **API integrations** - User-configured API endpoints
4. **RSS/Feed readers** - User-provided feed URLs
5. **Link preview generation** - User-provided URLs
6. **PDF generation from URLs** - User-provided content URLs
7. **OAuth with custom providers** - User-provided OAuth endpoints
8. **Proxy configuration UI** - Admin-provided proxy settings

**For each new feature, validate:**
- Is the URL/endpoint user-controllable?
- Is there an allowlist of permitted hosts?
- Are private IP ranges blocked?
- Are redirects disabled or validated?
- Is the feature necessary, or can it be avoided?

---

## Appendix A: Complete Guzzle Usage Map

### A.1 Guzzle Instantiation

**File:** `/repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php`
**Line:** 151

```php
$collaborators['httpClient'] = new HttpClient(
    array_intersect_key($options, array_flip($client_options))
);
```

**Called From:** `Microsoft` provider constructor (indirect)
**User Control:** NONE - Configuration is hardcoded in submissions.php

### A.2 HTTP Request Execution

**File:** `/repos/bybrynn-core/vendor/league/oauth2-client/src/Provider/AbstractProvider.php`
**Line:** 718

```php
public function getResponse(RequestInterface $request)
{
    return $this->getHttpClient()->send($request);
}
```

**Request URLs:**
1. `https://login.microsoftonline.com/cd47551c-33c7-4b7f-87a9-df19f9169121/oauth2/v2.0/token`
2. `https://graph.microsoft.com/oidc/userinfo`

**User Control:** NONE - URLs are hardcoded

### A.3 Data Flow Diagram

```
[User] 
  ↓ Provides authorization code via OAuth callback
  ↓ GET /submissions?code=ABC123&state=XYZ
  ↓
[submissions.php]
  ↓ Hardcoded configuration
  ↓ new Microsoft([...hardcoded URLs...])
  ↓
[OAuth Library]
  ↓ Constructs POST request
  ↓ URL: https://login.microsoftonline.com/.../token (hardcoded)
  ↓ Body: code=ABC123 (user-provided, but URL is not)
  ↓
[Guzzle HTTP Client]
  ↓ curl_exec()
  ↓
[Microsoft OAuth Server]
  ↓ Returns access token
  ↓
[OAuth Library]
  ↓ Constructs GET request
  ↓ URL: https://graph.microsoft.com/oidc/userinfo (hardcoded)
  ↓ Header: Authorization: Bearer <token>
  ↓
[Guzzle HTTP Client]
  ↓ curl_exec()
  ↓
[Microsoft Graph API]
  ↓ Returns user info
  ↓
[submissions.php]
  ↓ Receives user object (but does not use it - separate vulnerability)
```

**SSRF Attack Surface:** NONE - User controls `code` value but not request destinations

---

## Appendix B: SSRF Testing Checklist

For future security testing, validate the following:

### B.1 URL Injection Tests

- [ ] Can user input control scheme (http/https/ftp/file)?
- [ ] Can user input control host/domain?
- [ ] Can user input control port?
- [ ] Can user input control path?
- [ ] Can user input control query parameters?
- [ ] Can user input control fragment?

**Current Results:** ❌ NO to all - User cannot control any URL components

### B.2 Configuration Injection Tests

- [ ] Can user input control base_uri?
- [ ] Can user input control proxy settings?
- [ ] Can user input control verify (SSL) setting?
- [ ] Can user input control timeout settings?
- [ ] Can user input control redirect settings?

**Current Results:** ❌ NO to all - No configuration is user-controllable

### B.3 Cloud Metadata Tests

- [ ] Can application reach 169.254.169.254?
- [ ] Can application reach metadata.google.internal?
- [ ] Can application reach Azure Instance Metadata Service?

**Current Results:** N/A - No SSRF capability to test

### B.4 Internal Network Tests

- [ ] Can application reach 127.0.0.1?
- [ ] Can application reach 10.0.0.0/8?
- [ ] Can application reach 172.16.0.0/12?
- [ ] Can application reach 192.168.0.0/16?

**Current Results:** N/A - No SSRF capability to test

### B.5 Protocol Tests

- [ ] Can application use file:// protocol?
- [ ] Can application use ftp:// protocol?
- [ ] Can application use gopher:// protocol?
- [ ] Can application use dict:// protocol?

**Current Results:** ❌ NO - Only https:// used for hardcoded OAuth URLs

---

**END OF SSRF ANALYSIS**

**Assessment Complete**
**Document Version:** 1.0
**Total HTTP Clients Analyzed:** 1 (Guzzle via OAuth library)
**SSRF Vulnerabilities Found:** 0
**Overall Risk:** NONE (SECURE)
