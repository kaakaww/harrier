# Authentication Analysis Output Improvements

## Goals
The primary audience is AppSec engineers who need to:
1. Understand how authentication works in their application
2. Configure authentication and authorization in HawkScan
3. Identify security issues that need attention

## Current Problems

### 1. Too Much Noise
- CORS/CSP warnings repeated dozens of times
- Info-level findings drown out critical authentication information
- No deduplication or aggregation

### 2. Not Actionable
- "Custom" authentication method is meaningless
- No clear indication of what to configure in HawkScan
- Missing endpoint information for authentication flows

### 3. Poor Organization
- Authentication findings mixed with security warnings
- No clear sections for different auth mechanisms
- Important information scattered throughout output

### 4. Missing Key Information
- No clear "Authentication Summary" section
- No identification of authentication endpoints
- No token extraction guidance
- No session cookie names highlighted

## Proposed Improvements

### 1. Add Authentication Summary Section (Top Priority)

Place this FIRST, before any other output:

```
Authentication Summary
======================
Primary Method:    OAuth 2.0 Authorization Code (with PKCE)
Session Mechanism: JWT Bearer Tokens
Token Location:    Authorization: Bearer header

Key Endpoints:
  Authorization:   GET  /oauth/authorize
  Token Exchange:  POST /oauth/token
  API Requests:    *    /* (Bearer token required)

For HawkScan Configuration:
  1. Configure OAuth 2.0 authentication provider
  2. Extract JWT from /oauth/token response: $.access_token
  3. Use extracted token in Authorization header: "Bearer {token}"
  4. Token lifetime: ~3600s (refresh recommended)
```

### 2. Deduplicate and Aggregate Security Findings

Instead of:
```
CORS Issues:
  ⚠ CORS wildcard (*) used with credentials (security risk)
  ⚠ CORS wildcard (*) used with credentials (security risk)
  ⚠ CORS wildcard (*) used with credentials (security risk)
  ... (15 more times)
```

Show:
```
Security Findings Summary:
  ⚠ CORS wildcard with credentials (18 occurrences across 5 domains)
  ⚠ CSP allows unsafe-inline (12 HTML responses)
  ⚠ JWT token in URL (1 occurrence - entry 171)
  ℹ Missing CSP headers (13 HTML responses)
```

### 3. Make Authentication Methods Descriptive

Instead of "Custom", detect and display:
- "Cookie-Based Session (cookie: JSESSIONID)"
- "JWT Bearer Token (in Authorization header)"
- "API Key (in X-API-Key header)"
- "OAuth 2.0 Authorization Code with PKCE"
- "Form-Based Authentication → Session Cookie"
- "Basic Authentication (username:password in header)"

### 4. Add HawkScan Configuration Guidance

For each detected auth method, provide specific configuration guidance:

```
HawkScan Configuration:
━━━━━━━━━━━━━━━━━━━━━━━

Authentication Type: cookieAuthn
Cookie Name: JSESSIONID
Login Flow:
  1. POST /api/login
     Body: {"username": "{USERNAME}", "password": "{PASSWORD}"}
  2. Extract Set-Cookie: JSESSIONID from response
  3. Use JSESSIONID cookie for authenticated requests

Example stackhawk.yml:
```yaml
app:
  authentication:
    type: cookieAuthn
    cookieName: JSESSIONID
    cookieValue: "${AUTH_COOKIE}"

  autoLogin:
    enabled: true
    loginPath: /api/login
    loginBody: '{"username":"${TEST_USER}","password":"${TEST_PASS}"}'
```

### 5. Organize Output by Priority

**Order of sections:**
1. Authentication Summary (new - most important)
2. Authentication Methods (improved labels)
3. Authentication Flows (with endpoint details)
4. Sessions & Tokens (with extraction info)
5. Authentication Events (login/logout detected)
6. JWT Token Details (only if JWTs found)
7. SAML Flows (only if detected)
8. Security Findings Summary (deduplicated)
9. Detailed Security Findings (optional, behind --verbose flag)

### 6. Add Context and Explanations

For each finding, add brief context:

```
Sessions:
  1. JSESSIONID=d3f2a1... (243 requests)
     Type:        Cookie-based session
     First seen:  2025-11-09T20:52:03Z
     Last seen:   2025-11-09T20:55:06Z
     Duration:    3.1 minutes
     Security:    HttpOnly ✓, Secure ✓, SameSite=Lax

     → This is your application's main session cookie
     → Configure HawkScan to extract and use this cookie
```

### 7. Add Flags for Output Control

```bash
# Concise output (default) - Authentication Summary only
harrier stats --auth file.har

# Standard output - Summary + key findings
harrier stats --auth --verbose file.har

# Full output - Everything including repeated warnings
harrier stats --auth --verbose --all-findings file.har

# Focus on HawkScan config
harrier stats --auth --hawkscan-config file.har
```

### 8. Improve Empty Detection

When no authentication is detected, provide helpful guidance:

```
Authentication Summary
======================
⚠ No authentication mechanisms detected in this HAR file.

Possible reasons:
  1. HAR was captured before authentication
  2. Application uses authentication not yet supported
  3. Cookies/headers were sanitized from the HAR file

To improve detection:
  1. Ensure HAR includes a complete authentication flow
  2. Capture from login page through authenticated requests
  3. Verify cookies and authorization headers are included

For HawkScan:
  - If your app uses authentication, you'll need to configure it manually
  - See: https://docs.stackhawk.com/hawkscan/authenticated-scanning.html
```

## Implementation Priority

### High Priority (Do First)
1. Add Authentication Summary section
2. Deduplicate security findings (aggregate by type)
3. Improve authentication method labels (no more "Custom")
4. Add endpoint extraction for auth flows

### Medium Priority
5. Add HawkScan configuration examples
6. Reorganize output sections
7. Add --verbose and --hawkscan-config flags

### Lower Priority (Polish)
8. Add contextual explanations for findings
9. Improve empty detection messaging
10. Add ASCII art separators/boxes for clarity

## Example Improved Output

```
Authentication Summary
━━━━━━━━━━━━━━━━━━━━━━
Primary Method:    JWT Bearer Token Authentication
Session Type:      Stateless (JWT)
Token Location:    Authorization: Bearer {token}

Authentication Flow Detected:
  1. POST /api/auth/login
     → Returns JWT in response: $.access_token

  2. Authenticated requests use:
     Authorization: Bearer {jwt}

JWT Details:
  Algorithm:  RS256 (secure)
  Issuer:     auth.example.com
  Lifetime:   3600s (1 hour)
  Claims:     sub, email, roles

For HawkScan Configuration:
  authentication:
    type: tokenAuthn
    tokenExtraction:
      type: json
      location: body
      key: access_token
    tokenValue: Bearer ${AUTH_TOKEN}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Security Findings (3 critical, 5 warnings)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⚠️  JWT token exposed in URL query parameter (1 occurrence)
      Entry #171: /callback?token=eyJ...
      Fix: Use POST body or Authorization header instead

  ⚠️  CORS wildcard with credentials (12 occurrences)
      Affects: api.example.com, cdn.example.com
      Risk: Allows any origin to access authenticated endpoints
```

## Metrics for Success

After implementation, the output should:
- ✓ Take <30 seconds to understand authentication setup
- ✓ Provide copy-paste HawkScan configuration
- ✓ Highlight critical security issues clearly
- ✓ Not require scrolling through pages of repetitive warnings
- ✓ Work well for both experts and newcomers
