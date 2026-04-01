# Foretyx Data Plane — Security Audit & Fixes

## Executive Summary

This document details the comprehensive security audit performed on the Foretyx Data Plane and all vulnerabilities identified and fixed.

## Security Issues Fixed

### 1. **CRITICAL: Missing Authentication on Admin Endpoints**
**Severity:** CRITICAL  
**Issue:** The `/v1/logs` and `/v1/metrics` endpoints had no authentication, allowing any client to:
- Retrieve all telemetry events
- Access system metrics and statistics
- Potentially identify attack patterns or gain operational intelligence

**Fix:**
- Added `ADMIN_API_KEY` configuration parameter (SecretStr type)
- Implemented Bearer token validation via `SecurityValidator.validate_api_key()`
- All admin endpoints now require valid API key in `Authorization: Bearer <token>` header
- Invalid or missing keys return 401 Unauthorized or 403 Forbidden

**Files Modified:**
- `app/routes/admin.py` - Added authentication to all admin endpoints
- `app/config.py` - Added `admin_api_key` field
- `.env.example` - Added `ADMIN_API_KEY` parameter

---

### 2. **HIGH: Sensitive API Keys in Plain Text**
**Severity:** HIGH  
**Issue:** API keys and tokens stored as plain strings, risking:
- Accidental logging of secrets
- Exposure in error messages
- Insecure serialization

**Fix:**
- Changed `gemini_api_key` from `str` to `SecretStr`
- Changed `bridge_token` from `str` to `SecretStr`
- Changed `admin_api_key` to `SecretStr`
- Updated all code to call `.get_secret_value()` when accessing secrets
- Pydantic now redacts secrets from logs and error messages

**Files Modified:**
- `app/config.py` - Changed field types to SecretStr
- `app/engine/llm_router.py` - Updated API key usage
- `app/engine/event_emitter.py` - Updated token usage

---

### 3. **HIGH: Overly Permissive CORS Configuration**
**Severity:** HIGH  
**Issue:**
- CORS allowed all methods (`["*"]`) including DELETE, PUT
- CORS allowed all headers (`["*"]`)
- `allow_credentials=True` with permissive methods is dangerous
- Could enable CSRF attacks

**Fix:**
- Restricted `allow_methods` to `["GET", "POST", "OPTIONS"]`
- Restricted `allow_headers` to `["Content-Type", "Authorization"]`
- Added `cors_allow_credentials` config field (defaults to `False`)
- Added `max_age=3600` for CORS preflight caching
- CORS configuration now explicitly requires setting via env var

**Files Modified:**
- `app/main.py` - Updated CORS middleware configuration
- `app/config.py` - Added `cors_allow_credentials` field
- `.env.example` - Added CORS trust settings

---

### 4. **HIGH: Insecure Default Request Values**
**Severity:** HIGH  
**Issue:** ProcessRequest had default hardcoded values:
- `org_id="org_dev"`, `user_id="usr_dev"`, `session_id="session_dev"`
- Clients could bypass authentication by not providing these values
- No validation that values are actually provided
- Could allow unauthorized access or data mixing

**Fix:**
- Removed default values for `org_id` and `user_id` (now required fields)
- Made `session_id` optional but without default
- Pydantic validation now enforces these fields are provided
- Actual validation of these values is the responsibility of the bridge layer

**Files Modified:**
- `app/contracts/api.py` - Removed insecure defaults

---

### 5. **HIGH: Information Disclosure via Error Messages**
**Severity:** HIGH  
**Issue:** LLM error messages exposed raw exception details:
- `f"[LLM ERROR] {str(e)}"` could reveal internal API details
- Stack traces could be exposed in error messages
- Helps attackers understand system architecture

**Fix:**
- Created `SecurityValidator.sanitize_error_message()` utility
- Error messages now only indicate category (timeout, invalid params, etc.)
- Actual errors logged securely server-side, not returned to client
- Added logging of error types (not messages) for debugging

**Files Modified:**
- `app/security.py` - New error sanitization utility
- `app/routes/process.py` - Updated error handling

---

### 6. **MEDIUM: Missing Security Headers**
**Severity:** MEDIUM  
**Issue:** Application not sending security-related HTTP headers:
- No X-Content-Type-Options (MIME-sniffing vulnerability)
- No X-Frame-Options (Clickjacking vulnerability)
- No X-XSS-Protection (XSS vulnerability)
- No HSTS (Man-in-the-middle vulnerability)
- No CSP (Content injection vulnerability)

**Fix:**
- Created `SecurityHeadersMiddleware` to add all security headers
- Implemented `get_secure_headers()` function returning:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Content-Security-Policy: default-src 'none'`
  - `Referrer-Policy: no-referrer`
  - `Permissions-Policy: geolocation=(), microphone=(), camera=()`

**Files Modified:**
- `app/security.py` - Added header generation
- `app/main.py` - Added SecurityHeadersMiddleware to middleware stack

---

### 7. **MEDIUM: X-Forwarded-For Header Spoofing**
**Severity:** MEDIUM  
**Issue:** Rate limiter trusted X-Forwarded-For without validation:
- Clients could spoof IP addresses in headers
- Could bypass rate limiting by using different fake IPs
- Could cause legitimate users to be rate-limited

**Fix:**
- Created `SecurityValidator.validate_client_ip()` method
- Validates IP format (IPv4 and IPv6 patterns)
- Rejects obviously invalid IPs
- Updated rate limiter to validate X-Forwarded-For
- Updated access logger to validate X-Forwarded-For
- Invalid IPs logged as security warning

**Files Modified:**
- `app/security.py` - Added IP validation utility
- `app/middleware/rate_limiter.py` - Added IP validation
- `app/middleware/access_log.py` - Added IP validation

---

### 8. **MEDIUM: Client-Controlled Request IDs**
**Severity:** MEDIUM  
**Issue:** X-Request-ID header directly used without validation:
- Could contain log injection payloads
- Could be excessively long causing DoS
- Could contain special characters breaking log parsing

**Fix:**
- Added format validation: `^[a-zA-Z0-9\-_.]+$`
- Added length limit: 256 characters max
- Invalid request IDs rejected and new UUID generated
- Invalid IDs logged as security warning
- Prevents log injection and DoS attacks

**Files Modified:**
- `app/middleware/request_id.py` - Added validation logic

---

### 9. **MEDIUM: Missing Input Validation**
**Severity:** MEDIUM  
**Issue:** User input not fully validated:
- No maximum prompt length enforcement at entry
- No input type checking
- Could allow oversized requests causing DoS

**Fix:**
- Created `SecurityValidator.validate_prompt_length()` method
- Added validation to both `/guard` and `/process` endpoints
- Implemented `MIN_PROMPT_LENGTH = 1` and configurable max
- Returns 413 for oversized requests, 422 for invalid requests
- Errors logged appropriately

**Files Modified:**
- `app/security.py` - Added validation utilities
- `app/routes/guard.py` - Added prompt validation
- `app/routes/process.py` - Added prompt validation

---

### 10. **MEDIUM: Admin Endpoints Exposed in Startup Logs**
**Severity:** MEDIUM  
**Issue:** Startup logs listed all endpoints including admin ones:
- Information disclosure about protected endpoints
- Helps attackers identify attack surface
- Could reveal internal API structure

**Fix:**
- Removed endpoint list from startup logs
- Logs now only show host, port, and critical status info
- Admin endpoints not announced in application startup

**Files Modified:**
- `app/main.py` - Updated startup logging

---

### 11. **LOW: Database Not Encrypted**
**Severity:** LOW (depends on deployment)  
**Issue:** SQLite database stored unencrypted locally:
- Events database could be readable if filesystem compromised
- Metadata could be exposed (not actual PII per design, but still sensitive)
- No protection for data at rest

**Recommendation:** 
- Consider using `sqlcipher` for encrypted SQLite
- Or implement field-level encryption for sensitive events
- Ensure proper filesystem permissions (0600) on database file
- For production: Consider external logging/events system with encryption

---

### 12. **LOW: Rate Limiting Without Distributed Support**
**Severity:** LOW (depends on deployment)  
**Issue:** In-memory rate limiting only works on single instance:
- If deployed with multiple workers/instances, limiting bypassed
- Clients could hit each instance independently

**Recommendation:**
- For multi-instance deployment: Use Redis-backed rate limiting
- Or ensure load balancer has sticky sessions
- Document limitation in deployment guide

---

### 13. **LOW: No HTTPS Enforcement**
**Severity:** LOW (depends on deployment)  
**Issue:** No built-in HTTPS enforcement:
- Secrets could be transmitted over HTTP
- Man-in-the-middle attacks possible

**Fix:**
- Added `require_https` configuration parameter
- Added HSTS header (see Security Headers fix)
- Documentation updated to recommend HTTPS in production
- Added recommendation to use reverse proxy with TLS termination

**Files Modified:**
- `app/config.py` - Added `require_https` field
- `.env.example` - Added HTTPS configuration

---

## New Security Features

### 1. **Centralized Security Validator**
Created `app/security.py` with utilities for:
- API key validation (Bearer token format)
- Prompt length validation
- Client IP validation (format checking)
- Error message sanitization
- Security headers generation

### 2. **Enhanced Configuration**
Updated `app/config.py` with:
- `admin_api_key` (SecretStr) - Required for API access
- `require_https` - Production HTTPS enforcement flag
- `cors_allow_credentials` - Fine-grained CORS control
- `trusted_proxies` - Trusted proxy IP list

### 3. **Improved Error Handling**
- Sanitized error messages sent to clients
- Detailed error logging server-side
- No information disclosure in responses

### 4. **Request Validation**
- Prompt length validation at entry
- Input type and format validation
- Request ID format/length validation
- Client IP format validation

---

## Deployment Recommendations

### Production Checklist

1. **Environment Variables**
   ```bash
   # Generate a secure admin API key (32+ characters)
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   
   # Set in production .env:
   ADMIN_API_KEY=<generated-key>
   REQUIRE_HTTPS=true
   CORS_ALLOWED_ORIGINS=<your-frontend-domain>
   CORS_ALLOW_CREDENTIALS=false
   LOG_FORMAT=json
   LOG_LEVEL=WARNING
   ```

2. **Network Security**
   - Deploy behind reverse proxy (nginx, Caddy) with TLS/HTTPS
   - Proxy should handle HSTS and additional security headers
   - Use mutual TLS for service-to-service communication
   - Implement network policies to restrict access

3. **Access Control**
   - Rotate `ADMIN_API_KEY` regularly
   - Use different API keys for different environments
   - Store secrets in secure vault (AWS Secrets Manager, HashiCorp Vault)
   - Never commit secrets to version control

4. **Monitoring & Logging**
   - Enable JSON logging for ELK/CloudWatch integration
   - Monitor for authentication failures on admin endpoints
   - Alert on rate limiting triggers
   - Audit all admin API access

5. **Data Protection**
   - Ensure read-only filesystem for application code
   - Set restrictive file permissions on SQLite database
   - Consider encrypted database for production
   - Implement log rotation and retention policies

6. **API Keys & Tokens**
   - Implement key rotation policies
   - Use short-lived tokens where possible
   - Audit all API key usage
   - Revoke compromised keys immediately

---

## Testing Security Fixes

### 1. Test Admin Endpoint Authentication
```bash
# Without API key - should fail
curl http://localhost:8000/v1/logs

# With invalid API key - should fail
curl -H "Authorization: Bearer invalid" http://localhost:8000/v1/logs

# With valid API key - should succeed
curl -H "Authorization: Bearer $ADMIN_API_KEY" http://localhost:8000/v1/logs
```

### 2. Test Security Headers
```bash
curl -I http://localhost:8000/v1/guard
# Check response headers for security headers
```

### 3. Test Input Validation
```bash
# Empty prompt - should fail
curl -X POST http://localhost:8000/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt":""}'

# Oversized prompt - should fail with 413
curl -X POST http://localhost:8000/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt":"'"$(python -c 'print("x"*100000)')"'"}'
```

### 4. Test CORS
```bash
# Preflight request
curl -X OPTIONS http://localhost:8000/v1/guard \
  -H "Origin: http://example.com" \
  -H "Access-Control-Request-Method: POST" \
  -v
# Should NOT have Access-Control-Allow-Origin header for non-whitelisted origin
```

---

## Security Best Practices

### For Operators

1. **Keep Dependencies Updated**
   ```bash
   pip list --outdated
   pip install --upgrade <package>
   ```

2. **Monitor Security Advisories**
   - GitHub security alerts
   - Python Packaging Advisory Database
   - Vendor announcements

3. **Regular Security Audits**
   - Quarterly vulnerability scans
   - Annual penetration testing
   - Code review changes

4. **Incident Response**
   - Document all security incidents
   - Implement incident response plan
   - Rotate credentials after breaches
   - Post-mortem analysis

### For Developers

1. **Secure Coding**
   - Never log secrets
   - Validate all inputs
   - Use security-focused libraries
   - Review security fixes in dependencies

2. **Code Review**
   - Require security review for sensitive changes
   - Check for common vulnerabilities
   - Validate authentication/authorization logic

3. **Testing**
   - Include security tests in CI/CD
   - Test authentication failures
   - Test input validation
   - Test rate limiting

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [FastAPI Security](https://fastapi.tiangolo.com/deployment/security/)
- [Pydantic SecretStr](https://docs.pydantic.dev/latest/usage/types/secret/)
- [HTTP Security Headers](https://securityheaders.com/)

---

## Changelog

### Version 2.0.1 - Security Hardening

**Security Fixes:**
- Fixed missing authentication on admin endpoints (CRITICAL)
- Fixed sensitive API keys in plain text (HIGH)
- Fixed overly permissive CORS (HIGH)
- Fixed insecure default request values (HIGH)
- Fixed information disclosure via error messages (HIGH)
- Added security headers middleware (MEDIUM)
- Fixed X-Forwarded-For header spoofing (MEDIUM)
- Added client-controlled ID validation (MEDIUM)
- Added input validation for prompts (MEDIUM)
- Improved startup logging security (MEDIUM)

**New Features:**
- Centralized security validator module
- Enhanced configuration for security settings
- Improved error handling and logging
- Request validation and sanitization

---

## Contact & Support

For security issues, please report to: **security@foretyx.com**

Do NOT create public issues for security vulnerabilities.
