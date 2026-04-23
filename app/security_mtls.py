"""
mtls.py
=======
mTLS (mutual TLS) configuration helper (Guide Section 3.6).

mTLS terminates at the infrastructure layer (nginx/envoy), but the application
layer must:
  1. Validate that the TLS client certificate DN matches the expected org
  2. Extract the org_id / device_id from the certificate Subject
  3. Log certificate metadata for the audit trail

This module provides:
  - `MtlsValidator` — reads client cert info from request headers forwarded
    by the terminating proxy (standard nginx / Envoy mTLS pattern)
  - `require_mtls` — FastAPI dependency that enforces mTLS on protected routes
  - Stub for direct mTLS (Python ssl.SSLContext) for local dev / test environments

Reference headers (nginx `ssl_client_*`):
  X-Client-Cert-DN:       /CN=device-001/O=org-acme/OU=data-plane
  X-Client-Cert-Verified: SUCCESS
  X-Client-Cert-Fingerprint: SHA256:aa:bb:cc:...
  X-Client-Cert-Serial:   0x1A2B3C4D

NOTE: In production, ALWAYS verify X-Client-Cert-Verified=SUCCESS AND
      validate the DN against your CA's expected subject pattern.
      Never trust these headers from untrusted proxies — bind to
      trusted_proxies in config.
"""

import re
from typing import Optional

import structlog
from fastapi import HTTPException, Header, Request, status

logger = structlog.get_logger(__name__)

# Expected certificate DN pattern:
#   /CN=<device-id>/O=<org-id>/OU=data-plane
_DN_PATTERN = re.compile(
    r"/CN=(?P<cn>[^/]+)/O=(?P<org>[^/]+)(?:/OU=(?P<ou>[^/]+))?"
)


class CertificateInfo:
    """Parsed certificate information extracted from proxy headers."""

    def __init__(
        self,
        verified: bool,
        subject_dn: str,
        fingerprint: Optional[str],
        serial: Optional[str],
        org_id: Optional[str],
        device_id: Optional[str],
        org_unit: Optional[str],
    ):
        self.verified    = verified
        self.subject_dn  = subject_dn
        self.fingerprint = fingerprint
        self.serial      = serial
        self.org_id      = org_id
        self.device_id   = device_id
        self.org_unit    = org_unit

    def to_dict(self) -> dict:
        return {
            "verified":    self.verified,
            "subject_dn":  self.subject_dn,
            "fingerprint": self.fingerprint,
            "serial":      self.serial,
            "org_id":      self.org_id,
            "device_id":   self.device_id,
            "org_unit":    self.org_unit,
        }


class MtlsValidator:
    """
    Validates mTLS client certificate headers forwarded by the terminating proxy.

    Header sources:
      nginx  → ssl_client_verify, ssl_client_s_dn, ssl_client_fingerprint
      Envoy  → x-forwarded-client-cert (XFCC header — parsed separately)
    """

    # Header names (configurable)
    VERIFIED_HEADER     = "X-Client-Cert-Verified"
    DN_HEADER           = "X-Client-Cert-Dn"
    FINGERPRINT_HEADER  = "X-Client-Cert-Fingerprint"
    SERIAL_HEADER       = "X-Client-Cert-Serial"

    # Expected OU for data-plane devices
    EXPECTED_OU = "data-plane"

    @classmethod
    def extract(cls, request: Request) -> Optional[CertificateInfo]:
        """
        Extract certificate info from request headers.

        Returns None if mTLS headers are absent (proxy not configured).
        Returns CertificateInfo with verified=False if cert is invalid.
        """
        headers = request.headers

        verified_raw = headers.get(cls.VERIFIED_HEADER)
        if verified_raw is None:
            # mTLS headers absent — either proxy not configured or direct connection
            return None

        verified  = verified_raw.strip().upper() == "SUCCESS"
        dn        = headers.get(cls.DN_HEADER, "")
        fp        = headers.get(cls.FINGERPRINT_HEADER)
        serial    = headers.get(cls.SERIAL_HEADER)

        # Parse the DN
        org_id = device_id = org_unit = None
        match = _DN_PATTERN.search(dn)
        if match:
            device_id = match.group("cn")
            org_id    = match.group("org")
            org_unit  = match.group("ou")

        return CertificateInfo(
            verified=verified,
            subject_dn=dn,
            fingerprint=fp,
            serial=serial,
            org_id=org_id,
            device_id=device_id,
            org_unit=org_unit,
        )

    @classmethod
    def validate(
        cls,
        cert: CertificateInfo,
        expected_org_id: Optional[str] = None,
    ) -> bool:
        """
        Validate a CertificateInfo object.

        Checks:
          1. Certificate is verified by the CA
          2. OU == "data-plane" (device is a Data Plane instance)
          3. org_id matches expected_org_id (if provided)

        Returns True on success, False on failure.
        """
        if not cert.verified:
            logger.warning("mtls_cert_not_verified", dn=cert.subject_dn)
            return False

        if cert.org_unit and cert.org_unit.lower() != cls.EXPECTED_OU.lower():
            logger.warning(
                "mtls_unexpected_ou",
                expected=cls.EXPECTED_OU,
                actual=cert.org_unit,
            )
            return False

        if expected_org_id and cert.org_id != expected_org_id:
            logger.warning(
                "mtls_org_mismatch",
                expected=expected_org_id,
                actual=cert.org_id,
            )
            return False

        logger.info(
            "mtls_cert_validated",
            org_id=cert.org_id,
            device_id=cert.device_id,
            fingerprint=cert.fingerprint,
        )
        return True


# ── FastAPI Dependency ────────────────────────────────────────────────────────

async def require_mtls(request: Request) -> CertificateInfo:
    """
    FastAPI dependency — enforces mTLS on protected routes.

    Usage:
        @router.get("/protected")
        async def protected_route(cert: CertificateInfo = Depends(require_mtls)):
            return {"org": cert.org_id}

    In dev/test: if REQUIRE_MTLS=false (default), the dependency passes through
    with a dummy CertificateInfo so local testing works without a CA.
    """
    settings = request.app.state.settings
    require  = getattr(settings, "require_mtls", False)

    cert = MtlsValidator.extract(request)

    if cert is None:
        if require:
            logger.warning("mtls_headers_missing", path=str(request.url.path))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="mTLS client certificate required",
            )
        # Dev mode — return a permissive stub
        return CertificateInfo(
            verified=True,
            subject_dn="",
            fingerprint=None,
            serial=None,
            org_id="dev",
            device_id="local",
            org_unit="data-plane",
        )

    if not MtlsValidator.validate(cert):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="mTLS certificate validation failed",
        )

    return cert


# ── Local dev: SSLContext stub ────────────────────────────────────────────────

def create_ssl_context(
    certfile: str,
    keyfile: str,
    cafile: str,
) -> "ssl.SSLContext":
    """
    Create an ssl.SSLContext for direct mTLS (uvicorn --ssl-* flags).

    Use this only for local dev/integration testing.
    In production, mTLS terminates at nginx/envoy.

    Args:
        certfile: Path to server certificate (PEM)
        keyfile:  Path to server private key (PEM)
        cafile:   Path to CA certificate (PEM) — used to verify client certs

    Returns:
        ssl.SSLContext configured for mTLS
    """
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED  # enforce client cert
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
