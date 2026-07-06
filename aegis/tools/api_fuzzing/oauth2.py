"""OAuth2/OIDC security testing."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests


logger = logging.getLogger(__name__)


@dataclass
class OAuthFlowResult:
    flow_type: str
    success: bool
    vulnerability: str | None = None
    evidence: str = ""
    severity: str = "medium"


def test_authorization_code_flow(
    auth_url: str,
    token_url: str,
    client_id: str,
    redirect_uri: str,
    headers: dict[str, str] | None = None,
) -> list[OAuthFlowResult]:
    """Test OAuth2 authorization code flow for vulnerabilities."""
    results = []

    # Test 1: Open redirect via redirect_uri manipulation
    malicious_redirects = [
        "https://evil.com/callback",
        "https://evil.com%00.example.com/callback",
        f"{redirect_uri}@evil.com",
        f"{redirect_uri}.evil.com",
        f"javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        f"{redirect_uri}/../../../etc/passwd",
    ]

    for mal_redirect in malicious_redirects:
        try:
            resp = requests.get(
                auth_url,
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": mal_redirect,
                    "scope": "openid profile email",
                },
                headers=headers or {},
                timeout=10,
                verify=False,
                allow_redirects=False,
            )

            # If server redirects to malicious URL = vulnerability
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location or "javascript:" in location or "data:" in location:
                    results.append(OAuthFlowResult(
                        flow_type="authorization_code",
                        success=True,
                        vulnerability=f"Open redirect via redirect_uri: {mal_redirect}",
                        evidence=f"Server redirected to: {location}",
                        severity="high",
                    ))
                    break  # One proof is enough

        except Exception as exc:
            logger.debug("Redirect test failed: %s", exc)

    # Test 2: PKCE bypass (send code request without code_verifier)
    try:
        resp = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": "test_code",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                # No code_verifier = PKCE bypass attempt
            },
            headers=headers or {},
            timeout=10,
            verify=False,
        )

        if resp.status_code == 200:
            data = resp.json()
            if "access_token" in data:
                results.append(OAuthFlowResult(
                    flow_type="pkce_bypass",
                    success=True,
                    vulnerability="PKCE not enforced - code exchange without code_verifier",
                    evidence=f"Token obtained without PKCE: {json.dumps(data)[:200]}",
                    severity="critical",
                ))
        elif resp.status_code == 400:
            error = resp.json().get("error", "")
            if "verifier" not in error.lower():
                # Server rejected but didn't mention PKCE
                pass

    except Exception as exc:
        logger.debug("PKCE test failed: %s", exc)

    # Test 3: Token replay (reuse an old code)
    try:
        resp = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": "already_used_code",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            },
            headers=headers or {},
            timeout=10,
            verify=False,
        )

        # If we get a token from an old code = vulnerability
        if resp.status_code == 200:
            data = resp.json()
            if "access_token" in data:
                results.append(OAuthFlowResult(
                    flow_type="token_replay",
                    success=True,
                    vulnerability="Token replay - old authorization code accepted",
                    evidence="Server accepted already-used authorization code",
                    severity="critical",
                ))

    except Exception as exc:
        logger.debug("Token replay test failed: %s", exc)

    # Test 4: Scope escalation
    try:
        resp = requests.get(
            auth_url,
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid profile email admin.write superadmin",
            },
            headers=headers or {},
            timeout=10,
            verify=False,
            allow_redirects=False,
        )

        # If server doesn't reject elevated scopes
        if resp.status_code not in (400, 403):
            results.append(OAuthFlowResult(
                flow_type="scope_escalation",
                success=False,
                vulnerability="Server may accept elevated scopes without validation",
                evidence=f"Response status: {resp.status_code} for admin scopes",
                severity="medium",
            ))

    except Exception as exc:
        logger.debug("Scope escalation test failed: %s", exc)

    return results


def test_token_introspection(
    token_url: str,
    token: str,
    headers: dict[str, str] | None = None,
) -> OAuthFlowResult | None:
    """Test JWT token for common vulnerabilities."""
    try:
        # Decode JWT payload (without verification)
        parts = token.split(".")
        if len(parts) != 3:
            return None

        import base64

        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        vulns = []

        # Check for 'none' algorithm
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        if header.get("alg", "").lower() == "none":
            vulns.append("JWT uses 'none' algorithm - signature bypass possible")

        # Check for weak secret (common passwords)
        weak_secrets = ["secret", "password", "123456", "admin", "jwt_secret", "key"]
        for secret in weak_secrets:
            try:
                import hmac
                import hashlib

                test_sig = hmac.new(
                    secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256
                ).digest()
                import base64 as b64
                test_sig_b64 = b64.urlsafe_b64encode(test_sig).rstrip(b"=").decode()
                if test_sig_b64 == parts[2]:
                    vulns.append(f"JWT signed with weak secret: '{secret}'")
                    break
            except Exception:
                continue

        # Check for expired token used as valid
        if "exp" in payload:
            exp = payload["exp"]
            if exp < time.time():
                vulns.append(f"Token expired at {exp} but still accepted")

        # Check for missing claims
        required_claims = ["iss", "sub", "aud", "exp", "iat"]
        missing = [c for c in required_claims if c not in payload]
        if missing:
            vulns.append(f"Token missing recommended claims: {', '.join(missing)}")

        if vulns:
            return OAuthFlowResult(
                flow_type="jwt_analysis",
                success=True,
                vulnerability="; ".join(vulns),
                evidence=f"JWT header: {json.dumps(header)}, Payload: {json.dumps(payload)[:300]}",
                severity="critical" if any("none" in v.lower() or "weak" in v.lower() for v in vulns) else "high",
            )

    except Exception as exc:
        logger.debug("Token introspection failed: %s", exc)

    return None
