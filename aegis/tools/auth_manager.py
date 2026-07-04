"""
Authentication middleware for Aegis pentesting agent.

Handles:
- Login endpoint detection
- Credential injection into requests
- Token/JWT extraction from responses
- Session/cookie management
- Automatic token refresh
"""

import re
import json
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class StoredCredential:
    """A stored credential for a target site."""
    site_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    

@dataclass
class SessionState:
    """Active session state for a target."""
    target_url: str
    jwt_token: Optional[str] = None
    refresh_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    expires_at: Optional[float] = None
    token_type: str = "Bearer"


class AuthManager:
    """Manages authentication state for pentesting sessions."""
    
    def __init__(self):
        self.credentials: Dict[str, StoredCredential] = {}
        self.sessions: Dict[str, SessionState] = {}
    
    def load_credential(self, site_url: str, cred_data: Dict[str, Any]) -> None:
        """Load a credential from storage."""
        self.credentials[site_url] = StoredCredential(
            site_url=site_url,
            username=cred_data.get("username"),
            password=cred_data.get("password"),
            api_key=cred_data.get("api_key"),
            token=cred_data.get("token"),
            cookies=cred_data.get("cookies", {}),
            headers=cred_data.get("headers", {}),
        )
    
    def get_credential(self, site_url: str) -> Optional[StoredCredential]:
        """Get credential for a site."""
        return self.credentials.get(site_url)
    
    def detect_login_endpoint(self, target_url: str) -> List[str]:
        """Detect common login endpoint patterns."""
        common_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/api/login",
            "/api/auth/login",
            "/api/v1/auth/login",
            "/user/login",
            "/admin/login",
            "/wp-login.php",
            "/wp-admin/",
        ]
        return [f"{target_url.rstrip('/')}{path}" for path in common_paths]
    
    def detect_auth_headers(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """Extract authentication headers from response."""
        auth_headers = {}
        
        # Check for Authorization header
        if "authorization" in response_headers:
            auth_headers["Authorization"] = response_headers["authorization"]
        
        # Check for Set-Cookie
        if "set-cookie" in response_headers:
            cookies = self._parse_cookies(response_headers["set-cookie"])
            auth_headers.update(cookies)
        
        return auth_headers
    
    def extract_jwt_from_response(self, response_body: str) -> Optional[str]:
        """Extract JWT token from response body."""
        try:
            data = json.loads(response_body)
            # Common JWT field names
            jwt_fields = ["token", "access_token", "jwt", "accessToken", "id_token"]
            for field in jwt_fields:
                if field in data:
                    token = data[field]
                    if self._is_jwt(token):
                        return token
        except json.JSONDecodeError:
            pass
        
        # Try regex extraction
        jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        match = re.search(jwt_pattern, response_body)
        if match:
            return match.group(0)
        
        return None
    
    def extract_refresh_token(self, response_body: str) -> Optional[str]:
        """Extract refresh token from response."""
        try:
            data = json.loads(response_body)
            refresh_fields = ["refresh_token", "refreshToken", "refresh"]
            for field in refresh_fields:
                if field in data:
                    return data[field]
        except json.JSONDecodeError:
            pass
        return None
    
    def extract_cookies_from_response(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """Extract cookies from Set-Cookie headers."""
        cookies = {}
        if "set-cookie" in response_headers:
            cookie_header = response_headers["set-cookie"]
            if isinstance(cookie_header, list):
                for cookie in cookie_header:
                    cookies.update(self._parse_cookie_string(cookie))
            else:
                cookies.update(self._parse_cookie_string(cookie_header))
        return cookies
    
    def build_auth_headers(self, target_url: str) -> Dict[str, str]:
        """Build authentication headers for a request."""
        headers = {}
        
        # Get stored credential
        cred = self.get_credential(target_url)
        if cred:
            if cred.api_key:
                headers["Authorization"] = f"Bearer {cred.api_key}"
            elif cred.token:
                headers["Authorization"] = f"Bearer {cred.token}"
            headers.update(cred.headers)
        
        # Get session state
        session = self.sessions.get(target_url)
        if session:
            if session.jwt_token:
                headers["Authorization"] = f"{session.token_type} {session.jwt_token}"
            headers.update(session.headers)
        
        return headers
    
    def build_cookie_header(self, target_url: str) -> str:
        """Build Cookie header for a request."""
        cookies = {}
        
        # Get stored cookies
        cred = self.get_credential(target_url)
        if cred:
            cookies.update(cred.cookies)
        
        # Get session cookies
        session = self.sessions.get(target_url)
        if session:
            cookies.update(session.cookies)
        
        return "; ".join(f"{k}={v}" for k, v in cookies.items())
    
    def update_session(self, target_url: str, response_headers: Dict[str, str], response_body: str) -> None:
        """Update session state from response."""
        if target_url not in self.sessions:
            self.sessions[target_url] = SessionState(target_url=target_url)
        
        session = self.sessions[target_url]
        
        # Extract JWT
        jwt = self.extract_jwt_from_response(response_body)
        if jwt:
            session.jwt_token = jwt
            session.expires_at = self._get_jwt_expiry(jwt)
        
        # Extract refresh token
        refresh = self.extract_refresh_token(response_body)
        if refresh:
            session.refresh_token = refresh
        
        # Extract cookies
        new_cookies = self.extract_cookies_from_response(response_headers)
        session.cookies.update(new_cookies)
    
    def is_token_expired(self, target_url: str) -> bool:
        """Check if the current token is expired."""
        session = self.sessions.get(target_url)
        if not session or not session.expires_at:
            return False
        return time.time() > session.expires_at
    
    def _is_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT."""
        parts = token.split(".")
        return len(parts) == 3 and parts[0].startswith("eyJ")
    
    def _get_jwt_expiry(self, token: str) -> Optional[float]:
        """Extract expiry time from JWT."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            import base64
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            if "exp" in data:
                return float(data["exp"])
        except Exception:
            pass
        return None
    
    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        """Parse Set-Cookie header."""
        cookies = {}
        for part in cookie_header.split(","):
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.split(";")[0].strip()
        return cookies
    
    def _parse_cookie_string(self, cookie_str: str) -> Dict[str, str]:
        """Parse a single cookie string."""
        cookies = {}
        parts = cookie_str.split(";")
        if parts and "=" in parts[0]:
            name, value = parts[0].split("=", 1)
            cookies[name.strip()] = value.strip()
        return cookies


# Global auth manager instance
auth_manager = AuthManager()


def get_auth_manager() -> AuthManager:
    """Get the global auth manager."""
    return auth_manager
