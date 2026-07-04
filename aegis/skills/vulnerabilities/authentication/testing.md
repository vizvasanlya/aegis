---
name: authentication_testing
description: Comprehensive authentication testing - login detection, credential usage, token extraction, session management
---

# Authentication Testing

Complete guide for testing authentication mechanisms during pentests.

## Automatic Authentication Flow

When credentials are provided, follow this workflow:

### Step 1: Discover Login Endpoints

```python
# Common login paths to test
login_paths = [
    "/login", "/signin", "/auth/login", "/api/login",
    "/api/auth/login", "/api/v1/auth/login", "/user/login",
    "/admin/login", "/wp-login.php"
]

# Test each path
for path in login_paths:
    url = f"{target_url}{path}"
    response = requests.get(url)
    if response.status_code == 200:
        # Found login page
        analyze_login_form(response.text)
```

### Step 2: Analyze Login Form

```python
def analyze_login_form(html: str) -> dict:
    """Extract form details from login page."""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        
        # Find input fields
        inputs = form.find_all('input')
        fields = {}
        for inp in inputs:
            name = inp.get('name', '')
            input_type = inp.get('type', 'text')
            if name:
                fields[name] = input_type
        
        return {"action": action, "method": method, "fields": fields}
    
    return None
```

### Step 3: Login and Extract Tokens

```python
def login_and_extract_tokens(url: str, credentials: dict) -> dict:
    """Login and extract authentication tokens."""
    import requests
    
    # Make login request
    response = requests.post(url, json=credentials)
    
    if response.status_code == 200:
        data = response.json()
        
        # Extract JWT token
        token = None
        for key in ["token", "access_token", "jwt", "accessToken"]:
            if key in data:
                token = data[key]
                break
        
        # Extract refresh token
        refresh_token = data.get("refresh_token") or data.get("refreshToken")
        
        # Extract cookies
        cookies = dict(response.cookies)
        
        return {
            "token": token,
            "refresh_token": refresh_token,
            "cookies": cookies,
            "headers": {"Authorization": f"Bearer {token}"} if token else {}
        }
    
    return None
```

### Step 4: Use Tokens in Subsequent Requests

```python
def make_authenticated_request(url: str, auth_data: dict) -> requests.Response:
    """Make request with authentication."""
    headers = {}
    
    # Add JWT token
    if auth_data.get("token"):
        headers["Authorization"] = f"Bearer {auth_data['token']}"
    
    # Add custom headers
    headers.update(auth_data.get("headers", {}))
    
    # Add cookies
    cookies = auth_data.get("cookies", {})
    
    return requests.get(url, headers=headers, cookies=cookies)
```

## Testing Checklist

When testing authenticated endpoints:

- [ ] Discover login endpoints (try common paths)
- [ ] Analyze login form structure
- [ ] Test with provided credentials
- [ ] Extract JWT/token from response
- [ ] Store token for subsequent requests
- [ ] Test all authenticated endpoints
- [ ] Test authorization (IDOR, privilege escalation)
- [ ] Test token expiry and refresh
- [ ] Test session fixation
- [ ] Test logout functionality

## Token Types and Handling

### JWT Tokens
- Store in memory
- Add to `Authorization: Bearer <token>` header
- Check expiry before each request
- Refresh when expired

### Session Cookies
- Store in cookie jar
- Automatically included in requests
- Check for HttpOnly, Secure, SameSite flags

### API Keys
- Store securely
- Add to `Authorization: Bearer <key>` or custom header
- Never log or expose in responses

## Common Vulnerabilities to Test

1. **Broken Authentication** - Default credentials, weak passwords
2. **Session Fixation** - Session ID not regenerated after login
3. **Credential Stuffing** - No rate limiting on login
4. **Token Theft** - JWT in localStorage, XSS exposure
5. **Privilege Escalation** - Horizontal/vertical access control bypass
6. **IDOR** - Access other users' resources by changing IDs
7. **Missing Logout** - Tokens not invalidated server-side
8. **Weak Password Policy** - No complexity requirements
9. **No MFA** - Single factor authentication only
10. **Session Timeout** - No idle/absolute timeout

## Integration with Aegis

The agent should:
1. Check if credentials are provided for the target
2. Automatically detect and test login endpoints
3. Extract and store tokens after successful login
4. Use stored tokens for all subsequent requests
5. Report authentication vulnerabilities found
