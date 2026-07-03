# Strix Gap Analysis

> Comprehensive audit of missing features, improvement opportunities, and areas for growth.
> Generated: July 3, 2026

---

## Executive Summary

Strix is a well-architected AI penetration testing tool with strong core capabilities. This document identifies **30+ gaps** across 8 categories, prioritized by impact and effort. The most impactful quick wins are API spec support, JSON output, and dry-run mode.

**Overall Health Score: 8/10** — Strong foundation with clear paths for improvement.

---

## 1. API & Specification Support

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **OpenAPI/Swagger upload** | Agents auto-discover `/openapi.json` at common paths | `--api-spec` flag to accept spec files directly | 🔴 High | Medium |
| **nuclei OpenAPI mode** | Available in nuclei but not wired into Strix | Auto-detect and use `-im openapi` when spec is provided | 🟡 Medium | Low |
| **GraphQL introspection** | Skill exists but no dedicated flag | `--graphql-introspect` to auto-enumerate schema | 🟡 Medium | Low |
| **gRPC reflection** | No support | Service reflection and proto discovery | 🟡 Medium | High |

### Recommended: `--api-spec` Flag

```bash
# Current workaround
strix --target https://api.example.com --instruction-file ./openapi.yaml

# Desired
strix --target https://api.example.com --api-spec ./openapi.yaml
strix --target https://api.example.com --api-spec https://api.example.com/swagger.json
```

---

## 2. Testing Coverage

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **Mobile binary analysis** | Tests backend APIs only | APK/IPA reverse engineering, manifest analysis | 🔴 High | High |
| **WebSocket testing** | No dedicated skill | WS protocol testing, message injection, auth bypass | 🟡 Medium | Medium |
| **OAuth2/OIDC flows** | Partially covered in auth skill | Comprehensive OAuth2 testing (code flow, PKCE, token replay) | 🟡 Medium | Low |
| **Server-Sent Events (SSE)** | Not covered | SSE injection, event stream manipulation | 🟢 Low | Low |
| **HTTP/2 testing** | Not covered | H2.CL, H2.TE smuggling, rapid reset attacks | 🟡 Medium | Medium |
| **LDAP/Active Directory** | Not covered | Enterprise auth testing, Kerberoasting, AS-REP roast | 🔴 High | High |
| **IoT/Embedded** | Not covered | Device firmware, MQTT, CoAP testing | 🟢 Low | High |
| **Blockchain/Smart Contracts** | Not covered | Solidity analysis, reentrancy, flash loans | 🟢 Low | High |

---

## 3. Reporting & Output

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **JSON export** | Only TUI/text output | `--output-format json` for machine-readable results | 🔴 High | Low |
| **SARIF output** | Not available | `--output-format sarif` for GitHub code scanning integration | 🔴 High | Medium |
| **PDF report generation** | Text-only reports | Formatted PDF with charts, executive summary, remediation | 🟡 Medium | High |
| **Scan comparison** | No diff capability | `--diff scan-1 scan-2` to compare results over time | 🟡 Medium | Medium |
| **Compliance mapping** | CVSS scoring only | Map findings to SOC 2, ISO 27001, PCI DSS controls | 🟡 Medium | Medium |
| **Real-time streaming** | Live TUI updates | WebSocket/SSE endpoint for external dashboard integration | 🟢 Low | High |

### Recommended: JSON Output

```bash
# Current
strix --target https://example.com  # TUI output only

# Desired
strix --target https://example.com --output-format json > results.json
strix --target https://example.com --output-format sarif > results.sarif
strix --target https://example.com --output-format html > report.html
```

---

## 4. Developer Experience

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **`--version` timeout** | Times out on Windows | Instant version display | 🔴 High | Low |
| **`--verbose` flag** | Fixed log level | Adjustable verbosity (quiet/default/verbose/debug) | 🟡 Medium | Low |
| **`--list-models`** | Not available | Show supported models per provider | 🟡 Medium | Low |
| **`--dry-run`** | Not available | Preview targets and plan without executing | 🟡 Medium | Medium |
| **Progress tracking** | No percentage/ETA | Show completion %, estimated time remaining | 🟡 Medium | Medium |
| **`--help` examples** | Basic examples | Richer examples with common use cases | 🟢 Low | Low |
| **Shell completion** | Not available | Bash/Zsh/PowerShell tab completion | 🟢 Low | Medium |
| **`--config` validation** | Errors at runtime | Validate config file on startup with clear messages | 🟡 Medium | Low |

### Recommended: Dry-Run Mode

```bash
# Preview what would be tested
strix --target https://example.com --dry-run
# Output:
# Targets: https://example.com
# Scan mode: deep
# Skills to load: sql_injection, xss, ssrf, authentication_jwt
# Estimated LLM cost: ~$2.50
# Docker image: ghcr.io/usestrix/strix-sandbox:1.0.0
```

---

## 5. Configuration & Integration

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **`ANTHROPIC_API_KEY` alias** | Not recognized | Add to `AliasChoices` in `LlmSettings` | 🟡 Medium | Low |
| **Pydantic deprecation** | `model_fields` on instance | Use `type(s).model_fields` in `loader.py:63` | 🟡 Medium | Low |
| **`.strixignore`** | Not supported | Exclude files/dirs from white-box scans | 🟡 Medium | Medium |
| **Config profiles** | Single config | `~/.strix/profiles/prod.json`, `dev.json` | 🟢 Low | Medium |
| **Environment detection** | Manual setup | Auto-detect Docker, Python, API keys on first run | 🟡 Medium | Low |
| **Credential rotation** | Manual env vars | Support for `.env` files, credential managers | 🟢 Low | Medium |

---

## 6. Security & Robustness

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **Broad exception handling** | 132 `except Exception` blocks | Narrower exception types, better error propagation | 🟡 Medium | High |
| **Rate limiting** | Only budget cap | Per-provider rate limit awareness, automatic backoff | 🟡 Medium | Low |
| **Scan authentication** | Manual cookie/header setup | `--auth-cookie`, `--auth-header`, `--auth-token` flags | 🟡 Medium | Medium |
| **Proxy auth** | Not supported | `--proxy-auth user:pass` for corporate proxies | 🟡 Medium | Low |
| **Input sanitization** | LLM-generated payloads | Validate/sanitize targets before execution | 🟢 Low | Medium |
| **Audit logging** | Basic scan logging | Structured audit trail with timestamps, actions, findings | 🟡 Medium | Medium |

---

## 7. Missing Skills & Knowledge

| Category | Gap | Priority |
|----------|-----|----------|
| **Protocols** | WebSocket testing methodology | 🟡 Medium |
| **Protocols** | gRPC/protobuf security testing | 🟡 Medium |
| **Protocols** | MQTT/IoT protocol testing | 🟢 Low |
| **Frameworks** | Django/Flask/FastAPI security patterns | 🟡 Medium |
| **Frameworks** | Spring Boot/Java security testing | 🟡 Medium |
| **Technologies** | AWS Lambda/serverless security | 🟡 Medium |
| **Technologies** | Docker/container escape techniques | 🟡 Medium |
| **Technologies** | CI/CD pipeline security (GitHub Actions, GitLab CI) | 🟡 Medium |
| **Vulnerabilities** | XML-RPC/JSON-RPC injection | 🟢 Low |
| **Vulnerabilities** | Prototype pollution (JS) | 🟡 Medium |
| **Vulnerabilities** | Deserialization (Java, PHP, Python) | 🟡 Medium |
| **Vulnerabilities** | CORS misconfiguration | 🟡 Medium |
| **Reconnaissance** | Shodan/Censys integration | 🟢 Low |
| **Reconnaissance** | Certificate transparency logs | 🟢 Low |

---

## 8. Infrastructure & DevOps

| Gap | Current State | Desired State | Impact | Effort |
|-----|---------------|---------------|--------|--------|
| **Kubernetes deployment** | Docker only | Helm chart for K8s deployment | 🟡 Medium | High |
| **Webhook notifications** | None | Slack/Discord/email on vulnerability found | 🟡 Medium | Medium |
| **Jira/Linear integration** | None | Auto-create issues for findings | 🟢 Low | Medium |
| **Parallel scans** | Sequential | Scan multiple targets concurrently | 🟡 Medium | High |
| **Scan scheduling** | Manual | Cron-like scheduling for recurring scans | 🟢 Low | High |
| **Multi-user support** | Single user | Role-based access, scan ownership | 🟢 Low | High |
| **Docker image updates** | Manual pull | Auto-update check on startup | 🟢 Low | Low |
| **Windows support** | Partial (1 test fails) | Full Windows compatibility | 🟡 Medium | Low |

---

## Priority Matrix

### 🔴 High Impact, Low Effort (Quick Wins)
1. **`--api-spec` flag** — API testing from OpenAPI files
2. **JSON/SARIF output** — CI/CD integration
3. **`--dry-run` mode** — Safety and discoverability
4. **`--version` fix** — Remove timeout on Windows
5. **`ANTHROPIC_API_KEY` alias** — Better UX for Anthropic users
6. **Pydantic deprecation fix** — Future-proofing

### 🟡 High Impact, Medium Effort
7. **WebSocket testing skill** — Modern API coverage
8. **Scan comparison (`--diff`)** — Track posture over time
9. **PDF report generation** — Professional output
10. **`.strixignore` support** — Exclude files from scans
11. **Scan authentication flags** — Easier auth setup
12. **Progress tracking** — Better UX during long scans

### 🟢 Medium Impact, High Effort (Long-term)
13. **Mobile binary analysis** — APK/IPA reverse engineering
14. **Kubernetes deployment** — Enterprise scalability
15. **LDAP/AD testing** — Enterprise auth coverage
16. **Parallel scan orchestration** — Speed improvement
17. **Compliance mapping** — SOC 2, ISO 27001, PCI DSS

---

## Comparison with Competitors

| Feature | Strix | Burp Suite | OWASP ZAP | Nuclei |
|---------|-------|------------|-----------|--------|
| API spec upload | ❌ | ✅ | ✅ | ✅ |
| JSON output | ❌ | ✅ | ✅ | ✅ |
| SARIF output | ❌ | ❌ | ✅ | ❌ |
| PDF reports | ❌ | ✅ | ✅ | ❌ |
| Scan diff | ❌ | ✅ | ❌ | ❌ |
| Dry-run mode | ❌ | ❌ | ❌ | ✅ |
| WebSocket testing | ❌ | ✅ | ✅ | ❌ |
| gRPC support | ❌ | ✅ | ❌ | ❌ |
| Mobile binary | ❌ | ✅ | ❌ | ❌ |
| Multi-user | ❌ | ✅ | ❌ | ❌ |
| AI orchestration | ✅ | ❌ | ❌ | ❌ |
| Auto-fix code | ✅ | ❌ | ❌ | ❌ |
| White-box SAST | ✅ | ❌ | ❌ | ❌ |
| Free tier | ✅ | ❌ | ✅ | ✅ |

---

## Recommendations

### Phase 1: Quick Wins (1-2 weeks)
- Add `--api-spec` flag for OpenAPI/Swagger
- Add `--output-format json` and `--output-format sarif`
- Fix `--version` timeout on Windows
- Add `ANTHROPIC_API_KEY` env alias
- Fix Pydantic deprecation warning
- Add `--dry-run` mode

### Phase 2: Core Improvements (1-2 months)
- Add WebSocket testing skill
- Add scan comparison (`--diff`)
- Add `.strixignore` support
- Add progress tracking with ETA
- Add scan authentication flags
- Add PDF report generation

### Phase 3: Advanced Features (3-6 months)
- Mobile binary analysis (APK/IPA)
- Kubernetes deployment option
- LDAP/Active Directory testing
- Parallel scan orchestration
- Compliance mapping (SOC 2, ISO 27001)
- Webhook notifications

---

## Contributing

To help close these gaps:
1. Check [GitHub Issues](https://github.com/usestrix/strix/issues) for existing requests
2. Open a new issue for unlisted gaps
3. Submit a PR with the fix — see [Contributing Guide](https://docs.strix.ai/contributing)

---

*This document was generated through comprehensive codebase analysis of Strix v1.0.4.*
