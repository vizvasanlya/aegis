# Security Testing Landscape

## What Aegis Does Today

Aegis is an AI-powered web application and API penetration testing tool. It uses multi-agent orchestration to autonomously discover, validate, and report security vulnerabilities with working proof-of-concepts.

### Current Capabilities

| Capability | Status | Description |
|------------|--------|-------------|
| Web App Security (OWASP Top 10) | Full | All 8 mandatory categories: Auth, Access Control, Injection, Server-Side, Client-Side, Config, Business Logic, API Security |
| API Testing (REST, GraphQL, gRPC, WebSocket) | Partial | Schema discovery, parameter fuzzing, auth testing, mass assignment |
| Static Code Analysis (SAST) | Partial | Whitebox mode: semgrep, ast-grep, gitleaks, trufflehog, trivy fs |
| Dynamic Testing (DAST) | Full | Live exploitation with working PoCs, vulnerability chaining |
| Configuration/Header Analysis | Full | CORS, CSP, HSTS, security headers, error handling |
| Authentication/Session Testing | Full | JWT flaws, OAuth abuse, MFA bypass, session fixation |
| Injection Testing | Full | SQLi, NoSQLi, XSS, SSTI, XXE, command injection, LDAP |
| Business Logic Testing | Partial | Race conditions, workflow bypass, price manipulation |
| Multi-Agent Orchestration | Full | Parallel specialist agents, hierarchical decomposition |
| Vulnerability Chaining | Full | Combining low-severity findings into critical attack paths |
| Automated Reporting | Full | CVSS scoring, CWE/OWASP mapping, remediation steps, executive summary |

---

## Security Testing Types in the Market

### 1. Web Application Security Testing (DAST)

**What it tests:** Running web applications for vulnerabilities — XSS, SQL injection, CSRF, IDOR, authentication bypass, session management flaws, business logic errors.

**Market tools:** Burp Suite Professional, OWASP ZAP, Acunetix, Netsparker (Invicti), Qualys WAS, Detectify

**Aegis coverage:** PRIMARY FOCUS. Aegis performs autonomous DAST with AI agents that discover, validate, and chain vulnerabilities. It goes beyond traditional scanners by understanding application context and producing working exploit code.

### 2. API Security Testing

**What it tests:** REST, GraphQL, gRPC, and WebSocket APIs for authentication flaws, authorization bypass (BOLA/IDOR), injection, mass assignment, excessive data exposure, rate limiting, and schema violations.

**Market tools:** 42Crunch, APIsec, Akto, Wallarm, Postman (security tests), Escape GraphQL security

#### What Aegis Has

| Component | Status | Details |
|-----------|--------|---------|
| API fuzzing skill | EXISTS | `skills/tooling/api_fuzzing.md` (499 lines) — schema discovery, endpoint enumeration, JWT fuzzing, auth testing |
| GraphQL skill | EXISTS | `skills/vulnerabilities/graphql/advanced.md` (354 lines) — batching, nested query DoS, introspection abuse |
| WebSocket skill | EXISTS | `skills/vulnerabilities/websocket/testing.md` (248 lines) — CSWSH, message injection, auth bypass |
| gRPC skill | EXISTS | `skills/vulnerabilities/grpc/testing.md` (224 lines) — reflection abuse, auth bypass, message size DoS |
| OpenAPI parser | EXISTS | `interface/api_spec.py` — parses OpenAPI 3.x and Swagger 2.x specs |
| `--api-spec` flag | EXISTS | CLI flag accepts spec files |
| `api_fuzzing` tool module | EMPTY | Directory exists but has zero Python files |

#### What's Missing

| Gap | Current State | What's Needed | Priority |
|-----|---------------|---------------|----------|
| Dedicated API fuzzing tool module | Agent calls nuclei/ffuf via shell | Python module with structured request building, response analysis, finding correlation | Medium |
| GraphQL introspection automation | Manual via agent | `--graphql-introspect` flag to auto-enumerate schema | Medium |
| gRPC reflection/proto discovery | No support | Auto-discover services via gRPC reflection, parse .proto files | Medium |
| HTTP/2 testing | Not covered | H2.CL smuggling, H2.TE smuggling, rapid reset attacks | Medium |
| OAuth2/OIDC deep testing | Partial | Code flow, PKCE bypass, token replay, redirect URI manipulation | Medium |
| Schema violation testing | Not covered | Send invalid payloads against schema, test type confusion | Medium |
| Rate limit detection/bypass | Partially covered | Automated detection of rate limit thresholds | Low |

---

### 3. Static Application Security Testing (SAST)

**What it tests:** Source code for security vulnerabilities — injection flaws, hardcoded secrets, insecure configurations, dependency vulnerabilities, code patterns that lead to exploits.

**Market tools:** SonarQube, Semgrep, CodeQL, Checkmarx, Fortify, Bandit

#### What Aegis Has

| Component | Status | Details |
|-----------|--------|---------|
| Source-aware SAST playbook | EXISTS | `skills/custom/source_aware_sast.md` (152 lines) — semgrep, ast-grep, gitleaks, trufflehog, trivy fs |
| Semgrep skill | EXISTS | `skills/tooling/semgrep.md` |
| Supply chain skill | EXISTS | `skills/tooling/supply_chain.md` — dependency scanning, typosquatting |
| Gitleaks | IN SANDBOX | Pre-installed in Docker image |
| TruffleHog | IN SANDBOX | Pre-installed in Docker image |
| Trivy FS | IN SANDBOX | Pre-installed in Docker image |
| AST-grep | IN SANDBOX | Pre-installed in Docker image |
| Bandit | IN SANDBOX | Pre-installed but no dedicated skill |
| `sast/` tool module | DOES NOT EXIST | All SAST done via CLI invocations |

#### What's Missing

| Gap | Current State | What's Needed | Priority |
|-----|---------------|---------------|----------|
| SARIF output | Not available | Generate SARIF for GitHub Code Scanning integration | High |
| `.strixignore` support | Not implemented | Exclude files/dirs from whitebox scans | High |
| SAST-to-DAST correlation | Not automated | Auto-validate static findings with dynamic testing | High |
| Dedicated SAST tool module | CLI calls only | Python module orchestrating semgrep + ast-grep + gitleaks | Medium |
| CodeQL integration | Not available | Deep semantic analysis for complex taint flows | Medium |
| Java-specific SAST | Only semgrep defaults | Dedicated Java rules (deserialization, reflection, JDBC) | Medium |
| .NET-specific SAST | Only semgrep defaults | Dedicated .NET rules (ViewState, deserialization) | Medium |
| Go-specific SAST | Only semgrep defaults | Dedicated Go rules (unsafe, syscall, CGo) | Medium |
| Code coverage tracking | Not tracked | Know which code paths were tested vs untested | Medium |
| Incremental scanning | Full scan only | Scan only changed files in CI/CD | Medium |

---

### 4. Mobile Application Security Testing

**What it tests:** Android/iOS apps for insecure data storage, certificate pinning bypass, deep link vulnerabilities, improper platform usage, insecure communication, reverse engineering.

**Market tools:** MobSF, Frida, Objection, QARK, AndroBugs, Drozer

#### What Aegis Has

| Component | Status | Details |
|-----------|--------|---------|
| Mobile testing skill | DOES NOT EXIST | No `skills/vulnerabilities/mobile/` directory |
| Mobile tooling skill | DOES NOT EXIST | No `skills/tooling/apktool.md`, `frida.md`, etc. |
| Mobile tool module | DOES NOT EXIST | No `tools/mobile/` directory |
| APK/IPA analysis | DOES NOT EXIST | No reverse engineering capabilities |
| Mobile mentions | PASSING ONLY | Other skills mention "mobile" as a target channel |

#### What's Completely Missing

| Category | What's Needed | Priority |
|----------|---------------|----------|
| APK Reverse Engineering | Decompile APK, analyze manifest, permissions, components (apktool, jadx) | High |
| IPA Analysis | Extract IPA, analyze Info.plist, entitlements, Keychain | High |
| Manifest Audit | AndroidManifest.xml — exported components, permissions, debuggable flag | High |
| Certificate Pinning Bypass | Detect and bypass SSL pinning (Frida, Objection) | High |
| Insecure Data Storage | Check SharedPreferences, Keychain, SQLite for sensitive data | High |
| Insecure Network | Detect cleartext traffic, missing TLS, weak ciphers | High |
| Exported Components | Test exported Activities, Services, BroadcastReceivers (Android) | High |
| WebView Security | JS bridge injection, file access, universal XSS | High |
| Deep Link/URL Scheme | Test custom URL schemes for injection, intent redirection | Medium |
| Root/Jailbreak Bypass | Detect and bypass runtime integrity checks | Medium |
| Runtime Instrumentation | Hook functions, modify behavior at runtime (Frida) | High |
| Flutter/React Native | Cross-platform app security analysis | Medium |

#### Minimum Viable Mobile Testing (Build First)

1. **APK Analysis Module** — Decompile with jadx, parse AndroidManifest.xml, list permissions, detect exported components
2. **IPA Analysis Module** — Extract IPA, parse Info.plist, check Keychain access
3. **Frida Integration** — Certificate pinning bypass, runtime hooking
4. **Data Storage Audit** — Check for plaintext credentials, weak encryption
5. **Network Security Config** — Analyze network_security_config.xml (Android), ATS (iOS)

### 4. Container & Kubernetes Security

**What it tests:** Container image vulnerabilities, misconfigured Kubernetes manifests, RBAC policies, runtime threats, supply chain attacks on container images.

**Market tools:** Trivy, Grype, Falco, kube-bench, Aqua Security, Sysdig, Snyk Container

**Aegis coverage:** PARTIAL. In whitebox mode, Aegis runs `trivy fs` to scan filesystem dependencies. It does not analyze Kubernetes manifests, audit RBAC configurations, or monitor container runtime behavior.

### 5. Cloud Infrastructure Security

**What it tests:** IAM misconfigurations, exposed storage buckets, overly permissive security groups, cloud compliance benchmarks (CIS), secrets in cloud services.

**Market tools:** Prowler (AWS), ScoutSuite, CloudSploit, Steampipe, AWS Config Rules, Azure Security Center

**Aegis coverage:** PARTIAL. Aegis includes a `cloud_metadata/exploitation` skill that demonstrates SSRF-based cloud metadata access (AWS IMDS, GCP metadata). It does not perform cloud provider API auditing or compliance checking.

### 6. Infrastructure & Network Security

**What it tests:** Port scanning, service enumeration, OS-level vulnerabilities, network protocol flaws, SSL/TLS weaknesses, wireless security.

**Market tools:** Nessus, OpenVAS (Greenbone), Qualys, Rapid7 InsightVM, Nmap (detailed), Masscan

**Aegis coverage:** PARTIAL. The Docker sandbox includes nmap, naabu, and subfinder for basic reconnaissance. Aegis does not perform deep infrastructure vulnerability scanning, credentialed network audits, or wireless testing.

### 7. Software Composition Analysis (SCA)

**What it tests:** Known CVEs in open-source dependencies, license compliance risks, transitive dependency vulnerabilities, typosquatting detection.

**Market tools:** Snyk, Dependabot, OWASP Dependency-Check, Socket.dev, Mend (WhiteSource), JFrog Xray

**Aegis coverage:** PARTIAL. In whitebox mode, Aegis runs `trivy fs`, `gitleaks`, and `trufflehog` for dependency and secret scanning. It includes a `supply_chain` skill for typosquatting and backdoor detection. No dedicated SCA dashboard or PR-level dependency review workflow.

### 8. Social Engineering Testing

**What it tests:** Phishing simulations, pretexting, vishing, physical security assessments, employee awareness.

**Market tools:** GoPhish, King Phisher, Social Engineering Toolkit (SET), KnowBe4, Proofpoint Security Awareness

**Aegis coverage:** NOT SUPPORTED. Aegis focuses on technical vulnerability discovery, not human-targeted attacks. Social engineering requires email infrastructure, phone systems, and physical access — outside Aegis's scope.

### 9. IoT & Embedded Security

**What it tests:** Firmware extraction and analysis, hardware interface testing, MQTT/CoAP protocol security, device firmware CVEs, side-channel attacks.

**Market tools:** Firmware Analysis Toolkit, FACT, Binwalk, Ghidra, JTAG/s UART tools, IoT Inspector

**Aegis coverage:** NOT SUPPORTED. IoT testing requires hardware access, firmware analysis tools, and protocol-specific knowledge. Aegis operates at the application layer, not the hardware/firmware layer.

### 10. Red Team / Adversary Simulation

**What it tests:** Full adversary emulation across the kill chain — initial access, execution, persistence, privilege escalation, lateral movement, exfiltration, command and control.

**Market tools:** Cobalt Strike, MITRE CALDERA, Atomic Red Team, Sliver, Havoc

**Aegis coverage:** NOT SUPPORTED. Aegis performs penetration testing (finding and validating vulnerabilities), not full red team operations. It does not establish persistence, perform lateral movement across networks, or operate C2 infrastructure. However, vulnerability chaining in Aegis can demonstrate multi-step attack paths within a single application.

### 11. Compliance Scanning

**What it tests:** Mapping security controls to compliance frameworks (PCI-DSS, HIPAA, SOC2, GDPR, CIS Benchmarks).

**Market tools:** Chef InSpec, Prowler, ScoutSuite, AWS Config, Tenable.sc Compliance

**Aegis coverage:** NOT SUPPORTED. Aegis maps findings to CWE and OWASP Top 10, but does not produce formal compliance reports or assess against regulatory frameworks.

### 12. Secret Detection

**What it tests:** Hardcoded API keys, passwords, tokens, private keys in source code, git history, CI/CD pipelines, and configuration files.

**Market tools:** GitLeaks, TruffleHog, detect-secrets, GitHub secret scanning, GitGuardian

**Aegis coverage:** PARTIAL. In whitebox mode, Aegis runs `gitleaks` and `trufflehog` as part of source code triage. The `supply_chain` skill also covers dependency-related secret exposure.

---

## Comparison Matrix

| Testing Type | Market Leaders | Aegis Status | Gap |
|-------------|---------------|--------------|-----|
| Web App (DAST) | Burp Suite, ZAP, Acunetix | **Full** | — |
| API Security | 42Crunch, Akto | **Partial** | Skills exist but tool module empty; no GraphQL introspection automation, no HTTP/2 testing |
| SAST | SonarQube, Semgrep, CodeQL | **Partial** | Playbook + CLI tools exist; no SARIF, no .strixignore, no SAST-to-DAST correlation |
| Mobile App | MobSF, Frida, Drozer | **None** | No skills, no tools, no analysis capabilities — completely missing |
| Container/K8s | Trivy, Falco | **Partial** | No K8s manifest audit, no RBAC analysis |
| Cloud Infra | Prowler, ScoutSuite | **Partial** | No cloud API auditing, only metadata SSRF |
| Network/Nessus | Nessus, OpenVAS | **Partial** | Basic nmap/naabu recon only |
| SCA (Dependencies) | Snyk, Dependabot | **Partial** | trivy fs + gitleaks; no PR-level review |
| Social Engineering | GoPhish, SET | **None** | Human-targeted, out of scope |
| IoT/Firmware | Ghidra, Binwalk | **None** | Hardware required |
| Red Team | Cobalt Strike, Caldera | **None** | No C2/persistence |
| Compliance | Chef InSpec | **None** | No framework mapping |
| Secret Detection | GitLeaks, TruffleHog | **Partial** | In whitebox mode only |

### Detailed Gap Breakdown (API / SAST / Mobile)

| Area | Has Skills | Has Tool Module | Has CLI Integration | Maturity |
|------|-----------|----------------|---------------------|----------|
| API Security | Yes (499-line fuzzing skill + GraphQL + WebSocket + gRPC) | Empty directory | Partial (`--api-spec` flag) | Medium — skills solid, tooling is stub |
| SAST | Yes (152-line SAST playbook + semgrep + supply_chain) | No dedicated module | Implicit via agent CLI | Medium — playbook excellent, no structured module |
| Mobile | **None** — only passing mentions in other skills | **None** | **None** | **Missing entirely** |

---

## Aegis Differentiators

What makes Aegis unique compared to traditional tools:

1. **AI Multi-Agent System** — Multiple specialized agents work in parallel, each focused on specific vulnerability types, rather than a single scanner doing everything sequentially.

2. **Vulnerability Chaining** — Aegis combines low-severity findings into critical attack chains (e.g., info disclosure + IDOR = data breach).

3. **Working Proof-of-Concept** — Every finding comes with reproducible exploit code, not just a scanner signature match.

4. **Adaptive Testing** — Agents adjust their approach based on what they find, spawning new specialists for discovered attack surfaces.

5. **Both Static and Dynamic** — Whitebox mode combines source code analysis with live exploitation for maximum coverage.

6. **Context Understanding** — AI agents understand application logic, business flows, and trust boundaries — traditional scanners treat every parameter identically.

---

## Recommended Tool Stack (with Aegis)

For comprehensive security coverage, combine Aegis with:

| Layer | Tool | Purpose |
|-------|------|---------|
| Web App DAST | **Aegis** | AI-driven pentesting with PoCs |
| API Security | 42Crunch or Akto | Dedicated API schema analysis |
| SAST | SonarQube or Semgrep | Deep static analysis in CI/CD |
| SCA | Snyk or Dependabot | Dependency vulnerability management |
| Secret Detection | GitLeaks | Pre-commit secret scanning |
| Container Security | Trivy + Falco | Image scanning + runtime monitoring |
| Cloud Security | Prowler | Cloud configuration auditing |
| Network Scanning | Nessus or OpenVAS | Infrastructure vulnerability assessment |
| Mobile Security | MobSF | APK/IPA analysis |
| Compliance | Chef InSpec | Regulatory framework mapping |
