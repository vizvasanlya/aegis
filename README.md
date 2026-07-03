<p align="center">
  <a href="https://github.com/vizvasanlya/aegis">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Aegis Banner" width="100%">
  </a>
</p>

<div align="center">

# Aegis

### Open-source AI pentesting tool. Autonomous AI hackers that find and fix your app's vulnerabilities.

<br/>

[![License](https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/vizvasanlya/aegis?style=flat-square)](https://github.com/vizvasanlya/aegis)
[![Docker Image](https://img.shields.io/badge/Docker-ghcr.io/vizvasanlya%2Faegis--sandbox-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/vizvasanlya/aegis/pkgs/container/aegis-sandbox)

</div>

---

## Overview

Aegis is an AI-powered penetration testing tool that autonomously finds and validates security vulnerabilities. It runs your code dynamically, discovers weaknesses, and proves they're exploitable with working proof-of-concepts.

**Key Features:**

- **Full pentesting toolkit** - reconnaissance, exploitation, and validation out of the box
- **Multi-agent orchestration** - teams of AI pentesters that collaborate and scale
- **Real exploit validation** - working PoCs, not false positives
- **OWASP-compliant checklist** - mandatory 8-category testing coverage
- **Auto-fix & reporting** - generate patches and compliance-ready pentest reports

---

## Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key (OpenAI, Anthropic, Google, etc.)

### Installation

```bash
# Clone the repository
git clone https://github.com/vizvasanlya/aegis.git
cd aegis

# Install dependencies
uv sync

# Configure your AI provider
export AEGIS_LLM="openai/gpt-4o"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
aegis --target ./app-directory
```

### Docker Image

The sandbox Docker image is pulled automatically on first run:

```bash
# Image location
ghcr.io/vizvasanlya/aegis-sandbox:latest

# Or set explicitly
export AEGIS_IMAGE="ghcr.io/vizvasanlya/aegis-sandbox:latest"
```

---

## Features

### Mandatory Testing Checklist

Every scan completes all 8 categories based on OWASP Top 10 and PortSwigger:

| # | Category | What It Tests |
|---|----------|---------------|
| 1 | **Authentication & Session** | Default creds, JWT flaws, OAuth abuse, MFA bypass |
| 2 | **Access Control** | IDOR, privilege escalation, forced browsing |
| 3 | **Injection** | SQLi, NoSQLi, XSS, SSTI, XXE, command injection |
| 4 | **Server-Side** | SSRF, path traversal, deserialization, request smuggling |
| 5 | **Client-Side** | DOM XSS, CSRF, clickjacking, prototype pollution |
| 6 | **Configuration** | CORS, CSP, security headers, error handling |
| 7 | **Business Logic** | Race conditions, workflow bypass, input validation |
| 8 | **API Security** | REST/GraphQL auth, mass assignment, data exposure |

### Agentic Pentesting Tools

- **HTTP Interception Proxy** - Caido for request/response analysis
- **Browser Exploitation** - Automated testing for XSS, CSRF, auth bypass
- **Shell & Command Execution** - Exploit development and post-exploitation
- **Custom Exploit Runtime** - Python sandbox for PoC development
- **Reconnaissance & OSINT** - Attack surface mapping and fingerprinting
- **Static & Dynamic Analysis** - SAST + DAST capabilities

---

## Usage Examples

### Basic Scanning

```bash
# Scan a local codebase
aegis --target ./app-directory

# Security review of a GitHub repository
aegis --target https://github.com/org/repo

# Black-box web application assessment
aegis --target https://your-app.com
```

### Advanced Testing

```bash
# Grey-box authenticated testing
aegis --target https://your-app.com --instruction "Test with credentials: user:pass"

# Multi-target testing
aegis -t https://github.com/org/app -t https://your-app.com

# Focused testing
aegis --target api.your-app.com --instruction "Focus on IDOR and XSS"

# Custom instructions from file
aegis --target api.your-app.com --instruction-file ./rules.md
```

### Headless Mode

```bash
# Run without interactive UI
aegis -n --target https://your-app.com
```

### CI/CD Integration

```yaml
name: aegis-pentest

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Aegis
        run: |
          git clone https://github.com/vizvasanlya/aegis.git
          cd aegis && uv sync

      - name: Run Aegis
        env:
          AEGIS_LLM: ${{ secrets.AEGIS_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: aegis -n -t ./ --scan-mode quick
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AEGIS_LLM` | Yes | Model name (e.g., `openai/gpt-4o`) |
| `LLM_API_KEY` | Yes | API key for the LLM provider |
| `AEGIS_IMAGE` | No | Docker image (default: `ghcr.io/vizvasanlya/aegis-sandbox:latest`) |
| `AEGIS_DEBUG` | No | Enable debug logging (`1`, `true`, `yes`) |
| `AEGIS_TELEMETRY` | No | Enable telemetry (default: `true`) |
| `LLM_API_BASE` | No | Custom API base URL for local models |
| `PERPLEXITY_API_KEY` | No | For web search capabilities |

### Recommended Models

| Model | Provider | Command |
|-------|----------|---------|
| GPT-4o | OpenAI | `openai/gpt-4o` |
| Claude Sonnet 4.6 | Anthropic | `anthropic/claude-sonnet-4-6` |
| Gemini 2.5 Pro | Google | `vertex_ai/gemini-2.5-pro` |
| DeepSeek V4 | DeepSeek | `opencode/deepseek-v4` |

### Config File

Aegis saves configuration to `~/.aegis/cli-config.json` automatically.

---

## Architecture

```
aegis/
├── agents/          # Agent factory and prompt rendering
├── config/          # Settings and model configuration
├── core/            # Runner, execution loop, session management
├── interface/       # CLI and TUI interfaces
├── report/          # Vulnerability reporting and deduplication
├── runtime/         # Docker sandbox and Caido proxy
├── skills/          # Scan mode templates and vulnerability skills
├── telemetry/       # Usage tracking
├── tools/           # Pentesting tools (proxy, shell, browser, etc.)
└── utils/           # Shared utilities
```

---

## Scan Modes

| Mode | Duration | Depth | Use Case |
|------|----------|-------|----------|
| `quick` | 10-15 min | High-impact only | CI/CD, rapid checks |
| `standard` | 20-30 min | Balanced | Regular security testing |
| `deep` | 30-60 min | Exhaustive | Comprehensive assessments |

```bash
# Quick scan for CI/CD
aegis -n --target ./ --scan-mode quick

# Deep scan for thorough assessment
aegis --target https://your-app.com --scan-mode deep
```

---

## Vulnerability Reporting

Aegis generates structured reports with:

- **CVSS scoring** - severity based on exploitability and impact
- **Working PoCs** - reproducible exploit code
- **Remediation steps** - actionable fix recommendations
- **OWASP classification** - mapped to CWE/OWASP Top 10

Reports are saved to `aegis_runs/<run-name>/`:
```
aegis_runs/
└── sarvasetu-admin-pages-dev_667b/
    ├── run.json
    ├── vulnerabilities.json
    ├── vulnerabilities.csv
    ├── penetration_test_report.md
    └── aegis.log
```

---

## Docker Image

The sandbox image includes:

- **Kali Linux** base with 30+ pentesting tools
- **Caido** HTTP proxy for traffic interception
- **Nmap, Nuclei, SQLMap, ffuf, subfinder** and more
- **Playwright** for browser automation
- **Python/Node.js** for custom exploit development

Built from `containers/Dockerfile` and published via GitHub Actions.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

---

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built on the work of:
- [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
- [LiteLLM](https://github.com/BerriAI/litellm)
- [Caido](https://github.com/caido/caido)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Playwright](https://github.com/microsoft/playwright)

---

> **Warning:** Only test applications you own or have permission to test. You are responsible for using Aegis ethically and legally.
