# Aegis Skills

## Overview

Skills are specialized knowledge packages that enhance Aegis agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods.

## How Skills Work

When an agent is created, it loads specialized skills relevant to the task:

```python
# Agent creation with specialized skills
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    skills="authentication_jwt,business_logic"
)
```

Skills are dynamically injected into the agent's system prompt for context-specific expertise.

## Skill Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Advanced techniques for authentication bypasses, business logic flaws, race conditions |
| **`/frameworks`** | Testing methods for Django, Express, FastAPI, Next.js |
| **`/technologies`** | Techniques for Supabase, Firebase, Auth0, payment gateways |
| **`/protocols`** | Testing patterns for GraphQL, WebSocket, OAuth |
| **`/tooling`** | Playbooks for nmap, nuclei, httpx, ffuf, sqlmap |
| **`/cloud`** | AWS, Azure, GCP, Kubernetes security testing |
| **`/scan_modes`** | Quick, standard, and deep scan methodologies |
| **`/coordination`** | Multi-agent orchestration patterns |

## Creating Skills

A good skill includes:

- **Advanced techniques** - Non-obvious methods for the domain
- **Practical examples** - Working payloads and commands
- **Validation methods** - How to confirm findings
- **Context insights** - Version nuances and edge cases
- **YAML frontmatter** - `name` and `description` fields

## Contributing

Contributions welcome via [pull requests](https://github.com/vizvasanlya/aegis/pulls) or [GitHub issues](https://github.com/vizvasanlya/aegis/issues).
