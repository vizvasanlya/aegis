### Overview

To help make Aegis better for everyone, we collect anonymized data that helps us understand how to improve our AI security agent, guide new features, and fix bugs. This feedback loop is crucial for improving Aegis's capabilities.

We use [PostHog](https://posthog.com), an open-source analytics platform, for data collection. Our telemetry is fully transparent - you can review the source code to see exactly what we track.

### Telemetry Policy

Privacy is our priority. All collected data is anonymized by default. Each session gets a random UUID that is not persisted or tied to you. Your code, scan targets, vulnerability details, and findings always remain private and are never collected.

### What We Track

We collect only basic usage data:

- **Session Errors:** Duration and error types (not messages or stack traces)
- **System Context:** OS type, architecture, Aegis version
- **Scan Context:** Scan mode (quick/standard/deep), scan type (whitebox/blackbox)
- **Model Usage:** Which LLM model is being used (not prompts or responses)
- **Aggregate Metrics:** Vulnerability counts by severity

### What We Never Collect

- Usernames or identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### How to Opt Out

Telemetry is entirely optional:

```bash
export AEGIS_TELEMETRY=0
```

Set this environment variable before running Aegis to disable all telemetry.
