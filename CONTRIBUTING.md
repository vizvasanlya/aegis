# Contributing to Aegis

Thank you for your interest in contributing to Aegis! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.12+
- Docker (running)
- [uv](https://docs.astral.sh/uv/) (for dependency management)
- Git

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/vizvasanlya/aegis.git
   cd aegis
   ```

2. **Install development dependencies**
   ```bash
   make setup-dev

   # or manually:
   uv sync
   uv run pre-commit install
   ```

3. **Configure your LLM provider**
   ```bash
   export AEGIS_LLM="openai/gpt-4o"
   export LLM_API_KEY="your-api-key"
   ```

4. **Run Aegis in development mode**
   ```bash
   uv run aegis --target https://example.com
   ```

## Contributing Skills

Skills are specialized knowledge packages that enhance agent capabilities. See `aegis/skills/README.md` for detailed guidelines.

### Quick Guide

1. **Choose the right category** (`/vulnerabilities`, `/frameworks`, `/technologies`, etc.)
2. **Create a `.md` file** with your skill content
3. **Include practical examples** - Working payloads, commands, or test cases

## Code Quality

### Running Checks

```bash
# Format code
make format

# Lint code
make lint

# Type checking
make type-check

# Security checks
make security

# All checks
make check-all
```

### Code Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Write docstrings for public functions
- Keep functions under 50 lines when possible

## Testing

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_config_loader.py

# Run with coverage
uv run pytest --cov=aegis
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commits
3. Add tests for new functionality
4. Ensure all checks pass
5. Submit your pull request

### PR Guidelines

- Keep PRs focused on a single change
- Write clear commit messages
- Include tests for new features
- Update documentation if needed

## Reporting Issues

- Use GitHub Issues for bug reports
- Include steps to reproduce
- Provide environment details (OS, Python version, Docker version)
- Include relevant logs

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
