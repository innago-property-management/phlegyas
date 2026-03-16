# Contributing

Thanks for your interest in contributing to phlegyas!

## Development Setup

```bash
git clone https://github.com/innago-property-management/phlegyas.git
cd phlegyas
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest                    # All tests
pytest -v                 # Verbose
pytest tests/test_tier2_safe.py -v  # Specific file
```

All 299 tests must pass before submitting a PR.

## Code Style

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check phlegyas/ tests/          # Lint
ruff check --fix phlegyas/ tests/    # Auto-fix
ruff format phlegyas/ tests/         # Format
```

A pre-commit hook runs `ruff format` automatically. Install hooks with:

```bash
pip install pre-commit
pre-commit install
```

## Adding Patterns

### New Dangerous Patterns (Tier 1)
1. Add regex to the appropriate constant in `phlegyas/tier1_dangerous.py`
2. Add test(s) in `tests/test_tier1_dangerous.py`

### New Safe Patterns (Tier 2)
1. Add regex to the appropriate constant in `phlegyas/tier2_safe.py`
2. Add test(s) in `tests/test_tier2_safe.py`

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Run the full test suite (`pytest`)
4. Run linting (`ruff check phlegyas/ tests/`)
5. Submit a PR with a clear description of what and why

## Reporting Bugs

Open a GitHub issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Relevant logs or audit entries (redact any sensitive data)

## Security Issues

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
