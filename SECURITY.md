# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via [GitHub's private security advisory feature](https://github.com/innago-property-management/phlegyas/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

| Severity | Initial Response | Fix Target |
|----------|-----------------|------------|
| Critical | 24 hours | 48 hours |
| High | 3 business days | 1 week |
| Medium | 1 week | 2 weeks |
| Low | 2 weeks | Next release |

## Scope

This policy covers:
- The three-tier evaluation pipeline (Tier 1/2/2.5/3)
- The script trust store and content hashing
- AI evaluation prompt injection vectors
- Audit log data exposure
- Pattern bypass techniques (Tier 1 or Tier 2)

## Known Considerations

- **Tier 3 AI evaluation** uses LLM-as-judge, which has inherent prompt injection risks. We apply defense-in-depth (input sanitization, output validation, confidence thresholds) but this is an active area of research.
- **Audit logs** may contain tool input data. In production, configure `AUDIT_LOG_FILE` to a path with restricted permissions.
- **Debug logging** (`LOG_LEVEL=DEBUG`) outputs full request data. Do not use debug logging in shared or production environments.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x | Yes |
| 0.2.x | Yes |
| 0.1.x | No |
