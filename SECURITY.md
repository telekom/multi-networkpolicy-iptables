# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing `security-mnp@telekom.de` or by using
[GitHub Security Advisories](https://github.com/telekom/multi-networkpolicy-nftables/security/advisories/new).
Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Considerations

This project manages nftables rules in pod network namespaces and requires `NET_ADMIN` capabilities. Key security considerations:

- The daemon runs with elevated privileges (`NET_ADMIN`) to manage network namespaces
- It accesses the Kubernetes API to watch cluster resources
- nftables rules are applied directly to pod network namespaces
- Ensure proper RBAC is configured when deploying (see `deploy.yml`)
