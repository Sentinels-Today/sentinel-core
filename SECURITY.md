# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

We take the security of Sentinel Labs software seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, send a report to **admin@sentinels.today**.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any proof of concept (if available)
- Your PGP fingerprint (optional, for encrypted communication)

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

Contact admin@sentinels.today for the current PGP key.
-----END PGP PUBLIC KEY BLOCK-----
```

### What to expect

- We will acknowledge receipt within 48 hours.
- We will provide an initial assessment within 5 business days.
- We will keep you informed of progress throughout the remediation process.
- We will credit you in the release notes if you wish to be acknowledged.

## Disclosure Policy

We follow a coordinated disclosure process:

1. The reporter submits the vulnerability to admin@sentinels.today.
2. Sentinel Labs acknowledges receipt and begins investigation.
3. Sentinel Labs develops and tests a fix.
4. Sentinel Labs releases a fix and notifies the reporter.
5. The reporter and Sentinel Labs coordinate public disclosure timing.

We aim to release fixes within 30 days of initial report for critical vulnerabilities.

## Scope

The following are in scope:

- All Sentinel Labs open source repositories
- Sentinel Labs cloud services (sentinels.today)
- Sentinel Labs API endpoints

The following are out of scope:

- Third-party dependencies (report to the respective maintainer)
- Social engineering attacks
- Physical security attacks

## Bug Bounty

Sentinel Labs does not currently operate a bug bounty program. Security researchers who report valid vulnerabilities will be credited in release notes and, at our discretion, invited to join the security mailing list.

## Security Best Practices

### For Contributors

- Never commit secrets, keys, or credentials.
- Use environment variables for all configuration.
- Enable 2FA on your GitHub account.
- Sign your commits with GPG.

### For Deployments

- All Sentinel Labs components support deployment behind a reverse proxy.
- Use TLS 1.3 for all communications.
- Enforce key rotation policies.
- Enable audit logging.
- Use hardware security modules (HSMs) or TPMs for key storage in production.

## Contact

- Security: admin@sentinels.today
- PGP: Contact admin@sentinels.today for the current key.
