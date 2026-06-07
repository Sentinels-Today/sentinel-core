# Contributing to Sentinel Labs

Thank you for considering contributing to Sentinel Labs. This document outlines the process for contributing to any repository within the Sentinel Labs organization.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security Issues](#security-issues)

## Code of Conduct

All contributors must adhere to the [Code of Conduct](CODE_OF_CONDUCT.md). Unacceptable behavior will not be tolerated.

## Getting Started

1. Fork the repository you wish to contribute to.
2. Clone your fork locally.
3. Set up the development environment as described in the repository's README.
4. Create a new branch for your work.

## Development Workflow

Each repository follows a trunk-based development workflow:

- `main` -- stable, release-ready code
- `develop` -- integration branch for feature work
- `feat/*` -- feature branches
- `fix/*` -- bug fix branches
- `chore/*` -- maintenance and tooling

Feature branches should be short-lived (less than one week). Open a draft pull request early to signal intent and get early feedback.

## Commit Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:

- `feat` -- a new feature
- `fix` -- a bug fix
- `docs` -- documentation changes
- `style` -- code style changes (formatting, etc.)
- `refactor` -- code refactoring
- `perf` -- performance improvements
- `test` -- adding or updating tests
- `chore` -- tooling, configuration, CI
- `ci` -- CI/CD changes
- `build` -- build system changes

Scopes are repository-specific. Common scopes include `core`, `agent`, `sdk`, `api`, `ui`, `chain`, `cli`, `docs`.

Examples:

```
feat(core): add Ed25519 attestation verification
fix(agent): handle reconnection after network timeout
docs(api): document trust score endpoint
```

## Pull Request Process

1. Ensure all commits follow the commit convention.
2. Update documentation if your change introduces new behavior.
3. Add or update tests for all changes.
4. Ensure the CI pipeline passes (lint, typecheck, test, build).
5. Request review from at least one maintainer.
6. Address all review feedback.
7. Squash commits before merge.

All pull requests must be reviewed by at least one maintainer. Maintainers may request changes or reject pull requests that do not meet the project's standards.

## Coding Standards

### Rust

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Run `cargo clippy` and `cargo fmt` before committing.
- All public APIs must have doc comments.
- Use `thiserror` for error types.
- Use `tracing` for logging (not `log`).

### TypeScript

- Follow the [Google TypeScript Style Guide](https://google.github.io/styleguide/tsguide.html).
- Run `eslint` and `prettier` before committing.
- All public APIs must have JSDoc comments.
- Use Zod for runtime validation.
- Use `ts-results` or `neverthrow` for error handling (avoid exceptions for expected errors).

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/).
- Run `ruff` and `black` before committing.
- Use type hints everywhere.
- Use `pydantic` for data validation.

## Testing

- All new code must have tests.
- Unit tests should cover edge cases.
- Integration tests should cover critical paths.
- Test coverage should not decrease.

Repository-specific testing requirements are documented in each repository's README.

## Documentation

- All public APIs must be documented.
- Documentation should be written in MDX for Fumadocs.
- Use `sentinel-docs` for cross-repository documentation.
- Inline code comments should explain _why_, not _what_.

## Security Issues

Do not file a public issue for security vulnerabilities. Report them to admin@sentinels.today. See [SECURITY.md](SECURITY.md) for details.

## Getting Help

- Open a GitHub Discussion in the relevant repository.
- Join our Discord for real-time conversation.
- Tag `sentinelstoday` on Stack Overflow.

## Recognition

All contributors will be listed in the relevant repository's CONTRIBUTORS file. Significant contributions may result in a maintainer invitation.

---

Thank you for contributing to Sentinel Labs.
