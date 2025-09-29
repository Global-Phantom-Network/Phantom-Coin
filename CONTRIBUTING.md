# Contributing

Thank you for your interest in contributing to Phantom-Coin!

## Development Setup
- Rust stable, `cargo`
- Optional tools: `cargo-audit`, `cargo-deny`
- Run checks:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --all-targets`

## Branch/PR Guidelines
- Create feature branches from `main`.
- Keep PRs focused and small; include tests.
- Pass CI (fmt, clippy, build, tests) before review.
- Reference related issues in PR description.

## Commit Messages
- Conventional style suggested: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`

## Licensing
- By contributing, you agree your code is licensed under `AGPL-3.0-only`.
