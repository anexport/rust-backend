# Repository Guidelines

## Project Structure & Module Organization
- Core Rust code lives in `src/`, with layered modules such as `api/`, `application/`, `domain/`, `infrastructure/`, `middleware/`, and `config/`.
- Entry points are `src/main.rs` (binary) and `src/lib.rs` (library exports).
- Integration and end-to-end style tests are in `tests/` (for example `tests/core_api_tests.rs`, `tests/ws_security_tests.rs`), with shared helpers under `tests/common/`.
- Database migrations live in `migrations/`; operational and API docs are in `docs/`; local static frontend smoke page is in `frontend/`.

## Build, Test, and Development Commands
- `make run`: run the backend locally (`cargo run`).
- `make check`: fast compile validation (`cargo check`).
- `make build` / `make build-release`: debug or optimized build.
- `make test`: run all tests (`cargo test`).
- `make test-integration`: run integration tests (`cargo test --test '*'`).
- `make fmt-check`, `make clippy`, `make audit`: enforce formatting, linting, and dependency security.
- `make check-all`: CI-like local gate (`fmt-check + clippy + test + audit`).
- `make migrate` / `make migrate-revert`: apply or roll back SQLx migrations.
- `make docker-up` / `make docker-down`: start/stop local service dependencies.

## Coding Style & Naming Conventions
- Rust edition is 2021; format with `cargo fmt` (4-space indentation via rustfmt defaults).
- Treat lint warnings as errors (`cargo clippy -- -D warnings`).
- Use snake_case for functions/modules/files, CamelCase for types/traits, and UPPER_SNAKE_CASE for constants.
- Keep module boundaries aligned with domain layers (`api` -> `application` -> `domain` -> `infrastructure`).

## Testing Guidelines
- Prefer integration tests in `tests/*_tests.rs`; use descriptive names by behavior (example: `auth0_endpoints_tests.rs`).
- For DB-backed tests, ensure `DATABASE_URL` is set and migrations are applied before running tests.
- Add or update tests with every behavior change, especially auth, security, and websocket flows.

## Commit & Pull Request Guidelines
- Follow the repository’s conventional pattern where possible: `feat: ...`, `fix: ...`, `chore: ...`, `docs: ...`.
- Keep commits focused and scoped to one concern.
- PRs should include: purpose, key changes, test evidence (commands run), migration/config impact, and linked issue/task.
- Before opening a PR, run `make check-all` and note any non-default setup used (Auth0, DB, env vars).

## Security & Configuration Tips
- Copy `.env.example` to `.env` for local setup; never commit real secrets.
- Auth is Auth0-first in this codebase; validate `AUTH0_*` and `SECURITY__*` settings before testing protected endpoints.
