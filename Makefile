.PHONY: help fmt fmt-check clippy check build build-release test test-integration audit migrate migrate-revert check-all clean run docker-up docker-down

help:
	@echo "Available targets:"
	@echo "  fmt              - Format code with cargo fmt"
	@echo "  fmt-check        - Check code formatting"
	@echo "  clippy           - Run clippy linter with warnings as errors"
	@echo "  check            - Run cargo check"
	@echo "  build            - Build project in debug mode"
	@echo "  build-release    - Build project in release mode"
	@echo "  test             - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  audit            - Run cargo audit for security vulnerabilities"
	@echo "  migrate          - Run database migrations"
	@echo "  migrate-revert   - Revert last database migration"
	@echo "  check-all        - Run fmt-check, clippy, test, and audit"
	@echo "  clean            - Remove build artifacts"
	@echo "  run              - Run the application"
	@echo "  docker-up        - Start docker-compose services"
	@echo "  docker-down      - Stop docker-compose services"

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy -- -D warnings

check:
	cargo check

build:
	cargo build

build-release:
	cargo build --release

test:
	cargo test

test-integration:
	cargo test --test '*'

audit:
	cargo audit

migrate:
	sqlx migrate run

migrate-revert:
	sqlx migrate revert

check-all: fmt-check clippy test audit

clean:
	cargo clean

run:
	cargo run

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
