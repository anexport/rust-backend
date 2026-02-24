FROM lukemathwalker/cargo-chef:latest-rust-1.93 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching layer
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rust-backend /app/rust-backend
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/config /app/config

EXPOSE 8080
ENTRYPOINT ["./rust-backend"]
