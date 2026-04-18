FROM rust:slim-bookworm AS build

RUN apt-get update && \
    apt-get install --no-install-recommends -y musl-tools pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY .env.sample ./.env

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/stackdog /app/stackdog

EXPOSE 5000

ENTRYPOINT ["/app/stackdog"]
