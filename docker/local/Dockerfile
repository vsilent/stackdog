# build stage
FROM rust:slim as build

# install sqlite3 and create new empty binary project
RUN apt-get update; \
    apt-get install --no-install-recommends -y sqlite3 libsqlite3-dev; \
    rm -rf /var/lib/apt/lists/*; \
    USER=root cargo new --bin app
WORKDIR /app

# copy manifests
COPY ./Cargo.toml ./Cargo.toml

# build this project to cache dependencies
RUN cargo build --release; \
    rm src/*.rs

# copy project source and necessary files
COPY ./src ./src

# add .env and secret.key for Docker env
RUN touch .env;

# rebuild app with project source
RUN rm -rf ./target/release/deps/stackdog*; \
    cargo build --release


# deploy stage
FROM debian:buster-slim

# create app directory
WORKDIR /app

# install libpq
RUN apt-get update; \
    apt-get install --no-install-recommends -y libpq-dev; \
    rm -rf /var/lib/apt/lists/*

# copy binary and configuration files
COPY --from=build /app/target/release/stackdog .
COPY --from=build /app/.env .

# expose port
EXPOSE 5000

RUN /usr/bin/sqlite3 /app/db/stackdog.db

# run the binary
ENTRYPOINT ["/app/stackdog"]
