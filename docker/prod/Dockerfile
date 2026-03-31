# base image
FROM debian:bookworm-slim

WORKDIR /app

# install ca-certificates for HTTPS requests
RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# copy binary and configuration files
COPY ./stackdog .
COPY ./.env .

EXPOSE 5000

ENTRYPOINT ["/app/stackdog"]
