# base image
FROM debian:buster-slim

# create app directory
RUN mkdir app
WORKDIR /app

# install libpq
RUN apt-get update; \
    apt-get install --no-install-recommends -y libpq-dev; \
    rm -rf /var/lib/apt/lists/*

# copy binary and configuration files
COPY ./stackdog .
COPY ./.env .

# expose port
EXPOSE 5000

# run the binary
ENTRYPOINT ["/app/stackdog"]