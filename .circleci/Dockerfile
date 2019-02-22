FROM elixir:1.8.1-alpine

RUN apk add --no-cache \
        gcc \
        libsodium-dev=1.0.16-r0 \
        make \
        musl-dev

RUN mix local.rebar --force && \
    mix local.hex --force

WORKDIR /app
