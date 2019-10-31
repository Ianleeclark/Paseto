FROM elixir:1.9-alpine

RUN apk add --no-cache \
        gcc \
        libsodium-dev=1.0.18-r0 \
        make \
        musl-dev

RUN mix local.rebar --force && \
    mix local.hex --force

WORKDIR /app
