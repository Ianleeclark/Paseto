FROM erlang:24-alpine

#
# Largely copied from https://github.com/c0b/docker-elixir, but modified to
# install libsodium.
#

# elixir expects utf8.
ENV ELIXIR_VERSION="v1.13" \
LANG=C.UTF-8

RUN set -xe \
  && ELIXIR_DOWNLOAD_URL="https://github.com/elixir-lang/elixir/archive/${ELIXIR_VERSION}.tar.gz" \
  && buildDeps=' \
  ca-certificates \
  curl \
  make \
  ' \
  && apk add --no-cache --virtual .build-deps $buildDeps \
  && curl -fSL -o elixir-src.tar.gz $ELIXIR_DOWNLOAD_URL \
  && mkdir -p /usr/local/src/elixir \
  && tar -xzC /usr/local/src/elixir --strip-components=1 -f elixir-src.tar.gz \
  && rm elixir-src.tar.gz \
  && cd /usr/local/src/elixir \
  && make install clean \
  && apk del .build-deps

RUN apk add --no-cache \
  gcc \
  libsodium-dev=1.0.18-r0 \
  make \
  musl-dev

RUN mix local.rebar --force && \
  mix local.hex --force

WORKDIR /app

CMD ["iex"]
