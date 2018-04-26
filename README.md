# Paseto
[![Build Status](https://travis-ci.org/GrappigPanda/Paseto.svg?branch=master)](https://travis-ci.org/GrappigPanda/Paseto)

**TODO: Add description**

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `paseto` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:paseto, "~> 0.1.0"}
  ]
end
```

### If using V2 (more secure)

This can be a bit of a pain, but erlang *must* be statically compiled with openssl v1.1 (https://www.openssl.org/source/ Current as of writing this at 25 Apr 2018) or with a dynamic ssl linking. An example of building erlang like this can be seen below:

```bash
cd erlang_source_directory
./configure --enable-dynamic-ssl-lib
make
make install
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/paseto](https://hexdocs.pm/paseto).

