# Paseto
[![Build Status](https://travis-ci.org/GrappigPanda/Paseto.svg?branch=master)](https://travis-ci.org/GrappigPanda/Paseto)

**TODO: Add description**

## Installation

You need libsodium installed on your machine.

```bash
# Installing on FreeBSD
$ cd /usr/ports/security/libsodium/ && make install clean

# Installing on Ubuntu
$ sudo apt install libsodium-dev

# Installing on Fedora
$ dnf install libsodium-devel

# Redhat & Cent OS
$ yum install libsodium-devel

# Installing on OSX
$ brew install libsodium
```

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `paseto` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:paseto, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/paseto](https://hexdocs.pm/paseto).

