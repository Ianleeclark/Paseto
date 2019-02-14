# Paseto
[![CircleCI](https://circleci.com/gh/GrappigPanda/Paseto/tree/master.svg?style=svg)](https://circleci.com/gh/GrappigPanda/Paseto/tree/master)
[![Hex.pm](https://img.shields.io/hexpm/v/paseto.svg)](https://hex.pm/packages/paseto)
[HexDocs][]

This repository houses an elixir implementation of [Paseto](https://github.com/paragonie/paseto)

From the reference implementation of Paseto:

# What is Paseto?

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
Paseto gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use Paseto in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

## Considerations for using this library

There are a few library/binary requirements required in order for the Paseto 
library to work on any computer:
1. Erlang version >= 20.1
    * This is required because this was the first Erlang version to introduce
      crypto:sign/5.
2. libsodium >= 1.0.13 
    * This is required for cryptography used in Paseto.
    * This can be found at https://github.com/jedisct1/libsodium
3. openssl >= 1.1 
    * This is needed for XChaCha-Poly1305 used for V2.Local Paseto

## Want to use this library through Guardian or Plugs?

Check out some of my other libraries:
* https://github.com/GrappigPanda/paseto_plug
* https://github.com/GrappigPanda/guardian_paseto

### Paseto

#### Paseto Example 1

```
v2.local.QAxIpVe-ECVNI1z4xQbm_qQYomyT3h8FtV8bxkz8pBJWkT8f7HtlOpbroPDEZUKop_vaglyp76CzYy375cHmKCW8e1CCkV0Lflu4GTDyXMqQdpZMM1E6OaoQW27gaRSvWBrR3IgbFIa0AkuUFw.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `local` (shared-key authenticated encryption)
* Payload (hex-encoded):
  ```
  400c48a557be10254d235cf8c506e6fea418a26c93de1f05b55f1bc64cfca412
  56913f1fec7b653a96eba0f0c46542a8a7fbda825ca9efa0b3632dfbe5c1e628
  25bc7b5082915d0b7e5bb81930f25cca9076964c33513a39aa105b6ee06914af
  581ad1dc881b1486b4024b9417
  ```
  * Nonce: `400c48a557be10254d235cf8c506e6fea418a26c93de1f05`
  * Authentication tag: `6914af581ad1dc881b1486b4024b9417`
* Decrypted Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
  * Key used in this example (hex-encoded):
    ```
    707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f  
    ``` 
* Footer:
  ```
  Paragon Initiative Enterprises
  ```

#### Paseto Example 2

```
v2.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ91gC7-jCWsN3mv4uJaZxZp0btLJgcyVwL-svJD7f4IHyGteKe3HTLjHYTGHI1MtCqJ-ESDLNoE7otkIzamFskCA
```

This decodes to:

* Version: `v2`
* Purpose: `public` (public-key digital signature)
* Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
* Signature (hex-encoded):
  ```
  d600bbfa3096b0dde6bf8b89699c59a746ed2c981cc95c0bfacbc90fb7f8207c
  86b5e29edc74cb8c761318723532d0aa27e1120cb36813ba2d908cda985b2408
  ```
* Public key (hex-encoded):
  ```
  11324397f535562178d53ff538e49d5a162242970556b4edd950c87c7d86648a
  ```

To learn what each version means, please see [this page in the documentation](https://github.com/paragonie/paseto/tree/master/docs/01-Protocol-Versions).

## Using Paseto (in Elixir)

### Generating a token
```elixir
iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
iex> keypair = {pk, sk}
iex> token = Paseto.generate_token("v2", "public", "This is a test message", keypair)
"v2.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSe-sJyD2x_fCDGEUKDcvjU9y3jRHxD4iEJ8iQwwfMUq5jUR47J15uPbgyOmBkQCxNDydR0yV1iBR-GPpyE-NQw"
```

In short, we generate a keypair using libsalty (libsodium elixir bindings) and generate the token using that keypair.

P.S. If you're confused about how to serialize the above keys, you can use [Hexate](https://github.com/rjsamson/hexate) which is a dependency of this project:

```elixir
iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
iex> pk |> Hexate.encode()
"a17c258ffdd864b3614bd445465ff96e0b16e8509e28e7ba60734f7c433ab7e8"
```

### Parsing a token
```elixir
iex> token = "v2.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSe-sJyD2x_fCDGEUKDcvjU9y3jRHxD4iEJ8iQwwfMUq5jUR47J15uPbgyOmBkQCxNDydR0yV1iBR-GPpyE-NQw"
iex> Paseto.parse_token(token, keypair)
{:ok,
  %Paseto.Token{
    footer: nil,
    payload: "This is a test message",
    purpose: "public",
    version: "v2"
  }}
"""
```

More info can be found in the [HexDocs][].

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
    {:paseto, "~> 1.1.0"}
  ]
end
```

[HexDocs]: https://hexdocs.pm/paseto
