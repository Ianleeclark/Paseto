defmodule Paseto.TestVectors do
  @moduledoc false

  alias Paseto.{V2LocalKey, V2PublicKeyPair, V1LocalKey, V1PublicKeyPair}

  def load(fixture_file) do
    fixture_file
    |> Code.eval_file()
    |> elem(0)
  end

  def to_v1_local_example(vector_spec) do
    vector = vector_spec[:vector]
    token = vector_spec[:token]
    payload = vector_spec[:payload]

    key =
      V1LocalKey.new(
        vector_spec
        |> Keyword.fetch!(:key)
        |> parse_hex()
      )

    nonce =
      case Keyword.fetch(vector_spec, :nonce) do
        {:ok, nonce} ->
          parse_hex(nonce)

        _ ->
          nil
      end

    footer = Keyword.get(vector_spec, :footer, "")

    example = %{key: key, nonce: nonce, payload: payload, footer: footer, token: token}

    {vector, Macro.escape(example)}
  end

  def to_v2_local_example(vector_spec) do
    vector = vector_spec[:vector]
    token = vector_spec[:token]
    payload = vector_spec[:payload]

    key =
      V2LocalKey.new(
        vector_spec
        |> Keyword.fetch!(:key)
        |> parse_hex()
      )

    nonce =
      case Keyword.fetch(vector_spec, :nonce) do
        {:ok, nonce} ->
          parse_hex(nonce)

        _ ->
          nil
      end

    footer = Keyword.get(vector_spec, :footer, "")

    example = %{key: key, nonce: nonce, payload: payload, footer: footer, token: token}

    {vector, Macro.escape(example)}
  end

  def to_v1_public_example(vector_spec) do
    vector = vector_spec[:vector]
    token = vector_spec[:token]
    payload = vector_spec[:payload]

    pk =
      vector_spec
      |> Keyword.fetch!(:public_key)
      |> String.trim()
      |> Paseto.RSAPublicKey.decode()

    keypair = V1PublicKeyPair.new(pk, "fake secret key")

    footer = Keyword.get(vector_spec, :footer, "")

    example = %{keypair: keypair, payload: payload, footer: footer, token: token}

    {vector, Macro.escape(example)}
  end

  def to_v2_public_example(vector_spec) do
    vector = vector_spec[:vector]
    token = vector_spec[:token]
    payload = vector_spec[:payload]

    sk =
      vector_spec
      |> Keyword.fetch!(:private_key)
      |> parse_hex()

    pk =
      vector_spec
      |> Keyword.fetch!(:public_key)
      |> parse_hex()

    keypair = V2PublicKeyPair.new(pk, sk)

    footer = Keyword.get(vector_spec, :footer, "")

    example = %{keypair: keypair, payload: payload, footer: footer, token: token}

    {vector, Macro.escape(example)}
  end

  defp parse_hex(hex) do
    hex
    |> String.replace(" ", "", global: true)
    |> Base.decode16!(case: :lower)
  end
end
