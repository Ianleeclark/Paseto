defmodule Paseto do
  @moduledoc """
  Main entry point for consumers. Will parse the provided payload and return a version
  (currently only v1 and v2 exist) struct.

  Tokens are broken up into several components:
  * version: v1 or v2 -- v2 suggested
  * purpose: Local or Public -- Local -> Symmetric Encryption for payload & Public -> Asymmetric Encryption for payload
  * payload: A signed or encrypted & b64 encoded string
  * footer: An optional value, often used for storing keyIDs or other similar info.
  """

  alias Paseto.{Token, V1, V2, Utils}

  @doc """
  """
  @spec peek(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def peek(token) do
    case token do
      "v1.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v2.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v1.public." <> _rest ->
        V1.peek(token)

      "v2.public." <> _rest ->
        V2.peek(token)
    end
  end

  @doc """
  Handles parsing a token. Providing it just the entire token will return the
  `Paseto.Token` struct with all fields populated.

  # Examples:
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
  @spec parse_token(String.t(), binary()) :: {:ok, %Token{}} | {:error, String.t()}
  def parse_token(token, key) do
    with {:ok, %Token{version: version, purpose: purpose, payload: payload, footer: footer}} =
           Utils.parse_token(token),
         {:ok, verified_payload} <- _parse_token(version, purpose, payload, key, footer) do
      decoded_footer =
        if footer == "" do
          nil
        else
          Utils.b64_decode!(footer)
        end

      {:ok,
       %Token{
         version: version,
         purpose: purpose,
         payload: verified_payload,
         footer: decoded_footer
       }}
    end
  end

  @spec _parse_token(String.t(), String.t(), String.t(), String.t(), String.t() | tuple()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp _parse_token(version, purpose, payload, key, footer) do
    case String.downcase(version) do
      "v1" ->
        case purpose do
          "local" ->
            V1.decrypt(payload, key, footer)

          "public" ->
            {pk, _sk} = key
            V1.verify(payload, pk, footer)
        end

      "v2" ->
        case purpose do
          "local" ->
            V2.decrypt(payload, key, footer)

          "public" ->
            {pk, _sk} = key
            V2.verify(payload, pk, footer)
        end
    end
  end

  @doc """
  Handles generating a token:

  Tokens are broken up into several components:
  * version: v1 or v2 -- v2 suggested
  * purpose: Local or Public -- Local -> Symmetric Encryption for payload & Public -> Asymmetric Encryption for payload
  * payload: A signed or encrypted & b64 encoded string
  * footer: An optional value, often used for storing keyIDs or other similar info.

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> keypair = {pk, sk}
      iex> token = generate_token("v2", "public", "This is a test message", keypair)
      "v2.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSe-sJyD2x_fCDGEUKDcvjU9y3jRHxD4iEJ8iQwwfMUq5jUR47J15uPbgyOmBkQCxNDydR0yV1iBR-GPpyE-NQw"
      iex> Paseto.parse_token(token, keypair)
      {:ok,
        %Paseto.Token{
        footer: nil,
        payload: "This is a test message",
        purpose: "public",
        version: "v2"
        }}
  """
  @spec generate_token(String.t(), String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def generate_token(version, purpose, payload, secret_key, footer \\ "") do
    _generate_token(version, purpose, payload, secret_key, footer)
  end

  @spec _generate_token(String.t(), String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp _generate_token(version, "public", payload, {_pk, sk}, footer) do
    case String.downcase(version) do
      "v2" -> V2.sign(payload, sk, footer)
      "v1" -> V1.sign(payload, sk, footer)
      _ -> {:error, "Invalid version selected. Only v1 & v2 supported."}
    end
  end

  @spec _generate_token(String.t(), String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp _generate_token(version, "local", payload, key, footer) do
    case String.downcase(version) do
      "v2" -> V2.encrypt(payload, key, footer)
      "v1" -> V1.encrypt(payload, key, footer)
      _ -> {:error, "Invalid version selected. Only v1 & v2 supported."}
    end
  end
end
