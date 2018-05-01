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

  alias Paseto.{Token, V1, V2}

  @doc """
  """
  @spec parse_token(String.t(), binary()) :: {:ok, %Token{}} | {:error, String.t()}
  def parse_token(token, key) do
    case String.split(token, ".") do
      [version, purpose, payload, footer] ->
        with {:ok, decoded_footer} <- Base.url_decode64(footer, padding: false),
             {:ok, verified_payload} <- _parse_token(version, purpose, payload, key, footer)
        do
          {:ok,
            %Token{
              version: version,
              purpose: purpose,
              payload: verified_payload,
              footer: decoded_footer
            }}
        else
          {:error, _reason} = error -> error
          _ ->
            {:error, "Invalid (non-base64 encoded) payload in token."}
        end

      [version, purpose, payload] ->
        case Base.url_decode64(payload, padding: false) do
          {:ok, payload} ->
            {:ok,
             %Token{
               version: version,
               purpose: purpose,
               payload: payload,
               footer: nil
             }}

          :error ->
            {:error, "Invalid (non-base64 encoded) payload in token."}
        end

      _ ->
        {:error, "Invalid token encountered during token parsing"}
    end
  end

  @spec _parse_token(String.t(), String.t(), String.t(), String.t(), String.t() | tuple()) :: {:ok, String.t()} | {:error, String.t()}
  defp _parse_token(version, purpose, payload, key, footer \\ "") do
    require Logger
    Logger.debug(payload)
    case String.downcase(version) do
      "v1" ->
        case purpose do
          "local" -> V1.decrypt(payload, key, footer)
          "public" ->
            {pk, _sk} = key
            V1.verify(payload, pk, footer)
        end
      "v2" ->
        case purpose do
          "local" -> V2.decrypt(payload, key, footer)
          "public" ->
            {pk, _sk} = key
            V2.verify(payload, pk, footer)
        end
    end
  end

  @doc """
  """
  @spec generate_token(String.t(), String.t(), String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def generate_token(version, purpose, payload, secret_key, footer \\ "") do
    _generate_token(version, purpose, payload, secret_key, footer)
  end

  @spec _generate_token(String.t(), String.t(), binary, String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp _generate_token(version, "public", payload, {_pk, sk}, footer) do
    case String.downcase(version) do
      "v2" -> V2.sign(payload, sk, footer)
      "v1" -> V1.sign(payload, sk, footer)
      _ -> {:error, "Invalid version selected. Only v1 & v2 supported."}
    end
  end

  @spec _generate_token(String.t(), String.t(), binary, String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp _generate_token(version, "local", payload, key, footer) do
    case String.downcase(version) do
      "v2" -> V2.encrypt(payload, key, footer)
      "v1" -> V1.encrypt(payload, key, footer)
      _ -> {:error, "Invalid version selected. Only v1 & v2 supported."}
    end
  end
end
