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
  defp parse_token(token, key) do
    case String.split(token, ".") do
      [version, purpose, payload, footer] ->
        case Base.decode64(token) do
          {:ok, payload} ->
            {:ok,
             %Token{
               version: version,
               purpose: purpose,
               payload: payload,
               footer: footer
             }}

          :error ->
            {:error, "Invalid (non-base64 encoded) payload in token."}
        end

      [version, purpose, payload] ->
        case Base.decode64(payload) do
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

  @doc """
  """
  @spec generate_token(String.t(), String.t(), String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def generate_token(version, purpose, payload, secret_key, footer \\ "") do
    _generate_token(version, purpose, payload, secret_key, footer)
  end

  @spec _generate_token(String.t(), String.t(), binary, String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp _generate_token(version, "public", payload, secret_key, footer) do
    case String.downcase(version) do
      "v2" -> V2.sign(payload, secret_key, footer)
      "v1" -> V1.sign(payload, secret_key, footer)
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
