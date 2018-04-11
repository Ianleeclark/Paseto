defmodule Paseto do
  @moduledoc """
  Main entry point for consumers. Will parse the provided payload and return a version
  (currently only v1 and v2 exist) struct.
  """

  alias Paseto.{Token, V1, V2}

  @doc """
  Handles parsing a paseto token

  ## Examples

  iex> Paseto.parse("v1.local.dGVzdA==")
  {:ok, %Paseto.V1{version: "v1", purpose: "local", payload: "test", footer: nil}}

  """
  @spec parse(String.t()) :: {:ok, %Paseto.V1{}} | {:ok, %Paseto.V2{}} | {:error, String.t()}
  def parse(token) do
    case parse_token(token) do
      {:ok, %{version: "v1"} = parsed_token} ->
        {:ok, V1.from_token(parsed_token)}

      {:ok, %{version: "v2"} = parsed_token} ->
        {:ok, V2.from_token(parsed_token)}

      {:ok, %{version: _}} ->
        {:error, "Invalid token version. Only versions 1 & 2 are supported"}

      {:error, _} = err ->
        err
    end
  end

  # TODO(ian): Add docstring and check out the typespec w/ exception
  @spec parse!(String.t()) :: %Paseto.V1{} | %Paseto.V2{}
  def parse!(payload) do
    case parse(payload) do
      {:ok, token} -> token
      {:error, error_message} -> raise error_message
    end
  end

  # TODO(ian): Add a docstring here explaining pieces.
  @spec parse_token(String.t()) :: {:ok, %Token{}} | {:error, String.t()}
  def parse_token(payload) do
    case String.split(payload, ".") do
      [version, purpose, payload, footer] ->
        case Base.decode64(payload) do
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
end
