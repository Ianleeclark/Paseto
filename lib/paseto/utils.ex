defmodule Paseto.Utils do
  @moduledoc false

  use Bitwise

  @doc """
  A binary match pattern shortcut to encode a 64-bit unsigned integer into a
  little-endian binary string.

  ## Examples

      iex> import Paseto.Utils, only: :macros
      iex> <<42 :: le64>>
      <<42, 0, 0, 0, 0, 0, 0, 0>>
  """
  defmacro le64 do
    quote do: unsigned - little - integer - 64
  end

  @doc """
  Handles padding multi-part messages before they're sent off to a cryptographic function.

  NOTE: this is currently used in both v1 and v2 protocols.

  NOTE: There's a 99% chance you're using this library incorrectly if you are calling this function.

  ## Examples

      iex> Paseto.Utils.pre_auth_encode(["Paragon"])
      "\x01\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00Paragon"
  """
  @spec pre_auth_encode([String.t()]) :: binary()
  def pre_auth_encode(pieces) when is_list(pieces) do
    Enum.into(pieces, <<Enum.count(pieces)::le64>>, fn piece ->
      <<byte_size(piece)::le64>> <> piece
    end)
  end

  @doc """
  Encode a binary string into a base64url encoded string (without padding).

  ## Examples

      iex> Paseto.Utils.b64_encode(<<206, 158, 75, 219, 56, 182, 139, 177>>)
      "zp5L2zi2i7E"
  """
  @spec b64_encode(binary()) :: binary()
  def b64_encode(input) when is_binary(input), do: Base.url_encode64(input, padding: false)

  @doc """
  Decode a base64url encoded string (without padding) into a binary string.

  ## Examples

      iex> Paseto.Utils.b64_decode("zp5L2zi2i7E")
      {:ok, <<206, 158, 75, 219, 56, 182, 139, 177>>}

      iex> Paseto.Utils.b64_decode("bad input")
      :error
  """
  @spec b64_decode(binary()) :: {:ok, binary()} | :error
  def b64_decode(input) when is_binary(input), do: Base.url_decode64(input, padding: false)

  @doc """
  Decode a base64url encoded string (without padding) into a binary string.

  An `ArgumentError` exception is raised if the padding is incorrect or a
  non-alphabet character is present in the string.

  ## Examples

      iex> Paseto.Utils.b64_decode!("zp5L2zi2i7E")
      <<206, 158, 75, 219, 56, 182, 139, 177>>

      iex> Paseto.Utils.b64_decode!("bad input")
      ** (ArgumentError) non-alphabet digit found: \" \" (byte 32)
  """
  @spec b64_decode(binary()) :: binary()
  def b64_decode!(input) when is_binary(input), do: Base.url_decode64!(input, padding: false)

  @doc """
  Parse a token into the `Paseto.Token` struct without decrypting/verifying the
  payload.

  ## Examples

      iex> Paseto.Utils.parse_token("v2.local.payload")
      {:ok, %Paseto.Token{version: "v2", purpose: "local", payload: "payload", footer: ""}}

      iex> Paseto.Utils.parse_token("v1.public.payload.footer")
      {:ok, %Paseto.Token{version: "v1", purpose: "public", payload: "payload", footer: "footer"}}

      iex> Paseto.Utils.parse_token("v2.public")
      {:error, "Invalid token format"}
  """
  @spec parse_token(String.t()) :: {:ok, %Paseto.Token{}} | {:error, String.t()}
  def parse_token(token) when is_binary(token) do
    case String.split(token, ".") do
      [version, purpose, payload]
      when version in ["v1", "v2"] and purpose in ["public", "local"] ->
        {:ok,
         %Paseto.Token{
           version: version,
           purpose: purpose,
           payload: payload,
           footer: ""
         }}

      [version, purpose, payload, footer]
      when version in ["v1", "v2"] and purpose in ["public", "local"] ->
        {:ok,
         %Paseto.Token{
           version: version,
           purpose: purpose,
           payload: payload,
           footer: footer
         }}

      _ ->
        {:error, "Invalid token format"}
    end
  end
end
