defmodule Paseto.Utils do
  @moduledoc false

  use Bitwise

  @doc """
  Handles padding multi-part messages before they're sent off to a cryptographic function.

  NOTE: this is currently used in both v1 and v2 protocols.

  NOTE: There's a 99% chance you're using this library incorrectly if you are calling this function.
  """
  @spec pre_auth_encode([String.t()]) :: String.t()
  def pre_auth_encode(pieces) when is_list(pieces) do
    convert(le64(Enum.count(pieces))) <>
      Enum.into(pieces, <<>>, fn piece ->
        case piece do
          {piece_msg, size_in_bytes} ->
            convert(le64(round(size_in_bytes / 8))) <>
              Base.encode16(<<piece_msg::size(size_in_bytes)>>)

          piece ->
            convert(le64(byte_size(piece))) <> Base.encode16(piece)
        end
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

  @spec le64(number) :: any
  defp le64(chunk) do
    # Performs Little Endian 64 bit encoding

    Enum.into(0..7, <<>>, fn x ->
      chunk2 =
        if x == 7 do
          chunk &&& 127
        else
          chunk
        end

      <<chunk2 >>> (x * 8) &&& 255>>
    end)
  end

  @spec convert(binary) :: String.t()
  defp convert(<<x::8>>) do
    x |> Integer.to_string(16) |> String.pad_leading(2, "0")
  end

  @spec convert(binary) :: String.t()
  defp convert(<<x::8, rest::binary>>) do
    (x |> Integer.to_string(16) |> String.pad_leading(2, "0")) <> convert(rest)
  end
end
