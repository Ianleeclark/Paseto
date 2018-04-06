defmodule Paseto.Utils.Utils do
  @moduledoc """
  Miscellaneous functions used by several parts of the codebase
  """

  use Bitwise

  @spec pre_auth_encode([String.t]) :: String.t
  def pre_auth_encode(pieces) when is_list(pieces) do
    convert(encode_little_endian(Enum.count(pieces))) <> Enum.into(
      pieces,
      <<>>,
      fn piece ->
        convert(encode_little_endian(String.length(piece))) <> Base.encode16(piece)
      end
    )
  end

  # TODO(ian): Change type from any to charlist
  @spec encode_little_endian(number) :: any
  def encode_little_endian(chunk) do
    Enum.into(
      0..7,
      <<>>,
      fn x ->
        chunk2 = if x == 7 do
          chunk &&& 127
        else
          chunk
        end

        << (((chunk2 >>> (x * 8)) &&& 255)) >>
    end)
  end

  def convert(<< x :: 8 >>) do
    x |> Integer.to_string(16) |> String.pad_leading(2, "0")
  end
  def convert(<< x :: 8, rest :: binary >>) do
    (x |> Integer.to_string(16) |> String.pad_leading(2, "0")) <> convert(rest)
  end
end
