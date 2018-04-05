defmodule Paseto.Utils.Utils do
  @moduledoc """
  Miscellaneous functions used by several parts of the codebase
  """

  use Bitwise

  @spec pre_auth_encode([]) :: String.t
  def pre_auth_encode([]) do
    "\x00\x00\x00\x00\x00\x00\x00\x00"
  end
  def pre_auth_encode(['']) do
    "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  end
  @spec pre_auth_encode([String.t]) :: String.t
  def pre_auth_encode(pieces) when is_list(pieces) do
    output = encode_little_endian(Enum.count(pieces))
    Enum.map(
      pieces,
      fn piece ->
        output <> encode_little_endian(piece) <> piece
      end
    )
  end

  @spec encode_little_endian(String.t) :: String.t
  defp encode_little_endian(chunk) do
    output = ""
    Enum.map(
      0..8,
      fn i ->
        if i == 7 do
          n = chunk &&& 127
        end

        output = output <> (chunk &&& 255)
        n = chunk >>> 8
      end
    )

    output
  end
end
