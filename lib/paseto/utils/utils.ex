defmodule Paseto.Utils.Utils do
  @moduledoc """
  Miscellaneous functions used by several parts of the codebase
  """

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
        convert(le64(String.length(piece))) <> Base.encode16(piece)
      end)
  end

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
