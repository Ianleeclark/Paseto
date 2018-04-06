defmodule Paseto.Utils.Utils do
  @moduledoc """
  Miscellaneous functions used by several parts of the codebase
  """

  use Bitwise

  require Logger

  @spec pre_auth_encode([String.t]) :: String.t
  def pre_auth_encode(pieces) when is_list(pieces) do
    encode_little_endian(Enum.count(pieces)) <> Enum.into(
      pieces,
      <<>>,
      fn piece ->
        << x :: binary >> = piece
        encode_little_endian(String.length(piece)) <> x
      end
    )
  end

  # TODO(ian): Change type from any to charlist
  @spec encode_little_endian(number) :: any
  def encode_little_endian(chunk) do
    Enum.into(
      0..8,
      <<>>,
      fn x ->
        if x == 7 do
          chunk = chunk &&& 127
        end

        << (((chunk >>> (x * 8)) &&& 255)) >>
    end)
  end
end
