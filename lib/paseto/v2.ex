defmodule Paseto.V2 do
  # TODO(ian): List some more info here, why you might choose v2, &c.
  @moduledoc """
  The Version2 implementation of the Paseto protocol.
  """

  alias Paseto.Token

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @spec from_token(%Token{}) :: %__MODULE__{}
  def from_token(token) do
    %__MODULE__{
      version: token.version,
      purpose: token.purpose,
      payload: token.payload,
      footer: token.footer
    }
  end
end
