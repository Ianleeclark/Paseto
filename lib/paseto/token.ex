defmodule Paseto.Token do
  @moduledoc """
  The Token represents the claims object passed between services, over rpc, &c.
  """

  @typedoc """
  """
  @type t :: %{
          version: String.t(),
          purpose: String.t(),
          payload: String.t(),
          footer: nil | String.t()
        }

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys
end
