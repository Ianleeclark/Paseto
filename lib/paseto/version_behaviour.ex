defmodule Paseto.VersionBehaviour do
  @moduledoc false

  # Housekeeping/general functionality
  @callback from_token(%Paseto.Token{}) :: any()

  # Local Operations
  @callback encrypt(String.t(), binary, String.t()) :: String.t() | {:error, String.t()}
  @callback decrypt(String.t(), binary, String.t()) :: {:ok, String.t()} | {:error, String.t()}

  # Public Operations
  @callback sign(String.t(), binary, String.t()) :: String.t() | {:error, String.t()}
  @callback sign(String.t(), binary, String.t()) :: {:ok, String.t()} | {:error, String.t()}
end
