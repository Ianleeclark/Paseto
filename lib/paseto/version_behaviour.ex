defmodule Paseto.VersionBehaviour do
  @moduledoc false

  # Housekeeping/general functionality
  @callback from_token(Paseto.Token.t()) :: any()
  @callback peek(String.t()) :: String.t()

  # Local Operations
  @callback encrypt(data :: String.t(), public_key :: binary, footer :: String.t()) ::
              String.t() | {:error, String.t()}
  @callback decrypt(encrypted_data :: String.t(), secret_key :: binary, footer :: String.t()) ::
              {:ok, String.t()} | {:error, String.t()}

  # Public Operations
  @callback sign(data :: String.t(), public_key :: binary, footer :: String.t()) ::
              String.t() | {:error, String.t()}
  @callback verify(encrypted_data :: String.t(), secret_key :: [binary()], footer :: String.t()) ::
              {:ok, String.t()} | {:error, String.t()}
end
