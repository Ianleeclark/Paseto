defmodule Paseto.V2 do
  # TODO(ian): List some more info here, why you might choose v2, &c.
  @moduledoc """
  The Version2 implementation of the Paseto protocol.
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils.Utils
  alias Paseto.Utils.Crypto

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

  @doc """
  Handles encrypting the payload and returning a valid token

  Examples:
  """
  @spec encrypt(String.t(), String.t(), String.t()) :: String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "") do
    h = "#{@header}.local."
    n = :crypto.strong_rand_bytes(24)
    nonce = Blake2.hash2b(data, 24, n)

    pre_auth_encoded = Utils.pre_auth_encode([h, n, footer])

    ciphertext = Crypto.chacha20_poly1305_encrypt(data, pre_auth_encoded, nonce, key)

    case footer do
      "" -> h <> b64_encode(n <> ciphertext)
      _ -> h <> b64_encode(n <> ciphertext) <> "." <> b64_encode(footer)
    end
  end

  @doc """
  Handles decrypting a token given the correct key
  """
  @spec decrypt(String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "") do
  end

  @doc """
  Handles signing the token for public use.

  """
  @spec sign(String.t(), String.t(), String.t()) :: String.t()
  def sign(data, secret_key, footer \\ "") do
  end

  @doc """
  Handles verifying the signature belongs to the provided key.
  """
  @spec verify(String.t(), String.t(), String.t() | nil) :: {:ok, binary} | {:error, String.t()}
  def verify(header, signed_message, [exp, mod] = public_key, footer \\ "")
      when byte_size(mod) == 256 do
  end

  @spec b64_encode(binary) :: binary
  defp b64_encode(input) when is_binary(input), do: Base.url_encode64(input, padding: false)

  @spec b64_decode(binary) :: binary
  defp b64_decode(input) when is_binary(input), do: Base.url_decode64(input, padding: false)

  @spec b64_decode(binary) :: binary
  defp b64_decode!(input) when is_binary(input), do: Base.url_decode64!(input, padding: false)
end
