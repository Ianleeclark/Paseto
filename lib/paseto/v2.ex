defmodule Paseto.V2 do
  # TODO(ian): List some more info here, why you might choose v2, &c.
  @moduledoc """
  The Version2 implementation of the Paseto protocol.
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils.Utils
  alias Paseto.Utils.Crypto

  require Logger

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

  @key_len 32
  @nonce_len_bits 192
  @nonce_len round(@nonce_len_bits / 8)
  @header "v2"

  @doc """
  Handles encrypting the payload and returning a valid token

  # Examples:
  iex> key = <<56, 165, 237, 250, 173, 90, 82, 73, 227, 45, 166, 36, 121, 213, 122, 227, 188,
  168, 248, 190, 39, 11, 243, 40, 236, 206, 123, 237, 189, 43, 220, 66>>
  iex> Paseto.V2.encrypt("This is a test message", key)
  """
  @spec encrypt(String.t(), String.t(), String.t()) :: String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "") do
    aead_encrypt(data, key, footer)
  end

  @doc """
  Handles decrypting a token payload given the correct key.

  # Examples:
  iex> key = <<56, 165, 237, 250, 173, 90, 82, 73, 227, 45, 166, 36, 121, 213, 122, 227, 188,
  168, 248, 190, 39, 11, 243, 40, 236, 206, 123, 237, 189, 43, 220, 66>>
  iex(21)> Paseto.V2.decrypt("AUfxx2uuiOXEXnYlMCzesBUohpewQTQQURBonherEWHcRgnaJfMfZXCt96hciML5PN9ozels1bnPidmFvVc", key)
  {:ok, "This is a test message"}
  """
  @spec decrypt(String.t(), String.t(), String.t() | nil) ::
  {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "") do
    aead_decrypt(data, key, footer)
  end

  @doc """
  Handles signing the token for public use.
  """
  @spec sign(String.t(), String.t(), String.t()) :: String.t()
  def sign(_data, _secret_key, _footer \\ "") do
  end

  @doc """
  Handles verifying the signature belongs to the provided key.
  """
  @spec verify(String.t(), String.t(), String.t() | nil) :: {:ok, binary} | {:error, String.t()}
  def verify(_header, _signed_message, [_exp, mod] = _public_key, _footer \\ "")
  when byte_size(mod) == 256 do
  end

  @spec aead_encrypt(String.t(), String.t(), String.t()) :: String.t() | {:error, String.t()}
  defp aead_encrypt(_data, key, _footer) when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_encrypt(data, key, footer) when byte_size(key) == @key_len do
    h = "#{@header}.local."
    n = :crypto.strong_rand_bytes(@nonce_len)
    nonce = Blake2.hash2b(data, @nonce_len, n)
    pre_auth_encode = Utils.pre_auth_encode([h, nonce, footer])

    {:ok, ciphertext} = Crypto.xchacha20_poly1305_encrypt(data, pre_auth_encode, nonce, key)

    case footer do
      "" -> h <> b64_encode(nonce <> ciphertext)
      _ -> h <> b64_encode(nonce <> ciphertext) <> "." <> b64_encode(footer)
    end
  end

  @spec aead_decrypt(String.t(), binary, String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt(_data, key, _footer) when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_decrypt(data, key, footer) when byte_size(key) == @key_len do
    h = "#{@header}.local."
    decoded_payload = b64_decode!(data)

    decoded_footer =
      case footer do
        "" -> ""
        _ -> b64_decode!(footer)
      end

    <<nonce::size(@nonce_len_bits), ciphertext::binary>> = decoded_payload
    pre_auth_encode = Utils.pre_auth_encode([h, <<nonce::size(@nonce_len_bits)>>, decoded_footer])

    case Crypto.xchacha20_poly1305_decrypt(
          ciphertext,
          pre_auth_encode,
          <<nonce::size(@nonce_len_bits)>>,
          key
        ) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, reason} -> {:error, "Failed to decrypt payload due to: #{reason}"}
    end
  end

  @spec b64_encode(binary) :: binary
  defp b64_encode(input) when is_binary(input), do: Base.url_encode64(input, padding: false)

  @spec b64_decode!(binary) :: binary
  defp b64_decode!(input) when is_binary(input), do: Base.url_decode64!(input, padding: false)
end
