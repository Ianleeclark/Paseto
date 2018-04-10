defmodule Paseto.V1 do
  # TODO(ian): List some more info here, why you might choose v1, &c.
  @moduledoc """
  The Version1 implementation of the Paseto protocol.
  """

  alias Paseto.Token
  alias Paseto.Utils.Utils
  alias Paseto.Utils.Crypto, as: PasetoCrypto

  require Logger

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @header 'v1'
  @cipher_mode 'aes-256-ctr'
  @hash_algo 'sha384'

  @symmetric_key_bytes 32

  @nonce_size 32
  @mac_size 48
  @sign_size 256

  @spec from_token(%Token{}) :: %__MODULE__{}
  def from_token(token) do
    %__MODULE__{
      version: token.version,
      purpose: token.purpose,
      payload: token.payload,
      footer: token.footer
    }
  end

  @spec encrypt(String.t, String.t, nil | String.t) :: String.t
  def encrypt(data, key, footer \\ nil) do
    # TODO(ian): Ensure the symmetric key version is supported in v1

    aead_encrypt(data, key, footer)
  end

  @spec decrypt(String.t, String.t, String.t | nil) :: String.t
  def decrypt(data, key, footer \\ nil) do
  end

  @spec decrypt(String.t, String.t, String.t | nil) :: String.t
  def sign(data, key, footer \\ nil) do
  end

  @spec decrypt(String.t, String.t, String.t | nil) :: String.t
  def verify(signed_message, key, footer \\ nil) do
  end

  @spec get_symmetric_key_byte_length() :: number
  defp get_symmetric_key_byte_length() do
  end

  @spec generate_asymmetric_secret_key() :: String.t
  defp generate_asymmetric_secret_key() do
  end

  @spec generate_symmetric_key() :: String.t
  def generate_symmetric_key do
  end

  @spec aead_encrypt(String.t, String.t, String.t | nil) :: String.t
  defp aead_encrypt(plaintext, key, footer \\ nil) do
    h = "#{@header}.local."

    nonce = get_nonce(plaintext, :crypto.strong_rand_bytes(@nonce_size))
    << leftmost :: size(128), rightmost :: size(128) >> = nonce
    ek = HKDF.derive(:sha384, key, 32, << leftmost :: 128 >>, "paseto-encryption-key")
    ak = HKDF.derive(:sha384, key, 32, << leftmost :: 128 >>, "paseto-auth-key-for-aead")

    ciphertext = PasetoCrypto.aes_256_ctr_encrypt(ek, plaintext, << rightmost :: 128 >>)

    pre_auth_hash = Utils.pre_auth_encode([h, nonce, ciphertext, footer])
    |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    case footer do
      nil -> h <> Base.encode64(nonce <> ciphertext <> pre_auth_hash)
      _ -> h <> Base.encode64(nonce <> ciphertext <> pre_auth_hash) <> "." <> Base.encode64(footer)
    end
  end

  @spec aead_decrypt(String.t, String.t, String.t, String.t | nil) :: String.t
  defp aead_decrypt(message, header, key, footer \\ nil) do
    expected_len = String.length(header)
    given_header = String.slice(message, 0..expected_len)

    decoded = case Base64.decode(given_header) do
      {:ok, decoded_value} ->
        decoded_value
      {:error, reason} ->
        msg = "Failed to decode header #{given_header} during decryption due to #{reason}"
        Logger.debug(msg)
        {:error, msg}
    end

    length = String.length(decoded)
    nonce = String.slice(decoded, 0..@nonce_size)

    ciphertext = String.slice(decoded, (length - @nonce_size + @mac_size)..length)
    mac = String.slice(decoded, @nonce_size..(length - @nonce_size + @mac_size))

    << leftmost :: size(128), rightmost :: size(128) >> = nonce
    ek = HKDF.derive(:sha384, key, 32, << leftmost :: 128 >>, "paseto-encryption-key")
    ak = HKDF.derive(:sha384, key, 32, << leftmost :: 128 >>, "paseto-auth-key-for-aead")

    calc = Utils.pre_auth_encode([header, nonce, ciphertext, footer])
    |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    retval = if calc == mac do
      plaintext = " TODO IAN FILL THIS OUT"
      {:ok, plaintext}
    else
      {:error, "Calculated hmac didn't match hmac from token."}
    end
  end

  @spec get_nonce(String.t, String.t) :: binary
  def get_nonce(m, n) do
    PasetoCrypto.hmac_sha384(n, m, 32)
  end

  @spec get_rsa :: String.t
  defp get_rsa() do
  end

  @spec get_rsa_public_key(String.t) :: String.t
  defp get_rsa_public_key(key_data) do
  end
end
