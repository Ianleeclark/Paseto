defmodule Paseto.V2 do
  @moduledoc """
  The Version2 implementation of the Paseto protocol.

  More information about the implementation can be found here:
  1.) https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md

  In short, asymmetric encryption is handled by Ed25519, whereas symmetric encryption is handled by xchachapoly1305
  Libsodium bindings are used for these crypto functions.
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils
  alias Paseto.Utils.Crypto
  alias Salty.Sign.Ed25519

  import Paseto.Utils, only: [b64_decode!: 1]

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

  @header_public "v2.public."
  @header_local "v2.local."

  @key_len 32
  @nonce_len 24

  @doc """
  Handles encrypting the payload and returning a valid token

  # Examples:
      iex> key = <<56, 165, 237, 250, 173, 90, 82, 73, 227, 45, 166, 36, 121, 213, 122, 227, 188, 168, 248, 190, 39, 11, 243, 40, 236, 206, 123, 237, 189, 43, 220, 66>>
      iex> Paseto.V2.encrypt("This is a test message", key)
      "v2.local.voHwaLKK64eSfnCGoJuxJvoyncIpDrg2AkFbRTBeOOBdytn8XoRtl_sRORjlGdTvPageE38TR7dVlv5wxw0"
  """
  @spec encrypt(String.t(), String.t(), String.t(), binary | nil) ::
          String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "", n \\ nil) do
    aead_encrypt(data, key, footer, n || :crypto.strong_rand_bytes(@nonce_len))
  end

  @doc """
  Handles decrypting a token payload given the correct key.

  # Examples:
      iex> key = <<56, 165, 237, 250, 173, 90, 82, 73, 227, 45, 166, 36, 121, 213, 122, 227, 188, 168, 248, 190, 39, 11, 243, 40, 236, 206, 123, 237, 189, 43, 220, 66>>
      iex> Paseto.V2.decrypt("AUfxx2uuiOXEXnYlMCzesBUohpewQTQQURBonherEWHcRgnaJfMfZXCt96hciML5PN9ozels1bnPidmFvVc", key)
      {:ok, "This is a test message"}
  """
  @spec decrypt(String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "") do
    aead_decrypt(data, key, footer)
  end

  @doc """
  Handles signing the token for public use.

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> Paseto.V2.sign("Test Message", sk)
      "v2.public.VGVzdAJxQsXSrgYBkcwiOnWamiattqhhhNN_1jsY-LR_YbsoYpZ18-ogVSxWv7d8DlqzLSz9csqNtSzDk4y0JV5xaAE"
  """
  @spec sign(String.t(), String.t(), String.t()) :: String.t()
  def sign(data, secret_key, footer \\ "") when byte_size(secret_key) == 64 do
    pre_auth_encode = Utils.pre_auth_encode([@header_public, data, footer])

    {:ok, sig} = Ed25519.sign_detached(pre_auth_encode, secret_key)

    Utils.b64_encode_token(@header_public, data <> sig, footer)
  end

  @doc """
  Handles verifying the signature belongs to the provided key.

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> Paseto.V2.sign("Test Message", sk)
      "v2.public.VGVzdAJxQsXSrgYBkcwiOnWamiattqhhhNN_1jsY-LR_YbsoYpZ18-ogVSxWv7d8DlqzLSz9csqNtSzDk4y0JV5xaAE"
      iex> Paseto.V2.verify("VGVzdAJxQsXSrgYBkcwiOnWamiattqhhhNN_1jsY-LR_YbsoYpZ18-ogVSxWv7d8DlqzLSz9csqNtSzDk4y0JV5xaAE", pk)
      "{:ok, "Test"}"
  """
  @spec verify(String.t(), String.t(), String.t() | nil) :: {:ok, binary} | {:error, String.t()}
  def verify(signed_message, public_key, footer \\ "") do
    decoded_footer = b64_decode!(footer)
    decoded_message = b64_decode!(signed_message)

    data_size = byte_size(decoded_message) - 64
    <<data::binary-size(data_size), sig::binary-64>> = decoded_message

    pre_auth_encode = Utils.pre_auth_encode([@header_public, data, decoded_footer])

    case Ed25519.verify_detached(sig, pre_auth_encode, public_key) do
      :ok -> {:ok, data}
      {:error, _reason} -> {:error, "Failed to verify signature."}
    end
  end

  @doc """
  Allows looking at the claims without having verified them.
  """
  @spec peek(token :: String.t()) :: String.t()
  def peek(token) do
    {:ok, %Paseto.Token{payload: payload}} = Utils.parse_token(token)

    get_claims_from_signed_message(payload)
  end

  ##############################
  # Internal Private Functions #
  ##############################

  @spec get_claims_from_signed_message(signed_message :: String.t()) :: String.t()
  def get_claims_from_signed_message(signed_message) do
    decoded_message = b64_decode!(signed_message)
    data_size = byte_size(decoded_message) - 64
    <<data::binary-size(data_size), _sig::binary-64>> = decoded_message

    data
  end

  @spec aead_encrypt(String.t(), String.t(), String.t(), binary) ::
          String.t() | {:error, String.t()}
  defp aead_encrypt(_data, key, _footer, _n) when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_encrypt(data, key, footer, n) when byte_size(key) == @key_len do
    nonce = Blake2.hash2b(data, @nonce_len, n)
    pre_auth_encode = Utils.pre_auth_encode([@header_local, nonce, footer])

    {:ok, ciphertext} = Crypto.xchacha20_poly1305_encrypt(data, pre_auth_encode, nonce, key)

    Utils.b64_encode_token(@header_local, nonce <> ciphertext, footer)
  end

  @spec aead_decrypt(String.t(), binary, String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt(_data, key, _footer) when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_decrypt(data, key, footer) when byte_size(key) == @key_len do
    decoded_payload = b64_decode!(data)
    decoded_footer = b64_decode!(footer)

    <<nonce::binary-size(@nonce_len), ciphertext::binary>> = decoded_payload

    pre_auth_encode = Utils.pre_auth_encode([@header_local, nonce, decoded_footer])

    case Crypto.xchacha20_poly1305_decrypt(ciphertext, pre_auth_encode, nonce, key) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, reason} -> {:error, "Failed to decrypt payload due to: #{reason}"}
    end
  end
end
