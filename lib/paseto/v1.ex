defmodule Paseto.V1 do
  @moduledoc """
  The Version1 implementation of the Paseto protocol.

  More information about the implementation can be found here:
  1.) https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils
  alias Paseto.Utils.Crypto, as: PasetoCrypto

  import Paseto.Utils, only: [b64_decode: 1, b64_decode!: 1]

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @header_public "v1.public."
  @header_local "v1.local."

  @hash_algo :sha384

  @nonce_size 32
  @mac_size 48
  @signature_size 256

  @doc """
  Takes a token and will decrypt/verify the signature and return the token in a more digestable manner
  """
  @spec from_token(Token.t()) :: %__MODULE__{}
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

  # Examples:
      iex> Paseto.V1.encrypt("This is a test message", "Test Key")
      "v1.local.3qbJND5q6IbF7cZxxWjmSTaVyMo2M3LaEDJ8StdFXw8PTUo55YIyy2BhIaAN6m-IdbGmdwM_ud1IpOyrz3CysNIkjBjab7NLRPbksV-XIsWYRFX6r7z2jsIfH-8emAv_BVtXi9lY"
  """
  @spec encrypt(String.t(), String.t(), String.t(), binary | nil) ::
          String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "", n \\ nil) do
    aead_encrypt(data, key, footer, n || :crypto.strong_rand_bytes(@nonce_size))
  end

  @doc """
  Handles decrypting a token given the correct key

  # Examples:
      iex> token = Paseto.V1.encrypt("This is a test message", "Test Key")
      iex> token
      "v1.local.3qbJND5q6IbF7cZxxWjmSTaVyMo2M3LaEDJ8StdFXw8PTUo55YIyy2BhIaAN6m-IdbGmdwM_ud1IpOyrz3CysNIkjBjab7NLRPbksV-XIsWYRFX6r7z2jsIfH-8emAv_BVtXi9lY"
      iex> Paseto.V1.decrypt(token, "Test Key")
      "{:ok, "This is a test message"}"
  """
  @spec decrypt(String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "") do
    aead_decrypt(data, @header_local, key, footer)
  end

  @doc """
  Handles signing the token for public use.

  # Examples:
      iex> {public_key, secret_key} = :crypto.generate_key(:rsa, {2048, 65_537})
      iex> Paseto.V1.sign("This is a test message!", secret_key)
      "v1.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSGswqHiZVv31r99PZphr2hqJQe81Qc_7XkxHyVb_7-xORKp-VFJdEiqfINgLnwxo8n1pkIDH4_9UfhpEyS1ivgxfYe-55INfV-OyzSpHMbuGA0xviIln0fdn98QljGwh3uDFduXnfaWeBYA6nE0JingWEvVG-V8L12IdFh1rq9ZWLleFVsn719Iz8BqsasmFAICLRpnToL7X1syHdZ6PjhBnStCM5GHHzCwbdvj64P5QqxvtUzTfXBBeC-IKu_HVxIxY9VaN3d3KQotBZ1J6W1oJ4cX0JvUR4pIaq3eKfOKdoR5fUkyjS0mP9GjjoJcW8oiKKqb3dAaCHZW9he2iZNn"
  """
  @spec sign(String.t(), String.t(), String.t()) :: String.t() | {:error, String.t()}
  def sign(data, public_key, footer \\ "") do
    m2 = Utils.pre_auth_encode([@header_public, data, footer])

    signature =
      :crypto.sign(:rsa, @hash_algo, m2, public_key, [
        {:rsa_padding, :rsa_pkcs1_pss_padding},
        {:rsa_mgf1_md, @hash_algo}
      ])

    Utils.b64_encode_token(@header_public, data <> signature, footer)
  rescue
    _ -> {:error, "Signing failure."}
  end

  @doc """
  Handles verifying the signature belongs to the provided key.

  # Examples:
      iex> {public_key, secret_key} = :crypto.generate_key(:rsa, {2048, 65_537})
      iex> token = Paseto.V1.sign("This is a test message!", secret_key)
      "v1.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSGswqHiZVv31r99PZphr2hqJQe81Qc_7XkxHyVb_7-xORKp-VFJdEiqfINgLnwxo8n1pkIDH4_9UfhpEyS1ivgxfYe-55INfV-OyzSpHMbuGA0xviIln0fdn98QljGwh3uDFduXnfaWeBYA6nE0JingWEvVG-V8L12IdFh1rq9ZWLleFVsn719Iz8BqsasmFAICLRpnToL7X1syHdZ6PjhBnStCM5GHHzCwbdvj64P5QqxvtUzTfXBBeC-IKu_HVxIxY9VaN3d3KQotBZ1J6W1oJ4cX0JvUR4pIaq3eKfOKdoR5fUkyjS0mP9GjjoJcW8oiKKqb3dAaCHZW9he2iZNn"
      iex> [version, purpose, payload] = String.split(token, ".")
      iex> V1.verify(version <> "." <> purpose <> ".", payload, public_key)
      "{:ok, "This is a test message!"}"
  """
  @spec verify(
          String.t(),
          [binary()],
          String.t() | nil
        ) :: {:ok, binary} | {:error, binary()}
  def verify(signed_message, [_exp, mod] = public_key, footer \\ "")
      when byte_size(mod) == 256 do
    with {:ok, decoded} <- valid_b64?(:decode, signed_message),
         {:ok, decoded_footer} <- b64_decode(footer) do
      message_size = byte_size(decoded) - @signature_size

      <<
        message::binary-size(message_size),
        signature::binary-size(@signature_size)
      >> = decoded

      m2 = Utils.pre_auth_encode([@header_public, message, decoded_footer])

      case :crypto.verify(
             :rsa,
             @hash_algo,
             m2,
             signature,
             public_key,
             [
               {:rsa_padding, :rsa_pkcs1_pss_padding},
               {:rsa_mgf1_md, @hash_algo}
             ]
           ) do
        true -> {:ok, message}
        false -> {:error, "Failed to verify signature."}
      end
    else
      :error -> {:error, "Failed to decode token during verification."}
      err -> {:error, "Token verification failed due to #{inspect(err)}"}
    end
  end

  @spec get_claims_from_signed_message(signed_message :: String.t()) :: String.t()
  defp get_claims_from_signed_message(signed_message) do
    case valid_b64?(:decode, signed_message) do
      {:ok, decoded} ->
        message_size = byte_size(decoded) - @signature_size

        <<
          message::binary-size(message_size),
          _signature::binary-size(@signature_size)
        >> = decoded

        message

      {:error, _reason} = err ->
        err
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

  @spec aead_encrypt(String.t(), String.t(), String.t() | nil, binary) :: String.t()
  defp aead_encrypt(plaintext, key, footer, n) do
    nonce = get_nonce(plaintext, n)
    <<leftmost::binary-16, rightmost::binary-16>> = nonce
    ek = HKDF.derive(@hash_algo, key, 32, leftmost, "paseto-encryption-key")
    ak = HKDF.derive(@hash_algo, key, 32, leftmost, "paseto-auth-key-for-aead")

    ciphertext = PasetoCrypto.aes_256_ctr_encrypt(ek, plaintext, rightmost)

    pre_auth_hash =
      [@header_local, nonce, ciphertext, footer]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    Utils.b64_encode_token(@header_local, nonce <> ciphertext <> pre_auth_hash, footer)
  end

  @spec aead_decrypt(String.t(), String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt(message, header, key, footer) do
    expected_len = String.length(header)
    given_header = String.slice(message, 0..(expected_len - 1))

    decoded =
      case b64_decode(message) do
        {:ok, decoded_value} ->
          decoded_value

        :error ->
          {:error, "Failed to decode header #{given_header} during decryption"}
      end

    length = byte_size(decoded)
    ciphertext_len = length - @nonce_size - @mac_size
    footer = b64_decode!(footer)

    <<
      nonce::binary-size(@nonce_size),
      ciphertext::binary-size(ciphertext_len),
      mac::binary-48
    >> = decoded

    <<leftmost::binary-16, rightmost::binary-16>> = nonce

    ek = HKDF.derive(@hash_algo, key, 32, leftmost, "paseto-encryption-key")
    ak = HKDF.derive(@hash_algo, key, 32, leftmost, "paseto-auth-key-for-aead")

    calc =
      [header, nonce, ciphertext, footer]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    if calc == mac do
      {:ok, PasetoCrypto.aes_256_ctr_decrypt(ek, ciphertext, rightmost)}
    else
      {:error, "Calculated hmac didn't match hmac from token."}
    end
  end

  @spec get_nonce(String.t(), String.t()) :: binary
  defp get_nonce(m, n) do
    PasetoCrypto.hmac_sha384(n, m, 32)
  end

  @spec valid_b64?(atom(), binary) :: {:ok, binary} | {:error, String.t()}
  defp valid_b64?(:decode, input) do
    case b64_decode(input) do
      {:ok, _decoded} = retval -> retval
      _ -> {:error, "Invalid payload. Payload was not b64 encoded."}
    end
  end
end
