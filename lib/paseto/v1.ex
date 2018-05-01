defmodule Paseto.V1 do
  # TODO(ian): List some more info here, why you might choose v1, &c.
  @moduledoc """
  The Version1 implementation of the Paseto protocol.
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils.Utils
  alias Paseto.Utils.Crypto, as: PasetoCrypto

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @header 'v1'
  @hash_algo :sha384

  @nonce_size 32
  @mac_size 48
  @signature_size 2048

  @doc """
  Takes a token and will decrypt/verify the signature and return the token in a more digestable manner
  """
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
  iex> Paseto.V1.encrypt("This is a test message", "Test Key")
  "v1.local.3qbJND5q6IbF7cZxxWjmSTaVyMo2M3LaEDJ8StdFXw8PTUo55YIyy2BhIaAN6m-IdbGmdwM_ud1IpOyrz3CysNIkjBjab7NLRPbksV-XIsWYRFX6r7z2jsIfH-8emAv_BVtXi9lY"
  """
  @spec encrypt(String.t(), String.t(), String.t()) :: String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "") do
    aead_encrypt(data, key, footer)
  end

  @doc """
  Handles decrypting a token given the correct key

  Examples:
  iex> token = Paseto.V1.encrypt("This is a test message", "Test Key")
  iex> token
  "v1.local.3qbJND5q6IbF7cZxxWjmSTaVyMo2M3LaEDJ8StdFXw8PTUo55YIyy2BhIaAN6m-IdbGmdwM_ud1IpOyrz3CysNIkjBjab7NLRPbksV-XIsWYRFX6r7z2jsIfH-8emAv_BVtXi9lY"
  iex> Paseto.V1.decrypt(token, "Test Key")
  {:ok, "This is a test message"}
  """
  @spec decrypt(String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "") do
    aead_decrypt(data, "#{@header}.local.", key, footer)
  end

  @doc """
  Handles signing the token for public use.

  Examples:
  iex> {public_key, secret_key} = :crypto.generate_key(:rsa, {2048, 65_537})
  iex> V1.sign("This is a test message!", secret_key)
  "v1.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSGswqHiZVv31r99PZphr2hqJQe81Qc_7XkxHyVb_7-xORKp-VFJdEiqfINgLnwxo8n1pkIDH4_9UfhpEyS1ivgxfYe-55INfV-OyzSpHMbuGA0xviIln0fdn98QljGwh3uDFduXnfaWeBYA6nE0JingWEvVG-V8L12IdFh1rq9ZWLleFVsn719Iz8BqsasmFAICLRpnToL7X1syHdZ6PjhBnStCM5GHHzCwbdvj64P5QqxvtUzTfXBBeC-IKu_HVxIxY9VaN3d3KQotBZ1J6W1oJ4cX0JvUR4pIaq3eKfOKdoR5fUkyjS0mP9GjjoJcW8oiKKqb3dAaCHZW9he2iZNn"
  """
  @spec sign(String.t(), String.t(), String.t()) :: String.t()
  def sign(data, secret_key, footer \\ "") do
    h = "#{@header}.public."
    m2 = Utils.pre_auth_encode([h, data, footer])

    signature =
      :crypto.sign(:rsa, @hash_algo, m2, secret_key, [
        {:rsa_padding, :rsa_pkcs1_pss_padding},
        {:rsa_mgf1_md, @hash_algo}
      ])

    case footer do
      "" -> h <> b64_encode(data <> signature)
      _ -> h <> b64_encode(data <> signature) <> "." <> b64_encode(footer)
    end
  end

  @doc """
  Handles verifying the signature belongs to the provided key.

  Examples:
  iex> {public_key, secret_key} = :crypto.generate_key(:rsa, {2048, 65_537})
  iex> token = V1.sign("This is a test message!", secret_key)
  "v1.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSGswqHiZVv31r99PZphr2hqJQe81Qc_7XkxHyVb_7-xORKp-VFJdEiqfINgLnwxo8n1pkIDH4_9UfhpEyS1ivgxfYe-55INfV-OyzSpHMbuGA0xviIln0fdn98QljGwh3uDFduXnfaWeBYA6nE0JingWEvVG-V8L12IdFh1rq9ZWLleFVsn719Iz8BqsasmFAICLRpnToL7X1syHdZ6PjhBnStCM5GHHzCwbdvj64P5QqxvtUzTfXBBeC-IKu_HVxIxY9VaN3d3KQotBZ1J6W1oJ4cX0JvUR4pIaq3eKfOKdoR5fUkyjS0mP9GjjoJcW8oiKKqb3dAaCHZW9he2iZNn"
  iex> [version, purpose, payload] = String.split(token, ".")
  iex> V1.verify(version <> "." <> purpose <> ".", payload, public_key)
  {:ok, "This is a test message!"}
  """
  @spec verify(String.t(), String.t(), String.t() | nil) :: {:ok, binary} | {:error, String.t()}
  def verify(signed_message, [exp, mod] = public_key, footer \\ "")
      when byte_size(mod) == 256 do
    header = "v1.public."
    with :ok <- valid_header?(:verify, header),
         {:ok, decoded} <- valid_b64?(:decode, signed_message) do
      message_size = round((byte_size(decoded) - @signature_size / 8) * 8)
      <<message::size(message_size), signature::size(@signature_size)>> = decoded

      m2 = Utils.pre_auth_encode([header, <<message::size(message_size)>>, footer])

      case :crypto.verify(
             :rsa,
             @hash_algo,
             m2,
             <<signature::size(@signature_size)>>,
             public_key,
             [
               {:rsa_padding, :rsa_pkcs1_pss_padding},
               {:rsa_mgf1_md, @hash_algo}
             ]
           ) do
        true -> {:ok, <<message::size(message_size)>>}
        false -> {:error, "Failed to verify signature."}
      end
    else
      {:error, _reason} = err -> err
    end
  end

  @spec aead_encrypt(String.t(), String.t(), String.t() | nil) :: String.t()
  defp aead_encrypt(plaintext, key, footer) do
    h = "#{@header}.local."

    nonce = get_nonce(plaintext, :crypto.strong_rand_bytes(@nonce_size))
    <<leftmost::size(128), rightmost::size(128)>> = nonce
    ek = HKDF.derive(@hash_algo, key, 32, <<leftmost::128>>, "paseto-encryption-key")
    ak = HKDF.derive(@hash_algo, key, 32, <<leftmost::128>>, "paseto-auth-key-for-aead")

    ciphertext = PasetoCrypto.aes_256_ctr_encrypt(ek, plaintext, <<rightmost::128>>)

    pre_auth_hash =
      [h, nonce, ciphertext, footer]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    case footer do
      "" ->
        h <> b64_encode(nonce <> ciphertext <> pre_auth_hash)

      _ ->
        h <> b64_encode(nonce <> ciphertext <> pre_auth_hash) <> "." <> b64_encode(footer)
    end
  end

  @spec aead_decrypt(String.t(), String.t(), String.t(), String.t() | nil) :: String.t()
  defp aead_decrypt(message, header, key, footer) do
    expected_len = String.length(header)
    given_header = String.slice(message, 0..(expected_len - 1))

    footer_len =
      case footer do
        "" -> 0
        _ -> byte_size(footer) + 1 + 1
      end

    decoded =
      case b64_decode(message) do
        {:ok, decoded_value} ->
          decoded_value

        {:error, reason} ->
          {:error, "Failed to decode header #{given_header} during decryption due to #{reason}"}
      end

    length = byte_size(decoded)
    ciphertext_len = (length - @nonce_size - @mac_size) * 8
    footer = b64_decode!(footer)

    <<nonce::256, ciphertext::size(ciphertext_len), mac::384>> = decoded
    <<leftmost::128, rightmost::128>> = <<nonce::256>>

    ek = HKDF.derive(@hash_algo, key, 32, <<leftmost::128>>, "paseto-encryption-key")
    ak = HKDF.derive(@hash_algo, key, 32, <<leftmost::128>>, "paseto-auth-key-for-aead")

    calc =
      [header, {nonce, @nonce_size * 8}, {ciphertext, ciphertext_len}, footer]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    if calc == <<mac::384>> do
      plaintext =
        PasetoCrypto.aes_256_ctr_decrypt(
          ek,
          <<ciphertext::size(ciphertext_len)>>,
          <<rightmost::128>>
        )

      {:ok, plaintext}
    else
      {:error, "Calculated hmac didn't match hmac from token."}
    end
  end

  @spec get_nonce(String.t(), String.t()) :: binary
  defp get_nonce(m, n) do
    PasetoCrypto.hmac_sha384(n, m, 32)
  end

  @spec b64_encode(binary) :: binary
  defp b64_encode(input) when is_binary(input), do: Base.url_encode64(input, padding: false)

  @spec b64_decode(binary) :: binary
  defp b64_decode(input) when is_binary(input), do: Base.url_decode64(input, padding: false)

  @spec b64_decode(binary) :: binary
  defp b64_decode!(input) when is_binary(input), do: Base.url_decode64!(input, padding: false)

  @spec valid_b64?(atom(), binary) :: {:ok, binary} | {:error, String.t()}
  defp valid_b64?(:decode, input) do
    case b64_decode(input) do
      {:ok, _decoded} = retval -> retval
      _ -> {:error, "Invalid payload. Payload was not b64 encoded."}
    end
  end

  @spec valid_header?(:verify, String.t()) :: :ok | {:error, String.t()}
  defp valid_header?(:verify, header) do
    case String.equivalent?(header, "#{@header}.public.") do
      true -> :ok
      false -> {:error, "Token doesn't start with correct header"}
    end
  end

  @spec valid_header?(:decrypt, String.t()) :: :ok | {:error, String.t()}
  defp valid_header?(:decrypt, header) do
    case String.equivalent?(header, "#{@header}.local") do
      true -> :ok
      false -> {:error, "Token doesn't start with correct header"}
    end
  end
end
