defmodule Paseto.Utils.Crypto do
  @moduledoc false

  alias Salty.Aead.Xchacha20poly1305Ietf

  @doc """
  AES-256 in counter mode for encrypting. Used for v1 local.
  """
  @spec aes_256_ctr_encrypt(binary, binary, binary) :: binary
  def aes_256_ctr_encrypt(key, data, nonce) do
    {_, ciphertext} =
      :crypto.stream_init(:aes_ctr, key, nonce)
      |> :crypto.stream_encrypt(data)

    ciphertext
  end

  @doc """
  AES-256 in counter mode for decrypting. Used for v1 local.
  """
  @spec aes_256_ctr_decrypt(binary, String.t(), binary) :: binary
  def aes_256_ctr_decrypt(key, data, nonce) do
    {_, plaintext} =
      :crypto.stream_init(:aes_ctr, key, nonce)
      |> :crypto.stream_decrypt(data)

    plaintext
  end

  @doc """
  Encryption method used for v2 local. See: libsodium
  """
  @spec xchacha20_poly1305_encrypt(String.t(), binary, binary, binary) ::
          {:ok, binary} | {:error, String.t()}
  def xchacha20_poly1305_encrypt(_message, _aad, nonce, key)
      when byte_size(nonce) != 24 and byte_size(key) == 32 do
    {:error, "Invalid nonce for xchacha. Expected 24, got #{byte_size(nonce)}"}
  end

  def xchacha20_poly1305_encrypt(_message, _aad, nonce, key)
      when byte_size(nonce) == 24 and byte_size(key) != 32 do
    {:error, "Invalid key for xchacha. Expected 32, got #{byte_size(key)}"}
  end

  def xchacha20_poly1305_encrypt(_message, _aad, nonce, key)
      when byte_size(nonce) != 24 and byte_size(key) != 32 do
    {:error,
     "Invalid key/nonce for xchacha. Expected 32/24 bytes, got #{byte_size(key)}/#{
       byte_size(nonce)
     }, respectively."}
  end

  def xchacha20_poly1305_encrypt(message, aad, nonce, key)
      when byte_size(nonce) == 24 and byte_size(key) == 32 do
    # NOTE: nsec (the `nil` value here, isn't used in libsodium.)
    Xchacha20poly1305Ietf.encrypt(message, aad, nil, nonce, key)
  end

  @doc """
  Encryption method used for v2 local. See: libsodium
  """
  @spec xchacha20_poly1305_decrypt(String.t(), binary, binary, binary) ::
          binary | {:error, String.t()} | no_return()
  def xchacha20_poly1305_decrypt(_message, _aad, nonce, key)
      when byte_size(nonce) != 24 and byte_size(key) == 32 do
    {:error, "Invalid nonce for xchacha. Expected 24, got #{byte_size(nonce)}"}
  end

  def xchacha20_poly1305_decrypt(_message, _aad, nonce, key)
      when byte_size(nonce) == 24 and byte_size(key) != 32 do
    {:error, "Invalid key for xchacha. Expected 32, got #{byte_size(key)}"}
  end

  def xchacha20_poly1305_decrypt(_message, _aad, nonce, key)
      when byte_size(nonce) != 24 and byte_size(key) != 32 do
    {:error,
     "Invalid key/nonce for xchacha. Expected 32/24 bytes, got #{byte_size(key)}/#{
       byte_size(nonce)
     }, respectively."}
  end

  def xchacha20_poly1305_decrypt(message, aad, nonce, key)
      when byte_size(nonce) == 24 and byte_size(key) == 32 do
    # NOTE: Again, `nsec` isn't used.
    Xchacha20poly1305Ietf.decrypt(nil, message, aad, nonce, key)
  rescue
    err -> {:error, "Decrypt failed due to #{inspect(err)}"}
  end

  @doc """
  Performs a HMAC-SHA384
  """
  @spec hmac_sha384(String.t(), String.t()) :: binary
  def hmac_sha384(key, data) do
    :crypto.hmac(:sha384, key, data)
  end

  @doc """
  Performs a HMAC-SHA384 and limits the resultant size of the mac to `trim_bytes` total bytes.
  """
  @spec hmac_sha384(String.t(), String.t(), number) :: binary
  def hmac_sha384(key, data, trim_bytes) do
    :crypto.hmac(:sha384, key, data, trim_bytes)
  end
end
