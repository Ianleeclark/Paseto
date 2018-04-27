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
  """
  @spec chacha20_poly1305_encrypt(String.t(), binary, binary, binary) :: binary
  def chacha20_poly1305_encrypt(message, ad, << nonce :: size(192) >>, << key :: size(256) >>) do
    <<leftmost::96, rightmost::96>> = << nonce :: size(192) >>
    # NOTE: nsec (the `nil` value here, isn't used in libsodium.)
    Xchacha20poly1305Ietf.encrypt(message, ad, nil, << nonce :: size(192) >>, << key :: size(256) >>)
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
