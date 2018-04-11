defmodule Paseto.Utils.Crypto do
  @moduledoc """
  """

  @spec aes_256_ctr_encrypt(binary, String.t(), binary) :: binary
  def aes_256_ctr_encrypt(key, data, nonce) when is_binary(nonce) do
    {_, ciphertext} =
      :crypto.stream_init(:aes_ctr, key, nonce)
      |> :crypto.stream_encrypt(data)

    ciphertext
  end

  @spec aes_256_ctr_decrypt(binary, String.t(), binary) :: binary
  def aes_256_ctr_decrypt(key, data, nonce) when is_binary(nonce) do
    {_, plaintext} =
      :crypto.stream_init(:aes_ctr, key, nonce)
      |> :crypto.stream_decrypt(data)

    plaintext
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
