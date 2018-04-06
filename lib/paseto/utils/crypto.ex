defmodule Paseto.Utils.Crypto do

  @spec aes_256_ctr(binary, String.t, binary) :: binary
  def aes_256_ctr(<< key :: 2048 >>, data, nonce) do
    {_, ciphertext} = :crypto.stream_init(:aes_ctr, key, nonce)
    |> :crypto.stream_encrypt(to_string(data))

    ciphertext
  end

  @doc """
  Performs a HMAC-SHA384
  """
  @spec hmac_sha384(String.t(), String.t()) :: String.t()
  def hmac_sha384(key, data) do
    :crypto.hmac(:sha384, key, data)
  end

  @doc """
  Performs a HMAC-SHA384 and limits the resultant size of the mac to `trim_bytes` total bytes.
  """
  @spec hmac_sha384(String.t(), String.t(), number) :: String.t()
  def hmac_sha384(key, data, trim_bytes) do
    :crypto.hmac(:sha384, key, data, trim_bytes)
  end

  @doc """
  Key derivation function used to generate a key for the AES 256 counter encryption

  More info can be found: https://tools.ietf.org/html/rfc5869
  """
  @spec hkdf(number, String.t(), String.t(), String.t())
  def hkdf(length, ikm, salt, info) do
    extract(salt, ikm)
  end

  defp extract(salt, ikm) do
    :crypto.hmac(:sha384, salt, ikm)
  end

  defp expand() do
    l = ???
    n = Float.ceil(384 / )
    Enum.into(
      1..n,
      "",
      fn x ->
        :crypto.hmac()
      end
    )
    :crypto.hmac(:sha384, )
  end
end
