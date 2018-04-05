defmodule Paseto.Utils.Crypto do

  @spec aes_256_ctr(binary, String.t, binary) :: binary
  def aes_256_ctr(<< key :: size(2048) >>, data, nonce) do
    {_, ciphertext} = :crypto.stream_init(:aes_ctr, key, nonce)
    |> :crypto.stream_encrypt(to_string(data))

    ciphertext
  end

  def hmac_sha384(key, data) do
    :crypto.hmac(:sha384, key, data)
  end
  def hmac_sha384(key, data, trim_bytes) do
    :crypto.hmac(:sha384, key, data, trim_bytes)
  end

  def hkdf(length, ikm, salt, info) do
    hash_len = 32
    prk = hmac_sha384(salt, ikm)
    t = ""
    okm = ""

    entire_key = Enum.map(
      0..Float.ceil(length / 32),
      fn i ->
        # TODO(ian): Fix this below it might be broken
        t = hmac_sha384(prk, t <> info <> "[#{inspect(i+1)}]")
        okm = okm <> t
      end
    )

    String.slice(entire_key, Range.new(0, length))
  end
end
