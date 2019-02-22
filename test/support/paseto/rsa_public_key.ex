defmodule Paseto.RSAPublicKey do
  @moduledoc false

  import Record

  defrecord :rsa_pk,
            :RSAPublicKey,
            Record.extract(:RSAPublicKey, from_lib: "public_key/include/public_key.hrl")

  def decode(rsa_pk_pem) do
    [rsa_pk_entry] = :public_key.pem_decode(rsa_pk_pem)
    rsa_pk_rec = :public_key.pem_entry_decode(rsa_pk_entry)
    rsa_pk_mod = rsa_pk(rsa_pk_rec, :modulus)
    [<<1, 0, 1>>, <<rsa_pk_mod::size(256)-unit(8)>>]
  end
end
