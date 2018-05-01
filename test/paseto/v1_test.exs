defmodule PasetoTest.V1 do
  use ExUnit.Case

  alias Paseto.V1

  @public_exponent 65_537

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = "TEST KEY"
      result = V1.encrypt(message, key) |> String.replace("v1.local.", "")

      assert V1.decrypt(result, key) == {:ok, message}
    end

    test "Simple encrypt/decrypt, now with feet" do
      message = "Test Message"
      key = "TEST KEY"
      footer = "key-id:04440"
      encoded_footer = Base.url_encode64(footer, padding: false)
      result = V1.encrypt(message, key, footer)

      assert V1.decrypt(result, key, encoded_footer) == {:ok, message}
    end
  end

  describe "Sign/Verify tests" do
    test "Simple sign/verify, footerless" do
      message = "Test Message"
      {pk, sk} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      signed_token = V1.sign(message, sk)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify(payload, pk) == {:ok, message}
    end

    test "Simple sign/verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {pk, sk} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      signed_token = V1.sign(message, sk, footer)
      [_, _, payload, _] = String.split(signed_token, ".")

      assert V1.verify(payload, pk, footer) == {:ok, message}
    end

    test "Invalid PK fails to verify, footerless" do
      message = "Test Message"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      signed_token = V1.sign(message, sk1)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify(payload, pk2) == {:error, "Failed to verify signature."}
    end

    test "Invalid PK fails to verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      signed_token = V1.sign(message, sk1, footer)
      [_, _, payload, _] = String.split(signed_token, ".")

      assert V1.verify(payload, pk2, footer) ==
               {:error, "Failed to verify signature."}
    end
  end
end
