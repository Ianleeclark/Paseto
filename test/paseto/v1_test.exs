defmodule PasetoTest.V1 do
  use ExUnit.Case

  alias Paseto.V1

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = "TEST KEY"
      result = V1.encrypt(message, key)

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
      {pk, sk} = :crypto.generate_key(:rsa, {2048, 65537})
      signed_token = V1.sign(message, sk)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify("v1.public.", payload, pk) == message
    end

    test "Invalid PK fails to verify, footerless" do
      message = "Test Message"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, 65537})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, 65537})
      signed_token = V1.sign(message, sk1)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify("v1.public.", payload, pk2) == {:error, "Failed to verify signature."}
    end

    test "Invalid PK fails to verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, 65537})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, 65537})
      signed_token = V1.sign(message, sk1)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify("v1.public.", payload, pk2) == {:error, "Failed to verify signature."}
    end

    test "Simple sign/verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {pk, sk} = :crypto.generate_key(:rsa, {2048, 65537})
      signed_token = V1.sign(message, sk, footer)
      payload = String.replace(signed_token, "v1.public.", "")
      [_, _, payload, _] = String.split(signed_token, ".")

      assert V1.verify("v1.public.", payload, pk, footer) == message
    end
  end
end
