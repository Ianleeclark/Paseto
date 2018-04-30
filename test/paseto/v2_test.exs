defmodule PasetoTest.V2 do
  use ExUnit.Case

  alias Paseto.V2
  alias Salty.Box.Curve25519xchacha20poly1305, as: Box

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = :crypto.strong_rand_bytes(32)
      result = V2.encrypt(message, key)
      payload = String.replace(result, "v2.local.", "")

      assert V2.decrypt(payload, key) == {:ok, message}
    end

    test "Simple encrypt/decrypt, now with feet" do
      message = "Test Message"
      key = :crypto.strong_rand_bytes(32)
      footer = "key-id:04440"
      encoded_footer = Base.url_encode64(footer, padding: false)
      result = V2.encrypt(message, key, footer)

      payload =
        result
        |> String.replace("v2.local.", "")
        |> String.replace("." <> encoded_footer, "")

      assert V2.decrypt(payload, key, encoded_footer) == {:ok, message}
    end
  end

  describe "Sign/Verify tests" do
    test "Simple sign/verify, footerless" do
      message = "Test Message"
      {:ok, pk, sk} = Box.keypair()
      signed_token = V2.sign(message, sk)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V2.verify("v1.public.", payload, pk) == {:ok, message}
    end

    test "Simple sign/verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {:ok, pk, sk} = Box.keypair()
      signed_token = V2.sign(message, sk, footer)
      [_, _, payload, _] = String.split(signed_token, ".")

      assert V1.verify("v1.public.", payload, pk, footer) == {:ok, message}
    end

    test "Invalid PK fails to verify, footerless" do
      message = "Test Message"
      {:ok, pk1, sk1} = Box.keypair()
      {:ok, pk2, sk2} = Box.keypair()
      signed_token = V2.sign(message, sk1)
      payload = String.replace(signed_token, "v1.public.", "")

      assert V1.verify("v1.public.", payload, pk2) == {:error, "Failed to verify signature."}
    end

    test "Invalid PK fails to verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {:ok, _pk1, sk1} = Box.keypair()
      {:ok, pk2, _sk2} = Box.keypair()
      signed_token = V2.sign(message, sk1, footer)
      [_, _, payload, _] = String.split(signed_token, ".")

      assert V1.verify("v1.public.", payload, pk2, footer) ==
               {:error, "Failed to verify signature."}
    end
  end
end
