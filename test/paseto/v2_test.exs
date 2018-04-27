defmodule PasetoTest.V2 do
  use ExUnit.Case

  alias Paseto.V2

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
        String.replace(result, "v2.local.", "") |> String.replace("." <> encoded_footer, "")

      assert V2.decrypt(payload, key, encoded_footer) == {:ok, message}
    end
  end
end
