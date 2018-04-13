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
    end

    test "Simple sign/verify, with footer" do
    end
  end
end
