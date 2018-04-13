defmodule PasetoTest.V2 do
  use ExUnit.Case

  alias Paseto.V2

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = "TEST KEY"
      result = V2.encrypt(message, key)

      assert V2.decrypt(result, key) == {:ok, message}
    end

    test "Simple encrypt/decrypt, now with feet" do
      message = "Test Message"
      key = "TEST KEY"
      footer = "key-id:04440"
      encoded_footer = Base.url_encode64(footer, padding: false)
      result = V2.encrypt(message, key, footer)

      assert V2.decrypt(result, key, encoded_footer) == {:ok, message}
    end
  end
end
