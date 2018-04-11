defmodule PasetoTest.V1 do
  use ExUnit.Case
  doctest Paseto.V1

  alias Paseto.V1

  describe "test cases for local symmetric key results" do
    test "Assure encrypt produces sane values" do
    end
  end

  describe "Token generation tests. Just making sure valid b64 stuff is emitted" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = "TEST KEY"
      result = V1.encrypt(message, key)

      assert V1.decrypt(result, key) == {:ok, message}
    end
  end

  describe "Misc. Tests" do
    test "Asset get_nonce derives correct nonces" do
      msg_a = "The quick brown fox jumped over the lazy dog."
      msg_b = "The quick brown fox jumped over the lazy dof."
      nonce = Hexate.decode("808182838485868788898a8b8c8d8e8f")
      expected_a = "5e13b4f0fc111bf0cf9de4e97310b687858b51547e125790513cc1eaaef173cc"
      expected_b = "e1ba992f5cccd31714fd8c73adcdadabb00d0f23955a66907170c10072d66ffd"

      assert expected_a == Hexate.encode(V1.get_nonce(msg_a, nonce))
      assert expected_b == Hexate.encode(V1.get_nonce(msg_b, nonce))
    end
  end
end
