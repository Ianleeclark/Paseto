defmodule PasetoTest.V1 do
  use ExUnit.Case
  doctest Paseto.V1

  alias Paseto.V1

  describe "test cases for local symmetric key results" do
    test "Assure encrypt produces sane values" do
    end
  end

  describe "Token generation tests. Just making sure valid b64 stuff is emitted" do
    test "v1 encrypt without footer" do
      # TODO(ian): Replace this with a symmetric key gen
      symm_key = "\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v"
      token = Paseto.V1.encrypt("This is a signed, non-JSON message.", symm_key)
      assert token == "v1.local.B0VgDOyAtKza1ZCsPzlwQZGTfrpbo1vgzUwCvyxLiSM-gw3TC_KtMqX8woy8BuuE9-pRQNmnTGAru5OmVLzPDnDBHXbd8Sz5rssiTz5TZKLqSyYHsgBzfc53PqsTxLvw09QAy5KBSpKErPX_EfF0Od6-Ig"
    end

    test "v1 encrypt with footer" do
      # TODO(ian): Replace this with a symmetric key gen
      symm_key = "test"
      token = Paseto.V1.encrypt("This is a signed, non-JSON message.", symm_key, "key-id:gandalf0")
      assert token == "v1.local.vu2ZV_apVDvIhExdenX6rm5w13E3LraRbgN9tabtspSR6KQQt5XdGY5Hho64VRj6Pa6gd-5w5XwmRZbnrxfSVYyvXrVfyDJC7pqQDgae8-MHDg5rZul7kFiH6ExXWx-1hJupWSkRnfQy168PzwS14xiTgw.a2V5LWlkOmdhbmRhbGYw"
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
