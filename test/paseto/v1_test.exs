defmodule PasetoTest.V1 do
  use ExUnit.Case
  doctest Paseto.V1

  alias Paseto.V1

  describe "test cases for local symmetric key results" do
    test "Assure encrypt produces sane values" do
    end
  end

  describe "reference tests -- tests taken from paseto docs/other libraries" do
    test "v1 encrypt without footer" do
      # TODO(ian): Replace this with a symmetric key gen
      symm_key = "test"
      token = Paseto.V1.encrypt('This is a signed, non-JSON message.', symm_key)
      assert token == "v1.local.B0VgDOyAtKza1ZCsPzlwQZGTfrpbo1vgzUwCvyxLiSM-gw3TC_KtMqX8woy8BuuE9-pRQNmnTGAru5OmVLzPDnDBHXbd8Sz5rssiTz5TZKLqSyYHsgBzfc53PqsTxLvw09QAy5KBSpKErPX_EfF0Od6-Ig"
    end

    test "v1 encrypt with footer" do
      # TODO(ian): Replace this with a symmetric key gen
      symm_key = "test"
      token = Paseto.V1.encrypt('This is a signed, non-JSON message.', symm_key, 'key-id:gandalf0')
      assert token == "v1.local.vu2ZV_apVDvIhExdenX6rm5w13E3LraRbgN9tabtspSR6KQQt5XdGY5Hho64VRj6Pa6gd-5w5XwmRZbnrxfSVYyvXrVfyDJC7pqQDgae8-MHDg5rZul7kFiH6ExXWx-1hJupWSkRnfQy168PzwS14xiTgw.a2V5LWlkOmdhbmRhbGYw"
    end
  end
end
