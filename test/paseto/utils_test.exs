defmodule PasetoTest.Utils do
  use ExUnit.Case
  doctest Paseto.Utils.Utils

  alias Paseto.Utils.Utils

  describe "pre auth encode tests" do
    test "Assure encrypt produces sane values" do
      assert Utils.pre_auth_encode([]) == "\x00\x00\x00\x00\x00\x00\x00\x00"
      assert Utils.pre_auth_encode(['']) == "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      assert Utils.pre_auth_encode(['test']) == "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
    end
  end
end
