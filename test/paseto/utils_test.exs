defmodule PasetoTest.Utils do
  use ExUnit.Case
  use ExUnitProperties

  doctest Paseto.Utils

  alias Paseto.Utils

  describe "pre auth encode tests" do
    test "examples from the specifications" do
      assert Utils.pre_auth_encode([]) == "\x00\x00\x00\x00\x00\x00\x00\x00"

      assert Utils.pre_auth_encode([""]) ==
               "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

      assert Utils.pre_auth_encode(["test"]) ==
               "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"

      assert_raise FunctionClauseError, fn -> Utils.pre_auth_encode("test") end
    end
  end

  describe "base64url encoding/decoding" do
    test "Decoding malformed strings" do
      assert Utils.b64_decode("bad input") == :error
      assert_raise ArgumentError, fn -> Utils.b64_decode!("bad input") end
    end

    property "b64_decode!(b64_encode(binary)) == binary" do
      check all input <- StreamData.binary(min_length: 1),
                encoded = Utils.b64_encode(input) do
        assert input == Utils.b64_decode!(encoded)
        assert {:ok, ^input} = Utils.b64_decode(encoded)
      end
    end
  end
end
