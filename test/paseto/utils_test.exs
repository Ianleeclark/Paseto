defmodule PasetoTest.Utils do
  use ExUnit.Case
  use ExUnitProperties

  doctest Paseto.Utils

  alias Paseto.Utils

  describe "pre auth encode tests" do
    test "empty list encoding" do
      assert Utils.pre_auth_encode([]) == "0000000000000000"
    end

    test "empty string encoding" do
      assert Utils.pre_auth_encode([""]) == "01000000000000000000000000000000"
    end

    test "Paragon" do
      assert Utils.pre_auth_encode(["Paragon"]) ==
               "0100000000000000070000000000000050617261676F6E"
    end

    test "Two non-empty strings" do
      assert Utils.pre_auth_encode(["Paragon", "Initiative"]) ==
               "0200000000000000070000000000000050617261676F6E0A00000000000000496E6974696174697665"
    end

    test "array of two empty strings" do
      assert Utils.pre_auth_encode(["", ""]) == "020000000000000000000000000000000000000000000000"
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
