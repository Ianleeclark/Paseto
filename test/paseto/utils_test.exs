defmodule PasetoTest.Utils do
  use ExUnit.Case
  doctest Paseto.Utils.Utils

  alias Paseto.Utils.Utils

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
end
