defmodule PasetoTest do
  use ExUnit.Case
  doctest Paseto

  describe "test cases for parsing tokens" do
    test "assure footer-less tokens parse correctly" do
      {:ok, token} = Paseto.parse("v1.local.dGVzdA==")
      assert token.version == "v1"
      assert token.purpose == "local"
      assert token.payload == "test"
      assert token.footer == nil
    end

    test "assure tokens with footers parse correctly" do
      {:ok, token} = Paseto.parse("v1.local.dGVzdA==.kid=key001")
      assert token.version == "v1"
      assert token.purpose == "local"
      assert token.payload == "test"
      assert token.footer == "kid=key001"
    end

    test "assure tokens with realistic payloads parse correctly" do
      {:ok, token} =
        Paseto.parse(
          "v1.local.eyJ1c2VySWQiOiAiYWVhNDI3N2YtZmY1My00ZTdlLThkYzMtMGVlYzAwZGFiMjA5IiwgInBlcm1pc3Npb25NYXNrIjogMTIzNDEyMzR9.kid=key001"
        )

      assert token.version == "v1"
      assert token.purpose == "local"

      assert token.payload ==
               "{\"userId\": \"aea4277f-ff53-4e7e-8dc3-0eec00dab209\", \"permissionMask\": 12341234}"

      assert token.footer == "kid=key001"
    end

    test "assure invalid tokens (bad b64 encoding for payload) fail" do
      {:error, retval} = Paseto.parse("v1.local.badbase64encoding==.kid=key001")
      assert retval == "Invalid (non-base64 encoded) payload in token."
    end

    test "assure invalid version numbers error out" do
      {:error, retval} = Paseto.parse("v3.local.dGVzdA==.kid=key001")
      assert retval == "Invalid token version. Only versions 1 & 2 are supported"
    end

    test "assure malformed tokens error" do
      {:error, retval} = Paseto.parse("v3.local")
      assert retval == "Invalid token encountered during token parsing"
    end
  end
end
