defmodule PasetoTest do
  use ExUnit.Case
  use ExUnitProperties

  alias Salty.Sign.Ed25519

  @public_exponent 65_537

  defp version_generator() do
    ExUnitProperties.gen all version <- StreamData.member_of(["v1", "v2"]) do
      version
    end
  end

  defp purpose_generator() do
    ExUnitProperties.gen all purpose <- StreamData.member_of(["local", "public"]) do
      purpose
    end
  end

  defp key_generator(version, purpose) do
    case version do
      "v1" ->
        case purpose do
          "local" -> "test key"
          "public" -> :crypto.generate_key(:rsa, {2048, @public_exponent})
        end

      "v2" ->
        case purpose do
          "local" ->
            :crypto.strong_rand_bytes(32)

          "public" ->
            {:ok, pk, sk} = Ed25519.keypair()
            {pk, sk}
        end
    end
  end

  property "Property tests for generator/parse_tokens" do
    check all version <- version_generator(),
              purpose <- purpose_generator(),
              footer <- StreamData.string(:ascii, min_length: 1),
              plaintext <- StreamData.string(:ascii, min_length: 1),
              key = key_generator(version, purpose),
              generated_token = Paseto.generate_token(version, purpose, plaintext, key, footer),
              max_runs: 500 do
      header = version <> "." <> purpose <> "."
      assert String.starts_with?(generated_token, header)
      assert String.ends_with?(generated_token, "." <> Base.url_encode64(footer, padding: false))

      x = Paseto.parse_token(generated_token, key)

      token =
        case x do
          {:ok, new_token} -> new_token
          {:error, reason} -> flunk("Failed to parse token due to: #{reason}")
        end

      assert token.footer == footer
      assert token.version == version
      assert token.purpose == purpose
      assert token.payload == plaintext

      case token.purpose do
        "local" ->
          assert Paseto.peek(generated_token) == {:error, :no_peek_for_encrypted_tokens}
        "public" ->
          assert Paseto.peek(generated_token) == plaintext
      end
    end
  end
end
