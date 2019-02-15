defmodule PasetoTest.V2 do
  use ExUnit.Case

  alias Paseto.V2
  alias Paseto.Utils
  alias Paseto.Token
  alias Salty.Sign.Ed25519

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = :crypto.strong_rand_bytes(32)

      {:ok, %Token{payload: encrypted_payload}} =
        message
        |> V2.encrypt(key)
        |> Utils.parse_token()

      assert V2.decrypt(encrypted_payload, key) == {:ok, message}
    end

    test "Simple encrypt/decrypt, now with feet" do
      message = "Test Message"
      key = :crypto.strong_rand_bytes(32)
      footer = "key-id:04440"

      {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
        message
        |> V2.encrypt(key, footer)
        |> Utils.parse_token()

      assert V2.decrypt(encrypted_payload, key, encoded_footer) == {:ok, message}
    end

    test "Decrypt a token created by the reference implementation" do
      # use ParagonIE\Paseto\Keys\SymmetricKey;
      # use ParagonIE\Paseto\Protocol\Version2;
      # use ParagonIE\ConstantTime\Base64UrlSafe;
      #
      # $sharedKey = SymmetricKey(new Version2());
      # echo Base64UrlSafe::encodeUnpadded($sharedKey->raw());
      # => ES4yfkB2RI6QdY_BYysrvG8PdJk2AvCWWqKZe6X4wDA
      encoded_shared_key = "ES4yfkB2RI6QdY_BYysrvG8PdJk2AvCWWqKZe6X4wDA"
      shared_key = Utils.b64_decode!(encoded_shared_key)

      # $plaintext = "v2 local example";
      # $footer = "v2 local footer";
      #
      # echo Version2::encrypt($plaintext, $sharedKey, $footer);
      # => v2.local.qqqaTzKU0p71KHXG6xjn1CtVR8R1B9GCAjCYMCeGg85vqkXRNpbSX3dT6lQSBQ-g1n4mB_GZ1H0.djIgbG9jYWwgZm9vdGVy
      token =
        "v2.local.qqqaTzKU0p71KHXG6xjn1CtVR8R1B9GCAjCYMCeGg85vqkXRNpbSX3dT6lQSBQ-g1n4mB_GZ1H0.djIgbG9jYWwgZm9vdGVy"

      {:ok,
       %Token{
         payload: encrypted_payload,
         footer: encoded_footer
       }} = Utils.parse_token(token)

      assert Utils.b64_decode!(encoded_footer) == "v2 local footer"

      assert V2.decrypt(encrypted_payload, shared_key, encoded_footer) ==
               {:ok, "v2 local example"}
    end
  end

  describe "Sign/Verify tests" do
    test "Simple sign/verify, footerless" do
      message = "Test Message"
      {:ok, pk, sk} = Ed25519.keypair()

      {:ok, %Token{payload: signed_payload}} =
        message
        |> V2.sign(sk)
        |> Utils.parse_token()

      assert V2.verify(signed_payload, pk) == {:ok, message}
    end

    test "Simple sign/verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {:ok, pk, sk} = Ed25519.keypair()

      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        message
        |> V2.sign(sk, footer)
        |> Utils.parse_token()

      assert V2.verify(signed_payload, pk, encoded_footer) == {:ok, message}
    end

    test "Invalid PK fails to verify, footerless" do
      message = "Test Message"
      {:ok, _pk1, sk1} = Ed25519.keypair()
      {:ok, pk2, _sk2} = Ed25519.keypair()

      {:ok, %Token{payload: signed_payload}} =
        message
        |> V2.sign(sk1)
        |> Utils.parse_token()

      assert V2.verify(signed_payload, pk2) == {:error, "Failed to verify signature."}
    end

    test "Invalid PK fails to verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {:ok, _pk1, sk1} = Ed25519.keypair()
      {:ok, pk2, _sk2} = Ed25519.keypair()

      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        message
        |> V2.sign(sk1, footer)
        |> Utils.parse_token()

      assert V2.verify(signed_payload, pk2, encoded_footer) ==
               {:error, "Failed to verify signature."}
    end

    test "Verify a token created by the reference implementation" do
      # use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
      # use ParagonIE\Paseto\Protocol\Version2;
      # use ParagonIE\ConstantTime\Base64UrlSafe;
      #
      # $secretKey = AsymmetricSecretKey(new Version2());
      # echo Base64UrlSafe::encodeUnpadded($secretKey->raw());
      # => 9xCi52l6M59Lix7EvEZHqceBjD5-10R7n_jpc2P0BREUZzW4SfV8ft_LAs7gw0avSVvhWhns1rf6BbOERCP2XQ
      encoded_secret_key =
        "9xCi52l6M59Lix7EvEZHqceBjD5-10R7n_jpc2P0BREUZzW4SfV8ft_LAs7gw0avSVvhWhns1rf6BbOERCP2XQ"

      secret_key = Utils.b64_decode!(encoded_secret_key)
      public_key = Ed25519.sk_to_pk(secret_key)

      # $plaintext = "v2 public example"
      # $footer = "v2 public footer"
      # echo Version2::sign($plaintext, $secretKey, $footer);
      # => v2.public.djIgcHVibGljIGV4YW1wbGUA-NAijhLJmBdhqgrJrhD2ktdU8lJlJQ_E020Oq6T97TFVsnn90ayCQ_enXozH9iyVng3oP61fINVnMGYo3FUG.djIgcHVibGljIGZvb3Rlcg
      token =
        "v2.public.djIgcHVibGljIGV4YW1wbGUA-NAijhLJmBdhqgrJrhD2ktdU8lJlJQ_E020Oq6T97TFVsnn90ayCQ_enXozH9iyVng3oP61fINVnMGYo3FUG.djIgcHVibGljIGZvb3Rlcg"

      {:ok,
       %Token{
         payload: signed_payload,
         footer: encoded_footer
       }} = Utils.parse_token(token)

      assert Utils.b64_decode!(encoded_footer) == "v2 public footer"
      assert V2.verify(signed_payload, public_key, encoded_footer) == {:ok, "v2 public example"}
    end
  end
end
