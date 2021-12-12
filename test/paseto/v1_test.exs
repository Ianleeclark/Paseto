defmodule Paseto.V1Test do
  use ExUnit.Case

  alias Paseto.Token
  alias Paseto.V1
  alias Paseto.Utils
  alias Paseto.{V1LocalKey, V1PublicKeyPair}

  @public_exponent 65_537

  describe "Encryption/Decryption tests" do
    test "Simple encrypt/decrypt, footerless" do
      message = "Test Message"
      key = "TEST KEY"

      {:ok, %Token{payload: encrypted_payload}} =
        message
        |> V1.encrypt(V1LocalKey.new(key))
        |> Utils.parse_token()

      assert V1.decrypt(encrypted_payload, V1LocalKey.new(key)) == {:ok, message}
    end

    test "Simple encrypt/decrypt, now with feet" do
      message = "Test Message"
      key = "TEST KEY"
      footer = "key-id:04440"

      {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
        message
        |> V1.encrypt(V1LocalKey.new(key), footer)
        |> Utils.parse_token()

      assert V1.decrypt(encrypted_payload, V1LocalKey.new(key), encoded_footer) == {:ok, message}
    end

    test "Decrypt a token created by the reference implementation" do
      # use ParagonIE\Paseto\Keys\SymmetricKey;
      # use ParagonIE\Paseto\Protocol\Version1;
      #
      # $sharedKey = new SymmetricKey("shared secret", new Version1());
      shared_key = "shared secret"

      # $plaintext = "v1 local example";
      # $footer = "v1 local footer";
      #
      # echo Version1::encrypt($plaintext, $sharedKey, $footer);
      # => v1.local.ous5R3LiajBem46SNTR7JVkQ2lp0TORTNWkNYPWiOEtOAzPL6Oq65NjxKEe1lDuKMIH13fGwc1qXzQnh-PLnUv4Ul5alMX0kELWhsksHOz0IqlSuqStCQcBcn42KvcZ7.djEgbG9jYWwgZm9vdGVy
      token =
        "v1.local.ous5R3LiajBem46SNTR7JVkQ2lp0TORTNWkNYPWiOEtOAzPL6Oq65NjxKEe1lDuKMIH13fGwc1qXzQnh-PLnUv4Ul5alMX0kELWhsksHOz0IqlSuqStCQcBcn42KvcZ7.djEgbG9jYWwgZm9vdGVy"

      {:ok,
       %Token{
         payload: encrypted_payload,
         footer: encoded_footer
       }} = Utils.parse_token(token)

      assert Utils.b64_decode!(encoded_footer) == "v1 local footer"

      assert V1.decrypt(encrypted_payload, V1LocalKey.new(shared_key), encoded_footer) ==
               {:ok, "v1 local example"}
    end
  end

  describe "Sign/Verify tests" do
    test "Simple sign/verify, footerless" do
      message = "Test Message"
      {pk, sk} = :crypto.generate_key(:rsa, {2048, @public_exponent})

      {:ok, %Token{payload: signed_payload}} =
        message
        |> V1.sign(V1PublicKeyPair.new(pk, sk))
        |> Utils.parse_token()

      assert V1.verify(signed_payload, V1PublicKeyPair.new(pk, sk)) == {:ok, message}
    end

    test "Simple sign/verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {pk, sk} = :crypto.generate_key(:rsa, {2048, @public_exponent})

      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        message
        |> V1.sign(V1PublicKeyPair.new(pk, sk), footer)
        |> Utils.parse_token()

      assert V1.verify(signed_payload, V1PublicKeyPair.new(pk, sk), encoded_footer) ==
               {:ok, message}
    end

    test "Invalid PK fails to verify, footerless" do
      message = "Test Message"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, @public_exponent})

      {:ok, %Token{payload: signed_payload}} =
        message
        |> V1.sign(V1PublicKeyPair.new(pk2, sk1))
        |> Utils.parse_token()

      assert V1.verify(signed_payload, V1PublicKeyPair.new(pk2, sk1)) ==
               {:error, "Failed to verify signature."}
    end

    test "Invalid PK fails to verify, with footer" do
      message = "Test Message"
      footer = "key-id:533434"
      {_pk1, sk1} = :crypto.generate_key(:rsa, {2048, @public_exponent})
      {pk2, _sk2} = :crypto.generate_key(:rsa, {2048, @public_exponent})

      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        message
        |> V1.sign(V1PublicKeyPair.new(pk2, sk1), footer)
        |> Utils.parse_token()

      assert V1.verify(signed_payload, V1PublicKeyPair.new(pk2, sk1), encoded_footer) ==
               {:error, "Failed to verify signature."}
    end

    @rsa_pk_pem "test/fixtures/v1_pk.pem"
                |> File.read!()
                |> String.trim()

    test "Verify a token created by the reference implementation" do
      # use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
      # use ParagonIE\Paseto\Protocol\Version1;
      # use ParagonIE\ConstantTime\Base64UrlSafe;
      #
      # $secretKey = AsymmetricSecretKey::generate(new Version1());
      # $publicKey = $secretKey->getPublicKey();
      # # dump $publicKey->raw() to "v1_pk.pem"
      public_key = Paseto.RSAPublicKey.decode(@rsa_pk_pem)

      # $plaintext = "v1 public example"
      # $footer = "v1 public footer"
      # echo Version1::sign($plaintext, $secretKey, $footer);
      # => v1.public.djEgcHVibGljIGV4YW1wbGU-fW3BlFXkUn4EE12Bvq--UdiWYD5ox4PmikGt3g0vZfZTI4BN4LG1tdbfsF3oSdymL52WqyQEKd7fYs00HsBKJntMC8lEHuzSR04mUEMWM1bkcdwfEzWKLVbVcqJI-RsCu0cfEHPvsEMrmBapcvOl72buRgXJxkmQzD5N337KPx-qROiJH79SixOVqdbWkgBIXU3kIG8qZBlAGui_zyoAQieekrvqL0oDNi7WbiZT0Oj00hKn1NMz-iOuV8AxeTMcd3pC4wcaKQ9Z6-l12a7ImGX6mkbo03snTG6XCW81tL2CNasDmL_vnKR0fu3udSyq6JxXWi27fyWwrgAieZz3.djEgcHVibGljIGZvb3Rlcg

      token =
        "v1.public.djEgcHVibGljIGV4YW1wbGU-fW3BlFXkUn4EE12Bvq--UdiWYD5ox4PmikGt3g0vZfZTI4BN4LG1tdbfsF3oSdymL52WqyQEKd7fYs00HsBKJntMC8lEHuzSR04mUEMWM1bkcdwfEzWKLVbVcqJI-RsCu0cfEHPvsEMrmBapcvOl72buRgXJxkmQzD5N337KPx-qROiJH79SixOVqdbWkgBIXU3kIG8qZBlAGui_zyoAQieekrvqL0oDNi7WbiZT0Oj00hKn1NMz-iOuV8AxeTMcd3pC4wcaKQ9Z6-l12a7ImGX6mkbo03snTG6XCW81tL2CNasDmL_vnKR0fu3udSyq6JxXWi27fyWwrgAieZz3.djEgcHVibGljIGZvb3Rlcg"

      {:ok,
       %Token{
         payload: signed_payload,
         footer: encoded_footer
       }} = Utils.parse_token(token)

      assert Utils.b64_decode!(encoded_footer) == "v1 public footer"

      assert V1.verify(
               signed_payload,
               V1PublicKeyPair.new(public_key, ""),
               encoded_footer
             ) == {:ok, "v1 public example"}
    end
  end
end
