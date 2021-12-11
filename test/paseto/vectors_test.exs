defmodule Paseto.VectorsTest do
  use ExUnit.Case, async: true

  alias Paseto.{TestVectors, Token, Utils, V1, V2}

  describe "v1.local (shared-key encryption) test vectors" do
    vectors = TestVectors.load("test/fixtures/test_vectors/v1_local.exs")

    for {vector, quoted_example} <- Enum.map(vectors, &TestVectors.to_v1_local_example/1) do
      test vector do
        %{key: key, nonce: nonce, payload: payload, footer: footer, token: token} =
          unquote(quoted_example)

        assert V1.encrypt(payload, key, footer, nonce) == token

        {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
          Utils.parse_token(token)

        assert V1.decrypt(encrypted_payload, key, encoded_footer) == {:ok, payload}
      end
    end
  end

  describe "v1.public (public-key authentication) test vectors" do
    vectors = TestVectors.load("test/fixtures/test_vectors/v1_public.exs")

    for {vector, quoted_example} <- Enum.map(vectors, &TestVectors.to_v1_public_example/1) do
      test vector do
        %{pk: pk, payload: payload, footer: footer, token: token} = unquote(quoted_example)

        {:ok, %Token{payload: signed_payload, footer: encoded_footer}} = Utils.parse_token(token)

        assert Utils.b64_decode!(encoded_footer) == footer
        assert V1.verify(signed_payload, pk, encoded_footer) == {:ok, payload}
      end
    end
  end

  describe "v2.local (shared-key encryption) test vectors" do
    vectors = TestVectors.load("test/fixtures/test_vectors/v2_local.exs")

    for {vector, quoted_example} <- Enum.map(vectors, &TestVectors.to_v2_local_example/1) do
      test vector do
        %{key: key, nonce: nonce, payload: payload, footer: footer, token: token} =
          unquote(quoted_example)

        assert V2.encrypt(payload, key, footer, nonce) == token

        {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
          Utils.parse_token(token)

        assert V2.decrypt(encrypted_payload, key, encoded_footer) == {:ok, payload}
      end
    end
  end

  describe "v2.public (public-key authentication) test vectors" do
    vectors = TestVectors.load("test/fixtures/test_vectors/v2_public.exs")

    for {vector, quoted_example} <- Enum.map(vectors, &TestVectors.to_v2_public_example/1) do
      test vector do
        %{keypair: keypair, payload: payload, footer: footer, token: token} =
          unquote(quoted_example)

        assert V2.sign(payload, keypair, footer) == token

        {:ok, %Token{payload: signed_payload, footer: encoded_footer}} = Utils.parse_token(token)

        assert V2.verify(signed_payload, keypair, encoded_footer) == {:ok, payload}
      end
    end
  end
end
