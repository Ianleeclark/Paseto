defmodule Paseto.V1PublicKeyPair do
  @required_keys [:algorithm, :public_key, :secret_key]
  defstruct @required_keys

  @spec new([binary()], [binary()]) :: __MODULE__
  def new(public_key, secret_key \\ nil) do
    %__MODULE__{
      algorithm: :v1_public,
      public_key: public_key,
      secret_key: secret_key
    }
  end
end

defmodule Paseto.V1LocalKey do
  @required_keys [:algorithm, :key]
  defstruct @required_keys

  @spec new(key :: [binary()]) :: __MODULE__
  def new(key) do
    %__MODULE__{
      algorithm: :v1_local,
      key: key
    }
  end
end

defmodule Paseto.V2PublicKeyPair do
  @required_keys [:algorithm, :public_key, :secret_key]
  defstruct @required_keys

  @public_key_len 32
  @secret_key_len 64

  @spec new([binary()], [binary()]) :: __MODULE__
  def new(public_key, secret_key \\ nil)
      when byte_size(public_key) == @public_key_len and byte_size(secret_key) == @secret_key_len do
    %__MODULE__{
      algorithm: :v2_public,
      public_key: public_key,
      secret_key: secret_key
    }
  end
end

defmodule Paseto.V2LocalKey do
  @required_keys [:algorithm, :key]
  defstruct @required_keys

  @spec new(key :: [binary()]) :: __MODULE__
  def new(key) do
    %__MODULE__{
      algorithm: :v2_local,
      key: key
    }
  end
end
