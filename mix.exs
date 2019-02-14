defmodule Paseto.MixProject do
  use Mix.Project

  def project do
    [
      app: :paseto,
      version: "1.1.1",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      description: description(),
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:credo, "~> 0.9.0-rc1", only: [:dev, :test], runtime: false},
      {:hkdf, "~> 0.1.0"},
      {:blake2, "~> 1.0"},
      {:salty, "~> 0.1.3", hex: :libsalty},
      {:stream_data, "~> 0.1", only: :test},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      testall: ["credo", "test"]
    ]
  end

  defp description do
    "An Elixir implementation of the Paseto (Platform Agnostic Security Token) protocol."
  end

  defp package do
    [
      name: "paseto",
      files: ["lib", "mix.exs", "README.*", "LICENSE"],
      maintainers: ["Ian Lee Clark"],
      licenses: ["BSD"],
      links: %{"Github" => "https://github.com/GrappigPanda/Paseto"}
    ]
  end
end
