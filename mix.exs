defmodule Paseto.MixProject do
  use Mix.Project

  def project do
    [
      app: :paseto,
      version: "1.4.0",
      elixir: "~> 1.13",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      description: description(),
      package: package(),
      # Make sure that `testall` always runs under `MIX_ENV=test`
      preferred_cli_env: [testall: :test]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.4", only: [:dev, :test], runtime: false},
      {:hkdf, "~> 0.2.0"},
      {:blake2, "~> 1.0"},
      {:libsalty2, "~> 0.3.0"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:stream_data, "~> 0.5.0", only: :test}
    ]
  end

  defp aliases do
    [
      testall: ["credo", "test"]
    ]
  end

  defp elixirc_paths(:test), do: ~w[lib test/support]
  defp elixirc_paths(_), do: ~w[lib]

  defp description do
    "An Elixir implementation of the Paseto (Platform Agnostic Security Token) protocol."
  end

  defp package do
    [
      name: "paseto",
      files: ["lib", "mix.exs", "README.*", "LICENSE"],
      maintainers: ["Ian Lee Clark"],
      licenses: ["BSD"],
      links: %{"Github" => "https://github.com/ianleeclark/Paseto"}
    ]
  end
end
