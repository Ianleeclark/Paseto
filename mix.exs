defmodule Paseto.MixProject do
  use Mix.Project

  def project do
    [
      app: :paseto,
      version: "1.3.1",
      elixir: "~> 1.9",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      description: description(),
      package: package(),
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore.exs",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false},
      {:hkdf, "~> 0.1.0"},
      {:blake2, "~> 1.0"},
      {:libsalty2, "~> 0.2.1"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0.0-rc.6", only: [:dev, :test], runtime: false},
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
