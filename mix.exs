defmodule Paseto.MixProject do
  use Mix.Project

  def project do
    [
      app: :paseto,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
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
      {:hkdf, "~> 0.1.0"}
    ]
  end

  defp aliases do
    [
      testall: ["credo", "test"]
    ]
  end
end
