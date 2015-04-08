defmodule ElixirJsonwebtoken.Mixfile do
  use Mix.Project

  def project do
    [
      app: :jsonwebtoken,
      version: "0.0.1",
      elixir: "~> 1.0",
      deps: deps,
      description: description,
      package: package
    ]
  end

  defp deps do
    [
      {:jazz, git: "https://github.com/meh/jazz.git"}
    ]
  end

  defp description do
    "A simple JSON Web Token (JWT) implementation. Forces verification to get the payload."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md"],
      contributors: ["Dave Bryson"],
      links: %{
        "GitHub" => "https://github.com/davebryson/elixir_jsonwebtoken",
      }
    ]
  end
end
