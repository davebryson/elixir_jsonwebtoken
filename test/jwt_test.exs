defmodule JwtTest do
  use ExUnit.Case
  use Jsonwebtoken

  test "test RS512 with cert" do
    alg = "RS512"
    private_key = File.read!(Path.join(__DIR__, "priv.pem"))
    public_key = File.read!(Path.join(__DIR__, "pub.pem"))

    token = JWT.sign(alg,%{sub: "dave"}, private_key)
    {:ok, payload} = JWT.verify(alg,token,public_key)

    assert payload["sub"] == "dave"
  end

  test "test RS256 with cert" do
    alg = "RS256"
    private_key = File.read!(Path.join(__DIR__, "priv.pem"))
    public_key = File.read!(Path.join(__DIR__, "pub.pem"))

    token = JWT.sign(alg,%{sub: "dave"}, private_key)
    {:ok, payload} = JWT.verify(alg,token,public_key)

    assert payload["sub"] == "dave"
  end

  test "with RSA PUBLIC KEY" do 
    alg = "RS256"
    private_key = File.read!(Path.join(__DIR__, "rsa-private.pem"))
    public_key = File.read!(Path.join(__DIR__, "rsa-public-key.pem"))

    token = JWT.sign(alg,%{sub: "dave"}, private_key)
    {:ok, payload} = JWT.verify(alg,token,public_key)

    assert payload["sub"] == "dave"
  end

  test "with PUBLIC KEY" do 
    alg = "RS256"
    private_key = File.read!(Path.join(__DIR__, "rsa-private.pem"))
    public_key = File.read!(Path.join(__DIR__, "rsa-public.pem"))

    token = JWT.sign(alg,%{sub: "dave"}, private_key)
    {:ok, payload} = JWT.verify(alg,token,public_key)

    assert payload["sub"] == "dave"
  end

  test "fails with wrong public pem" do
    alg = "RS256"
    private_key = File.read!(Path.join(__DIR__, "rsa-private.pem"))
    public_key = File.read!(Path.join(__DIR__, "pub.pem"))

    token = JWT.sign(alg,%{sub: "dave"}, private_key)
    {:error, _payload} = JWT.verify(alg,token,public_key)
  end

  test "with HMAC 256" do
    alg = "HS256"
    secret = "this is a secret"
    token = JWT.sign(alg,%{sub: "dave"}, secret)
    {:ok, payload} = JWT.verify(alg,token,secret)

    assert payload["sub"] == "dave"
  end

  test "fail on a bad secret" do
    alg = "HS512"
    secret = "this is a secret"
    bad_secret = "ooops"
    token = JWT.sign(alg,%{sub: "dave"}, secret)
    {:error, _} = JWT.verify(alg,token,bad_secret)
  end
end
