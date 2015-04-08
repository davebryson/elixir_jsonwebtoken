defmodule JwtTest do
  use ExUnit.Case
  use Jsonwebtoken

  @example_token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE0Mjg0OTI0MzYsInN1YiI6ImRhdmViIn0.MHddC5w0sz-wrrxmN24tCLGaY3wYZxe_AfEmueryLOkPdoUwCxa6P_m2Omzz-aXfBWO7EwuTjEG5Kdbg0rHhz88jOgTWiyLEcLwdoH2X3uhBcTHVO69rLxfG3vOOgHDcYIkUblaaKTHhOwNyN4oGPLpDXslYDRGDZA611vIRBXHRba-7A5PupiKcK_W3ulRUgQxBZi3Z0de3DdowMBSC3XqLFtsVk7PeHkVuone0mXSUhSu5qkjdfntj_AU24jmlcHSUphDSou--B16ZWmeo0NXgbGz6i_zMetY8LHLfrmWCvcyvF1lqYg3VqpfHzbuCaGQEbz7TkraKtYEJBTrmuQ"

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
    assert payload["iat"]
    assert payload["iat"] > 1000
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

  test "parse exiting token" do
    # Contains the payload: {iat: 1428492436, sub: "daveb"}
    public_key = File.read!(Path.join(__DIR__, "rsa-public.pem"))
    {:ok, payload} = JWT.verify("RS256",@example_token,public_key)
    assert payload["sub"] == "daveb"
    assert payload["iat"] == 1428492436
  end

  test "set expiration function" do 
    # Will expire in 10 seconds even if I preset it
    payload = JWT.expire_payload(%{sub: "dave", exp: 0}, "10s")
    assert payload.exp > payload.iat
  end

  test "warn on expired token" do
    alg = "HS256"
    secret = "this is a secret"
    payload = JWT.expire_payload(%{sub: "dave"},"0")
    token = JWT.sign(alg,payload, secret)
    {:warn, _payload} = JWT.verify(alg,token,secret) 
  end
end
