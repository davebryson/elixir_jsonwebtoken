Jsonwebtoken (JWT)
===================================================================
Simple API for signing and verifying JSON Web Tokens.

Supports the following algorithms: HS256, HS384, HS512, RS256, RS384, RS512. 
We don't support the 'none' algorithm, and you only get the payload if the token verifies.

Examples
--------

```elixir

use Jsonwebtoken

# Using RSA

# Load the Keys
private_key = File.read!(Path.join(__DIR__, "priv.pem"))
public_key = File.read!(Path.join(__DIR__, "pub.pem"))

# Create the token
token = JWT.sign("RS512",%{sub: "dave"}, private_key)

# Verify and get the payload
{:ok, payload} = JWT.verify("RS512",token,public_key)

# Get your data
name = payload["sub"]

# If verification fails...
{:error, reason} = JWT.verify("RS512",token,public_key)

# Using HMAC

secret = "this is a secret"
token = JWT.sign("HS256",%{sub: "dave"}, secret)
{:ok, payload} = JWT.verify("HS256",token,secret)

# Create a token that expires in 30 days

payload = JWT.expire_payload(%{sub: "dave"}, "30days")
token = JWT.sign(alg, payload, secret)

```

This library was inspired by jwt-elixir: https://github.com/onkel-dirtus/jwt-elixir