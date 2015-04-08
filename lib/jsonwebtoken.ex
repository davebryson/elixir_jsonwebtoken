defmodule Jsonwebtoken do
    @moduledoc """
        Simple API for signing and verifying JSON Web tokens. 
        Supports the following algorithms: HS256, HS384, HS512, RS256, RS384, RS512. 
        We don't support the 'none' algorithm. And you only get the payload if the
        token verifies.
    """
    defmacro __using__(_opts) do
        quote do
            alias Jsonwebtoken, as: JWT
        end
    end

    use Jazz

    @rsa_algorithms ~W[RS256 RS384 RS512]
    @hmac_algorithms ~W[HS256 HS384 HS512]

    @doc """
        Sign the payload with a given algorithm, passing either a secret or RSA KEY string
        returns the token 
    """
    def sign(alg, payload, pk) do 
        header = to_json_and_encode(%{alg: alg, typ: "JWT"})
        payload = to_json_and_encode(payload)

        msg = header <> "." <> payload
        sig = signit(alg,msg,pk)
        msg <> "." <> sig
    end

    # Sign with the RSA Private key
    defp signit(alg, header_payload, secret_or_private_key) when alg in @rsa_algorithms do
        public_key = :public_key.pem_decode(secret_or_private_key) |> hd |> :public_key.pem_entry_decode
        :public_key.sign(header_payload, digest_type(alg), public_key) |> Base.url_encode64     
    end
    # Sign with HMAC
    defp signit(alg, header_payload, secret_or_private_key) when alg in @hmac_algorithms do
        :crypto.hmac(digest_type(alg), secret_or_private_key, header_payload) |> Base.url_encode64
    end

    @doc """
        Verify the token using either the HMAC secret or RSA KEY.
        Note, you only get the payload if it verifies.
        returns {:ok, payload} | {:error, message}
        where payload is Map
    """
    def verify(alg, token, secret_or_pubkey) do
        [header,payload,signature] = String.split(token,".")
        message = header <> "." <> payload

        case verify_it(alg,message,signature,secret_or_pubkey) do
            true ->
                # returns {:ok, decoded_payload}
                decode64_and_json(payload)
            _ ->
                {:error, "Failed verification"}
        end
    end

    ### Internal helpers below ###

    # RSA Algorithms
    defp verify_it(alg, header_payload, signature, secret_or_pubkey) when alg in @rsa_algorithms do
        # Decode the public key to the structure recognized by :public_key
        pub_key = :public_key.pem_decode(secret_or_pubkey) |> hd
        pkf = extract_public_key(pub_key)
        {:ok, decoded_sig} = Base.url_decode64(signature)
        :public_key.verify(header_payload, digest_type(alg), decoded_sig, pkf)
    end
    # HMAC Algorithms
    defp verify_it(alg, header_payload, signature, secret) when alg in @hmac_algorithms do
        signature == :crypto.hmac(digest_type(alg), secret, header_payload) |> Base.url_encode64
    end

     # Check of it's a Cert. If it is, we need to extract the public key from it. 
     # this is when it gets fun using the :public_key api...
    defp extract_public_key({:Certificate, _, _} = pem_decoded_key) do
        {_,{_,_,_,_,_,_,_,subject_pubkey_info,_,_,_},_,_} = :public_key.pem_entry_decode(pem_decoded_key)
        {_, {:AlgorithmIdentifier, algId, _params}, {0, key0}} = subject_pubkey_info
        keyType = :pubkey_cert_records.supportedPublicKeyAlgorithms(algId)
        :public_key.der_decode(keyType, key0) 
    end
    # Should be an RSA Public key
    defp extract_public_key(rsa_pem) do
        :public_key.pem_entry_decode(rsa_pem) 
    end

    # JSON encode it and BaseUrl64 it
    defp to_json_and_encode(value) do
        {:ok, json} = JSON.encode(value)
        json |> Base.url_encode64
    end

    # UNBase64Url it and JSON decode it
    defp decode64_and_json(value) do
        {:ok, d1 } = Base.url_decode64(value) 
        d1 |> JSON.decode
    end

    # THIS CODE WAS ADAPTED FROM THE JWT-ELIXIR WORK:
    digest_algorithms = @rsa_algorithms ++ @hmac_algorithms 
    digest_types = Enum.map digest_algorithms, fn algorithm ->
        digest_type =
        algorithm
            |> String.replace(~r/(R|H)S/, "sha")
            |> String.to_existing_atom
        { algorithm, digest_type }
    end
    Enum.map digest_types, fn { alg, digest_type } ->
        defp(digest_type(unquote(alg)), do: unquote(digest_type))
    end
end
