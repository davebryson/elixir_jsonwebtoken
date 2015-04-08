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
    alias Timex.Date
    import Milliseconds

    @rsa_algorithms ~W[RS256 RS384 RS512]
    @hmac_algorithms ~W[HS256 HS384 HS512]
    @drop_for_expiration [:exp, "exp", :iat, "iat"]

    @doc """
        Create a payload that will expire after a given amount of time.
        Ex: JWT.expire_payload(%{sub: "dave"},"1d")
        Will expire the JWT in 1 day.  See the millisecond lib for other
        time examples
    """
    def expire_payload(payload, timeout) do
        future_time = convert(timeout)
        iat_value = seconds_since_epoch
        exp_value = iat_value + future_time

        Map.drop(payload,@drop_for_expiration)
            |> Map.put(:iat, iat_value)
            |> Map.put(:exp, exp_value)
    end

    @doc """
        Sign the payload with a given algorithm, passing either a secret or RSA KEY string
        returns the token 
    """
    def sign(alg, payload, pk) do 
        header = to_json_and_encode(%{alg: alg, typ: "JWT"})

        # Create an issued at (iat) claim
        payload_encoded = 
        unless Map.has_key?(payload,:iat) or Map.has_key?(payload,"iat") do
            Map.put(payload,:iat, seconds_since_epoch) |> to_json_and_encode
        else
            to_json_and_encode(payload) 
        end

        msg = header <> "." <> payload_encoded
        sig = signit(alg,msg,pk)
        msg <> "." <> sig
    end

    # Sign with the RSA Private key
    defp signit(alg, header_payload, secret_or_private_key) when alg in @rsa_algorithms do
        public_key = :public_key.pem_decode(secret_or_private_key) |> hd |> :public_key.pem_entry_decode
        :public_key.sign(header_payload, digest_type(alg), public_key) |> jwt_encode     
    end
    # Sign with HMAC
    defp signit(alg, header_payload, secret_or_private_key) when alg in @hmac_algorithms do
        :crypto.hmac(digest_type(alg), secret_or_private_key, header_payload) |> jwt_encode
    end

    @doc """
        Verify the token using either the HMAC secret or RSA KEY.
        Note, you only get the payload if it verifies.
        returns {:ok, payload} | {:warn, payload} | {:error, message}
        where payload is Map. :warn is returned if the token expired
    """
    def verify(alg, token, secret_or_pubkey) do
        [header,payload,signature] = String.split(token,".")
        message = header <> "." <> payload

        case verify_it(alg,message,signature,secret_or_pubkey) do
            true ->
                {:ok,pload} = decode64_and_json(payload)
                case is_expired?(pload) do
                    true ->
                        {:warn, pload}
                    _ ->
                        {:ok, pload}
                end
            _ ->
                {:error, "Failed verification"}
        end
    end

    # Pattern match on payload checking for expirations
    defp is_expired?(%{"exp" => exp_value, "iat" => iat_value}), do: exp_value >= iat_value
    defp is_expired?(_), do: false

    ### Internal helpers below ###

    # RSA Algorithms
    defp verify_it(alg, header_payload, signature, secret_or_pubkey) when alg in @rsa_algorithms do
        # Decode the public key to the structure recognized by :public_key
        pub_key = :public_key.pem_decode(secret_or_pubkey) |> hd
        pkf = extract_public_key(pub_key)
        decoded_sig = jwt_decode(signature)
        :public_key.verify(header_payload, digest_type(alg), decoded_sig, pkf)
    end
    # HMAC Algorithms
    defp verify_it(alg, header_payload, signature, secret) when alg in @hmac_algorithms do
        signature == :crypto.hmac(digest_type(alg), secret, header_payload) |> jwt_encode
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
    defp extract_public_key(rsa_pem), do: :public_key.pem_entry_decode(rsa_pem) 


    # JSON encode it and BaseUrl64 it
    defp to_json_and_encode(value) do
        {:ok, json} = JSON.encode(value)
        json |> jwt_encode
    end

    # UNBase64Url it and JSON decode it
    defp decode64_and_json(value) do
        jwt_decode(value) |> JSON.decode
    end

    defp seconds_since_epoch do
        Date.convert(Date.now, :secs) 
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

    # why we remove the '='.  The JWT spec makes reference to 
    # the fact that no other charaters should be added to the content when verifying
    # https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-7.2
    def jwt_encode(binary) when is_binary(binary) do
        Base.url_encode64(binary) |> String.replace("=", "")
    end

    # Why we add the '=' back with pad().  Because the Base.url_decoder expect
    # padding with an '='
    def jwt_decode(encoded) do
        r = pad(encoded)
        Base.url_decode64!(r)
    end

    defp pad(string) do
        case rem(String.length(string), 4) do
            0 -> string
            _ -> pad(string <> "=")
        end
    end
end
