
defmodule Jsonwebtoken.Openssl do
    @moduledoc """
        Helper to sign tokens using password encypted private keys.  Erlang
        public key does not appear to work with private keys signed with AES-256.
        This uses Port to talk to openssl to extract the private key and sign a token.
        Probably best used for a Mix task
    """

    
    @doc """
        Sign a token with a given password protected RSA private key
          alg     : is the RS algorithm
          payload : map of the claims
          filename: should be the complete path and filename of the private key pem: 
                    Path.join(__DIR__, "my-priv-key.pem")
          password: the password for the private key
    """
    def sign_with_rsa_key(alg, payload, filename, password) do
        true = File.exists?(filename)
        token = process(alg, payload, filename, password)
        {:ok, token}
    end

    defp process(alg, payload, filename, password) do
        pid = self()
        command = "openssl rsa -in \'#{filename}\' -passin pass:#{password}"
        
        port = Port.open({:spawn, shell_command(command)},
                         [:stream, :binary, :exit_status, :hide, :use_stdio, :stderr_to_stdout])
        loop(pid, port)
        receive do
            {:ok, data} ->
                Jsonwebtoken.sign(alg,payload,data)
        after 5000 ->
            # Hack to handle bad shell command
            IO.puts("Helper process timed out... do you have openssl installed?")
            :error
        end
    end

    defp loop(pid, port) do
        receive do
            {^port, {:data, private_key}} ->
                case match(private_key) do
                    true -> send pid, {:ok, private_key}
                    _ ->   loop(pid, port)
                end
            {^port, {:exit_status, status}} ->
                status
        end 
    end

    defp match(<<"-----BEGIN RSA PRIVATE KEY-----"::binary, _rest::binary>>), do: true 
    defp match(_), do: false

    # Borrowed from Mix.Shell
    defp shell_command(command) do
        case :os.type do
        {:unix, _} ->
            command = command
                |> String.replace("\"", "\\\"")
                |> :binary.bin_to_list
                'sh -c "' ++ command ++ '"'

        {:win32, osname} ->
            command = :binary.bin_to_list(command)
            case {System.get_env("COMSPEC"), osname} do
                {nil, :windows} -> 'command.com /c ' ++ command
                {nil, _}        -> 'cmd /c ' ++ command
                {cmd, _}        -> '#{cmd} /c ' ++ command
            end
            
        end
    end
end