rule proxy_tunnel_ps1
{
    meta:
        Author = "Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com"
        date = "18July2024"
        Refrence = "https://github.com/Arno0x/PowerShellScripts/blob/master/proxyTunnel.ps1"

    strings:
        $1 = "$proxy = [System.Net.WebRequest]::GetSystemWebProxy()" ascii nocase
        $2 = "[String]$destHost = $( Read-Host \"Enter tunnel destination IP or Hostname: \" )," ascii nocase
        $3 = "[Int]$destPort = $( Read-Host \"Enter tunnel destination port: \" )" ascii nocase
        $4 = "$request = [System.Net.HttpWebRequest]::Create(\"http://\" + $destHost + \":\" + $destPort )" ascii nocase
        $5 = "$listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($bindIP), $bindPort)" ascii nocase
        $6 = "$proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials"ascii nocase

    condition:
        2 of them
}

rule ReverseSocksProxyHandler_py

{
    meta:
        Author = "Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com"
        date = "18July2024"
        Refrence = "https://github.com/p3nt4/Invoke-SocksProxy/blob/master/ReverseSocksProxyHandler.py"

    strings:
        $1 = "(\"Reverse Socks Connection Received: {}:{}\".format(address[0], address[1]))" ascii nocase
        $2 = "(\"Usage:{} <handlerPort> <proxyPort> <certificate> <privateKey>\".format(sys.argv[0]))" ascii nocase
        $3 = "def handlerServer(q, handlerPort, certificate, privateKey)" ascii nocase
        $4 = "dock_socket.bind(('', int(handlerPort)))" ascii nocase

    condition:
        2 of them
}


rule Invoke_SocksProxy_psm1

{
    meta:
        Author = "Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com"
        date = "18July2024"
        Refrence = "https://github.com/p3nt4/Invoke-SocksProxy/blob/master/Invoke-SocksProxy.psm1"

    strings:
        $1 = "elseif($socksVer -eq 4){" ascii nocase
        $2 = "GetHostAddresses($ip)[0].IPAddressToString" ascii nocase
        $3 = "New-Object System.Net.Sockets.TcpClient" ascii nocase
        $4 = "new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]" ascii nocase


condition:
        (2 of ($3)) and any of them
}
