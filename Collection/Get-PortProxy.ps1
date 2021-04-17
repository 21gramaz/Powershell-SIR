<#    PortProxy Parse:
    https://www.powershellgallery.com/packages/NetshUtils/0.1.447696-alpha/Content/public%5Cinterface%5Cportproxy%5CGet-PortProxy.ps1
#>

function Get-PortProxy {
    $command = "netsh interface portproxy show all"
    $ProxyPortOutput = Invoke-Expression -Command $command

    $ProxyPorPattern = '^\s*(?<ListenAddress>[^\s]+)\s+(?<ListenPort>\d+)\s+(?<ConnectAddress>[^\s]+)\s+(?<ConnectPort>\d+)\s*$'
    $ProxyPort = @()
    $ProxyPortOutput | Where-Object { $_ -match $ProxyPorPattern } | ForEach-Object {
        $properties = @{
            InternetProtocol = "v4tov4"
            ListenAddress    = $Matches.ListenAddress
            ListenPort       = [int]::Parse($Matches.ListenPort)
            ConnectAddress   = $Matches.ConnectAddress
            ConnectPort      = [int]::Parse($Matches.ConnectPort)
        }
        $ProxyPort += New-Object -TypeName PSObject -Property $properties
    }
    return $ProxyPort
}