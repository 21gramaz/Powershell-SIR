<#Get-OSdetails
This module will have functions to list:
    1 - Services Runing                                                                     Done
    2 - List of processs (process tree and command lines and path of the image)             Done
    3 - Ports open with repectives process                                                  Done
    4 - Registry (startup locations)                                                        Done
    5 - Firewall rules                                                                      Done
    6 - Enumerate local users
    7 - DNS Cache                                                                           Done
    8 - User Sessions.                                                                      Done
    9 - Collect Number of hashed passwords cached allowed in lsass.
    10 - General System info:
            • System Time and Date                                                          Partial
            • Operational system version info.                                              Partial
            • Drives Info                                                                   
            • Network interface details 
            • Routing Table
    11 - Installed Programs                                                                 Done
    12 - Firewall Logs
    13 - PortProxy Configurations                                                           Done
#>


function Get-SystemDetails {
    param (
        [Parameter()]
        [switch]
        $Localhost,

        [Parameter()]
        [String]
        $OutputPath,

        [Parameter()]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )

    begin {

        

        #creates folder to copy the logs
        if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null } 
        $osdetails = {
            function Get-TimeStamp { get-date -Format "MM/dd/yyyy HH:mm:ss K" }
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: System Details this might take some minutes"  -ForegroundColor Green
            $details = @("")
            if (( ($PSVersionTable).PSVersion.Major -ge 5) -and (($PSVersionTable).PSVersion.Minor -ge 1)) {
                $imagehashes = @()
                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Process Image Hashes"  -ForegroundColor Green
                $allprocessimages = (Get-WmiObject Win32_Process).Path | Select-Object -Unique
                foreach ($processimage in $allprocessimages) { $imagehashes += Get-FileHash $processimage }

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Computer info"  -ForegroundColor Green
                $CompInfo=Get-ComputerInfo

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Installed software"  -ForegroundColor Green
                $InstalledProd=Get-WmiObject win32_product

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Services"  -ForegroundColor Green
                $ServiceDetails=Get-WmiObject Win32_Service

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Installed HotFix"  -ForegroundColor Green
                $InstalledHotifixes=Get-ComputerInfo | Select-Object -ExpandProperty OSHotFixes

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: AutoRuns"  -ForegroundColor Green
                $PSautoruns=Get-PSAutorun -All

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: DNS Cache"  -ForegroundColor Green
                $DNSCacheContent=Get-DnsClientCache

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: System Processes"  -ForegroundColor Green
                $SystemProcess=Get-WmiObject Win32_Process

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Network Connections"  -ForegroundColor Green
                $NetworkConnections=Get-NetTCPConnection

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Firewall Rules"  -ForegroundColor Green
                $FirewallRules= Get-NetFirewallRule

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Proxy Port Configuration"  -ForegroundColor Green
                $ProxyPortConfig=Get-PortProxy

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Logged Users"  -ForegroundColor Green
                $LoggedUsers=Get-LoggedOnUser

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Installed software"  -ForegroundColor Green
                $ProcessTreeGraph=Show-ProcessTree

                $properties = @{
                    OSdetails          = $CompInfo
                    InstalledProducts  = $InstalledProd
                    Services           = $ServiceDetails
                    Hotfixes           = $InstalledHotifixes
                    Autoruns           = $PSautoruns
                    DNSCache           = $DNSCacheContent
                    RunningProcess     = $SystemProcess
                    ProcessImageHashes = $imagehashes
                    TCPConnection      = $NetworkConnections
                    FirewallRules      = $FirewallRules
                    PortProxy          = $ProxyPortConfig
                    LoggedOnUser       = $LoggedUsers
                    ProcessTree        = $ProcessTreeGraph
                }
            }
            else {
                write-host "[+][$(Get-TimeStamp)] Powershell version does not support collection"  -ForegroundColor Red
                break
            }

            $details = New-Object -TypeName PSObject -Property $properties   #netstat receive the object with the relevant information
            return $details
        }
        $osdetailsparameters = @{scriptblock = $osdetails }
    
    }
    process {
        try {
            $ShowProcessTreePath = $PSScriptRoot + "\Show-ProcessTree.ps1"
            $GetPortProxyPath = $PSScriptRoot + "\Get-PortProxy.ps1"
            $GetLoggedOnUsersPath  = $PSScriptRoot + "\Get-LoggedOnUser.ps1"
            if ($Localhost) {
                $AutoRunsPath = (Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.psd1).FullName
                Remove-Module -Name Get-LoggedOnUser, Get-PortProxy, Show-ProcessTree -ErrorAction SilentlyContinue
                Import-Module $AutoRunsPath, $ShowProcessTreePath, $GetPortProxyPath, $GetLoggedOnUsersPath           
                $details = Invoke-Command @osdetailsparameters
            }
            else {
                $AutoRunsPath = (Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.ps1).FullName
                Invoke-Command -Session $session $AutoRunsPath 
                Invoke-Command -Session $session $ShowProcessTreePath
                Invoke-Command -Session $session $GetPortProxyPath
                Invoke-Command -Session $session $GetLoggedOnUsersPath 
                $details = Invoke-Command -Session $Session @osdetailsparameters 
            }
            write-host "[+][$(Get-TimeStamp)] Exporting information to CSV"  -ForegroundColor Green

            $details.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
            $details.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
            $details.Services | Export-Csv -Path $OutputPath\Services.csv
            $details.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv
            $details.Autoruns | Export-Csv -Path $OutputPath\Autoruns.csv
            $details.DNSCache | Export-Csv -Path $OutputPath\DNSCache.csv
            $details.RunningProcess | Export-Csv -Path $OutputPath\RunningProcess.csv
            $details.ProcessImageHashes | Export-Csv -Path $OutputPath\ProcessImageHashes.csv
            $details.TCPConnection | Export-Csv -Path $OutputPath\TCPConnection.csv
            $details.FirewallRules | Export-Csv -Path $OutputPath\FirewallRules.csv
            $details.PortProxy | Export-Csv -Path $OutputPath\PortProxy.csv
            $details.LoggedOnUser | Export-Csv -Path $OutputPath\LoggedOnUser.csv
            $details.ProcessTree > $OutputPath\ProcessTree.txt

        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Get-SystemDetails... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }

    }
}
