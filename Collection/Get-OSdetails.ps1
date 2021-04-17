<#Get-OSdetails
This module will have functions to list:
    1 - Services Runing                                                                     Done
    2 - List of processs (process tree and command lines and path of the image)             Done
    3 - Ports open with repectives process                                                  Done
    4 - Registry (startup locations)                                                        Done
    5 - Firewall rules/Firewall logs
    6 - Enumerate local users
    7 - DNS Cache                                                                           Done
    8 - User Sessions.
    9 - Collect Number of hashed passwords cached allowed in lsass.
    10 - General System info:
            • System Time and Date
            • Operational system version info.
            • Drives Info
            • Network interface details
            • Routing Table
    11 - Installed Programs                                                                 Done
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
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering System Details this might take some minutes"  -ForegroundColor Green
            $details = @("")
            if(( ($PSVersionTable).PSVersion.Major -ge 5) -and (($PSVersionTable).PSVersion.Minor -ge 1)){
                $imagehashes=@()
                $allprocessimages=(Get-WmiObject Win32_Process).Path | Select-Object -Unique
                foreach ($processimage in $allprocessimages) {$imagehashes+=Get-FileHash $processimage}

                $properties = @{
                    OSdetails          = $(Get-ComputerInfo)
                    InstalledProducts  = $(Get-WmiObject win32_product)
                    Services           = $(Get-WmiObject Win32_Service)
                    Hotfixes           = $(Get-ComputerInfo | Select-Object -ExpandProperty OSHotFixes)
                    Autoruns           = $(Get-PSAutorun -All)
                    DNSCache           = $(Get-DnsClientCache)
                    RunningProcess     = $(Get-WmiObject Win32_Process)
                    ProcessImageHashes = $imagehashes
                    TCPConnection      = $(Get-NetTCPConnection)
                }
            }
            else {
                $imagehashes=@()
                $allprocessimages=(Get-WmiObject Win32_Process).Path | Select-Object -Unique
                foreach ($processimage in $allprocessimages) {$imagehashes+=Get-FileHash $processimage}
                #Get-CimInstance -ClassName Win32_ComputerSystem
                $properties = @{
                    OSdetails          = "not implemented"
                    InstalledProducts  = $(Get-WmiObject win32_product)
                    Services           = $(Get-WmiObject Win32_Service)
                    Hotfixes           = "not implemented"
                    Autoruns           = $(Get-PSAutorun -All)
                    DNSCache           = $(Get-DnsClientCache)
                    RunningProcess     = $(Get-WmiObject Win32_Process)
                    ProcessImageHashes = $imagehashes
                    TCPConnection      = $(Get-NetTCPConnection)
                }
            }

            $details = New-Object -TypeName PSObject -Property $properties   #netstat receive the object with the relevant information
            return $details
        }
        $osdetailsparameters = @{scriptblock = $osdetails }
    
    }
    process {
        try{
            write-host "[+][$(Get-TimeStamp)] Exporting information to CSV"  -ForegroundColor Green
            if($Localhost){
                $AutoRunsPath=(Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.psd1).FullName
                Import-Module $AutoRunsPath
                $details=Invoke-Command @osdetailsparameters
                $details.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
                $details.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
                $details.Services | Export-Csv -Path $OutputPath\Services.csv
                $details.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv
                $details.Autoruns | Export-Csv -Path $OutputPath\Autoruns.csv
                $details.DNSCache | Export-Csv -Path $OutputPath\DNSCache.csv
                $details.RunningProcess | Export-Csv -Path $OutputPath\DNSCache.csv
                $details.ProcessImageHashes | Export-Csv -Path $OutputPath\ProcessImageHashes.csv
                $details.TCPConnection | Export-Csv -Path $OutputPath\TCPConnection.csv
            }
            else{
                $AutoRunsPath=(Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.ps1).FullName
                Invoke-Command -Session $session $AutoRunsPath 
                $details=Invoke-Command -Session $Session @osdetailsparameters 
                $details.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
                $details.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
                $details.Services | Export-Csv -Path $OutputPath\Services.csv
                $details.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv
                $details.Autoruns | Export-Csv -Path $OutputPath\Autoruns.csv
                $details.DNSCache | Export-Csv -Path $OutputPath\DNSCache.csv
                $details.RunningProcess | Export-Csv -Path $OutputPath\DNSCache.csv
                $details.ProcessImageHashes | Export-Csv -Path $OutputPath\ProcessImageHashes.csv
                $details.TCPConnection | Export-Csv -Path $OutputPath\TCPConnection.csv
            }

        }
        catch{
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Get-SystemDetails... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }

    }
}
