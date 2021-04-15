<#Get-OSdetails
This module will have functions to list:
    1 - Services Runing
    2 - List of processs (process tree and command lines and path of the image)
    3 - Ports open with repectives process
    4 - Registry (startup locations)
    5 - Firewall rules/Firewall logs
    6 - Enumerate local users
    7 - DNS Cache
    8 - User Sessions.
    9 - Collect Number of hashed passwords cached allowed in lsass. 
    10 - General System info: 
            • System Time and Date
            • Operational system version info.
            • Drives Info
            • Network interface details
            • Routing Table
    11 - Installed Programs
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
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering System Details"  -ForegroundColor Green
            $details = @("")
            $properties = @{
                OSdetails          = $(Get-ComputerInfo)
                InstalledProducts  = $(Get-WmiObject win32_product)
                Services           = $(Get-WmiObject Win32_Service)
                Hotfixes           = $(Get-ComputerInfo | Select-Object -ExpandProperty OSHotFixes)
            }
            $details = New-Object -TypeName PSObject -Property $properties   #netstat receive the object with the relevant information
            return $details
        }
        $osdetailsparameters = @{scriptblock = $osdetails }
    
    }
    process {
        try{
            if($Localhost){
                $details=Invoke-Command @osdetailsparameters
                $details.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
                $details.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
                $details.Services | Export-Csv -Path $OutputPath\Services.csv
                $details.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv
            }
            else{
                $details=Invoke-Command -Session $Session @osdetailsparameters 
                $details.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
                $details.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
                $details.Services | Export-Csv -Path $OutputPath\Services.csv
                $details.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv
            }

        }
        catch{
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Get-SystemDetails... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }

    }
}
