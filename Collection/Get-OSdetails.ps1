<#Get-OSdetails
This module will have functions to list:
Basic:
    - General System info:
            • System Time and Date                                                          Done
            • Operational system version info.                                              Done
            • Drives Info                                                                   Done                               
            • Network interface details                                                     Done
            • Routing Table                                                                 Done
    - Services Runing                                                                     Done
    - List of processs (process tree and command lines and path of the image)             Done
    - Ports open with repectives process                                                  Done
    - Firewall rules                                                                      Done
    - Enumerate local users                                                               Done
    - DNS Cache                                                                           Done
    - User Sessions.                                                                      Done
    - Installed Programs                                                                  Done
    - Network Connections                                                                 Done

Medium:
    - SMB Sessions                                                                       Not Implemented
    - PortProxy Configurations                                                           Done
    - Autoruns (Persistence/Execution)                                                   Done

Advanced:
    - MFT records                                                                       Done
    - SHIM cache                                                                        Not Implemented
    - AM Cache                                                                          Not Implemented
    - Collect Number of hashed passwords cached in the system.                          Not Implemented

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
        $Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Basic", "Medium","Detailed")]
        [string]
        $InformationLevel
    )

    begin {
        
        #creates folder to copy the logs
        if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null } 
        $osdetailsbasic = {
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

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: DNS Cache"  -ForegroundColor Green
                $DNSCacheContent=Get-DnsClientCache

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: System Processes"  -ForegroundColor Green
                $SystemProcess=Get-WmiObject Win32_Process

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Network Connections"  -ForegroundColor Green
                $NetworkConnections=Get-NetTCPConnection

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Firewall Rules"  -ForegroundColor Green
                $FirewallRules= Get-NetFirewallRule

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Logged Users"  -ForegroundColor Green
                $LoggedUsers=Get-LoggedOnUser

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Current Process Tree"  -ForegroundColor Green
                $ProcessTreeGraph=Show-ProcessTree

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Network Routes"  -ForegroundColor Green
                $NetworkRoutes=Get-NetRoute

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Network Interfaces"  -ForegroundColor Green
                $NetworkInterfaces=Get-NetAdapter

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: File system Drives"  -ForegroundColor Green
                $FileSystemDrives=Get-PSDrive | Where-Object {$_.Provider -match "FileSystem"}

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Local users"  -ForegroundColor Green
                $LocalUsers=Get-LocalUser

                $properties = @{
                    OSdetails               = $CompInfo
                    InstalledProducts       = $InstalledProd
                    Services                = $ServiceDetails
                    Hotfixes                = $InstalledHotifixes
                    DNSCache                = $DNSCacheContent
                    RunningProcess          = $SystemProcess
                    ProcessImageHashes      = $imagehashes
                    TCPConnection           = $NetworkConnections
                    FirewallRules           = $FirewallRules
                    LoggedOnUser            = $LoggedUsers
                    ProcessTree             = $ProcessTreeGraph
                    NetworkRoutes           = $NetworkRoutes
                    NetworkInterfaces       = $NetworkInterfaces
                    FileSystemDrives        = $FileSystemDrives
                    LocalUsers              = $LocalUsers
                }
            }
            else {
                write-host "[+][$(Get-TimeStamp)] Powershell version does not support collection"  -ForegroundColor Red
                break
            }

            $details = New-Object -TypeName PSObject -Property $properties   
            return $details
        }
        $osdetailsbasicparameters = @{scriptblock = $osdetailsbasic }
    
        $osdetailsmedium = {
            function Get-TimeStamp { get-date -Format "MM/dd/yyyy HH:mm:ss K" }
            $mediumdetails = @("")
            if (( ($PSVersionTable).PSVersion.Major -ge 5) -and (($PSVersionTable).PSVersion.Minor -ge 1)) {

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: AutoRuns"  -ForegroundColor Green
                $PSautoruns=Get-PSAutorun -All

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: Proxy Port Configuration"  -ForegroundColor Green
                $ProxyPortConfig=Get-PortProxy

                $mediumproperties = @{
                    Autoruns                = $PSautoruns
                    PortProxy               = $ProxyPortConfig
                }
            }
            else {
                write-host "[+][$(Get-TimeStamp)] Powershell version does not support collection"  -ForegroundColor Red
                break
            }

            $mediumdetails = New-Object -TypeName PSObject -Property $mediumproperties   
            return $mediumdetails
        }
        $osdetailsmediumparameters = @{scriptblock = $osdetailsmedium }

        $osdetailsdetailed = {
            function Get-TimeStamp { get-date -Format "MM/dd/yyyy HH:mm:ss K" }
            $detaileddetails = @("")
            if (( ($PSVersionTable).PSVersion.Major -ge 5) -and (($PSVersionTable).PSVersion.Minor -ge 1)) {

                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Gathering: MFT records"  -ForegroundColor Green
                $MasterFileTableRecords=Get-ForensicFileRecord

                $properties = @{
                    MasterFileTableRecords  = $MasterFileTableRecords
                }
            }
            else {
                write-host "[+][$(Get-TimeStamp)] Powershell version does not support collection"  -ForegroundColor Red
                break
            }

            $detaileddetails = New-Object -TypeName PSObject -Property $properties   
            return $detaileddetails
        }
        $osdetailsdetailedparameters = @{scriptblock = $osdetailsdetailed }

    }
    process {
        try {
            $ShowProcessTreePath = $PSScriptRoot + "\Show-ProcessTree.ps1"
            $GetLoggedOnUsersPath  = $PSScriptRoot + "\Get-LoggedOnUser.ps1"
            $GetPortProxyPath = $PSScriptRoot + "\Get-PortProxy.ps1"
            if ($InformationLevel -eq "Basic" -or $InformationLevel -eq  "Medium" -or $InformationLevel -eq "Detailed"){
                if ($Localhost) {
                    #importing modules to localhost
                    Remove-Module -Name Get-LoggedOnUser, Show-ProcessTree -ErrorAction SilentlyContinue
                    Import-Module $ShowProcessTreePath, $GetLoggedOnUsersPath        
                    $basicdetails = Invoke-Command @osdetailsbasicparameters
                }
                else {
                    #importing the modules in the sessions
                    Invoke-Command -Session $session $ShowProcessTreePath
                    Invoke-Command -Session $session $GetLoggedOnUsersPath 
                    $basicdetails = Invoke-Command -Session $session @osdetailsbasicparameters 
                }
            }
            if ($InformationLevel -eq "Medium" -or $InformationLevel -eq "Detailed"){
                if ($Localhost) {
                    #importing modules to localhost
                    $AutoRunsPath = (Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.psd1).FullName
                    Remove-Module -Name Get-PortProxy -ErrorAction SilentlyContinue
                    Import-Module $AutoRunsPath, $GetPortProxyPath     
                    $mediumdetails = Invoke-Command @osdetailsmediumparameters
                }
                else {
                    #importing the modules in the sessions
                    $AutoRunsPath = (Get-ChildItem -Path "$PSScriptRoot\Autoruns\" -Recurse Autoruns.ps1).FullName
                    #Remove-Module -Name Get-PortProxy
                    Invoke-Command -Session $session $AutoRunsPath 
                    Invoke-Command -Session $session $GetPortProxyPath
                    $mediumdetails = Invoke-Command -Session $session @osdetailsmediumparameters 
                }
            }
            if ($InformationLevel -eq "Detailed"){
                if ($Localhost) {
                    #importing modules to localhost
                    $Forensicsv2Path = (Get-ChildItem -Path "$PSScriptRoot\PowerForensicsv2\" -Recurse PowerForensicsv2.dll).FullName
                    Copy-Item $Forensicsv2Path -Destination "C:\Windows\Temp\" 
                    $ForensicDLLPath="C:\Windows\Temp\PowerForensicsv2.dll"
                    Import-Module $ForensicDLLPath -ErrorAction Continue        
                    $detaileddetails = Invoke-Command @osdetailsdetailedparameters
                }
                else {
                    #importing the modules in the sessions
                    $Forensicsv2Path = (Get-ChildItem -Path "$PSScriptRoot\PowerForensicsv2\" -Recurse PowerForensicsv2.dll).FullName
                    Copy-Item $Forensicsv2Path -Destination "C:\Windows\Temp\" -ToSession $session
                    Invoke-Command -Session $session -ScriptBlock { $RemoteForensicsv2Path = "C:\Windows\Temp\PowerForensicsv2.dll"; Import-Module $RemoteForensicsv2Path -ErrorAction Continue} | Out-Null
                    $detaileddetails = Invoke-Command -Session $session @osdetailsdetailedparameters -ErrorAction Continue
                }
            }
            
            write-host "[+][$(Get-TimeStamp)] Exporting information to CSV"  -ForegroundColor Green
            if ($InformationLevel -eq "Basic" -or $InformationLevel -eq "Medium" -or $InformationLevel -eq "Detailed"){
                $basicdetails.OSdetails | Export-Csv -Path $OutputPath\OSdetails.csv
                $basicdetails.InstalledProducts | Export-Csv -Path $OutputPath\InstalledProducts.csv
                $basicdetails.Services | Export-Csv -Path $OutputPath\Services.csv
                $basicdetails.Hotfixes | Export-Csv -Path $OutputPath\Hotfixes.csv                
                $basicdetails.DNSCache | Export-Csv -Path $OutputPath\DNSCache.csv
                $basicdetails.RunningProcess | Export-Csv -Path $OutputPath\RunningProcess.csv
                $basicdetails.ProcessImageHashes | Export-Csv -Path $OutputPath\ProcessImageHashes.csv
                $basicdetails.TCPConnection | Export-Csv -Path $OutputPath\TCPConnection.csv
                $basicdetails.FirewallRules | Export-Csv -Path $OutputPath\FirewallRules.csv                
                $basicdetails.LoggedOnUser | Export-Csv -Path $OutputPath\LoggedOnUser.csv 
                $basicdetails.NetworkRoutes | Export-Csv -Path $OutputPath\NetworkRoutes.csv 
                $basicdetails.NetworkInterfaces | Export-Csv -Path $OutputPath\NetworkInterfaces.csv
                $basicdetails.FileSystemDrives | Export-Csv -Path $OutputPath\FileSystemDrives.csv
                $basicdetails.LocalUsers | Export-Csv -Path $OutputPath\LocalUsers.csv
                $basicdetails.ProcessTree > $OutputPath\ProcessTree.txt      
            }
            if ($InformationLevel -eq "Medium" -or $InformationLevel -eq "Detailed"){
                $mediumdetails.PortProxy | Export-Csv -Path $OutputPath\PortProxy.csv
                $mediumdetails.Autoruns | Export-Csv -Path $OutputPath\Autoruns.csv
            }
            if ($InformationLevel -eq "Detailed"){
                $detaileddetails.MasterFileTableRecords | Export-Csv -Path $OutputPath\MasterFileTableRecords.csv -ErrorAction Continue
            }
      
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Get-SystemDetails... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }

    }
}
