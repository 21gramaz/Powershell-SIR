<#
  .SYNOPSIS
  Invoke-SIR its a powershell script that aim to help in Investigation (information and artifact collection), containment and remediation part of Security Incident Response for Windows. Live response script.

  .DESCRIPTION
  Invoke-SIR.ps1 is responsible to determine which of the other 3 child scripts will be called, depending which stage of SIR you are in, these three other scripts are:
  1 - Invoke-InformationGathering.ps1 it is responsible to gather information using third party modules or own modules, the scripts/modules below are used:
        -Get-OSDetails.ps1 - Most of the commands used here are simple commands to list system information or to call third party modules:
            *AutoRuns Module - https://github.com/LeeHolmes/AutoRuns - Mostly do the same as autoruns.exe part of sysinternal tools, to find persistence and execution techiniques.
            *PowerForensics Module - https://powerforensics.readthedocs.io/en/latest/ - Used the DLL to import-modules and get MFT records, but it owns a very wide range of forensic CMDlets.
            *Get-PortProxy.ps1 - https://www.powershellgallery.com/packages/NetshUtils/0.1.447696-alpha/Content/public%5Cinterface%5Cportproxy%5CGet-PortProxy.ps1 - Used to bring Port-Proxy information, when people are pivoting in the host this kind of configuration might be used to routing.
            *Show-ProcessTree.ps1 - https://p0w3rsh3ll.wordpress.com/ - Used to review process tree graphically (easier than have a list of process to find what is suspicious)
  2 - Invoke-Contaiment.ps1 is responsible to help to contain the incident with the following functions:
        -Host isolation/release. (Implmented)
        -Process termination. (Not Implemented)
        -Terminate user session. (Not Implemented)
        -Restart service. (Not Implemented)
  3 - Invoke-Remediation.ps1 - not implemented
        -Service Removal.  
        -WMI persistence removal.  
        -Task Scheduler removal.  
        -User removal.  
        -Remove endpoint Firewall Rule/Proxy.  
        -Remove list of files by path+name or hash.  
        -Remove Application (Maybe)  
        -Remove browser extenstions  (Maybe)  
  To learn more please go to https://github.com/21gramaz/Powershell-security-incident-response-helpers

  .PARAMETER Collection
  This parameter sets the script to use the ParameterSet Collection that will include the following paramenters:
    -CollectionOutputPath
    -CollectionType
    -ComputerName
    -UseCreds
    -UseSession

  .PARAMETER Containment
   This parameter sets the script to use the ParameterSet Contaiment that will include the following paramenters:
    -ContainmentType
    -ComputerName
    -UseCreds
    -UseSession

  .PARAMETER Remediation
  This parameter sets the script to use the ParameterSet Remediation. (Not implemented)

  .PARAMETER DownloadLatestThirdPartyModules
  Used to update the following third party modules:
    -PowerForensicsV2
    -Autoruns

  .PARAMETER CollectionType
  Used to set the collection for one of these three options:
    -Disk. (Implemented)
    -Memory. It will use winpmem.exe downloaded https://github.com/Velocidex/WinPmem/releases from to dump volatile memory. (Implemented for Local system)
    -All. (Implemented for local system)

  .PARAMETER InformationLevel
  Used to set the level of information being gathered from the system as describes the below:
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

  .PARAMETER FilesCollectionLevel
  Used to set the level of files being copied from the system as describes the below:
    Disabled:
    - Create a table of retention time for each evtx log                                Done

    Basic:
    - Create a table of retention time for each evtx log                                Done
    - Copy the System, Appliacation and Security EVTX files                             Done

    Medium:
    - Create a table of retention time for each evtx log                                Done
    - Copy all EVTX files                                                               Done
    - Copy prefetch files                                                               Done
    - Copy Firewall Logs                                                                Done
    - Copy Browser History                                                              Not implmented

    Detailed:
    - Create a table of retention time for each evtx log                                Done
    - Copy all EVTX files                                                               Done
    - Copy prefetch files                                                               Done
    - Copy Firewall Logs - Get-NetFirewallProfile                                       Done
    - Copy Browser History                                                              Not implmented
    - Copy IIS logs                                                                     Not implmented
    - Copy Exchange logs                                                                Not implmented
    - Copy Temp Files                                                                   Not implmented

  .PARAMETER ContainmentType
  Used to update the following third party modules:
    -NetworkIsolation.  (Implemented)
    -NetworkRelease.  (Implemented)

  .PARAMETER ComputerName
  Remote computer in which you want to run the script, if not set it will run in the local system.

  .PARAMETER UseCreds
  If the current powershell session does not have administrator privileges or does not have winrm permission, you can use username and password to do it. Once set the script will popup a window get-credential. If not set the script will try to run the script with the session already given permissions.

  .PARAMETER UseSessions
  If there is a session opened to the system you can specify the ComputerName and -UseSession, the script will pick sessions with name SIR (all PSSessions opened by this script are named SIRN where N is a incremental number example: SIR1) in it.

  .INPUTS
  You can pipe system names/IPs in which you want to run the script.

  .OUTPUTS
  If you are using the Collection parameter all the information gathered and the transcription of the script will be saved in $PSScriptRoot\Collection\Reports.
  If you are using Contaiment/Remediation paramenter the output would be the transcription saved in $PSScriptRoot\Collection\Reports

  .EXAMPLE
  .
  Network Isolation for host 192.168.168.156 using username+password.
  PS> .\Invoke-SIR.ps1 -Containment -ContainmentType NetworkIsolation -ComputerName 192.168.168.156 -UseCreds

  Network release will work remotely just with -UseSessions Parameter, because it uses an already defined session as new sessions will not be allowed.
  PS> .\Invoke-SIR.ps1 -Containment -ContainmentType NetworkRelease -ComputerName 192.168.168.156 -UseSessions

  Network Isolation for localhost
  PS> .\Invoke-SIR.ps1 -Containment -ContainmentType NetworkIsolation

  .EXAMPLE
  .
  Collects information from a remote computer using the current powershell session permissions.
  PS> .\Invoke-SIR.ps1 -Collection -CollectionType Disk -ComputerName 192.168.168.156

  Collects information from the local system using the current powershell session permissions.
  PS> .\Invoke-SIR.ps1 -Collection -CollectionType Disk
#>
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Parameter(ParameterSetName = "Collection")]
    [Parameter(ParameterSetName = "Contaiment")]
    [string[]]
    $ComputerName,

    [Parameter(ParameterSetName = "Collection")]
    [switch]
    $Collection,

    [Parameter(ParameterSetName = "Contaiment")]
    [switch]
    $Containment,

    [Parameter(ParameterSetName = "Remediation")]
    [switch]
    $Remediation,

    [Parameter(Mandatory = $true, ParameterSetName = "Collection")]
    [ValidateSet("Disk", "Memory", "All")]
    [string]
    $CollectionType,

    [Parameter(ParameterSetName = "Collection")]
    [string]
    $CollectionOutputPath = "$PSScriptRoot\Collection\Reports",

    [Parameter(ParameterSetName = "Collection")]
    [ValidateSet("Basic", "Medium","Detailed")]
    [string]
    $InformationLevel = "Basic",

    [Parameter(ParameterSetName = "Collection")]
    [ValidateSet("Disabled","Basic", "Medium","Detailed")]
    [string]
    $FilesCollectionLevel = "Medium",
    
    [Parameter(Mandatory = $true, ParameterSetName = "Contaiment")]
    [ValidateSet("NetworkIsolation", "NetworkRelease")]
    [string]
    $ContainmentType,

    [Parameter(Mandatory = $true, ParameterSetName = "Remediation")]
    [switch]
    $RemediationType,

    [Parameter(ParameterSetName = "Collection")]
    [Parameter(ParameterSetName = "Contaiment")]
    [switch]
    $UseCreds,

    [Parameter(ParameterSetName = "Collection")]
    [Parameter(ParameterSetName = "Contaiment")]
    [switch]
    $UseSessions,

    [Parameter(Mandatory = $true, ParameterSetName = "UpdateModules")]
    [switch]
    $DownloadLatestThirdPartyModules
)

begin {
    Start-Transcript -OutputDirectory "$PSScriptRoot\Collection\Reports\" -NoClobber
    $ErrorActionPreference = "stop"
    function Get-TimeStamp {
        get-date -Format "MM/dd/yyyy HH:mm:ss K"
    }
    function get-basicinfo {
        param(
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]    
            $ComputerName,
            
            [Parameter()]
            [System.Management.Automation.PSCredential]
            $Credential,

            [Parameter()]
            [System.Management.Automation.Runspaces.PSSession]
            $Session
        )

        $command = {
            $hostinfo = Get-CimInstance Win32_OperatingSystem;
            $hostinfo | Add-Member -NotePropertyName PowershellVersion -NotePropertyValue $PSVersionTable;
            return $hostinfo
        }
        $parameters = @{scriptblock = $command }
        write-host "[*][$(Get-TimeStamp)] Gathering basic information about the host" -ForegroundColor Yellow
        if ($null -ne $ComputerName) {
            try { 
                $hostinfo2 = Invoke-Command -Session $Session @parameters -ErrorAction Stop 
                $hostinfo2 | Add-Member -NotePropertyName ComputerName -NotePropertyValue $ComputerName -ErrorAction Stop
                    
            }
            catch {
                write-host "[-][$(Get-TimeStamp)] Houston we have a problem gathering the basic info... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit
            }
            return $hostinfo2
        }
        else {
            $hostinfo1 = Get-CimInstance Win32_OperatingSystem;
            $hostinfo1 | Add-Member -NotePropertyName PowershellVersion -NotePropertyValue $PSVersionTable;
            return $hostinfo1
        }
    }
    function Get-ModuleAutoruns{
        write-host "[+][$(Get-TimeStamp)] Checking if AutoRuns modules is installed." -ForegroundColor Green
        if(Test-Path -Path "$PSScriptRoot\Collection\AutoRuns"){
            do{
                write-host "[+][$(Get-TimeStamp)] Removing previous installed version" -ForegroundColor Green
                Remove-Item -Path "$PSScriptRoot\Collection\AutoRuns" -Force -Recurse -ErrorAction Continue 
            }while (Test-Path -Path "$PSScriptRoot\Collection\AutoRuns")

            write-host "[+][$(Get-TimeStamp)] Downloading latest Autoruns Module" -ForegroundColor Green
            Save-Module -Name AutoRuns -Repository PSGallery -Path "$PSScriptRoot\Collection\"
            $AutoRunsModulesPath=Get-ChildItem -Path "$PSScriptRoot\Collection\Autoruns\" -Recurse Autoruns.psm1
            $AutoRunPS1=$($AutoRunsModulesPath.DirectoryName) + "\AutoRuns.ps1"
            copy-item $AutoRunsModulesPath.FullName -Destination $AutoRunPS1
            if(Test-Path -Path "$PSScriptRoot\Collection\AutoRuns"){
                write-host "[+][$(Get-TimeStamp)] Autoruns Downloaded" -ForegroundColor Green
            }
        }
        else{
            write-host "[+][$(Get-TimeStamp)] Downloading latest Autoruns Module" -ForegroundColor Green
            Save-Module -Name AutoRuns -Repository PSGallery -Path "$PSScriptRoot\Collection\"
        }
    }
    function Get-ModulePowerForensicsv2{
        write-host "[+][$(Get-TimeStamp)] Checking if PowerForensicsv2 modules is installed." -ForegroundColor Green
        if(Test-Path -Path "$PSScriptRoot\Collection\PowerForensicsv2"){
            do{
                write-host "[+][$(Get-TimeStamp)] Removing previous installed version" -ForegroundColor Green
                Remove-Item -Path "$PSScriptRoot\Collection\PowerForensicsv2" -Force -Recurse -ErrorAction Continue 
            }while (Test-Path -Path "$PSScriptRoot\Collection\PowerForensicsv2")

            write-host "[+][$(Get-TimeStamp)] Downloading latest PowerForensicsv2 Module" -ForegroundColor Green
            Save-Module -Name PowerForensicsv2 -Repository PSGallery -Path "$PSScriptRoot\Collection\"
            #$PowerForensicsv2ModulesPath=Get-ChildItem -Path "$PSScriptRoot\Collection\PowerForensicsv2\" -Recurse Autoruns.psm1
            #$AutoRunPS1=$($PowerForensicsv2ModulesPath.DirectoryName) + "\AutoRuns.ps1"
            #copy-item $PowerForensicsv2ModulesPath.FullName -Destination $AutoRunPS1
            if(Test-Path -Path "$PSScriptRoot\Collection\PowerForensicsv2"){
                write-host "[+][$(Get-TimeStamp)] PowerForensicsv2 Downloaded" -ForegroundColor Green
            }
        }
        else{
            write-host "[+][$(Get-TimeStamp)] Downloading latest PowerForensicsv2 Module" -ForegroundColor Green
            Save-Module -Name PowerForensicsv2 -Repository PSGallery -Path "$PSScriptRoot\Collection\"
        }
    }
    function Get-CleanedUp{
        if ($UseCreds) {
            foreach ($computer in $ComputerName) {
                write-host "[*][$(Get-TimeStamp)] Initiating Powershell clean up sessions with password" -ForegroundColor Yellow
                $sessionName = "SIR" + $counter
                $cleanupsessions += New-PSSession $computer -Credential $creds -Name $sessionName -ErrorAction Stop
                $counter++
            }
        }
        elseif ($UseSessions) {
            write-host "[*][$(Get-TimeStamp)] Not supported, please remove C:\Windows\Temp\PowerForensicsv2.dll mannually" -ForegroundColor Yellow
        }
        else {
            write-host "[*][$(Get-TimeStamp)] Initiating Powershell clean up sessions with existing powershell console privileges" -ForegroundColor Yellow
            foreach ($computer in $ComputerName) {
                $sessionName = "SIR" + $counter
                $cleanupsessions += New-PSSession $computer -Name $sessionName -ErrorAction Stop
                $counter++
            }
        }
        Start-Sleep -Seconds 10
        Invoke-Command -Session $cleanupsessions -ScriptBlock { $RemoteForensicsv2Path = "C:\Windows\Temp\PowerForensicsv2.dll"; Remove-Item -Force -Path  $RemoteForensicsv2Path -ErrorAction Continue; if( $(Test-Path $RemoteForensicsv2Path) -eq $false ){ function Get-TimeStamp { get-date -Format "MM/dd/yyyy HH:mm:ss K" }; write-host "[*][$(Get-TimeStamp)] DLL Removed" -ForegroundColor Yellow}} | Out-Null
        write-host "[*][$(Get-TimeStamp)] Removing clean up PSsessions" -ForegroundColor Yellow
        Remove-PSSession -Session $cleanupsessions
    }
}
process {
    #Collecting credentials if necessary
    if ($usecreds) {
        $creds = Get-Credential
    }

    #Initiating session if not local
    #Needs to be done on multiple sessions:

    if ($null -ne $ComputerName) {
        $sessions = @()
        #checking number of sessions named SIR to name the next session correctly.
        $sessionoffset = ((Get-PSSession | Where-Object { $_.Name -match "SIR" } | Where-Object { $_.State -eq "Opened" } ).Name -replace "SIR", "")
        $sessionoffsetnumber = ($sessionoffset  | Measure-Object -Maximum ).Maximum + 1
        $counter = $sessionoffsetnumber
        try {
            if ($usecreds) {
                foreach ($computer in $ComputerName) {
                    write-host "[*][$(Get-TimeStamp)] Initiating Powershell sessions with password" -ForegroundColor Yellow
                    $sessionName = "SIR" + $counter
                    $sessions += New-PSSession $computer -Credential $creds -Name $sessionName -ErrorAction Stop 
                    $counter++
                }
            }
            elseif ($usesessions) {
                write-host "[*][$(Get-TimeStamp)] Initiating Powershell sessions with existing sessions" -ForegroundColor Yellow
                foreach ($computer in $ComputerName) {
                    $sessions += Get-PSSession | Where-Object { $_.Name -match "SIR" } | Where-Object { $_.State -eq "Opened" } | Where-Object { $_.ComputerName -eq $computer } | Sort-Object -Property ComputerName -Unique
                }
            }
            else {
                write-host "[*][$(Get-TimeStamp)] Initiating Powershell sessions with existing powershell console privileges" -ForegroundColor Yellow
                foreach ($computer in $ComputerName) {
                    $sessionName = "SIR" + $counter
                    $sessions += New-PSSession $computer -Name $sessionName -ErrorAction Stop
                    $counter++
                }
            }
        }
        catch {
            Write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-SIR - Starting sessions..." -ForegroundColor Red
            Write-host $_ -ForegroundColor Red
            exit 
        }
    }

    #Getting basic info
    $hostsinfo = @()
    if ($null -ne $ComputerName) {
        try {
            foreach ($session in $sessions) {
                $hostsinfo += get-basicinfo -ComputerName $ComputerName -Session $session -ErrorAction Stop
            }
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-SIR - getting basic info... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            exit
        }
    }
    elseif($null -eq $DownloadLatestThirdPartyModules) {
        try {
            $hostsinfo = get-basicinfo -ErrorAction Stop
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-SIR - getting basic info... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            exit
        }
    }

    foreach ($hostinfo in $hostsinfo) {
        write-host "[+][$(Get-TimeStamp)] Basic information gathered Host: " $hostinfo.CSName ", OS Version: " $hostinfo.Version ", Arch: " $hostinfo.OSArchitecture " PS version: "  $hostinfo.PowershellVersion.PSVersion -ForegroundColor Green
    }
    
    #Call IR phase
    if ($null -ne $ComputerName) {
        if ($Collection) {
            write-host "[+][$(Get-TimeStamp)] Starting Collection" -ForegroundColor Green
            if($(Test-Path $CollectionOutputPath) -eq $false){New-Item -ItemType Directory -Force -Path $CollectionOutputPath | Out-Null}
            try {
                Remove-Module -Name Invoke-InformationGathering -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-InformationGathering.ps1" 
                Invoke-InformationGathering -InformationGatheringType $CollectionType -OutputPath $CollectionOutputPath -ComputerInfo $hostsinfo -Session $sessions -InformationLevel $InformationLevel -FilesCollectionLevel $FilesCollectionLevel
                write-host "[*][$(Get-TimeStamp)] Removing existent PSsessions" -ForegroundColor Yellow
                Remove-PSSession -Session $sessions
                #After collection I needed to remove the powershell forensic DLL from the remote hosts, as there I am not aware on how to 
                #write-host "[*][$(Get-TimeStamp)] Cleaning up collection files (PowershellForensic DLL)" -ForegroundColor Yellow
                if ($InformationLevel -eq "Detailed"){ Get-CleanedUp }                
            }
            catch {
                write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-SIR - Collection... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        if ($Containment) {
            foreach ($session in $sessions) {
                write-host "[+][$(Get-TimeStamp)] Starting Containment" -ForegroundColor Green
                try {
                    Remove-Module -Name Invoke-Containment -ErrorAction SilentlyContinue
                    Import-Module -Name "$PSScriptRoot\Invoke-Containment.ps1"
                    Invoke-Containment -ContainmentType $ContainmentType -ComputerInfo $hostinfo -Session $session
                }
                catch {
                    write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-SIR - Containment... " -ForegroundColor Red
                    Write-Host $_ -ForegroundColor Red
                }
            }
        }
        if ($Remediation) {
            write-host "Starting Remediation"
        }
        
    }
    else {
        if ($Collection) {
            write-host "[+][$(Get-TimeStamp)] Starting Collection" -ForegroundColor Green
            if($(Test-Path $CollectionOutputPath) -eq $false){New-Item -ItemType Directory -Force -Path $CollectionOutputPath | Out-Null}
            try {
                Remove-Module -Name Invoke-InformationGathering -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-InformationGathering.ps1" 
                Invoke-InformationGathering -InformationGatheringType $CollectionType -ComputerInfo $hostsinfo -LocalHost -OutputPath $CollectionOutputPath -InformationLevel $InformationLevel -FilesCollectionLevel $FilesCollectionLevel
            }
            catch {
                write-host "[-] Houston we have a problem in Invoke-SIR - Collection..." -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        if ($Containment) {
            write-host "[+][$(Get-TimeStamp)] Starting Containment" -ForegroundColor Green
            try {
                Remove-Module -Name Invoke-Containment -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-Containment.ps1" 
                Invoke-Containment -ContainmentType $ContainmentType -ComputerInfo $hostsinfo -LocalHost
            }
            catch {
                write-host "[-][$(Get-TimeStamp)]  Houston we have a problem in Invoke-SIR - Containment... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        if ($Remediation) {
            write-host "Starting Remediation"
        }
    }

    if ($DownloadLatestThirdPartyModules){
        try {
            Get-ModuleAutoruns
            Get-ModulePowerForensicsv2
        }
        catch {
            write-host "[-] Houston we have a problem in UpdateThirdPartyModules..." -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            
        }
        
    }
    Stop-Transcript
}