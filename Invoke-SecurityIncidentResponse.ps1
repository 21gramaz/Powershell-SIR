# Executes Basic checks for the target host/hosts.
#
#[CmdletBinding(DefaultParameterSetName = "Containment")]
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
    $usecreds,

    [Parameter(ParameterSetName = "Collection")]
    [Parameter(ParameterSetName = "Contaiment")]
    [switch]
    $usesessions,

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
                write-host "[-][$(Get-TimeStamp)] Houston we had a problem gathering the basic info... " -ForegroundColor Red
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
        if ($usecreds) {
            foreach ($computer in $ComputerName) {
                write-host "[*][$(Get-TimeStamp)] Initiating Powershell clean up sessions with password" -ForegroundColor Yellow
                $sessionName = "SIR" + $counter
                $cleanupsessions += New-PSSession $computer -Credential $creds -Name $sessionName -ErrorAction Stop
                $counter++
            }
        }
        elseif ($usesessions) {
            write-host "[*][$(Get-TimeStamp)] Not supported, please remove C:\Users\Public\PowerForensicsv2.dll mannually" -ForegroundColor Yellow
        }
        else {
            write-host "[*][$(Get-TimeStamp)] Initiating Powershell clean up sessions with existing powershell console privileges" -ForegroundColor Yellow
            foreach ($computer in $ComputerName) {
                $sessionName = "SIR" + $counter
                $cleanupsessions += New-PSSession $computer -Name $sessionName -ErrorAction Stop
                $counter++
            }
        }
        Invoke-Command -Session $cleanupsessions -ScriptBlock { $RemoteForensicsv2Path = "C:\Users\Public\PowerForensicsv2.dll"; Remove-Item -Force -Path  $RemoteForensicsv2Path -ErrorAction Continue; if( $(Test-Path $RemoteForensicsv2Path) -eq $false ){ function Get-TimeStamp { get-date -Format "MM/dd/yyyy HH:mm:ss K" }; write-host "[*][$(Get-TimeStamp)] DLL Removed" -ForegroundColor Yellow}} | Out-Null
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
            Write-host "[-][$(Get-TimeStamp)]Houston we had a problem..." -ForegroundColor Red
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
            write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            exit
        }
    }
    elseif($null -eq $DownloadLatestThirdPartyModules) {
        try {
            $hostsinfo = get-basicinfo -ErrorAction Stop
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
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
            try {
                Remove-Module -Name Invoke-InformationGathering -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-InformationGathering.ps1" 
                Invoke-InformationGathering -InformationGatheringType $CollectionType -OutputPath $CollectionOutputPath -ComputerInfo $hostsinfo -Session $sessions
                write-host "[*][$(Get-TimeStamp)] Removing existent PSsessions" -ForegroundColor Yellow
                Remove-PSSession -Session $sessions
                #After collection I needed to remove the powershell forensic DLL from the remote hosts, as there I am not aware on how to 
                write-host "[*][$(Get-TimeStamp)] Cleaning up collection files (PowershellForensic DLL)" -ForegroundColor Yellow
                Get-CleanedUp
            }
            catch {
                write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
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
                    write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
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
            try {
                Remove-Module -Name Invoke-InformationGathering -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-InformationGathering.ps1" 
                Invoke-InformationGathering -InformationGatheringType $CollectionType -ComputerInfo $hostsinfo -LocalHost -OutputPath $CollectionOutputPath
            }
            catch {
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
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
                write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
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
            write-host "[-] Houston we have a problem in UpdateThirdPartyModules" -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            
        }
        
    }
    Stop-Transcript
}