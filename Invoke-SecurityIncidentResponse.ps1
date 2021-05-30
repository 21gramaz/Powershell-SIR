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
            write-host "[+][$(Get-TimeStamp)] Downloading latest Autoruns Module" -ForegroundColor Green
            Save-Module -Name AutoRuns -Repository PSGallery -Path "$PSScriptRoot\Collection\"
            $AutoRunsModulesPath=Get-ChildItem -Path "$PSScriptRoot\Collection\Autoruns\" -Recurse Autoruns.psm1
            $AutoRunPS1=$($AutoRunsModulesPath.DirectoryName) + "\AutoRuns.ps1"
            copy-item $AutoRunsModulesPath.FullName -Destination $AutoRunPS1
            if("$PSScriptRoot\Collection\AutoRuns"){
                write-host "[+][$(Get-TimeStamp)] Autoruns Downloaded" -ForegroundColor Green
            }
        }
        catch {
            write-host "[-] Houston we have a problem in UpdateThirdPartyModules" -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            
        }
        
    }
    Stop-Transcript
}