<#Invoke-InformationGathering
This module will have all functions to 
    Disk:
    1 - Collect windows logs from winevt.
    2 - Check IIS instalation paths and collect logs.
    3 - Services Runing
    4 - List of processs (process tree and command lines and path of the image)
    5 - Ports open with repectives process
    6 - Registry (startup locations)
    7 - Firewall rules/Firewall logs
    8 - Enumerate local users
    9 - DNS Cache
    10 - User Sessions.
    11 - Collect Number of hashed passwords cached allowed in lsass. 
    12 - System Time and Date
    13 - Operational system version info.
    14 - Drives Info.
    15 - Task schedules.
    16 - Network interface details
    17 - Routing Table
    18 - 
#>

function Get-TimeStamp
{
    get-date -Format "MM/dd/yyyy HH:mm:ss K"
}

function Invoke-DiskInformationGathering
{
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]    
        $ComputerName,

        [Parameter()]
        [switch]
        $Localhost,

        [Parameter()]
        [String]
        $OutputPath,

        [Parameter()]
        [Object]
        $Session
        )
    $ErrorActionPreference = "stop"
    $psdrivefreespace={
        $drivesfreespace1=(Get-PSDrive |Where-Object {$_.Provider -match "FileSystem"})
        return $drivesfreespace1
    }
    $psdrivefreespaceparameter=@{scriptblock = $psdrivefreespace}

    try
    {
        write-host "[*][$(Get-TimeStamp)] Inittiating disk information Gathering" -ForegroundColor Yellow
        Remove-Module -Name Invoke-WindowsEventsCollectionMetadata -ErrorAction SilentlyContinue
        Import-Module -Name "$PSScriptRoot\Collection\Invoke-WindowsEventsCollectionMetadata.ps1"
        if($Localhost)
        {
            $formatedlogsize=Invoke-WindowsEventsCollectionMetadata -LocalHost -OutputPath $OutputPath
            $drivesfreespace=Invoke-Command @psdrivefreespaceparameter
            foreach ($drive in $drivesfreespace)
            {
                $drivefreespace='{0,7:N2}' -f ($drive.Free / 1MB)
                if($drive.Free -gt $formatedlogsize)
                {
                    Write-Host "[+][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is enough space to copy" -ForegroundColor Green
                }
                else
                {
                    Write-Host "[-][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is not enough space to copy" -ForegroundColor Red
                    Write-Host "Free space and try again"
                    break
                }
                
            }
        }
        else 
        {
            foreach($singlesession in $session)
            {
                $logsize=Invoke-WindowsEventsCollectionMetadata -Session $singlesession -OutputPath $OutputPath
                $logstotalsize = $logstotalsize+$logsize
            }

            $drivesfreespace=Invoke-Command @psdrivefreespaceparameter 
            $formatedlogsize='{0,7:N2}' -f $logstotalsize
            Write-Host "[+][$(Get-TimeStamp)] Total log size: $formatedlogsize MB" -ForegroundColor Green
            foreach ($drive in $drivesfreespace)
            {
                $drivefreespace='{0,7:N2}' -f ($drive.Free / 1MB)
                if($drive.Free -gt $logstotalsize)
                {
                    Write-Host "[+][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is enough space to copy" -ForegroundColor Green
                }
                else
                {
                    Write-Host "[-][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is not enough space to copy" -ForegroundColor Red
                    Write-Host "Free space and try again"
                    break
                }
            }
        }
    }
    catch
    {
        write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
    }
}


function Invoke-MemoryInformationGathering
{
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]    
        $ComputerName,

        [Parameter()]
        [switch]
        $Localhost,

        [Parameter()]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
        )

    write-host "Memory information Gathering"
        

}

function Invoke-InformationGathering
{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $InformationGatheringType,

        [Parameter()]
        [Object]
        $ComputerInfo,

        [Parameter()]
        [switch]
        $LocalHost,

        [Parameter()]
        [String]
        $OutputPath,

        [Parameter()]
        [Object]
        $Session
    )
    begin{
        <#$psdrivefreespace={
            $drivesfreespace1=(Get-PSDrive |Where-Object {$_.Provider -match "FileSystem"})
            return $drivesfreespace1
        }
        $psdrivefreespaceparameter=@{scriptblock = $psdrivefreespace}#>

    }
    Process
    {
        try
        {
            if($LocalHost)
            {
                if($InformationGatheringType -eq "Disk")
                { 
                    Invoke-DiskInformationGathering -LocalHost -OutputPath $OutputPath
                }
                elseif($InformationGatheringType -eq "Memory")
                { 
                    Invoke-MemoryInformationGathering -LocalHost -OutputPath $OutputPath
                }
                else 
                {
                    write-host "[-] Information Gathering type not existent or not implemented, check spelling and try again." -ForegroundColor Red
                }
            }
            else
            {
                if($InformationGatheringType -eq "Disk")
                {
                    Invoke-DiskInformationGathering -Session $session -OutputPath $OutputPath
                }
                elseif($InformationGatheringType -eq "Memory")
                { 
                    Invoke-MemoryInformationGathering -ComputerName $ComputerInfo.ComputerName -Session $Session -OutputPath $OutputPath
                }
                else 
                {
                    write-host "[-][$(Get-TimeStamp)] Information Gathering type  not existent or not implemented, check spelling and try again." -ForegroundColor Red
                }
            }
        }
        catch
        {
            write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }
}