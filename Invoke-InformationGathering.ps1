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
        [System.Management.Automation.Runspaces.PSSession]
        $Session
        )

    try
    {
        write-host "[*][$(Get-TimeStamp)] Inittiating disk information Gathering" -ForegroundColor Yellow
        Remove-Module -Name Invoke-WindowsEventsCollection -ErrorAction SilentlyContinue
        Import-Module -Name "$PSScriptRoot\Collection\Invoke-WindowsEventsCollection.ps1"
        if($Localhost)
        {
            Invoke-WindowsEventsCollection -LocalHost 
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
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )
    try
    {
        if($LocalHost)
        {
            if($InformationGatheringType -eq "Disk")
            { 
                Invoke-DiskInformationGathering -LocalHost
            }
            elseif($InformationGatheringType -eq "Memory")
            { 
                Invoke-MemoryInformationGathering -LocalHost
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
                Invoke-DiskInformationGathering -ComputerName $ComputerInfo.ComputerName -Session $Session
            }
            elseif($InformationGatheringType -eq "Memory")
            { 
                Invoke-MemoryInformationGathering -ComputerName $ComputerInfo.ComputerName -Session $Session 
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