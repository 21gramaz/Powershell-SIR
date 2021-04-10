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
    12 - General System info: 
            • System Time and Date
            • Operational system version info.
            • Drives Info
            • Network interface details
            • Routing Table

#>

function Invoke-DiskInformationGathering {
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
    
    begin {
        $ErrorActionPreference = "stop"
        $OutputDrive = (Get-Item $OutputPath).PSDrive.Name

        function Get-TimeStamp {
            get-date -Format "MM/dd/yyyy HH:mm:ss K"
        }

        function Confirm-DiskSpace {
            param(    
                [Parameter()]
                [String]
                $LogSize,

                [Parameter()]
                [String]
                $OutputDrive
            )
            #gets drives freespace 
            $psdrivefreespace =
            {
                $drivesfreespace1 = (Get-PSDrive | Where-Object { $_.Provider -match "FileSystem" })
                return $drivesfreespace1
            }
            $psdrivefreespaceparameter = @{scriptblock = $psdrivefreespace }

            $drivesfreespace = Invoke-Command @psdrivefreespaceparameter
            $formatedlogsize = '{0,7:N2}' -f $LogSize
            Write-Host "[+][$(Get-TimeStamp)] Total log size: $formatedlogsize MB" -ForegroundColor Green
            
            #Checks if the path provided 
            foreach ($drive in $drivesfreespace) {
                if ($drive.Name -eq $OutputDrive) {
                    $drivefreespace = '{0,7:N2}' -f ($drive.Free / 1MB)
                    if ($drive.Free -gt $LogSize) {
                        Write-Host "[+][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is enough space to copy" -ForegroundColor Green
                    }
                    else {
                        Write-Host "[-][$(Get-TimeStamp)] Drive $drive has $drivefreespace Mb, there is not enough space to copy" -ForegroundColor Red
                        Write-Host "Free space and try again"
                        break
                    }
                }
                <#If the script cant confirm the the drive space
                #never have tested this case:
                else{
                    do{
                        $copyconfirmation=Read-Host "[*][$(Get-TimeStamp)] Could not check drive space to copy logs do you wish to continue?(Yes|No)" -ForegroundColor Yellow
                        if ($copyconfirmation -eq "Yes"){
                            Write-host "Copying Files"
                        }
                        else{
                            Write-host "Stopping Script"
                            break
                        }
                    }while(($copyconfirmation -ne "Yes") -and ($copyconfirmation -ne "No")) 
                }#>
            }
        }
    }

    Process {
        try {
            write-host "[*][$(Get-TimeStamp)] Inittiating disk information Gathering" -ForegroundColor Yellow
            Remove-Module -Name Invoke-WindowsEventsCollection -ErrorAction SilentlyContinue
            Import-Module -Name "$PSScriptRoot\Collection\Invoke-WindowsEventsCollection.ps1"
            if ($Localhost) {
                #capturing logs metadata info: size, retention, creation date, sha256 hash.
                $formatedlogsize = Invoke-WindowsEventsCollectionMetadata -LocalHost -OutputPath $OutputPath
                #confirming there is enough disk space for windows logs
                Confirm-DiskSpace -LogSize $formatedlogsize -OutputDrive $OutputDrive
                #copying files to collection path
                Invoke-WindowsEventsCollection -Localhost -OutputPath 
            }
            else {
                #capturing logs metadata info: size, retention, creation date, sha256 hash.
                foreach ($singlesession in $session) {
                    $logsize = Invoke-WindowsEventsCollectionMetadata -Session $singlesession -OutputPath $OutputPath\$($singlesession.ComputerName)
                    $logstotalsize = $logstotalsize + $logsize
                }
                #confirming there is enough disk space
                Confirm-DiskSpace -LogSize $logstotalsize -OutputDrive $OutputDrive
                foreach ($singlesession in $session) {
                    Invoke-WindowsEventsCollection -Session $singlesession -OutputPath $OutputPath\$($singlesession.ComputerName)
                }
            }
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }
    
}


function Invoke-MemoryInformationGathering {
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

function Invoke-InformationGathering {
    param(
        [Parameter(Mandatory = $true)]
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
    begin {

    }
    Process {
        try {
            if ($LocalHost) {
                if ($InformationGatheringType -eq "Disk") { 
                    Invoke-DiskInformationGathering -LocalHost -OutputPath $OutputPath
                }
                elseif ($InformationGatheringType -eq "Memory") { 
                    Invoke-MemoryInformationGathering -LocalHost -OutputPath $OutputPath
                }
                else {
                    write-host "[-] Information Gathering type not existent or not implemented, check spelling and try again." -ForegroundColor Red
                }
            }
            else {
                if ($InformationGatheringType -eq "Disk") {
                    Invoke-DiskInformationGathering -Session $session -OutputPath $OutputPath
                }
                elseif ($InformationGatheringType -eq "Memory") { 
                    Invoke-MemoryInformationGathering -ComputerName $ComputerInfo.ComputerName -Session $Session -OutputPath $OutputPath
                }
                else {
                    write-host "[-][$(Get-TimeStamp)] Information Gathering type  not existent or not implemented, check spelling and try again." -ForegroundColor Red
                }
            }
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }
}