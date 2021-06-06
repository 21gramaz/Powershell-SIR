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
    13 - Installed Programs
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
        $Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Basic", "Medium","Detailed")]
        [string]
        $InformationLevel,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Disabled","Basic", "Medium","Detailed")]
        [string]
        $FilesCollectionLevel
    )
    
    begin {
        $ErrorActionPreference = "stop"
        $OutputDrive = (Get-Item $OutputPath).PSDrive.Name

        function Get-RandomMD5{
            #https://gist.githubusercontent.com/benrobot/67bacea1b1bbe4eb0d9529ba2c65b2a6/raw/4f36375e8a32cc007d868199f8500a286f1ec774/HashString.ps1 changed from sha256 to md5 because of path size.
            $MD5=new-object System.Security.Cryptography.MD5CryptoServiceProvider | ForEach-Object {$_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$(Get-Date -UFormat %s)"))} | ForEach-Object {$_.ToString("x2")}
            foreach ($string in $MD5) {$randomMD5string+=$string}
            return $randomMD5string
        }
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
            }
        }
    }

    Process {
        try {
            write-host "[*][$(Get-TimeStamp)] Inittiating disk information Gathering" -ForegroundColor Yellow
            Remove-Module -Name Invoke-WindowsFilesCollection -ErrorAction SilentlyContinue
            Remove-Module -Name Get-OSdetails -ErrorAction SilentlyContinue
            Import-Module -Name "$PSScriptRoot\Collection\Invoke-WindowsFilesCollection.ps1"
            Import-Module -Name "$PSScriptRoot\Collection\Get-OSdetails.ps1"
            if ($Localhost) {
                #capturing logs metadata info: size, retention, creation date, sha256 hash.
                #$formatedlogsize = Invoke-WindowsEventsCollectionMetadata -LocalHost -OutputPath $OutputPath\$env:COMPUTERNAME
                $formatedlogsize = Invoke-WindowsEventsCollectionMetadata -LocalHost -OutputPath $OutputPath
                #confirming there is enough disk space for windows logs
                Confirm-DiskSpace -LogSize $formatedlogsize -OutputDrive $OutputDrive
                #copying files to collection path
                if($FilesCollectionLevel -eq "Disabled"){
                    write-host "[*][$(Get-TimeStamp)] File Collection Disabled" -ForegroundColor Yellow
                }
                if($FilesCollectionLevel -eq "Basic"){
                    Invoke-BasicWindowsEventsCollection -Localhost -OutputPath $OutputPath
                }
                if($FilesCollectionLevel -eq "Medium"){
                    Invoke-WindowsEventsCollection -Localhost -OutputPath $OutputPath
                    Invoke-WindowsPrefetchCollection -Localhost -OutputPath $OutputPath
                    Invoke-WindowsFirewalllogsCollection -Localhost -OutputPath $OutputPath
                }

                #gathering system information
                Get-SystemDetails -Localhost -OutputPath $OutputPath -InformationLevel $InformationLevel
            }
            else {
                #capturing logs metadata info: size, retention, creation date, sha256 hash.
                #foreach ($singlesession in $session) {
                    #$RandomMD5=Get-RandomMD5
                    #$RandomFolderPath="$($singlesession.ComputerName)" + "-" + "$RandomMD5"
                    #$logsize = Invoke-WindowsEventsCollectionMetadata -Session $singlesession -OutputPath $OutputPath\$($singlesession.ComputerName)
                    #$logsize = Invoke-WindowsEventsCollectionMetadata -Session $singlesession -OutputPath $OutputPath
                    #$logstotalsize = $logstotalsize + $logsize
                #}
                #$logsize = Invoke-WindowsEventsCollectionMetadata -Session $singlesession -OutputPath $OutputPath
                #confirming there is enough disk space
                #Confirm-DiskSpace -LogSize $logstotalsize -OutputDrive $OutputDrive
                #foreach ($singlesession in $session) {

                    if($FilesCollectionLevel -eq "Disabled"){
                        write-host "[*][$(Get-TimeStamp)] File Collection Disabled" -ForegroundColor Yellow
                    }
                    if($FilesCollectionLevel -eq "Basic"){
                        Invoke-BasicWindowsEventsCollection Session $session -OutputPath $OutputPath
                    }
                    if($FilesCollectionLevel -eq "Medium"){
                        Invoke-WindowsPrefetchCollection -Session $session -OutputPath $OutputPath
                        Invoke-WindowsEventsCollection -Session $session -OutputPath $OutputPath
                        Invoke-WindowsFirewalllogsCollection -Session $session -OutputPath $OutputPath
                    }
                    #gathering system information
                    Get-SystemDetails -Session $session -OutputPath $OutputPath -InformationLevel $InformationLevel
                #}
            }
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-DiskInformationGathering... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }
    
}


function Invoke-MemoryInformationGathering {
    param (
        [Parameter()]
        [switch]
        $Localhost,

        [Parameter()]
        [String]
        $OutputPath
    )
    begin{
        if ($OutputPath) { New-Item -ItemType Directory -Force -Path "$OutputPath\MemDump" | Out-Null }
        $winpmembin="$PSScriptRoot\Collection\WinPMem\winpmem.exe"
        $rawmemfilepath="$OutputPath\MemDump\mem.raw"
        function Get-TimeStamp {
            get-date -Format "MM/dd/yyyy HH:mm:ss K"
        }

    }
    process{
        write-host "[+][$(Get-TimeStamp)] Inittiating Memory acquisition" -ForegroundColor Green
        Invoke-Expression "& '$winpmembin' '$rawmemfilepath'"
        if($(Test-Path -Path "$rawmemfilepath" -PathType Leaf) -eq $true){
            write-host "[+][$(Get-TimeStamp)] File mem.raw has been created successfully" -ForegroundColor Green
            #$memdumphash = Get-FileHash -Algorithm SHA256 $rawmemfilepath
            #$memrawsha256=$memdumphash.Hash
            #write-host "[+][$(Get-TimeStamp)] File mem.raw sha256 is: $memrawsha256" -ForegroundColor Green
            #write-host "[+][$(Get-TimeStamp)] Exporting SHA256 value to csv file located $sha256csvpath" -ForegroundColor Green
            #$memdumphash | Export-Csv -Path $sha256csvpath
        }
        else{
            write-host "[-][$(Get-TimeStamp)] Something went wrong" -ForegroundColor Red
        }
        
    }   
    
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

        [Parameter(Mandatory = $true)]
        [ValidateSet("Basic", "Medium","Detailed")]
        [string]
        $InformationLevel,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Disabled","Basic", "Medium","Detailed")]
        [string]
        $FilesCollectionLevel,

        [Parameter()]
        [Object]
        $Session
    )
    begin {
        function Get-RandomMD5{
            #https://gist.githubusercontent.com/benrobot/67bacea1b1bbe4eb0d9529ba2c65b2a6/raw/4f36375e8a32cc007d868199f8500a286f1ec774/HashString.ps1 changed from sha256 to md5 because of path size.
            $MD5=new-object System.Security.Cryptography.MD5CryptoServiceProvider | ForEach-Object {$_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$(Get-Date -UFormat %s)"))} | ForEach-Object {$_.ToString("x2")}
            foreach ($string in $MD5) {$randomMD5string+=$string}
            return $randomMD5string
        }
        function Get-EvidenceHash{
            param(
                [Parameter()]
                [Object]
                $EvidencePath
            )
            $EvidenceHashTable=@()
            $AllEvidenceFiles = (Get-ChildItem -Recurse -Path $EvidencePath).FullName
            foreach($EvidenceFile in $AllEvidenceFiles){
                $EvidenceHashTable += Get-FileHash $EvidenceFile
            }
            return $EvidenceHashTable
        }

    }
    Process {
        try {
            if ($LocalHost) {
                $RandomMD5=Get-RandomMD5
                $RandomFolderPath="$env:COMPUTERNAME" + "-" + "$RandomMD5"
                $OutputPath="$OutputPath\$RandomFolderPath"
                if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }  
                if ($InformationGatheringType -eq "Disk") { 
                    Invoke-DiskInformationGathering -LocalHost -OutputPath $OutputPath -InformationLevel $InformationLevel -FilesCollectionLevel $FilesCollectionLevel
                }
                elseif ($InformationGatheringType -eq "Memory") { 
                    Invoke-MemoryInformationGathering -LocalHost -OutputPath $OutputPath
                }
                elseif ($InformationGatheringType -eq "All") { 
                    Invoke-MemoryInformationGathering -LocalHost -OutputPath $OutputPath
                    Invoke-DiskInformationGathering -LocalHost -OutputPath $OutputPath -InformationLevel $InformationLevel -FilesCollectionLevel $FilesCollectionLevel
                }
                else {
                    write-host "[-] Information Gathering type not existent or not implemented, check spelling and try again." -ForegroundColor Red
                }
                Write-host  "[+][$(Get-TimeStamp)] Creating evidence Hash Table." -ForegroundColor Green
                $EvidecenHashTable = Get-EvidenceHash -EvidencePath "$OutputPath"
                $EvidecenHashTable | Export-Csv -Path "$OutputPath\EvidenceHashTable.csv"
                $HashValue= (Get-FileHash -Algorithm SHA256 "$OutputPath\EvidenceHashTable.csv").Hash
                $hashtablepath="$OutputPath\EvidenceHashTable.csv"
                Write-host  "[+][$(Get-TimeStamp)] SHA256 hash for the table hash in $hashtablepath is $HashValue" -ForegroundColor Green
            }
            else {
                foreach ($singlesession in $session) {
                    $RandomMD5=Get-RandomMD5
                    $RandomFolderPath="$($singlesession.ComputerName)" + "-" + "$RandomMD5"
                    $OutputPath="$OutputPath\$RandomFolderPath"
                    if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }  
                    if ($InformationGatheringType -eq "Disk") {
                        Invoke-DiskInformationGathering -Session $singlesession -OutputPath $OutputPath -InformationLevel $InformationLevel -FilesCollectionLevel $FilesCollectionLevel
                    }
                    elseif ($InformationGatheringType -eq "Memory") { 
                        #Invoke-MemoryInformationGathering -ComputerName $ComputerInfo.ComputerName -Session $Session -OutputPath $OutputPath
                        Write-host  "[-][$(Get-TimeStamp)] Memory dump via network is not recomended." -ForegroundColor Red
                    }
                    else {
                        write-host "[-][$(Get-TimeStamp)] Information Gathering type  not existent or not implemented, check spelling and try again." -ForegroundColor Red
                    }
                }
            }
        }
        catch {
            write-host "[-][$(Get-TimeStamp)] Houston we have a problem in Invoke-InformationGathering... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }
}