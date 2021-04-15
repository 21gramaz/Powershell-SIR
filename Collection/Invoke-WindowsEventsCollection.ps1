<#
This script checks the retention period and copy all Windows Events to the export folder

1 - Add time logs
2 - add computer name to metadata
#>
function Get-TimeStamp {
    get-date -Format "MM/dd/yyyy HH:mm:ss K"
}

function Invoke-WindowsEventsCollection {
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
        $copywindowsevents = {
            function Get-TimeStamp {
                get-date -Format "MM/dd/yyyy HH:mm:ss K"
            }

            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating Windows events copy"  -ForegroundColor Green
            Copy-Item -Recurse -Path "C:\Windows\System32\winevt\Logs\" -Destination "C:\Users\Public\Logs"
        }
        $copywindowseventsparameters = @{scriptblock = $copywindowsevents }
        $removetempfolder = {
            function Get-TimeStamp {
                get-date -Format "MM/dd/yyyy HH:mm:ss K"
            }

            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Removing temp folder"  -ForegroundColor Green
            Remove-Item -Recurse -Force -Path "C:\Users\Public\Logs"
        }
        $removetempfolderparameters = @{scriptblock = $removetempfolder }

    }
    process {
        if ($Localhost) {
            Invoke-Command @copywindowseventsparameters
            Copy-Item "C:\Windows\System32\winevt\Logs\" -Destination $OutputPath -Recurse
            Invoke-Command @removetempfolderparameters
        }
        else {
            Invoke-Command -Session $Session @copywindowseventsparameters
            Copy-Item -FromSession $Session "C:\Users\Public\Logs" -Destination $OutputPath -Recurse | Out-Null
            Invoke-Command -Session $session @removetempfolderparameters
        }
    }



}
function Invoke-WindowsEventsCollectionMetadata {
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
        $logretentionscript = {
            function Get-TimeStamp {
                get-date -Format "MM/dd/yyyy HH:mm:ss K"
            }
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating metadata logs calculation"  -ForegroundColor Green
            $WindowsEventsMetadata = @()
            $LogFiles = Get-ChildItem -Recurse -File -Filter *.evtx -Path "$env:SystemRoot\System32\Winevt\Logs\"
            foreach ($logfile in $logfiles) {
                #find out log rentention for windows logs.
                $day = 86400000
                $retention = 0
                do {
                    $logfilepath = ($logfile.FullName).ToString()
                    [xml]$xmlfilter2 = @"
                        <QueryList>
                        <Query Id="0" Path="file://$logfilepath">
                            <Select Path="file://$logfilepath">*[System[TimeCreated[timediff(@SystemTime) &gt;= $day]]]</Select>
                        </Query>
                        </QueryList>
"@
                    $day += $day
                    $retention += 1
                }while ($status = (Get-WinEvent -FilterXml $xmlfilter2 -MaxEvents 1 -ErrorAction SilentlyContinue ).Equals)
                $status | Out-Null
                $metadata = @{
                    LogName               = $logfile.name
                    LogFullName           = $logfile.FullName
                    RetentionPeriodinDays = $retention
                    CreationTime          = $logfile.CreationTime
                    CreationTimeUTC       = $logfile.CreationTimeUtc
                    LastWriteTime         = $logfile.LastWriteTime
                    LastWriteTimeUtc      = $logfile.LastWriteTimeUtc
                    LastAccessTime        = $logfile.LastAccessTime
                    LastAccessTimeUtc     = $logfile.LastAccessTimeUtc
                    SizeinMb              = '{0,7:N2}' -f ($logfile.Length / 1MB)
                    ComputerName          = $env:COMPUTERNAME
                }
                $WindowsEventsMetadata += New-Object -TypeName PSObject -Property $metadata
            }
            return $WindowsEventsMetadata
        }
        $parameters = @{scriptblock = $logretentionscript }
    }
    process {
        try {
            $logsize = 0
            if ($Localhost) {
                write-host "[*][$(Get-TimeStamp)] Collecting Windows Events Metadata" -ForegroundColor Yellow
                $WEM = Invoke-Command @parameters -ErrorAction Stop 
                #creates folder for the session Computer Name
                if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }                     
                $WEM | Export-Csv -Path "$OutputPath\WindowsEventsMetadata.csv"
                    
                Write-Host "[+][$(Get-TimeStamp)] Windows Events Metadata saved to $OutputPath\WindowsEventsMetadata.csv"  -ForegroundColor Green
                foreach ($file in $WEM) { $logsize = $logsize + $file.SizeinMb }
                $formatedlogsize = '{0,7:N2}' -f $logsize
                    
                Write-Host "[+][$(Get-TimeStamp)] Total Windows Events Size(Mb): $formatedlogsize"  -ForegroundColor Green
                return $formatedlogsize               
            }
            else {
                write-host "[*][$(Get-TimeStamp)] Collecting Windows Events Metadata" -ForegroundColor Yellow
                $WEM = Invoke-Command -Session $Session @parameters -ErrorAction Stop  
                #creates folder for the session Computer Name
                if ($OutputPath) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null } 
                $WEM | Export-Csv -Path "$OutputPath\WindowsEventsMetadata-$($WEM[1].ComputerName).csv"
                    
                write-host "[+][$(Get-TimeStamp)] [$($WEM[1].ComputerName)] Windows Events Metadata saved to $OutputPath\WindowsEventsMetadata-$($WEM[1].ComputerName).csv"  -ForegroundColor Green
                foreach ($file in $WEM) { $logsize = $logsize + $file.SizeinMb }
                $formatedlogsize = '{0,7:N2}' -f $logsize
                Write-Host "[+][$(Get-TimeStamp)] [$($WEM[1].ComputerName)] Total Windows Events Size(Mb): $formatedlogsize"  -ForegroundColor Green
                return $logsize
            }
        }
        catch {
            write-host "[-] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            exit           
        }
    }

}