<#
This script has multiple functions related to copying artifacts from the target system to the IR system.
The following describes how each set for FilesCollectionLevel:

Disabled:
- Create a table of retention time for each evtx log

Basic:
- Create a table of retention time for each evtx log
- Copy the System, Appliacation and Security EVTX files

Medium:
- Create a table of retention time for each evtx log
- Copy all EVTX files
- Copy prefetch files
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)
- Copy Browser History (Not implmented)

Detailed:
- Create a table of retention time for each evtx log
- Copy all EVTX files
- Copy prefetch files
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)
- Copy Browser History (Not implmented)
- Copy IIS logs (Not implmented)
- Copy Exchange logs (Not implmented)
- Copy Temp Files

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
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\" -Destination "C:\Users\Public\Logs"
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
            #Invoke-Command @copywindowseventsparameters
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating Windows events copy"  -ForegroundColor Green
            Copy-Item "C:\Windows\System32\winevt\Logs\" -Destination $OutputPath -Recurse
            #Invoke-Command @removetempfolderparameters
        }
        else {
            Invoke-Command -Session $Session @copywindowseventsparameters
            Copy-Item -FromSession $Session "C:\Users\Public\Logs" -Destination $OutputPath -Recurse | Out-Null
            Invoke-Command -Session $session @removetempfolderparameters
        }
    }



}
function Invoke-WindowsPrefetchCollection{
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
        $copywindowsprefetch = {
            function Get-TimeStamp {
                get-date -Format "MM/dd/yyyy HH:mm:ss K"
            }

            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Verifying if Prefetch is enabled files copy"  -ForegroundColor Green
            $PrefetchValue=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\" -Name EnablePrefetcher | Select-Object EnablePrefetcher
            $PrefetchReg= $PrefetchValue.EnablePrefetcher
            if($PrefetchValue.EnablePrefetcher -eq 0){
                write-host "[-][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Prefetch disabled in the system EnablePrefetcher value: $PrefetchReg"  -ForegroundColor Red
            }
            else{
                Copy-Item -Recurse -Path "C:\Windows\Prefetch\" -Destination "C:\Users\Public\Logs"
            }
        }
        $copywindowsprefetchsparameters = @{scriptblock = $copywindowsprefetch }
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
            try{
                write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating Prefetch files copy"  -ForegroundColor Green
                Copy-Item -Recurse "C:\Windows\Prefetch\" -Destination $OutputPath 
            }
            catch {
                write-host "[-][$(Get-TimeStamp)] Houston we have a problem copying prefetch files... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        else {
            try{
                Invoke-Command -Session $Session @copywindowsprefetchsparameters
                Copy-Item -FromSession $Session "C:\Users\Public\Logs" -Destination $OutputPath -Recurse -ErrorAction Continue | Out-Null
                Invoke-Command -Session $session @removetempfolderparameters
            }
            catch {
                write-host "[-][$(Get-TimeStamp)] Houston we have a problem copying prefetch files... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
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
            write-host "[-] Houston we have a problem in Invoke-WindowsEventsCollectionMetadata... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
            exit           
        }
    }

}
function Invoke-BasicWindowsEventsCollection {
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

            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating Basic Windows events copy (Security/System/Appliacations)"  -ForegroundColor Green
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\" -Filter "Security*" -Destination "C:\Users\Public\Logs"
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\" -Filter "System*" -Destination "C:\Users\Public\Logs"
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\" -Filter "Application*" -Destination "C:\Users\Public\Logs"
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
            #Invoke-Command @copywindowseventsparameters
            write-host "[+][$(Get-TimeStamp)] [$env:COMPUTERNAME][*RemoteSystemTimeStamp] Initiating Basic Windows events copy (Security/System/Appliacations)"  -ForegroundColor Green
            #Copy-Item "C:\Windows\System32\winevt\Logs\" -Destination $OutputPath -Recurse
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\"  -Filter "Security*" -Destination $OutputPath
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\"  -Filter "System*" -Destination $OutputPath
            Copy-Item -Recurse -Force -Path "C:\Windows\System32\winevt\Logs\"  -Filter "Application*" -Destination $OutputPath
            #Invoke-Command @removetempfolderparameters
        }
        else {
            Invoke-Command -Session $Session @copywindowseventsparameters
            Copy-Item -FromSession $Session "C:\Users\Public\Logs" -Destination $OutputPath -Recurse | Out-Null
            Invoke-Command -Session $session @removetempfolderparameters
        }
    }



}