<#
This script checks the retention period and copy all Windows Events to the export folder

1 - Add time logs
2 - add computer name to metadata
#>

function Invoke-WindowsEventsCollection
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

        begin
        {
            function Get-TimeStamp
            {
                get-date -Format "MM/dd/yyyy HH:mm:ss K"
            }
            
            $logretentionscript={

                $WindowsEventsMetadata=@()
                $LogFiles=Get-ChildItem -Recurse -File -Filter *.evtx -Path "$env:SystemRoot\System32\Winevt\Logs\"
                foreach ($logfile in $logfiles)
                {
                    #find out log rentention for windows logs.
                    $day=86400000
                    $retention=0
                    do{
                        $logfilepath=($logfile.FullName).ToString()
                        [xml]$xmlfilter2=@"
                        <QueryList>
                        <Query Id="0" Path="file://$logfilepath">
                            <Select Path="file://$logfilepath">*[System[TimeCreated[timediff(@SystemTime) &gt;= $day]]]</Select>
                        </Query>
                        </QueryList>
"@
                        $day+=$day
                        $retention+=1
                    }while($status=(Get-WinEvent -FilterXml $xmlfilter2 -MaxEvents 1 -ErrorAction SilentlyContinue ).Equals)
                    $status | Out-Null
                    $metadata=@{
                        LogName=$logfile.name
                        LogFullName=$logfile.FullName
                        RetentionPeriodinDays=$retention
                        CreationTime=$logfile.CreationTime
                        CreationTimeUTC=$logfile.CreationTimeUtc
                        LastWriteTime=$logfile.LastWriteTime
                        LastWriteTimeUtc=$logfile.LastWriteTimeUtc
                        LastAccessTime=$logfile.LastAccessTime
                        LastAccessTimeUtc=$logfile.LastAccessTimeUtc
                        SizeinMb='{0,7:N2}' -f ($logfile.Length / 1MB)
                        ComputerName=$env:COMPUTERNAME
                    }
                    $WindowsEventsMetadata += New-Object -TypeName PSObject -Property $metadata
                }
                return $WindowsEventsMetadata
            }
            $parameters=@{scriptblock = $logretentionscript}

            $psdrivefreespace={
                $drivesfreespace1=(Get-PSDrive |Where-Object {$_.Provider -match "FileSystem"})
                return $drivesfreespace1
            }
            $psdrivefreespaceparameter=@{scriptblock = $psdrivefreespace}

        }
        process
        {
            try{
                $logsize=0
                if($Localhost)
                {
                    write-host "[*][$(Get-TimeStamp)] Collecting Windows Events Metadata" -ForegroundColor Yellow
                    $WEM=Invoke-Command @parameters -ErrorAction Stop                     
                    $WEM | Export-Csv -Path "$PSScriptRoot\Reports\WindowsEventsMetadata.csv"
                    
                    Write-Host "[+][$(Get-TimeStamp)] Windows Events Metadata saved to $PSScriptRoot\Reports\WindowsEventsMetadata.csv"  -ForegroundColor Green
                    foreach ($file in $WEM){$logsize= $logsize+$file.SizeinMb}
                    $formatedlogsize='{0,7:N2}' -f $logsize
                    
                    Write-Host "[+][$(Get-TimeStamp)] Total Windows Events Size(Mb): $formatedlogsize"  -ForegroundColor Green
                    $drivesfreespace=Invoke-Command @psdrivefreespaceparameter
                    foreach ($drive in $drivesfreespace)
                    {
                        $drivefreespace='{0,7:N2}' -f ($drive.Free / 1MB)
                        if($drivefreespace -gt $formatedlogsize)
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
                    write-host "[*][$(Get-TimeStamp)] Collecting Windows Events Metadata" -ForegroundColor Yellow
                    $WEM=Invoke-Command -Session $Session @parameters -ErrorAction Stop 
                    $WEM | Export-Csv -Path "$PSScriptRoot\Reports\WindowsEventsMetadata-$($WEM[1].ComputerName).csv"
                    
                    write-host "[+][$(Get-TimeStamp)] Windows Events Metadata saved to $PSScriptRoot\Reports\WindowsEventsMetadata-$($WEM[1].ComputerName).csv"  -ForegroundColor Green
                    foreach ($file in $WEM){$logsize= $logsize+$file.SizeinMb}
                    $formatedlogsize='{0,7:N2}' -f $logsize
                    
                    Write-Host "[+][$(Get-TimeStamp)] Total Windows Events Size(Mb): $formatedlogsize"  -ForegroundColor Green

                    $drivesfreespace=Invoke-Command @psdrivefreespaceparameter 

                    foreach ($drive in $drivesfreespace)
                    {
                        $drivefreespace='{0,7:N2}' -f ($drive.Free / 1MB)
                        if($drivefreespace -gt $formatedlogsize)
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
                    #Write-Host "[+][$(Get-TimeStamp)] Total Windows Events Size(Mb): $formatedlogsize"  -ForegroundColor Green
                }
            }
            catch
            {
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit           
            }
        }

}