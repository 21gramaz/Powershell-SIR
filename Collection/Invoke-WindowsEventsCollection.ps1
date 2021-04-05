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
                    }
                    $WindowsEventsMetadata += New-Object -TypeName PSObject -Property $metadata
                }
                return $WindowsEventsMetadata
            }
            $parameters=@{scriptblock = $logretentionscript}


        }
        process
        {
            try{
                if($Localhost)
                {
                    write-host "[*][$(Get-TimeStamp)] Collecting Windows Events Metadata" -ForegroundColor Yellow
                    $WEM=Invoke-Command @parameters -ErrorAction Stop 
                    $WEM | Export-Csv -Path "$PSScriptRoot\Reports\WindowsEventsMetadata.csv"
                    write-host "[+][$(Get-TimeStamp)] Windows Events Metadata saved to $PSScriptRoot\Reports\WindowsEventsMetadata.csv"  -ForegroundColor Green
                }
                else 
                {
                    Invoke-Command @parameters -ErrorAction Stop 
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