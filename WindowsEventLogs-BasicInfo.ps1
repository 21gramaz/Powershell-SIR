$path=Read-Host "type path:"
$logfiles=Get-ChildItem -Recurse -File -Filter *.evtx -Path $path


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
Write-Host "The logs " $logfile " has " $retention "days"

}
