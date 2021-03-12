$parse1 = Select-String -Path "C:\Users\ferna\Downloads\TPP\Logs\IIS\logs\LogFiles\W3SVC1*.log" -Pattern 'POST /owa/auth/Current/themes/resources/'

foreach($line in $parse1){

write-host "Might want to investigate this" -ForegroundColor DarkRed
write-host $line -ForegroundColor DarkYellow


}

#checking IIS logs
write-host "Starting with IIS logs"
$iilogpath = Read-Host "path for IIS logs"
$logfiles=Get-ChildItem -Path $iilogpath -Recurse -File
write-host "this output indicates of attempt of exploit of CVE-2021-26855 it might be indication of webshell upload attempt to access mailboxes bypassing authentications"
write-host "references:https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ and https://twitter.com/jas502n/status/1368882907893223425/photo/1"
foreach ($logfile in $logfiles){
    $CVE26855 =Select-String -Path $logfile.FullName -Pattern '(POST /owa/auth/Current/themes/resources/)|(POST /ecp/)' | select-string -NotMatch '(.aspx)|(DDIService.svc)|(InboxRules.svc)|(TransportRules.svc)'| Select-String -SimpleMatch 200

}

#checking windows logs
write-host "`r`n`r`nStarting basic Windows logs checks"
$windowslogpath = Read-Host "path for windows logs"
cd $windowslogpath


write-host "`r`n`r`nthis output will tell you wether the command for webshell upload worked"
Get-WinEvent -path 'MSExchange Management.evtx' | Get-Member | Where-Object {$_.Details -match "JScript"} | select TimeCreated, Message


Get-WinEvent -FilterHashtable @{Path="$windowslogpath\MSExchange Management.evtx"}
Get-Content 'MSExchange Management.evtx '

write-host "`r`n`r`nlooking for windows defender events"
Get-WinEvent -Path '.\Microsoft-Windows-Windows Defender%4Operational.evtx' | Where-Object {$_.Id -in 1117, 5007} |select TimeCreated, Id, Message | Format-List

write-host "`r`n`r`nthis output will tell you if iis logs had been removed there was and attempt to remmove it (known techinique)"
Get-WinEvent -Path System.evtx  | Where-Object {$_.Id -in 9009}
write-host "`r`n`r`nthis output will tell you if iis had errors normally caused by exploitation)"
Get-WinEvent -Path System.evtx  | Where-Object {$_.Id -in 2303}

write-host "`r`n`r`nchecking for powershell encoded commands base64 was used during this capaign"
Get-WinEvent -Path 'Windows PowerShell.evtx' | Where-Object {$_.Message -match "(bypass -e)|(bypass -encoded)"} | select -ExpandProperty Message
Get-WinEvent -LogName "Windows PowerShell" | Where-Object {$_.Message -match "(bypass -e)|(bypass -encoded)"} | select -ExpandProperty Message


