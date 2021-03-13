<#The script is quick way to analyze IIS data#>

#"C:\Users\ferna\Downloads\TPP\Logs\IIS\logs\LogFiles\W3SVC1"
#checking IIS logs
write-host "Starting with IIS logs"
$iilogpath = Read-Host "path for IIS logs"
$logfiles=Get-ChildItem -Path $iilogpath -Recurse -Filter log

write-host "this output indicates of attempt of exploit of CVE-2021-26855 it might be indication of webshell upload attempt to access mailboxes bypassing authentications"
# references:https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ and https://twitter.com/jas502n/status/1368882907893223425/photo/1"



$iilogpath = "C:\Users\ferna\Downloads\TPP\Logs\IIS\logs\LogFiles\W3SVC1"
$logfiles=Get-ChildItem -Path $iilogpath -Recurse 
$fields=((get-content $logfiles[1].FullName | select -First 4 | sls -Pattern "Fields") -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","") -split ' '

foreach ($logfile in $logfiles){$lines=Get-content -path $logfile.FullName; $lines.count}

$completelogs=@("")*$logfiles.Count
$d=0
foreach ($logfile in $logfiles){
    $c=0
    $contentfile=get-content ($logfile).FullName
    $iislogobject=@("")*$contentfile.count
    foreach ($line in $contentfile){
        $parsedline=($line) -split ' '
            $properties = @{
                $fields[0] = $parsedline[0]
                $fields[1] = $parsedline[1]
                $fields[2] = $parsedline[2]
                $fields[3] = $parsedline[3]
                $fields[4] = $parsedline[4]
                $fields[5] = $parsedline[5]
                $fields[6] = $parsedline[6]
                $fields[7] = $parsedline[7]
            }
            $iislogobject[$c]=New-Object -TypeName PSObject -Property $properties   
            $c++
        }
        $completelogs[$d]=$iislogobject
        $d++
    }




    $log | select -First 10 | sls -Pattern '#Ver', '#Sof', '#Dat' , '#Fie' -NotMatch