$logparser = "c:\program files (x86)\Log Parser 2.2\logparser.exe"


$files=Get-ChildItem "C:\Users\ferna\Downloads\WiriOil-WOSLServer-Event-Logs\Logs"
foreach ($file in $files)
    {
        $query = "SELECT * INTO C:\Users\ferna\Desktop\Logs\WinLogs\WOSLServer\" + $file.Name +  ".csv FROM "+ $file.FullName
        $query
        & $logparser -i:evt -o:csv $query
    }



$logparser = "c:\program files (x86)\Log Parser 2.2\logparser.exe"


$files=Get-ChildItem "C:\Users\ferna\Downloads\WiriOil-WOSLMGT01-Event-Logs-1"
foreach ($file in $files)
    {
        $query = "SELECT * INTO C:\Users\ferna\Desktop\Logs\WinLogs\WOSLMGT01\" + $file.Name +  ".csv FROM "+ $file.FullName
        $query
        & $logparser -i:evt -o:csv $query
    }


Get-ChildItem -File -Path "C:\Users\ferna\Desktop\Logs\WinLogs\WOSLServer\" | Rename-Item -NewName { $_.Name -replace ' ','-' }



$logparser