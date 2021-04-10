<#
.SYNOPSIS
Connect the target computer and execute some basic checks to verify any abnormally.

.EXAMPLE

  "./checkhost.ps1 -host hostname -username txxxxxx"
#>

Param (
    [Parameter(Mandatory = $True)]
    [Alias('host')]
    [string]$hostname,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('user')]
    [string]$username,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('rest')]
    [string]$restofchecks,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('browser')]
    [string]$allchecks,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('samples')]
    [string]$retrievesamples,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('scan')]
    [string]$startscan,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('scanstatus')]
    [string]$scanstat,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('networkblock')]
    [string]$networkoutboundblock,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('networkunblock')]
    [string]$networkoutboundunblock,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Alias('windowslogs')]
    [string]$windowslog
)
#powershell.exe -ExecutionPolicy Bypass -Command "



Begin {
    $localuser = ($env:UserName).Substring(0, 7)


    Write-Output "Starting verification job"
    Write-Output "Checking if the host is online"

    $icmp = ping $hostname -n 1

    if ($icmp -Match "timed out") { Write-Output "We could not ping the host" }

    else {
        Write-Output "Ping Okay!"
        Write-Output "Opening WinRM session"
        
        try { $session = New-PSSession $hostname -ErrorAction Stop }
        catch {
            $ErrorMessage = $_.Exception.Message; 
            $FailedItem = $_.Exception.ItemName; 
            Write-Output "Houston we have a problem:"; 
            Write-Output $ErrorMessage; 
            break 
        }

        finally {
            Write-Output "Session opened"
        }
    }

}

Process {
    $day1 = ((date).Day).ToString() + '-' + ((date).Month).ToString() + '-' + ((date).Year).ToString()
    
    
    #Creating a folder is there is no folder in that day
    if ('$env:USERPROFILE\Documents\Hostcheck\$day1\$hostname') {
        New-Item -ItemType Directory -Force -Path C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname | Out-Null
    }
    #Checking Windows Version
    $windows_version = Invoke-Command -Session $session -ScriptBlock { [System.Environment]::OSVersion.Version.Major }
    Invoke-Command -Session $session -ScriptBlock { $users = (Get-ChildItem C:\Users\).Name | sls -Pattern '^t\d{6}$'; }

    switch ($windows_version) {
        10 { write-host "Windows 10 identified" }
        6 { write-host "Windows 7 identified" }
    }
    


    function retrievesamples {
        Param (
            [Parameter(Mandatory = $True)]
            [Alias('OS')]
            [string]$win_ver)


        switch ($win_ver) { #copy files from win10 folder
            10 {
                write-host "Initiating copy of samples"
                try { Copy-Item -FromSession $session "C:\ProgramData\Microsoft\Windows Defender\Quarantine\" -Destination "C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\" -Recurse }
                catch {
                    $ErrorMessage = $_.Exception.Message; 
                    $FailedItem = $_.Exception.ItemName; 
                    Write-Output "Houston we have a problem:"; 
                    Write-Output $ErrorMessage; 
                    break 
                }
                Write-Output "Copy done!";
            }
            6 {
     
                write-host "Initiating copy of samples"
                try { Copy-Item -FromSession $session "C:\ProgramData\Microsoft\Microsoft Antimalware\Quarantine\" -Destination "C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\"  -Recurse }
                catch {
                    $ErrorMessage = $_.Exception.Message; 
                    $FailedItem = $_.Exception.ItemName; 
                    Write-Output "Houston we have a problem:"; 
                    Write-Output $ErrorMessage; 
                    break 
                }
                Write-Output "Copy done!";
            }
        }   

    }


    function status {
        $scanstat =
        {
            Get-WinEvent -ProviderName 'Microsoft-Windows-Windows Defender' -MaxEvents 100 | Where-Object { $_.Id -clike "100*" } | Format-List
            write-host "Last threat detected:"
            Get-MpThreatDetection
        }
        Write-Output "Scan Status:"
        Invoke-Command -Session $session -ScriptBlock $scanstat 
    }

    function restofchecks {      
        $script =
        {
            #Retrieving system informations
            $system = systeminfo; 
            write-output $system | select -First 12;
            $usernamenotparsed = (gwmi Win32_LoggedOnUser).Antecedent | select -Unique | sls -Pattern 't\d{6}"$';
            $username = Select-String -Pattern '(?<=.",Name=""*).*?(?=".*)' -InputObject $usernamenotparsed | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[0].Value } | % { $_ -replace '"' }
            Write-Output "`r`n`r`nUsers found:(Just common users Txxxxxx)" 
            Write-Output $username 

            #retrieving Chrome externsions
            Write-Output "`r`n`r`nChrome extensions"
            $chromext = (Get-ChildItem "C:\Users\$username\AppData\Local\Google\Chrome\User Data\Default\Extensions\").Name ;
            Write-Output $chromext

            #retrieving Firefox externsions
            Write-Output "`r`n`r`nFirefox extensions"
            $jsonfile = get-content(Get-ChildItem -Path C:\Users\$username\AppData\Roaming\Mozilla\Firefox\Profiles\ -Include addons.json -Recurse -Force -ErrorAction SilentlyContinue)
            $extnamerex = '((?<=.,"name":""*).*?(?=","type".*))'
            #$extdescriptionrex='((?<=.,"description":""*).*?(?=","fullDescription".*))'
            $extname = Select-String -Pattern $extnamerex -InputObject $jsonfile -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value }
            #$extdescription = Select-String -Pattern $extdescriptionrex -InputObject $jsonfile -AllMatches | ForEach-Object {$_.Matches} | ForEach-Object {$_.Groups[1].Value}
            $extname


        
            #checking AutoRun Registry
            $privilegedrunonce = Get-ItemProperty -path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
            $privilegedrun = Get-ItemProperty -path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
            $unprivilegedrunonce = Get-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
            $unprivilegedrun = Get-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
            Write-Output "`r`n`r`nPrivileged RunOnce"
            $privilegedrunonce
            Write-Output "`r`n`r`nPrivileged Run"
            $privilegedrun
            Write-Output "`r`n`r`nUnprivileged RunOnce"
            $unprivilegedrunonce
            Write-Output "`r`n`r`nUnprivileged Run"
            $unprivilegedrun

            #check start up folder
            $startupfolder = Get-ChildItem "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            Write-Output "`r`n`r`nStartup folder Content"
            $startupfolder
        

            if ($system | select -First 3 | select -Skip 2 | sls -Pattern 'Microsoft Windows 10 Enterprise') {
                #retrieving last powershell console logs
                Write-Output "`r`n`r`nPowershell console logs"
                $powershelllogs2 = Get-Content "C:\Users\$username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
                $powershelllogs2
        
                #retrieving non microsoft related scheduled tasks
                Write-Output "`r`n`r`nNon Microsoft Scheduled tasks"
                Get-ScheduledTask | Select-Object Author, URI, TaskName, Description, State | Where-Object { $_.Author -notlike '*microsoft*' } | Where-Object { $_.URI -notlike '*microsoft*' } | fl
        
                #retrieving non microsoft related scheduled tasks
                Write-Output "`r`n`r`nAll executable in task scheduler"
                ((Get-ScheduledTask).Actions).Execute

                #retrieving AV info
                Write-Output "`r`n`r`nWindows Defender logs"
                Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, NISEnabled, FullScanStartTime, FullScanEndTime, AntivirusSignatureLastUpdated

                #retrieving Last threats detected
                Write-Output "`r`n`r`nLast Threats detected"
                Get-MpThreat | Select-Object IsActive, Resources, ThreatID, ThreatName | fl



            }
            else { write-host "Windows 7 does not log console command lines" }
        
            #retrieving last powershell executions 
            Write-Output "`r`n`r`nPowershell execution logs"
            (Get-EventLog -LogName 'Windows PowerShell' -Newest 3000 | Where-Object { $_.InstanceID -eq '800' -or '600' } ).Message  | sls -Pattern 'wsmprovhost.exe' -NotMatch | sls -Pattern '\\CCM\\SystemTemp' -NotMatch | % { $_ -split '\n' } |  sls -Pattern '(HostApplication)|(CommandLine)'
        

        }
        Write-Output "Initializing all checks"
        Write-Output "Dumping all info to C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\report.txt"
        Invoke-Command -Session $session -ScriptBlock $script >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\report.txt        
    } 

    function retrievewindowslogs {
        write-host "Size of WinEvent Logs(Mb):"
        Invoke-Command -Session $session -ScriptBlock { ((Get-ChildItem 'C:\Windows\System32\winevt\Logs' -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB) }
        write-host "Copying items to C:\Users\Public\tmp in the remote computer"
        Invoke-Command -Session $session -ScriptBlock { copy-item -Recurse -Path "C:\Windows\System32\winevt\Logs\" -Destination "C:\Users\Public\tmp" } 
        write-host "Starting compression"
        Invoke-Command -Session $session -ScriptBlock { set-location 'C:\Users\Public\tmp'; start-process -filepath 'C:\Program Files\7-Zip\7z.exe' -ArgumentList '-mx5 -r -pinfected a windowslogs.7z' }
        start-sleep -seconds 20
        Invoke-Command -Session $session -ScriptBlock { get-filehash 'C:\Users\Public\tmp\windowslogs.7z'; write-host 'size of compressed file'; ((Get-ChildItem 'C:\Users\Public\tmp\windowslogs.7z' -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB) }
        write-host "Starting copy to the local machine"
        Copy-Item -FromSession $session "C:\Users\Public\tmp\windowslogs.7z" -Destination "C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\"
        start-sleep -Seconds 20 
        write-host "removing tmp files"
        start-sleep -Seconds 10 
        Invoke-Command -Session $session -ScriptBlock { set-location C:\windows\ }
        Invoke-Command -Session $session -ScriptBlock { remove-item -Recurse -Force -Path C:\Users\Public\tmp }
        write-host "logs copied"
    }

    function addfirewallrule {
        write-host "adding local windows firewall rule 'Block Outbound connections"
        Invoke-Command -Session $session -ScriptBlock { New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block }
        write-host "host isolated. (it will still accept inbound connections)"
    }

    function removefirewallrule {
        write-host "removing local windows firewall rule 'Block Outbound connections"
        Invoke-Command -Session $session -ScriptBlock { Remove-NetFirewallRule -DisplayName "Block Outbound connections" }
        write-host "host released from isolation"
    }


    function startendpointscan10 {      
        $scanscript =
        {     
            #Starting Scan windows 10
            Update-MpSignature  
            Start-Sleep -s 20 
            Get-MpComputerStatus  
            Start-MpScan -AsJob -ScanType 2   
            Get-WinEvent -ProviderName 'Microsoft-Windows-Windows Defender' -MaxEvents 10 | Where-Object { $_.Id -clike "100*" } 
        }
        Write-Output "Initializing scan"
        Write-Output "Dumping all info to C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt"
        Invoke-Command -Session $session -ScriptBlock $scanscript >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt        
    } 


    
    function startendpointscan6 {      
        $scanprep =
        {
            #Starting Scan windows 7
            cd 'C:\Program Files\Microsoft Security Client' ;
            .\MpCmdRun.exe -Restore -Listall; 
            .\mpcmdrun.exe -SignatureUpdate;

        }
        Write-Output "Last Scan Events" >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt        
        Write-Output "Initializing scan"
        Write-Output "Dumping all info to C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt"
        Invoke-Command -Session $session -ScriptBlock $scanprep >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt
        Invoke-Command -Session $session -ScriptBlock { Get-EventLog -Newest 10 -LogName System -Source 'Microsoft Antimalware' | select -property Message, InstanceID, TimeWritten | where-object { $_.InstanceID -clike '100*' } } >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt
    
        Invoke-Command -Session $session -ScriptBlock { cd 'C:\Program Files\Microsoft Security Client' ; .\mpcmdrun.exe -Scan -ScanType 2 } >> C:\Users\$localuser\Documents\Hostcheck\$day1\$hostname\scan-report.txt
    
    } 
    

    if ($startscan -eq "Yes" -and $windows_version -eq 10) {   
        Write-Output "Checking verions samples"
        startendpointscan10;
    }

    if ($startscan -eq "Yes" -and $windows_version -eq 6) {   
        Write-Output "Checking verions samples"
        startendpointscan6;
    }

    if ($scanstat -eq "Yes" -and $windows_version -eq 10) {   

        status;
    }

    if ($retrievesamples -eq "Yes" -or $allchecks -eq "Yes") {   
        Write-Output "Retrieving samples"
        retrievesamples -win_ver $windows_version;
    }
    else {
        Write-Verbose -Message "If you dont need it please do not set the parameter, otherwise set Yes. :P"
    }
    
        
    if ($restofchecks -eq "Yes" -or $allchecks -eq "Yes") {   
        Write-Output "Retrieving Browser Extensions"
        restofchecks;
    }

    if ($windowslog -eq "Yes" -or $allchecks -eq "Yes") {   
        Write-Output "Retrieving windows logs"
        retrievewindowslogs;
    }

    if ($networkoutboundblock -eq "Yes" -or $allchecks -eq "Yes") {   
        Write-Output "Blocking outbound connections"
        addfirewallrule;
    }

    if ($networkoutboundunblock -eq "Yes" -or $allchecks -eq "Yes") {   
        Write-Output "Blocking outbound connections"
        removefirewallrule;
    }


    else {
        Write-Verbose -Message "If you dont need it please do not set the parameter, otherwise set Yes. :P"
    }

}

End {
    Write-Verbose -Message "Finishing verification Job"
}

