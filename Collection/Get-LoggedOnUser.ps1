
<#    Get logged on users:
    https://stackoverflow.com/questions/23219718/powershell-script-to-see-currently-logged-in-users-domain-and-machine-status
#> 

function Get-LoggedOnUser {

    #mjolinor 3/17/10
        
    $regexa = '.+Domain="(.+)",Name="(.+)"$'
    $regexd = '.+LogonId="(\d+)"$'
        
    $logontype = @{
        "0"  = "Local System"
        "2"  = "Interactive" #(Local logon)
        "3"  = "Network" # (Remote logon)
        "4"  = "Batch" # (Scheduled task)
        "5"  = "Service" # (Service account logon)
        "7"  = "Unlock" #(Screen saver)
        "8"  = "NetworkCleartext" # (Cleartext network logon)
        "9"  = "NewCredentials" #(RunAs using alternate credentials)
        "10" = "RemoteInteractive" #(RDP\TS\RemoteAssistance)
        "11" = "CachedInteractive" #(Local w\cached credentials)
    }
        
    $logon_sessions = @(Get-WmiObject win32_logonsession )
    $logon_users = @(Get-WmiObject win32_loggedonuser )
        
    $session_user = @{}
        
    $logon_users | ForEach-Object {
        $_.antecedent -match $regexa > $nul
        $username = $matches[1] + "\" + $matches[2]
        $_.dependent -match $regexd > $nul
        $session = $matches[1]
        $session_user[$session] += $username
    }
        
    $loggedonusers = @()
    $logon_sessions | ForEach-Object {
        $starttime = [management.managementdatetimeconverter]::todatetime($_.starttime)
        
        $loggedonuser = New-Object -TypeName psobject
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Session" -Value $_.logonid
        $HEXsession = '{0:X}' -f [int]($_.logonid)
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "HEXSession" -Value $HEXsession
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "User" -Value $session_user[$_.logonid]
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Type" -Value $logontype[$_.logontype.tostring()]
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Auth" -Value $_.authenticationpackage
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $starttime
        $loggedonusers += $loggedonuser
    }
    return $loggedonusers
}