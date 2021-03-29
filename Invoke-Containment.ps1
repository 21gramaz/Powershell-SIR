<#Invoke-Contaiment
This module will have all functions to 

#>
$ErrorActionPreference = "stop"
function Invoke-NetworkIsolation 
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
        write-host "[*]["$Session.ComputerName"] Attempting to add local windows firewall rule 'Block Outbound connections'. Nothing out is allowed" -ForegroundColor Yellow
        write-host "[*]["$Session.ComputerName"] Attempting to add local windows firewall rule 'Block Inbound connections'. Just RDP and WinRM are allowed" -ForegroundColor Yellow 
        
        #Commands that will be executed to add the firewall rules the server
        #It will block all incoming traffic this means all servers will stop to work like IIS/Exchange Server/AD.
        $firewallisolationrule={
            #New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block -RemotePort 0-87,89-388,390-65535 -Protocol UDP;
            #New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block -Protocol TCP;
            New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block -LocalPort 0-87,89-65535 -Protocol UDP
            New-NetFirewallRule -DisplayName "Block Inbound connections" -Direction Inbound -Action Block -LocalPort 0-5984,5987-65535 -Protocol TCP
            $firewallprofiles=Get-NetFirewallProfile;
            foreach ($profile in $firewallprofiles)
            {
                Set-NetFirewallProfile -Name ($profile).Name -Enabled True
            }
        }
        $parameters=@{scriptblock = $firewallisolationrule}

        #Commands that will be executed to check if the rules had been added.
        $containmentstatus={
            $CheckingRulesAdded=Get-NetFirewallRule | Where-Object {$_.DisplayName -match '(Block Outbound connections)|(Block Inbound connections)'}
            if($CheckingRulesAdded.Count -eq 2)
            {
                write-host "[+] Firewall rules successfully added" -ForegroundColor Green
                Write-Host "[+] Rules identifiers: " $CheckingRulesAdded.Name -ForegroundColor Green
                Write-Host "[*] Warning: If you are running this script to a remote computer do not close this Powershell Console you might lose the last working session" -ForegroundColor Yellow
            }
            else{
                write-host "[-] Firewall rules could not be found, something went wrong" -ForegroundColor Red
                exit
            }   
        }
        $statusparameters=@{scriptblock = $containmentstatus}

    }
    #Applying FW rules
    Process
    {
        if($Localhost)
        {
            try{
                Invoke-Command @parameters -ErrorAction Stop | Out-Null
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit           
            }
        }
        else
        {
            try{
                Invoke-Command -Session $Session @parameters -ErrorAction Stop | Out-Null
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit
            }
        }
    }
    
    #Checking if the firewall rules had been applied.
    end
    {
        if($Localhost)
        {
            try{
                Invoke-Command @statusparameters -ErrorAction Stop | Out-Null
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit        
            }
        }
        else 
        {
            try{
                Invoke-Command -Session $Session @statusparameters -ErrorAction Stop | Out-Null
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit
            }
        }
    }

    
}
function Invoke-NetworkRelease 
{
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]    
        $ComputerName,

        [Parameter()]
        [switch]
        $LocalHost,

        [Parameter()]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )

    begin
    {
        
        write-host "[*]["$Session.ComputerName"] Removing local windows firewall rule 'Block Outbound connections'" -ForegroundColor Yellow
        write-host "[*]["$Session.ComputerName"] Removing to remove local windows firewall rule 'Block Inbound connections'" -ForegroundColor Yellow
        #commands to be performed to release from isolation.
        $firewallremoverules={
            Remove-NetFirewallRule -DisplayName "Block Outbound connections"
            Remove-NetFirewallRule -DisplayName "Block Inbound connections"
        }
        $parameters=@{scriptblock = $firewallremoverules}

        #Commands to check of the rules had been removed.
        $containmentstatus={
            $CheckingRulesAdded=Get-NetFirewallRule | Where-Object {$_.DisplayName -match '(Block Outbound connections)|(Block Inbound connections)'}
            if($CheckingRulesAdded.Count -eq 2)
            {
                write-host "[-] Firewall could not be removed, please check your permissions and connectivity" -ForegroundColor Red
                Write-Host "Rules identifiers: " $CheckingRulesAdded.Name -ForegroundColor Red
                exit
            }
            else{
                write-host "[-] Firewall rules successfully removed " -ForegroundColor Green
            }   
        }
        $statusparameters=@{scriptblock = $containmentstatus}

    }

    process
    {
        if($LocalHost)
        {
            try
            {
                Invoke-Command @parameters -ErrorAction Stop
            }
            catch
            {
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        else
        {
            try
            {
                Invoke-Command -Session $Session @parameters -ErrorAction Stop
            }
            catch
            {
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
    }
    
    end
    {
        if($Localhost)
        {
            try{
                Invoke-Command @statusparameters -ErrorAction Stop 
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit        
            }
        }
        else 
        {
            try{
                Invoke-Command -Session $Session @statusparameters -ErrorAction Stop | Out-Null
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
                exit
            }
        }
    }


}
function Invoke-Containment
{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $ContainmentType,

        [Parameter()]
        [Object]
        $ComputerInfo,

        [Parameter()]
        [switch]
        $LocalHost,

        [Parameter()]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )

    if($LocalHost)
    {
        if($ContainmentType -eq "NetworkIsolation")
        { 
            Invoke-NetworkIsolation -LocalHost
        }
        elseif($ContainmentType -eq "NetworkRelease")
        { 
            Invoke-NetworkRelease -LocalHost
        }
        else 
        {
            write-host "[-] Containment type not existent or not implemented, check spelling and try again." -ForegroundColor Red
        }
    }
    else
    {
        if($ContainmentType -eq "NetworkIsolation")
        { 
            Invoke-NetworkIsolation -ComputerName $ComputerInfo.ComputerName -Session $Session
        }
        elseif($ContainmentType -eq "NetworkRelease")
        { 
            Invoke-NetworkRelease -ComputerName $ComputerInfo.ComputerName -Session $Session 
        }
        else 
        {
            write-host "[-] Containment type not existent or not implemented, check spelling and try again." -ForegroundColor Red
        }
    }
}

function Invoke-ContainmentConsole
{
    param(
        [Parameter()]
        [Object]
        $ComputerInfo,

        [Parameter()]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )
    do
    {
        try
        {
            Write-Host "ContaimentConsole> " -NoNewLine
            $command = $Host.UI.ReadLine()
            Invoke-Command -Session $Session -ScriptBlock {invoke-expression $using:command}
            #Invoke-Command -ScriptBlock {invoke-expression $using:command}
        }
        catch
        {
            write-host "[-] Houston we had a problem... " -ForegroundColor Red
            Write-Host $_ -ForegroundColor Red
        }
    }while($command -ne "exit")
    #Checks if the remote session is in an available state
    <#$remotesessions=Get-PSSession
    foreach ($remotesession in $remotesessions)
    {
        if ($remotesession -eq ){}
    }#>
    Invoke-NetworkRelease  -ComputerName $ComputerInfo.ComputerName -Session $Session 
}


#Export-ModuleMember function Get-Containment
