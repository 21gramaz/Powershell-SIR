<#Invoke-Contaiment
This module will have all functions to 

function addfirewallrule
{
    write-host "adding local windows firewall rule 'Block Outbound connections"
    Invoke-Command -Session $session -ScriptBlock {New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block}
    write-host "host isolated. (it will still accept inbound connections)"
}

function removefirewallrule
{
    write-host "removing local windows firewall rule 'Block Outbound connections"
    Invoke-Command -Session $session -ScriptBlock {Remove-NetFirewallRule -DisplayName "Block Outbound connections"}
    write-host "host released from isolation"
}
#>


function Invoke-NetworkIsolation {
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]    
        $ComputerName
    )
    write-host "adding local windows firewall rule 'Block Outbound connections'"
    $firewallisolationrule={New-NetFirewallRule -DisplayName "Block Outbound connections" -Direction Outbound -Action Block;
    New-NetFirewallRule -DisplayName "Block Inbound connections" -Direction Inbound -Action Block -LocalPort 0-5984,5987-65535 -Protocol TCP
        $firewallprofiles=Get-NetFirewallProfile;
        foreach ($profile in $firewallprofiles){
            Set-NetFirewallProfile -Name ($profile).Name -Enabled True
        }
    }

    $parameters=@{scriptblock = $firewallisolationrule}

    Invoke-Command -ComputerName $ComputerName @parameters
}
function Invoke-NetworkRelease {
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]    
        $ComputerName
    )
    $firewallisolationrule={Remove-NetFirewallRule -DisplayName "Block Outbound connections"
    Remove-NetFirewallRule -DisplayName "Block Inbound connections"}
    $parameters=@{scriptblock = $firewallisolationrule}
    write-host "removing local windows firewall rule 'Block Outbound connections"
    Invoke-Command -ComputerName $ComputerName @parameters
}
function Invoke-Containment{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $ContainmentType,

        [Parameter()]
        [Object]
        $ComputerInfo
    )


    if($ContainmentType -eq "NetworkIsolation"){
        Invoke-NetworkIsolation -ComputerName $ComputerInfo.ComputerName
    }
    if($ContainmentType -eq "NetworkRelease"){
        Invoke-NetworkRelease -ComputerName $ComputerInfo.ComputerName 
    }

}



#Export-ModuleMember function Get-Containment