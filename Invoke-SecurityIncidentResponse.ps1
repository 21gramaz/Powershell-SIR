# Executes Basic checks for the target host/hosts.
#
#
#Requires -Version 5


[CmdletBinding(DefaultParameterSetName = "Containment")]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]
    $ComputerName,

    [Parameter(Mandatory=$true,ParameterSetName = "Collection")]
    [switch]
    $Collection,

    [Parameter(Mandatory=$true,ParameterSetName = "Contaiment")]
    [switch]
    $Containment,

    [Parameter(Mandatory=$true,ParameterSetName = "Remediation")]
    [switch]
    $Remediation,

    [Parameter(ParameterSetName = "Collection")]
    [switch]
    $CollectionType,

    [Parameter(ParameterSetName = "Contaiment")]
    [string]
    $ContainmentType,

    [Parameter(ParameterSetName = "Remediation")]
    [switch]
    $RemediationType,

    [switch]
    $usecreds
)

begin{
    function get-basicinfo {
        param(
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]    
            $ComputerName,
            
            [System.Management.Automation.PSCredential]
            $Credential
        )

            $command={$hostinfo=Get-CimInstance Win32_OperatingSystem;
                $hostinfo | Add-Member -NotePropertyName PowershellVersion -NotePropertyValue $host.Version; 
                $hostinfo}
            $parameters=@{scriptblock = $command}
            if ($Credential) {
                $parameters.Credential = $Credential
            }
                if($null -ne $ComputerName){
                    $hostinfo=Invoke-Command -ComputerName $ComputerName @parameters
                    return $hostinfo
                }
                else{
                    $hostinfo=Invoke-Command @parameters
                    return $hostinfo
                }
    }
}
process{
    if($usecreds){
        $creds=Get-Credential
    }
    
    $hostsinfo=get-basicinfo -ComputerName $ComputerName -Credential $creds
    foreach ($hostinfo in $hostsinfo){
        if ($Collection){
            write-host "Startin Collection"
        }
        if ($Containment){
            write-host "Startin Containment"
            Import-Module -Name "$PSScriptRoot\Invoke-Containment.ps1"
            Invoke-Containment -ContainmentType All -ComputerInfo $hostinfo
        }
        if ($Remediation){
            write-host "Startin Remediation"
        }
    }

}