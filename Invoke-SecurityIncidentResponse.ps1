# Executes Basic checks for the target host/hosts.
#



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
    [string]
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
                $hostinfo | Add-Member -NotePropertyName PowershellVersion -NotePropertyValue $PSVersionTable; 
                $hostinfo}
            $parameters=@{scriptblock = $command}
            if ($Credential) {
                $parameters.Credential = $Credential
            }
                if($null -ne $ComputerName){
                    $hostinfo=Invoke-Command -ComputerName $ComputerName @parameters
                    $hostinfo | Add-Member -NotePropertyName ComputerName -NotePropertyValue $ComputerName
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
            
            Invoke-Containment -ContainmentType $ContainmentType -ComputerInfo $hostinfo 
            
        }
        if ($Remediation){
            write-host "Startin Remediation"
        }
    }

}