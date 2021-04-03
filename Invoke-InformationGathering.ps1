<#Invoke-InformationGathering
This module will have all functions to 
    Disk:
    1 - Collect windows logs from winevt.
    2 - Check IIS instalation paths and collect logs.
    3 - Services Runing
    4 - List of processs (process tree and command lines and path of the image)
    5 - Ports open with repectives process
    6 - Registry (startup locations)
    7 - Firewall rules/Firewall logs
    8 - Enumerate local users
    9 - DNS Cache
    10 - User Sessions.
    11 - Collect Number of hashed passwords cached allowed in lsass. 
#>

function Invoke-DiskInformationGathering
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

        

}