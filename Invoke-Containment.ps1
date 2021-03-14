<#Invoke-Contaiment
This module will have all functions to 
#>

function Invoke-Containment{
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $ContainmentType,
        [Parameter()]
        [Object]
        $ComputerInfo
    )

    Write-Host "Ive been here" 
    $ComputerInfo.PowershellVersion
    $ComputerInfo.Version
    $ComputerInfo.OSArchitecture
    $ContainmentType
}

#Export-ModuleMember function Get-Containment