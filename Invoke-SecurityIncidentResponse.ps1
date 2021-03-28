# Executes Basic checks for the target host/hosts.
#



[CmdletBinding(DefaultParameterSetName = "Containment")]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]
    $ComputerName,

    [Parameter(ParameterSetName = "Collection")]
    [switch]
    $Collection,

    [Parameter(ParameterSetName = "Contaiment")]
    [switch]
    $Containment,

    [Parameter(ParameterSetName = "Remediation")]
    [switch]
    $Remediation,

    [Parameter(Mandatory=$true,ParameterSetName = "Collection")]
    [string]
    $CollectionType,
    
    [Parameter(Mandatory=$true,ParameterSetName = "Contaiment")]
    [ValidateSet("NetworkIsolation", "NetworkRelease")]
    [string]
    $ContainmentType,

    [Parameter(Mandatory=$true,ParameterSetName = "Remediation")]
    [switch]
    $RemediationType,

    [switch]
    $usecreds
)

begin{
    $ErrorActionPreference = "stop"
    function get-basicinfo {
        param(
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]    
            $ComputerName,
            
            [Parameter()]
            [System.Management.Automation.PSCredential]
            $Credential,

            [Parameter()]
            [System.Management.Automation.Runspaces.PSSession]
            $Session
        )

            $command={
                $hostinfo=Get-CimInstance Win32_OperatingSystem;
                $hostinfo | Add-Member -NotePropertyName PowershellVersion -NotePropertyValue $PSVersionTable; 
                $hostinfo
            }
            $parameters=@{scriptblock = $command}
            #if ($Credential) {
                #$parameters.Credential = $Credential
            #}
                if($null -ne $ComputerName){
                    write-host "[*] Gathering basic information about the host" -ForegroundColor Yellow
                    try{ 
                        $hostinfo=Invoke-Command -Session $Session @parameters -ErrorAction Stop 
                        $hostinfo | Add-Member -NotePropertyName ComputerName -NotePropertyValue $ComputerName -ErrorAction Stop
                    }
                    catch {
                        write-host "[-] Houston we had a problem gathering the basic info... " -ForegroundColor Red
                        Write-Host $_ -ForegroundColor Red
                        exit
                    }
                    
                    return $hostinfo
                }
                else{
                    $hostinfo=Invoke-Command @parameters
                    return $hostinfo
                }
    }
}
process{
    #Collecting credentials if necessary
    if($usecreds){
        $creds=Get-Credential
    }

    #Initiating session if not local
    #Needs to be done on multiple sessions:
    if($null -ne $ComputerName)
    {
        $sessions=@()
        $counter=0
        try {
            if($usecreds)
            {
                $sessions=New-PSSession $ComputerName -Credential $creds -Name $ComputerName -ErrorAction Stop
            }
            else
            {
                foreach($computer in $ComputerName)
                {
                    $sessionName="Containment"+$counter
                    $sessions+=New-PSSession $computer -Name $sessionName -ErrorAction Stop
                    $counter++
                }
            }
        }
        catch 
        {
            Write-host "Houston we had a problem..." -ForegroundColor Red
            Write-host $_ -ForegroundColor Red
            exit 
        }
    }

    #Getting basic info
    $hostsinfo=@()
    try
    {
        foreach ($session in $sessions)
        {
            $hostsinfo+=get-basicinfo -ComputerName $ComputerName -Session $session -ErrorAction Stop
        }
    }
    catch{
        write-host "[-] Houston we had a problem... " -ForegroundColor Red
        Write-Host $_ -ForegroundColor Red
        exit
    }
    
    foreach ($hostinfo in $hostsinfo)
    {
        write-host "[+] Basic information gathered Host: " $hostinfo.CSName ", OS Version: " $hostinfo.Version ", Arch: " $hostinfo.OSArchitecture " PS version: "  $hostinfo.PowershellVersion.PSVersion -ForegroundColor Green
    }
    
    #Call IR phase
    if($null -ne $ComputerName)
    {
        foreach ($session in $sessions)
        {
            if ($Collection){
                write-host "Startin Collection"
            }
            if ($Containment){
                write-host "[+] Starting Containment" -ForegroundColor Green
                try{
                    Remove-Module -Name Invoke-Containment -ErrorAction SilentlyContinue
                    Import-Module -Name "$PSScriptRoot\Invoke-Containment.ps1"
                    Invoke-Containment -ContainmentType $ContainmentType -ComputerInfo $hostinfo -Session $session
                    #Invoke-ContainmentConsole -Session $session -ComputerInfo $hostsinfo
                }
                catch{
                    write-host "[-] Houston we had a problem... " -ForegroundColor Red
                    Write-Host $_ -ForegroundColor Red
                }
            }
            if ($Remediation){
                write-host "Startin Remediation"
            }
        }
    }
    else{
        if ($Collection){
            write-host "Startin Collection"
        }
        if ($Containment){
            write-host "[+] Starting Containment" -ForegroundColor Green
            try{
                Remove-Module -Name Invoke-Containment -ErrorAction SilentlyContinue
                Import-Module -Name "$PSScriptRoot\Invoke-Containment.ps1" 
                if($ComputerName){
                Invoke-Containment -ContainmentType $ContainmentType -ComputerInfo $hostinfo -LocalHost}
            }
            catch{
                write-host "[-] Houston we had a problem... " -ForegroundColor Red
                Write-Host $_ -ForegroundColor Red
            }
        }
        if ($Remediation){
            write-host "Startin Remediation"
        }
    }

}