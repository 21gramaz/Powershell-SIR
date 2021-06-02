# Powershell security incident response helpers

Timelining an incident:  
Incident -> Security Alert/Abnormal Behavior -> Incident Response Steps -> Forensic

Usually incident reponse will comes to this:  
Alert/Abnormal Behavior -> Someone find something wrong and turn off the server/desktop, lose all the memory and temporary files that would be crucial for further investigation -> As there is no way to determine what have been done the recommendation would be rebuild the server and reset all users that had any information/logged there.

In an ideal situation:  
Alert/Abnormal Behavior -> Artifact Collection -> Investigation -> confirmed incident ->Snapshot of the VM+Memory for futher investigation before any action -> Basic Containment ->  -> Remediation/Eradication -> lessons learned

When EDR+SIEM are not in play for an incident all comes to adhoc IR this project is made to enable analysts to automate the common part of it that would be:  
    Endpoint collection of logs and artifacts of interest.  
    Endpoint Containment.  
    Endpoint Remediation/Eradication.

For Help
Get-Help- .\Invoke-SIR.ps1 -Full

For examples
Get-Help .\Invoke-SIR.ps1 -Examples

## Invoke-SIR.ps1
    1 - Check OS version, CPU architeture, Hostname, DNS resolution.  
    2 - Powershell Version.  
    Call one of the subsequent scripts to perform artifact collection, containment or remediation depending one what is asked in the paramenters.  

## Invoke-InformationGathering.ps1

### Detection/Investigation/Artifacts Collection  
System information Basic:  
    - General System info:  
            • System Time and Date                                                          Done  
            • Operational system version info.                                              Done  
            • Drives Info                                                                   Done                         
            • Network interface details                                                     Done  
            • Routing Table                                                                 Done  
    - Services Runing                                                                     Done  
    - List of processs (process tree and command lines and path of the image)             Done  
    - Ports open with repectives process                                                  Done  
    - Firewall rules                                                                      Done  
    - Enumerate local users                                                               Done  
    - DNS Cache                                                                           Done  
    - User Sessions.                                                                      Done  
    - Installed Programs                                                                  Done  
    - Network Connections                                                                 Done  

Medium:  
    - SMB Sessions                                                                       Not Implemented  
    - PortProxy Configurations                                                           Done  
    - Autoruns (Persistence/Execution)                                                   Done  

Advanced:
    - MFT records                                                                       Done  
    - SHIM cache                                                                        Not Implemented  
    - AM Cache                                                                          Not Implemented  
    - Collect Number of hashed passwords cached in the system.                          Not Implemented  

Windows File Collection:
Disabled:
- Create a table of retention time for each evtx log

Basic:
- Create a table of retention time for each evtx log
- Copy the System, Appliacation and Security EVTX files

Medium:
- Create a table of retention time for each evtx log
- Copy all EVTX files
- Copy prefetch files
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)
- Copy Browser History (Not implmented)

Detailed:
- Create a table of retention time for each evtx log
- Copy all EVTX files
- Copy prefetch files
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)
- Copy Browser History (Not implmented)
- Copy IIS logs (Not implmented)
- Copy Exchange logs (Not implmented)
- Copy Temp Files

## Invoke-Containment  
### Containment  
    1 - Host isolation.  
    2 - Process termination.  
    3 - Terminate user session.  
    4 - Restart service.  

## Invoke-Remediation  (Not implemented yet)
### Remediation/Eradication  
    1 - Service Removal.  
    2 - WMI persistence removal.  
    3 - Task Scheduler removal.  
    4 - User removal.  
    5 - Remove endpoint Firewall Rule/Proxy.  
    6 - Remove list of files by path+name or hash.  
    7 - Remove Application (Maybe)  
    8 - Remove browser extenstions  (Maybe)  


References:
https://isc.sans.edu/forums/diary/Using+Powershell+in+Basic+Incident+Response+A+Domain+Wide+KillSwitch/25088/  
https://github.com/davehull/Kansa/tree/master/Modules  
https://digital-forensics.sans.org/community/papers/gcfa/live-response-powershell_3393  
https://powerforensics.readthedocs.io/en/latest/  
https://github.com/LeeHolmes/AutoRuns  