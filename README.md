# Powershell security incident response helpers  
  
The goal of this script is at some point cover the below for Windows:    
    Live Reponse - Data Collection.                              (75%-80% Complete)    
    Live Reponse - Containment.                                  (20%-30% Complete)    
    Live Reponse - Remediation/Eradication.                      (0% Complete)    

For Help  
Get-Help .\Invoke-SIR.ps1 -Full

For examples  
Get-Help .\Invoke-SIR.ps1 -Examples  

## Invoke-SIR.ps1
    1 - Check OS version, CPU architeture, Hostname, DNS resolution.  
    2 - Creates PSsessions used to run the the modules.  
    Call one of the subsequent scripts to perform artifact collection, containment or remediation depending one what is asked in the paramenters.  

## Invoke-InformationGathering.ps1

### Detection/Investigation/Artifacts Collection  
### System information  
Basic:  
- General System info:  
    - System Time and Date                                                          (Done)   
    - Operational system version info.                                              (Done)  
    - Drives Info                                                                   (Done)                           
    - Network interface details                                                     (Done)    
    - Routing Table                                                                 (Done)   
- Services Runing                                                                     (Done)   
- List of processs (process tree and command lines and path of the image)             (Done)  
- Ports open with repectives process                                                  (Done)    
- Firewall rules                                                                      (Done)   
- Enumerate local users                                                               (Done)   
- DNS Cache                                                                           (Done)  
- User Sessions.                                                                      (Done)  
- Installed Programs                                                                  (Done)  
- Network Connections                                                                 (Done)   

Medium:  
- SMB Sessions                                                                       (Not Implemented)  
- PortProxy Configurations                                                           (Done)  
- Autoruns (Persistence/Execution)                                                   (Done)  

Advanced:  
- MFT records                                                                       (Done)  
- SHIM cache                                                                        (Not Implemented)  
- AM Cache                                                                          (Not Implemented)  
- Collect Number of hashed passwords cached in the system.                          (Not Implemented)  

### Windows File Collection:  
Disabled:  
- Create a table of retention time for each evtx log (Done)  

Basic:
- Create a table of retention time for each evtx log (Done)  
- Copy the System, Appliacation and Security EVTX files (Done)  

Medium:
- Create a table of retention time for each evtx log (Done)  
- Copy all EVTX files (Done)  
- Copy prefetch files (Done)  
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)
- Copy Browser History (Not implmented)

Detailed:
- Create a table of retention time for each evtx log (Done)  
- Copy all EVTX files (Done)  
- Copy prefetch files (Done)  
- Copy Firewall Logs - Get-NetFirewallProfile (Not implmented)  
- Copy Browser History (Not implmented)  
- Copy IIS logs (Not implmented)  
- Copy Exchange logs (Not implmented)  
- Copy Temp Files (Not implmented)  

## Invoke-Containment  
### Containment  
    1 - Host isolation. (Done)
    2 - Process termination. (Not implmented)  
    3 - Terminate user session. (Not implmented)  
    4 - Restart service. (Not implmented)  

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

### Notes about Collection best Pratices
    1 - Least intrusive modes of collection are:  
        -.\Invoke-SIR.ps1 -Collection -CollectionType All -InformationLevel Medium -FilesCollectionLevel Medium (From a Network Drive or External Drive)  
        -.\Invoke-SIR.ps1 -Collection -CollectionType Disk -InformationLevel Medium -FilesCollectionLevel Disabled -ComputerName host1 -UseCreds (Remote collection is done via WINRM, the remote file collections  uses a temporary folder in the affected system C:\Windows\Temp\Logs, C:\Windows\Temp\FWlogs\ because I could not find a way to copy those via WINRM directly, all of them a removed after copied).  
    2 - Intrusive modes and why:  
        - For InformationLevel=detailed, it is needed to copy the PowerForensics DLL to the affected system so it can Import-Modules (by default powershell does not allow to import modules from network shares of external drives) from it, so it will modify the system at this point.  
        - For remote FilesCollectionLevel=Basic or above the temporary folders are created in order to successfully copy the files.  
    3 - Just because it is intrusive it does not means it is not working or prohibited, it just means that you accept the risk to pollute or lose a potential evidence.  
    4 - If possible download the script in a network share accessible for a specific user that have read+execute access to all files and write permissions in "$PSScriptRoot\Collection\Reports"
    5 - When CollectionType=All memory dump is done fisrt and disk collection second.
    6 - While running InformationLevel=Medium or above Powershell modules:
        - Autoruns can consume 250Mb+ RAM memory (in my tests)
        - PowerForensics FileRecords (MFT) can consume 700Mb+ RAM.
        - Remmeber that these will be executed just after the memory acquisition.
        7 - To dump the memory I am using WinPMem project and the dump is campatible with Volatility.
    8 - It creates a table of evidence file hashes at the end and give you the hash of the table in the output.
    9 - At this point the script just records the time of each executed function with the local system time, there is no remote time source to compare.

### Knwon Issues:
    1 - When collecting the MFT records via WINRM there is a chance the records exceeds the max object sizie like:  
        - The current deserialized object size of the data received from the remote server exceeded the allowed maximum object size. The current deserialized object size is 209747968. The allowed maximum object size    is 209715200.  
    2 - When collecting the MFT recoreds via WINRM the file C:\Windows\Temp\PowerForensicsv2.dll might not be deleted automatically, so delete it mannually if needed.  

References and code sources:  
https://isc.sans.edu/forums/diary/Using+Powershell+in+Basic+Incident+Response+A+Domain+Wide+KillSwitch/25088/  
https://github.com/davehull/Kansa/tree/master/Modules  
https://digital-forensics.sans.org/community/papers/gcfa/live-response-powershell_3393  
https://powerforensics.readthedocs.io/en/latest/  
https://github.com/LeeHolmes/AutoRuns  
https://github.com/Velocidex/WinPmem/releases  
https://www.sans.org/security-resources/posters/memory-forensics-cheat-sheet/365/download   
Incident Response & Computer Forensics, Third Edition  