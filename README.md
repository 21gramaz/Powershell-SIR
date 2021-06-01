#Powershell security incident response helpers

Timelining an incident:  
Incident -> Security Alert/Abnormal Behavior -> Incident Response Steps -> Forensicf

Usually incident reponse will comes to this:  
Alert/Abnormal Behavior -> Someone find something wrong and turn off the server/desktop, lose all the memory and temporary files that would be crucial for further investigation -> As there is no way to determine what have been done the recommendation would be rebuild the server and reset all users that had any information/logged there.

In an ideal situation:  
Alert/Abnormal Behavior -> Artifact Collection -> Investigation -> confirmed incident ->Snapshot of the VM+Memory for futher investigation before any action -> Basic Containment ->  -> Remediation/Eradication -> lessons learned

When EDR+SIEM are not in play for an incident all comes to adhoc IR this project is made to enable analysts to automate the common part of it that would be:  
    Endpoint collection of logs and artifacts of interest.  
    Endpoint Containment.  
    Endpoint Remediation/Eradication.  

Invoke-SecurityIncidentResponse  
    1 - Check OS version, CPU architeture, Hostname, DNS resolution.  
    2 - Powershell Version.  
    3 - Download necessary binaries to execute next steps like procdump and autorun (MS tools).  
    Call one of the subsequent scripts to perform artifact collection, containment or remediation depending one what is asked in the paramenters.  

Invoke-ArtifactsCollection

Detection/Investigation/Artifacts Collection  
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

Invoke-Containment  
Containment  
    1 - Host isolation.  
    2 - Process termination.  
    3 - Terminate user session.  
    4 - Restart service.  

Invoke-Remediation  
Remediation/Eradication  
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
