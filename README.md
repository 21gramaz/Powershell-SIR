#Powershell security incident response helpers

Timelining an incident:
Incident -> Security Alert/Abnormal Behavior -> Incident Response Steps -> Forensic

When EDR+SIEM are not in play for an incident all comes to adhoc IR this project is made to enable analysts to automate the common part of it that would be:
    Endpoint Containment.
    Endpoint Remediation/Eradication.
    Endpoint collection of logs and artifacts of interest.

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
    4 - User removal