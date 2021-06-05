@echo off 
Rem This batch is a sample of batch file to start the live response collection process fully automated.
set /p fileshare="FileShare address:"
net use G: \\%fileshare%\LRScript /u:LiveResponseUser
powershell -ep bypass -c  "G:\SIR\.\Invoke-SIR.ps1 -Collection -CollectionType All -InformationLevel Medium -FilesCollectionLevel Medium"
pause