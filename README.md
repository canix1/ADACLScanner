# AD ACL Scanner

## Current version
**Version: 5.4.3**

**30 August,2017**

**SHA256:** 534D84F4B46F63DAE278938873787BCA63CF8A2E1C9BFE3168C8DD06C6572D76

## History
Features and fixes https://github.com/canix1/ADACLScanner/wiki/History
#### 25/8/2017
Thanks to Kirill Nikolaev [exchange12rocks](https://github.com/exchange12rocks) for his contirbution. 
* Fixing pop-up windows disappear during window switching
* UNIX style endings in code 

## Download
**Right click and save as** - **[Here](https://github.com/canix1/ADACLScanner/raw/master/ADACLScan.ps1)**

## Description
* A tool completly written in PowerShell. 
* A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .

Related blog posts
* [Forensics - Active Directory ACL Investigation](https://blogs.technet.microsoft.com/pfesweplat/2017/01/28/forensics-active-directory-acl-investigation)
* [Take Control Over AD Permissions And The AD ACL Scanner Tool](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool)

## New Features
#### 25/8/2017
* New output format. Save to excel file without excel installed. Both from UI and command line. Requires ImportExcel PowerShell Module. You can install ImportExcel directly from the Powershell Gallery.
![](https://github.com/canix1/ADACLScanner/blob/master/src/SaveToExcel.jpg)

* Command line support.
![](https://github.com/canix1/ADACLScanner/blob/master/src/adaclscan_commandline.gif)
* Custom search filter for scanning objects. 
* Support input from pipeline. You can call ADACLScan.ps1 by sending a distinguishedName via pipeline.
* Added formated synopsis to the script.

![](https://github.com/canix1/ADACLScanner/blob/master/src/GUICustomSearch.gif)
## Features
It has the following features:
* View HTML reports of DACLs/SACLs and save it to disk. 
* Export DACLs/SACLs on Active Directory objects in a CSV format. 
* Export DACLs/SACLs on Active Directory objects in a Excel sheet. 
* Connect and browse you default domain, schema , configuration or a naming context defined by distinguishedname. 
* Browse naming context by clicking you way around, either by OU�s or all types of objects. 
* Report only explicitly assigned DACLs/SACLs. 
* Report on OUs , OUs and Container Objects or all object types. 
* Filter DACLs/SACLs for a specific access type.. Where does �Deny� permission exists? 
* Filter DACLs/SACLs for a specific identity. Where does "Domain\Client Admins" have explicit access? Or use wildcards like "jdoe". 
* Filter DACLs/SACLs for permission on specific object. Where are permissions set on computer objects? 
* Skip default permissions (defaultSecurityDescriptor) in report. Makes it easier to find custom permissions. 
* Report owner of object. 
* Compare previous results with the current configuration and see the differences by color scheme (Green=matching permissions, Yellow= new permissions, Red= missing permissions). 
* Report when permissions were modified 
* Can use AD replication metadata when comparing. 
* Can convert a previously created CSV file to a HTML report. 
* Effective rights, select a security principal and match it agains the permissions in AD. 
* Color coded permissions based on criticality when using effective rights scan. 
* List you domains and select one from the list. 
* Get the size of the security descriptor (bytes). 
* Rerporting on disabled inheritance . 
* Get all inherited permissions in report. 
* HTLM reports contain headers. 
* Summary of criticality for all report types. 
* Refresh Nodes by right-click container object. 
* Exclude of objects from report by matching string to distinguishedName 
* You can take a CSV file from one domain and use it for another. With replacing the old DN with the current domains you can resuse reports between domains. You can also replace the (Short domain name)Netbios name security principals. 
* Reporting on modified default security descriptors in Schema. 
* Verifying the format of the CSV files used in convert and compare functions. 
* When compairing with CSV file Nodes missing in AD will be reported as "Node does not exist in AD" 
* The progress bar can be disabled to gain speed in creating reports. 
* If the fist node in the CSV file used for compairing can't be connected the scan will stop. 
* Display group members in groups in the HTLM report. 
* Present the value of the true SDDL in NTsecurityDescriptor, bypassing Object-Specific ACE merge done when a new instance of the ObjectSecurity class is initialized.
## System requirements
* Powershell 2.0 or above 
* PowerShell using a single-threaded apartment 
* Some functions requires Microsoft .NET Framework version 4.0