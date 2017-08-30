<#
.Synopsis
    ADACLScan.ps1
     
    AUTHOR: Robin Granberg (robin.granberg@microsoft.com)
    
    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.
    
    This sample is not supported under any Microsoft standard support program or service. 
    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
    implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose. The entire risk arising out of the use or performance
    of the sample and documentation remains with you. In no event shall Microsoft, its authors,
    or anyone else involved in the creation, production, or delivery of the script be liable for 
    any damages whatsoever (including, without limitation, damages for loss of business profits, 
    business interruption, loss of business information, or other pecuniary loss) arising out of 
    the use of or inability to use the sample or documentation, even if Microsoft has been advised 
    of the possibility of such damages.

.DESCRIPTION
    A tool with GUI or command linte used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory.
    See https://github.com/canix1/ADACLScanner

.EXAMPLE
    .\ADACLScan.ps1

    Start in GUI mode.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM"

    Create a CSV file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -HTML

    Create a HTML file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -EXCEL

    Create a Excel file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -HTML -Show

    Opens the HTML (HTA) file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -OutputFolder C:\Temp

    Create a CSV file in the folder C:\Temp, with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree

    Create a CSV file with the permissions of the object CORP and all child objects of type OrganizationalUnit.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)"

    Create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)" -Server DC1

    Targeted search against server "DC1" that will create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)" -Server DC1 -Port 389

    Targeted search against server "DC1" on port 389 that will create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.OUTPUTS
    The output is an CSV or HTML report.

.LINK
    https://github.com/canix1/ADACLScanner

.NOTES
    Version: 5.4.3
    30 August, 2017

    *SHA256:* 

    *Fixed issues*
    ** Convert CSV to HTML report was broken, missing parameter added.
 
    ----
    Version: 5.4.2
    29 August, 2017

    *SHA256:* CC03A16FCDFA94B03DD61B0772B481100098D638A85D92B9023F3A143D61FC0E

    *Fixed issues*
    ** Effective rights report broken, now comparing using SIDs instead of names.
 
    ----
    Version: 5.4.1
    26 August, 2017

    *SHA256:* 8CB8785927EE353DEA60C1A0F331795D3AAC08EBF0D8D6D8311CB5A809A7E73D

    *Fixed issues*
    ** Compare function got broken report.
 
    ----
    Version: 5.4
    25 August, 2017

    *SHA256:* D6BAC8FD6E4BDA7931329E41F0BAEC4CA4A45232D046C777CC13A74138441C3E

    *New Features*
    ** New output format. Save to excel file without excel installed. Both from UI and command line. Requires ImportExcel PowerShell Module.
 
    ----
    Version: 5.3
    25 August, 2017

    *SHA256:* 39193B85E9B9977CF1231D14986D1799216D9AC132461806DC0C0F4F2710B54C

    *Minor Fixed issues*
    ** Removed Splash Window
    ** Makes modal pop-up windows visible in the taskbar - exchange12rocks (Kirill Nikolaev)
    ** Replaced UNIX endings with Windows endings - exchange12rocks (Kirill Nikolaev)
 
    ----
    Version: 5.2.1
    30 June, 2017

    *SHA256:* 5E80AC4E22EDC19878F1B9504F16EA0CFBA8E0D8DF18972157B0EC86AD6ED0B7

    *Minor Fixed issues*
    ** New-GUID not recongnized in Windows PowerShell versions lower than 5.0
 
    ----
    Version: 5.2
    29 June, 2017

    *SHA256:* B378746599D75747F38CD7E8BEEE67F04A62AC0F525E590CB3918C6015E23EC3

    *Fixed issues*
    ** Unused variable name
    ** Simultaneously running instances mess up with each other`s data 
    ** Console errors are registered when a machine cannot connect to LDAP 
 
    ----
    Version: 5.1
    26 April, 2017

    *SHA256:* 2EB425DC449B70F2741AEA8E982FADA5D5733D75E259D0B8F86EDD72BB6F10D9

    *Fixed issues*
    ** Domain node was not included in the results, unless you used a custom filter.
 
    ----
    Version: 5.0
    9 April, 2017

    *SHA256:* 4DA5B52BECED5829AAE53916CFF1FBF9222D0954F76F683DE90C21CC994C9C5C

    *New Features*
    ** Command line support.
    ** Custom search filter for scanning objects. 
    ** Support input form pipeline. You can call ADACLScn.ps1 by sending a distinguishedName via pipeline.
    ** Added formated synopsis to the script.

    *Fixed issues*
    ** Effective rights did not consider membership in Pre-Windows 2000 Compatible Access.
    ** Failed to scan objects with "/" in the name.Removed all instances of replacing distinguishedNames containing "/" with "\/". It's a legacy from when AD ACL Scanner was using SDS (System.DirectoryServices) namespace. S.DS.P (System.DirectoryServices.Protocols) take care of special characters.

 
    ----
    Version: 4.8
    7 February, 2017

    *SHA256:* 8FCC040FA75E0593372C3F4397F26F0A1B7418A8B69491C08F565F5C566BA6E1

    *New Features*
    ** Templates for Windows Server 2016
    ** Removed requirement on localization of names on well-known groups and built-in groups.
    ** Comparing using SIDs of security principals gives us the true state instead of names that could be modified.
    ** Better download windows.

    *Fixed issues*
    ** Users could not view permissions due to the collection of attributes that user possibly didn't have access to. (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Removed unnecessary retrieval of ldap attributes. (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Removed unused functions (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Removed duplicated function name (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** LoadWithPartialName is deprecated (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** A mandatory parameter has a default value (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Fixed unreachable code (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Removed unused variables (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Fixed typo (Credit to Kirill Nikolaev, Kaspersky Lab) 
 
    ----
    Version: 4.7.2
    12 January, 2017

    *SHA256:* C1FDC71E46229EA11482D99EBB80CA1A24C0284D3F01FAC618277EA9C91F98F0

    *New Features*
    ** 

    *Fixed issues*
    ** Browsing a container with more than 999 child objects and you will get (Exception calling "SendRequest" with "1" argument(s): "The size limit was exceeded")
    ** Updated windows size. Increased height to not render a scroll bar under large screen size.
    ** Reduced the window size when it is adapting to smaller screen size.

 
    ----
    Version: 4.7.0
    6 December, 2016

    *SHA256:* 82DDB2263C7969AF5608246560A340CAB997F554CBE989A816A03C98F0E7582F

    *New Features*
    ** Improved performance in preparing the scan. Updated function GetAllChildNodes. (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Improved support for connecting via IP-address only.
    ** Height of windows adapts to screen size.
    ** Better color coded criticality.

    *Fixed issues*
    ** Removed unused LDAP attribute in LDAP search

 
    ----
    Version: 4.6.0
    6 October, 2016

    *SHA256:* 2E80D4CD580B9EBD2AFC18FCE3614B386BA16ECEA7C416C81CD133B7361A003F

    *New Features*
    ** Display group members in groups in the HTLM report.
    ** Present the value of the true SDDL in NTsecurityDescriptor, bypassing Object-Specific ACE merge done when a new instance of the ObjectSecurity class is initialized.
    ** Added Active Directory schema version check for Windows Server 2016.
    ** Added Exchange Schema Version check for Exchange Server 2016 CU2 and Exchange Server 2016 CU3

    *Fixed issues*
    ** Get Forest Info search did not handle return of empty or zero response entries in a correct way 
    ** HTML and CSV file output option doesn't display HTA
 
    ----
    Version: 4.5.0
    19 June, 2016

    *SHA256:* CDDA9E265995E23F8738A2914E4E05593F692B194C634DF0B4D9FBF1B6DC2298

    *New Features*
    ** Added Exchange Schema Version check for Exchange Server 2016 CU1.(Credit to Kirill Nikolaev, Kaspersky Lab)

    *Fixed issues*
    ** Heavily improved code for “Skip Default Permissions”. Removed possible memory problem while scanning many objects.
    ** Improved code for “Skip Protected Permissions”. One ACE was missing.
    ** Null-valued array error while composing the list of domains. (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Null-valued array error when closing domain picker window w/o actually selecting one. (Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Updated LDAP filters for getting trusted domains.(Credit to Kirill Nikolaev, Kaspersky Lab)
    ** Fixed issues with use of credentials over trusts.
    ** Fixed issues with TokenGroups over trust lookup.
    ** Removed unused variables.
    ** Replaced aliases like %,?,Select,foreach and Sort.
    ** Put $null to the left in comparison strings.

    ----
    Version: 4.4.0
    16 June, 2016

    *SHA256:* 2803906C909BB7DE7024FEE981BCE6D927A0826215051AEDD088D61C10F9AB97

    *Fixed issues*
    ** Errors when scanning objects you don't have read access on.
    ** Comparing with template containing forest root failed when connected to child domain.
    ** Templates are updated with a more accurate DN.
    ** Errors when translating NT Identity fixed. 

    ----
    Version: 4.3.0
    2 May, 2016

    *SHA256:* 3473DDB452DE7640FAB03CAD3E8AAF6A527BDD6A7A311909CFEF9DE0B4B78333

    *New Features*
    ** You can exclude multiple paths, just for each object, select and right click to choose Exclude.

    *Fixed issues*
    ** Unresolved security principals was shown as empty instead of SID.
    ** Searching for SID's included built-in groups that did not translate before compare.

    ----
    Version: 4.2.0
    14 April, 2016

    *SHA256:* F340F6B56F11F879ED8A4C0DDA751FFF9538EE5105B2C0F39C79BED218E985E2:* 

    *Fixed issues*
    ** The validated write was express as only "Self" in the report.
    ** The validated write was never enumerated from the list of ControlAccessRights.

    ----
    Version: 4.1.0
    12 April, 2016

    *SHA256:* BE7ECB91AA0F819A1796739B0491CA4691DCBE718410CA8A7F9358B600754B2A

    *Fixed issues*
    ** Comparing builtin groups differ from running on DC and domain member.
    ** Connecting to custom DC did not collected forest info.

    ----
    Version: 4.0.0
    11 April, 2016

    *SHA256:* C72CD69C0E15C1A9A276485FD5073F958B26B1A777928740C67B7E347F38938B

    *New Features*
    ** Faster compare of Access Control Lists using USN from replication metadata.
    ** Primary directory service API changed to System.DirectoryServices.Protocols (S.DS.P).
    ** Connect to custom directory server and port like mounted backup or snapshot of NTDS.dit.
    ** Support for scanning AD LDS Instances.
    ** Name translation of AD LDS Identity references in security descriptor.
    ** Option to connect using credentials.
    ** Export defaultSecurityDescriptor.
    ** Compare DefaultSecurityDescriptor.
    ** Download OS specific csv templates for DefaultSecuritydescriptor.
    ** Connection Information tab provides information about the current connection.
    ** Resizable Window

    *Fixed issues*
    ** Change the column name in the header from "OU" to "Object".
    ** Display forest information like FFL,DFL,Schema Version, Exchange and Lync Schema version did not work due to wrong formatting of attributes.
    ** Solved problem with returning schema version information about Exchange and Lync.
    ** Minor improvements in the GUI. 

    ----
    Version: 3.2.0
    7 September, 2015

    *SHA1:* 61CB4D160B4003FDF51FFACDB777FF0DC28D83D1

    *New Features*
    ** Report single or all classSchema objects default security descriptor.
    ** Option to select between DACL or SDDL output of default security descriptors.
    ** Displays forest information like FFL,DFL,Schema Version, Exchange and Lync Schema version.
    ----
    Version: 3.1.0
    2 September, 2015

    *SHA1:* EBBB7083BE00108B14B661016A0D049EFF092971

    *New Features*
    ** Option to show objectClass of objects reported
    ** Option skip ACE's for "Protect object from accidental deletion"
    ** Error control on .Net Framework CLRVersion
    ----
    Version: 3.0.1
    10 July, 2015


    *Fixed issues*
    ** Reporting on modified default security descriptors in Schema did not work in Windows 10 or Windows Server Technical Preview 2.
    ----
    Version: 3.0
    9 July, 2015

    *New Features*
    ** You can take a CSV file from one domain and use it for another. With replacing the old DN with the current domains you can resuse reports between domains. You can also replace the (Short domain name)Netbios name security principals.
    ** Reporting on modified default security descriptors in Schema.
    ** Verifying the format of the CSV files used in convert and compare functions.
    ** When comparing with CSV file Nodes missing in AD will be reported as "Node does not exist in AD"
    ** The progress bar can be disabled to gain speed in creating reports.
    ** If the fist node in the CSV file used for comparing can't be connected the scan will stop.

    *Fixed issues*
    ** Only the first node in the CSV file was used in the comparison the rest was skipped.
    ** If a node in the CSV file did not exist in AD, the comparison failed.  
    ----
    Version: 2.2.2
    7 July, 2015

    *Fixed issues*
    ** If you run AD ACL Scanner in Windows 10 or Windows Server Technical Preview 2 you would always get mismatch during comparing. Problem fixed with if statement on System.Enum in PowerShell 5. 
    ----
    Version: 2.2.1
    6 July, 2015

    *New Features*
    ** Number of excluded objects reported in Log.

    *Fixed issues*
    ** Broken scan! Everything are excluded when searching Onelevel or Subtree.
    ----
    Version: 2.2.0
    4 July, 2015

    *New Features*
    ** Refresh Nodes by right-click container object. 
    ** Exclude of objects from report by matching string to distinguishedName
    ----
    Version: 2.1.2
    2 July, 2015

    *Fixed issues*
    ** Every scan required SeSecurityPrivilege (Manage auditing and security log) due to modifications of the SecurityMasks. Now this is done only once you explicitly scan SACL's. 
    ----
    Version: 2.1.1
    12 June, 2015

    *Fixed issues*
    ** If you ran AD ACL Scanner in Windows 10 or Windows Server Technical Preview 2 you would get an error. Problem fixed with if statement on System.Enum in PowerShell 5. 
    ----
    Version: 2.1.0
    21 May, 2015

    *New Features*
    ** Changed format on CSV output file. New format according to regular CSV type.
    ** Removed dependency on Active Directory PowerShell module for reporting on SACL's.
    ** Rename html report headers, Rights are called Access and if SACL's is used it's called Audit.
    ** HTLM reports contain headers
    ** Summary of criticality for all report types
    ** Support statement included

    *Fixed issues*
    ** Owner permissions are changed to the more accurate :Read permissions, Modify permissions.
    ** Error when running PS 2.0 "ProgressBarWindow".
    ** Correct name of SPN report file.
    ** Criticality coloring of "Info"-level fixed.
    ** Added error control for enumerating objects.
    ----
    Version: 2.0.3
    29 October, 2014

    *Fixed issues*
    ** PS 2.0 "Where-Object : Cannot bind argument to 'FilterScript' because it is null":5369.
    ----
    Version: 2.0.2
    28 October, 2014

    *New Features*
    ** Scan for SACL's
    ** Option to skip Splash through new parameter "NoSplash"
    ** Option to show help text through new parameter "Help"
    ** Translation of object GUID in CSV file.

    *Fixed issues*
    ** Require connection to domain before converting CSV to  HTML, otherwise object GUID translation will fail.
    ----
    Version: 2.0.1
    15 October, 2014

    *Fixed issues*
    ** issues related to connecting to ForestDnsZones and DomainDnsZones
    ----
    Version: 2.0
    October, 2014

    *New Features*
    ** New GUI
    ** Progress Bar
    ** Better browsing experience
    ** Better logging function
    ** Bug fixes
#>
Param
(
    # DistinguishedName to start your search at. Always included as long as your filter matches your object.
    [Parameter(Mandatory=$false, 
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true, 
                ValueFromRemainingArguments=$false, 
                Position=0,
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Base,

    # Filter. Specify your custom filter. Default is OrganizationalUnit.
    [Parameter(Mandatory=$false, 
                Position=1,
                ParameterSetName='Default')]
    [validatescript({$_ -like "(*=*)"})]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Filter,

    # Scope. Set your scope. Default is base.
    [Parameter(Mandatory=$false, 
                Position=2,
                ParameterSetName='Default')]
    [ValidateSet("base", "onelevel", "subtree")]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Scope = "base",

    # Server. Specify your specific server to target your search at.
    [Parameter(Mandatory=$false, 
                Position=3,
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Server,

    # Port. Specify your custom port.
    [Parameter(Mandatory=$false, 
                Position=4,
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Port,

    # Output folder path for where results are written.
    [Parameter(Mandatory=$false, 
                Position=5,
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $OutputFolder,

    # Generates a HTML report, default is a CSV.
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $HTML,
    
    # Generates a EXCEL report, default is a CSV.
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $EXCEL,
        
    # Open HTML report
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $Show,

    # Data Managment Delegation OU Name
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $help
)

[string]$global:SessionID = [GUID]::NewGuid().Guid
[string]$global:ACLHTMLFileName = "ACLHTML-$SessionID"
[string]$global:SPNHTMLFileName = "SPNHTML-$SessionID"
[string]$global:ModifiedDefSDAccessFileName = "ModifiedDefSDAccess-$SessionID"
[string]$global:LegendHTMLFileName = "LegendHTML-$SessionID"

if([threading.thread]::CurrentThread.ApartmentState.ToString() -eq 'MTA')               
{               
  write-host -ForegroundColor RED "RUN PowerShell.exe with -STA switch"              
  write-host -ForegroundColor RED "Example:"              
  write-host -ForegroundColor RED "    PowerShell -STA $PSCommandPath"    

  Write-Host "Press any key to continue ..."
  [VOID]$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
  
  Exit
}
#Set global value for time out in paged searches
$global:TimeoutSeconds = 120
#Set global value for page size in paged searches
$global:PageSize = 1000
# Hash table for Forest Level
$global:ForestFLHashAD = @{
	0="Windows 2000 Server";
	1="Windows Server 2003/Interim";
	2="Windows Server 2003";
	3="Windows Server 2008";
	4="Windows Server 2008 R2";
	5="Windows Server 2012";
	6="Windows Server 2012 R2";
	7="Windows Server 2016"
}
#Hash table for Domain Level
$global:DomainFLHashAD = @{
	0="Windows 2000 Server";
	1="Windows Server 2003/Interim";
	2="Windows Server 2003";
	3="Windows Server 2008";
	4="Windows Server 2008 R2";
	5="Windows Server 2012";
	6="Windows Server 2012 R2";
	7="Windows Server 2016"
}
$global:SchemaHashAD = @{
	13="Windows 2000 Server";
	30="Windows Server 2003";
	31="Windows Server 2003 R2";
	44="Windows Server 2008";
	47="Windows Server 2008 R2";
	56="Windows Server 2012";
	69="Windows Server 2012 R2";
	72="Windows Server 2016 Technical Preview";
    81="Windows Server 2016 Technical Preview 2";
    82="Windows Server 2016 Technical Preview 3";
    85="Windows Server 2016 Technical Preview 4";
    87="Windows Server 2016"
}
	
# List of Exchange Schema versions
$global:SchemaHashExchange = @{
	4397="Exchange Server 2000";
	4406="Exchange Server 2000 SP3";
	6870="Exchange Server 2003";
	6936="Exchange Server 2003 SP3";
	10628="Exchange Server 2007";
	10637="Exchange Server 2007";
	11116="Exchange Server 2007 SP1";
	14622="Exchange Server 2007 SP2 or Exchange Server 2010";
	14726="Exchange Server 2010 SP1";
	14732="Exchange Server 2010 SP2";
	14734="Exchange Server 2010 SP3";
	15137="Exchange Server 2013 RTM";
	15254="Exchange Server 2013 CU1";
	15281="Exchange Server 2013 CU2";
	15283="Exchange Server 2013 CU3";
	15292="Exchange Server 2013 SP1/CU4";
	15300="Exchange Server 2013 CU5";
	15303="Exchange Server 2013 CU6";
	15312="Exchange Server 2013 CU7";
    15317="Exchange Server 2016";
    15323="Exchange Server 2016 CU1";
    15325="Exchange Server 2016 CU2";
    15326="Exchange Server 2016 CU3";
}
	
# List of Lync Schema versions
$global:SchemaHashLync = @{
	1006="LCS 2005";
	1007="OCS 2007 R1";
	1008="OCS 2007 R2";
	1100="Lync Server 2010";
	1150="Lync Server 2013"
}
Function BuildSchemaDic
{

$global:dicSchemaIDGUIDs = @{"BF967ABA-0DE6-11D0-A285-00AA003049E2" ="user";`
"BF967A86-0DE6-11D0-A285-00AA003049E2" = "computer";`
"BF967A9C-0DE6-11D0-A285-00AA003049E2" = "group";`
"BF967ABB-0DE6-11D0-A285-00AA003049E2" = "volume";`
"F30E3BBE-9FF0-11D1-B603-0000F80367C1" = "gPLink";`
"F30E3BBF-9FF0-11D1-B603-0000F80367C1" = "gPOptions";`
"BF967AA8-0DE6-11D0-A285-00AA003049E2" = "printQueue";`
"4828CC14-1437-45BC-9B07-AD6F015E5F28" = "inetOrgPerson";`
"5CB41ED0-0E4C-11D0-A286-00AA003049E2" = "contact";`
"BF967AA5-0DE6-11D0-A285-00AA003049E2" = "organizationalUnit";`
"BF967A0A-0DE6-11D0-A285-00AA003049E2" = "pwdLastSet"}


$global:dicNameToSchemaIDGUIDs = @{"user"="BF967ABA-0DE6-11D0-A285-00AA003049E2";`
"computer" = "BF967A86-0DE6-11D0-A285-00AA003049E2";`
"group" = "BF967A9C-0DE6-11D0-A285-00AA003049E2";`
"volume" = "BF967ABB-0DE6-11D0-A285-00AA003049E2";`
"gPLink" = "F30E3BBE-9FF0-11D1-B603-0000F80367C1";`
"gPOptions" = "F30E3BBF-9FF0-11D1-B603-0000F80367C1";`
"printQueue" = "BF967AA8-0DE6-11D0-A285-00AA003049E2";`
"inetOrgPerson" = "4828CC14-1437-45BC-9B07-AD6F015E5F28";`
"contact" = "5CB41ED0-0E4C-11D0-A286-00AA003049E2";`
"organizationalUnit" = "BF967AA5-0DE6-11D0-A285-00AA003049E2";`
"pwdLastSet" = "BF967A0A-0DE6-11D0-A285-00AA003049E2"}
}

BuildSchemaDic

Add-Type -Assembly PresentationFramework

$ADACLGui = [hashtable]::Synchronized(@{})

$global:myPID = $PID
$CurrentFSPath = split-path -parent $MyInvocation.MyCommand.Path
$strLastCacheGuidsDom = ""
$sd = ""


[xml]$xamlForm1 = @"
<Window x:Class="ADACLScanXAMLProj.MainWindow"

        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD ACL Scanner"  WindowStartupLocation="CenterScreen" Height="890" Width="1023" ResizeMode="CanResizeWithGrip" WindowState="Normal" >
    <Window.Background>
        <LinearGradientBrush>
            <LinearGradientBrush.Transform>
                <ScaleTransform x:Name="Scaler" ScaleX="1" ScaleY="1"/>
            </LinearGradientBrush.Transform>
            <GradientStop Color="#CC064A82" Offset="1"/>
            <GradientStop Color="#FF6797BF" Offset="0.7"/>
            <GradientStop Color="#FF6797BF" Offset="0.3"/>
            <GradientStop Color="#FFD4DBE1" Offset="0"/>
        </LinearGradientBrush>
    </Window.Background>
    <Window.Resources>
        <XmlDataProvider x:Name="xmlprov" x:Key="DomainOUData"/>
        <DrawingImage x:Name="FolderImage" x:Key="FolderImage"  >
            <DrawingImage.Drawing>
                <DrawingGroup>
                    <GeometryDrawing Brush="#FF3D85F5">
                        <GeometryDrawing.Geometry>
                            <RectangleGeometry Rect="3,6,32,22" RadiusX="0" RadiusY="0" />
                        </GeometryDrawing.Geometry>
                    </GeometryDrawing>
                    <GeometryDrawing Brush="#FF3D81F5">
                        <GeometryDrawing.Geometry>
                            <RectangleGeometry Rect="18,3,13,5" RadiusX="2" RadiusY="2" />
                        </GeometryDrawing.Geometry>
                    </GeometryDrawing>
                </DrawingGroup>
            </DrawingImage.Drawing>
        </DrawingImage>
        <HierarchicalDataTemplate x:Key="NodeTemplate" ItemsSource="{Binding XPath=OU}">
            <StackPanel Orientation="Horizontal">
                <Image Width="16" Height="16" Stretch="Fill" Source="{Binding XPath=@Img}"/>
                <TextBlock Text="{Binding XPath=@Name}" Margin="2,0,0,0" />
            </StackPanel>
        </HierarchicalDataTemplate>
    </Window.Resources>
    <ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
        <Grid HorizontalAlignment="Left" VerticalAlignment="Top" Height="850" Width="990">
        <StackPanel Orientation="Vertical" Margin="10,0,0,0">
            <StackPanel Orientation="Horizontal">
                <StackPanel Orientation="Vertical">
                    <TabControl x:Name="tabConnect" Background="AliceBlue"  HorizontalAlignment="Left" Height="250" Margin="0,10,0,0" VerticalAlignment="Top" Width="350">
                        <TabItem x:Name="tabNCSelect" Header="Connect" Width="85">
                            <StackPanel Orientation="Vertical" Margin="05,0">
                                <StackPanel Orientation="Horizontal">
                                    <RadioButton x:Name="rdbDSdef" Content="Domain" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="65" IsChecked="True"/>
                                    <RadioButton x:Name="rdbDSConf" Content="Config" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="61"/>
                                    <RadioButton x:Name="rdbDSSchm" Content="Schema" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="65"/>
                                    <RadioButton x:Name="rdbCustomNC" Content="Custom" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="65"/>
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="05,05,0,0"  >
                                    <Label x:Name="lblServer" Content="Server:"  HorizontalAlignment="Left" Height="28" Margin="0,0,0,0" Width="45"/>
                                    <TextBox x:Name="txtBdoxDSServer" HorizontalAlignment="Left" Height="18"  Text="" Width="150" Margin="0,0,0.0,0" IsEnabled="False"/>
                                    <Label x:Name="lblPort" Content="Port:"  HorizontalAlignment="Left" Height="28" Margin="10,0,0,0" Width="35"/>
                                    <TextBox x:Name="txtBdoxDSServerPort" HorizontalAlignment="Left" Height="18"  Text="" Width="45" Margin="0,0,0.0,0" IsEnabled="False"/>
                                </StackPanel>
                                <StackPanel Orientation="Vertical" Margin="05,05,0,0"  >
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0.0,0"  >
                                        <Label x:Name="lblDomain" Content="Naming Context:"  HorizontalAlignment="Left" Height="28" Margin="0,0,0,0" Width="110"/>
                                        <CheckBox x:Name="chkBoxCreds" Content="Credentials" HorizontalAlignment="Right" Margin="80,0,0,0" Height="18" />
                                    </StackPanel>

                                    <TextBox x:Name="txtBoxDomainConnect" HorizontalAlignment="Left" Height="18"  Text="rootDSE" Width="285" Margin="0,0,0.0,0" IsEnabled="False"/>
                                </StackPanel>
                                <StackPanel Orientation="Horizontal"  Margin="05,05,0,0"  >
                                    <Button x:Name="btnDSConnect" Content="Connect" HorizontalAlignment="Left" Height="23" Margin="0,2,0,0" VerticalAlignment="Top" Width="84"/>
                                    <Button x:Name="btnListDdomain" Content="List Domains" HorizontalAlignment="Left" Height="23" Margin="50,2,0,0" VerticalAlignment="Top" Width="95"/>
                                </StackPanel>

                                <GroupBox x:Name="gBoxBrowse" Grid.Column="0" Header="Browse Options" HorizontalAlignment="Left" Height="47" Margin="00,05,0,0" VerticalAlignment="Top" Width="290" BorderBrush="Black">
                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                        <StackPanel Orientation="Horizontal">
                                            <RadioButton x:Name="rdbBrowseOU" Content="OU's" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="61" IsChecked="True"/>
                                            <RadioButton x:Name="rdbBrowseAll" Content="All Objects" HorizontalAlignment="Left" Height="18" Margin="20,05,0,0" VerticalAlignment="Top" Width="80"/>
                                            <CheckBox x:Name="chkBoxShowDel" Content="Show Deleted" HorizontalAlignment="Right" Margin="10,05,0,0" Height="18" />
                                        </StackPanel>
                                    </StackPanel>
                                </GroupBox>
                            </StackPanel>
                        </TabItem>
                        <TabItem x:Name="tabForestInfo" Header="Forest Info" Width="85">
                            <StackPanel Orientation="Vertical" Margin="0,05" Width="345" HorizontalAlignment="Left">
                                <Button x:Name="btnGetForestInfo" Content="Get Forest Info" Margin="0,0,0,0" Width="280" Height="19" />
                                <StackPanel Orientation="Horizontal" Margin="0,05">
                                    <Label x:Name="lblFFL" Content="Forest Functional Level:" Width="150" Height="24"/>
                                    <TextBox x:Name="txtBoxFFL" Text=""  Width="170" Margin="05,0" Height="19" />
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,01">
                                    <Label x:Name="lblDFL" Content="Domain Functional Level:" Width="150" Height="24"/>
                                        <TextBox x:Name="txtBoxDFL" Text="" Width="170" Margin="05,0" Height="19" />
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,01">
                                    <Label x:Name="ldblADSchema" Content="AD Schema Version:" Width="150" Height="24"/>
                                        <TextBox x:Name="txtBoxADSchema" Text="" Width="170" Margin="05,0" Height="19" />
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,01">
                                    <Label x:Name="lblExchSchema" Content="Exchange Schema Version:" Width="150" Height="24"/>
                                        <TextBox x:Name="txtBoxExSchema" Text="" Width="170" Margin="05,0" Height="19" />
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,01">
                                    <Label x:Name="lblLyncSchema" Content="Lync Schema Version:" Width="150" Height="24" VerticalAlignment="Top"/>
                                        <TextBox x:Name="txtBoxLyncSchema" Text="" Width="170" Margin="05,0,0,0" Height="19" />
                                </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,01">
                                        <Label x:Name="lblListObjectMode" Content="List Object Mode:" Width="150" Height="24" VerticalAlignment="Top"/>
                                        <TextBox x:Name="txtListObjectMode" Text="" Width="170" Margin="05,0,0,0" Height="19" />
                                    </StackPanel>
                                </StackPanel>
                        </TabItem>
                        <TabItem x:Name="tabConnectionInfo" Header="Connection Info" Width="100" Margin="0,0,0,0">
                            <StackPanel Orientation="Vertical" Margin="0,0" HorizontalAlignment="Left" Width="345">
                                 <Label x:Name="lblDC" Content="Domain Controller:" Width="175" Height="24" HorizontalAlignment="Left" />
                                <TextBox x:Name="txtDC" Text=""  Width="320" Margin="05,0" Height="19" HorizontalAlignment="Left"  />
                                <Label x:Name="lbldefaultnamingcontext" Content="Default Naming Context:" Width="175" Height="24" HorizontalAlignment="Left" />
                                    <TextBox x:Name="txtdefaultnamingcontext" Text="" Width="320" Margin="05,0" Height="19" HorizontalAlignment="Left" />
                                <Label x:Name="lblconfigurationnamingcontext" Content="Configuration Naming Context:" Width="175" Height="24" HorizontalAlignment="Left" />
                                    <TextBox x:Name="txtconfigurationnamingcontext" Text="" Width="320" Margin="05,0" Height="19" HorizontalAlignment="Left"  />
                                <Label x:Name="lblschemanamingcontext" Content="Schema Naming Context:" Width="175" Height="24" HorizontalAlignment="Left" />
                                    <TextBox x:Name="txtschemanamingcontext" Text="" Width="320" Margin="05,0" Height="19" HorizontalAlignment="Left"  />
                                <Label x:Name="lblrootdomainnamingcontext" Content="Root Domain Naming Context:" Width="175" Height="24" HorizontalAlignment="Left" />
                                    <TextBox x:Name="txtrootdomainnamingcontext" Text="" Width="320" Margin="05,0,0,0" Height="19" HorizontalAlignment="Left"  />
                            </StackPanel>
                        </TabItem>                        
                    </TabControl>
                    <GroupBox x:Name="gBoxSelectNodeTreeView" Grid.Column="0" Header="Nodes" HorizontalAlignment="Left" Height="355" Margin="0,0,0,0" VerticalAlignment="Top" Width="350" BorderBrush="Black">
                        <StackPanel Orientation="Vertical">
                            <TreeView x:Name="treeView1"  Height="330" Width="340"  Margin="0,5,0,5" HorizontalAlignment="Left"
                DataContext="{Binding Source={StaticResource DomainOUData}, XPath=/DomainRoot}"
                ItemTemplate="{StaticResource NodeTemplate}"
                ItemsSource="{Binding}">
                                <TreeView.ContextMenu>
                                    <ContextMenu x:Name="ContextMUpdateNode"  >
                                        <MenuItem Header="Refresh Childs">
                                            <MenuItem.Icon>
                                                <Image Width="15" Height="15" Source="{Binding XPath=@Icon}" />
                                            </MenuItem.Icon>
                                        </MenuItem>
                                        <MenuItem Header="Exclude Node">
                                            <MenuItem.Icon>
                                                <Image Width="15" Height="15" Source="{Binding XPath=@Icon2}" />
                                            </MenuItem.Icon>
                                        </MenuItem>
                                    </ContextMenu>

                                </TreeView.ContextMenu>
                            </TreeView>
                        </StackPanel>
                    </GroupBox>
                </StackPanel>
                <TabControl x:Name="tabConWiz" HorizontalAlignment="Left" Height="610" Margin="10,10,0,0" VerticalAlignment="Top" Width="612">
                    <TabItem x:Name="tabAdv" Header="Advanced" Height="22" VerticalAlignment="Top" >
                        <Grid Background="AliceBlue" HorizontalAlignment="Left" VerticalAlignment="Top" Height="580">
                                <StackPanel Orientation="Vertical">
                                <StackPanel Orientation="Horizontal">
                                <TabControl x:Name="tabScanTop" Background="AliceBlue"  HorizontalAlignment="Left" Height="550"  VerticalAlignment="Top" Width="300">
                                    <TabItem x:Name="tabScan" Header="Scan Options" Width="85">
                                        <Grid >
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <GroupBox x:Name="gBoxScanType" Header="Scan Type" HorizontalAlignment="Left" Height="71" Margin="2,1,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbDACL" Content="DACL (Access)" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="95" IsChecked="True"/>
                                                            <RadioButton x:Name="rdbSACL" Content="SACL (Audit)" HorizontalAlignment="Left" Height="18" Margin="20,10,0,0" VerticalAlignment="Top" Width="90"/>

                                                        </StackPanel>
                                                                <StackPanel Orientation="Horizontal" Height="35" Margin="0,0,0.2,0">
                                                                    <CheckBox x:Name="chkBoxRAWSDDL" Content="RAW SDDL" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                                </StackPanel>
                                                            </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxScanDepth" Header="Scan Depth" HorizontalAlignment="Left" Height="51" Margin="2,1,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbBase" Content="Base" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="61" IsChecked="True"/>
                                                            <RadioButton x:Name="rdbOneLevel" Content="One Level" HorizontalAlignment="Left" Height="18" Margin="20,10,0,0" VerticalAlignment="Top" Width="80"/>
                                                            <RadioButton x:Name="rdbSubtree" Content="Subtree" HorizontalAlignment="Left" Height="18" Margin="20,10,0,0" VerticalAlignment="Top" Width="80"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxRdbScan" Header="Objects to scan" HorizontalAlignment="Left" Height="75" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbScanOU" Content="OUs" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="61" IsChecked="True" GroupName="rdbGroupFilter"/>
                                                            <RadioButton x:Name="rdbScanContainer" Content="Containers" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="80" GroupName="rdbGroupFilter"/>
                                                            <RadioButton x:Name="rdbScanAll" Content="All Objects" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="80" GroupName="rdbGroupFilter"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbScanFilter" Content="" HorizontalAlignment="Left" Height="18" Margin="5,5,0,0" VerticalAlignment="Top" Width="15" GroupName="rdbGroupFilter"/>
                                                            <TextBox x:Name="txtCustomFilter" Text="(objectClass=*)" HorizontalAlignment="Left" Height="18" Width="250" Margin="0,0,0.0,0" IsEnabled="False"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxReportOpt" Header="View in report" HorizontalAlignment="Left" Height="165" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <CheckBox x:Name="chkBoxGetOwner" Content="View Owner" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                            <CheckBox x:Name="chkBoxACLSize" Content="DACL Size" HorizontalAlignment="Left" Height="18" Margin="30,05,0,0" VerticalAlignment="Top" Width="80"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal" Margin="0,0,0.2,0" Height="35">
                                                            <CheckBox x:Name="chkInheritedPerm" Content="Inherited&#10;Permissions" HorizontalAlignment="Left" Height="30" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                                <CheckBox x:Name="chkBoxGetOUProtected" Content="Inheritance&#10;Disabled" HorizontalAlignment="Left" Height="30" Margin="30,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal" Height="35" Margin="0,0,0.2,0">
                                                            <CheckBox x:Name="chkBoxDefaultPerm" Content="Skip Default&#10;Permissions" HorizontalAlignment="Left" Height="30" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                            <CheckBox x:Name="chkBoxReplMeta" Content="SD Modified date" HorizontalAlignment="Left" Height="30" Margin="30,05,0,0" VerticalAlignment="Top" Width="120"/>

                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal" Height="35" Margin="0,0,0.2,0">
                                                            <CheckBox x:Name="chkBoxSkipProtectedPerm" Content="Skip Protected&#10;Permissions" HorizontalAlignment="Left" Height="30" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                            <CheckBox x:Name="chkBoxObjType" Content="ObjectClass" HorizontalAlignment="Left" Height="30" Margin="30,05,0,0" VerticalAlignment="Top" Width="90"/>
                                                        </StackPanel>

                                                            </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxRdbFile" Header="Output Options" HorizontalAlignment="Left" Height="158" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbOnlyHTA" Content="HTML" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="61" GroupName="rdbGroupOutput" IsChecked="True"/>
                                                            <RadioButton x:Name="rdbHTAandCSV" Content="HTML and CSV file" HorizontalAlignment="Left" Height="18" Margin="20,05,0,0" VerticalAlignment="Top" Width="155" GroupName="rdbGroupOutput"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal">
                                                        <RadioButton x:Name="rdbOnlyCSV" Content="CSV file" HorizontalAlignment="Left" Height="18" Margin="5,02,0,0" VerticalAlignment="Top" Width="61" GroupName="rdbGroupOutput"/>
                                                        <RadioButton x:Name="rdbEXcel" Content="Excel file" HorizontalAlignment="Left" Height="18" Margin="20,05,0,0" VerticalAlignment="Top" Width="155" GroupName="rdbGroupOutput"/>
                                                        </StackPanel>
                                                        <CheckBox x:Name="chkBoxTranslateGUID" Content="Translate GUID's in CSV output" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="200"/>
                                                        <Label x:Name="lblTempFolder" Content="CSV file destination" />
                                                        <TextBox x:Name="txtTempFolder" Margin="0,0,02,0"/>
                                                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" >
                                                            <Button x:Name="btnGetTemplateFolder" Content="Change Folder" Margin="5,05,0,0" />
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                            </StackPanel>
                                        </Grid>
                                    </TabItem>
                                    <TabItem x:Name="tabOfflineScan" Header="Additional Options">
                                        <Grid>
                                            <StackPanel>
                                                <GroupBox x:Name="gBoxImportCSV" Header="CSV to HTML" HorizontalAlignment="Left" Height="136" Margin="2,1,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <Label x:Name="lblCSVImport" Content="This file will be converted HTML:" />
                                                        <TextBox x:Name="txtCSVImport"/>
                                                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                                                            <Button x:Name="btnGetCSVFile" Content="Select CSV" />
                                                        </StackPanel>
                                                        <CheckBox x:Name="chkBoxTranslateGUIDinCSV" Content="CSV file do not contain object GUIDs" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="290"/>
                                                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                                                            <Button x:Name="btnCreateHTML" Content="Create HTML View" />
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxCriticality" Header="Access Rights Criticality" HorizontalAlignment="Left" Height="150" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <CheckBox x:Name="chkBoxEffectiveRightsColor" Content="Show color coded criticality" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top" IsEnabled="True"/>
                                                        <Label x:Name="lblEffectiveRightsColor" Content="Use colors in report to identify criticality level of &#10;permissions.This might help you in implementing &#10;Least-Privilege Administrative Models" />
                                                        <Button x:Name="btnViewLegend" Content="View Color Legend" HorizontalAlignment="Left" Margin="5,0,0,0" IsEnabled="True" Width="110"/>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxProgress" Header="Progress Bar" HorizontalAlignment="Left" Height="75" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <CheckBox x:Name="chkBoxSkipProgressBar" Content="Use Progress Bar" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top" IsEnabled="True" IsChecked="True"/>
                                                        <Label x:Name="lblSkipProgressBar" Content="For speed you could disable the progress bar." />
                                                    </StackPanel>
                                                </GroupBox>
                                            </StackPanel>
                                        </Grid>
                                    </TabItem>
                                    <TabItem x:Name="tabOther" Header="Default SD">
                                        <Grid>
                                            <StackPanel>
                                                <StackPanel Orientation="Vertical" Margin="0,0,0,-40">
                                                    <GroupBox x:Name="gBoxdDefSecDesc" Header="Output Format" HorizontalAlignment="Left" Height="45" Margin="0,0,0,0" VerticalAlignment="Top" Width="290">
                                                        <StackPanel Orientation="Horizontal" Margin="0,0">
                                                            <RadioButton x:Name="rdbDefSD_Access" Content="DACL" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="50" IsChecked="True"/>
                                                            <RadioButton x:Name="rdbDefSD_SDDL" Content="SDDL" HorizontalAlignment="Left" Height="18" Margin="10,05,0,0" VerticalAlignment="Top" Width="50"/>
                                                        </StackPanel>
                                                    </GroupBox>
                                                    <CheckBox x:Name="chkModifedDefSD" Content="Only modified defaultSecurityDescriptors" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top"/>
                                                    <Label x:Name="lblObjectDefSD" Content="Select objects to scan:" />
                                                    <StackPanel Orientation="Horizontal" Margin="0,0">
                                                        <ComboBox x:Name="combObjectDefSD" HorizontalAlignment="Left" Margin="05,05,00,00" VerticalAlignment="Top" Width="120" IsEnabled="True" SelectedValue="*"/>
                                                        <Button x:Name="btnScanDefSD" Content="Run Scan" HorizontalAlignment="Right" Width="90" Height="19" Margin="37,05,00,00" IsEnabled="True"/>
                                                    </StackPanel>
                                                    <StackPanel Orientation="Horizontal" Margin="0,0">
                                                        <Button x:Name="btnGetSchemaClass" Content="Load all classSchema" HorizontalAlignment="Left" Width="120" Height="19" Margin="05,05,00,00" IsEnabled="True"/>
                                                        <Button x:Name="btnExportDefSD" Content="Export to CSV" HorizontalAlignment="Right" Width="90" Height="19" Margin="37,05,00,00" IsEnabled="True"/>
                                                    </StackPanel>
                                  
                                                    <GroupBox x:Name="gBoxdDefSecDescCompare" Header="Compare" HorizontalAlignment="Left" Height="260" Margin="0,0,0,0" VerticalAlignment="Top" Width="290">
                                                        <StackPanel  Margin="0,0">
                                                       
                                                        <Label x:Name="lblCompareDefSDText" Content="You can compare the current state with  &#10;a previously created CSV file." />
                                                        <Label x:Name="lblCompareDefSDTemplate" Content="CSV Template File" />
                                                        <TextBox x:Name="txtCompareDefSDTemplate" Margin="2,0,0,0" Width="275" IsEnabled="True"/>
                                                        <Button x:Name="btnGetCompareDefSDInput" Content="Select Template" HorizontalAlignment="Right" Width="90" Height="19" Margin="162,05,00,00" IsEnabled="True"/>
                                                        <Button x:Name="btnCompDefSD" Content="Run Compare" HorizontalAlignment="Right" Width="90" Height="19" Margin="162,05,00,00" IsEnabled="True"/>
                                                                    <Label x:Name="lblDownloadCSVDefSD" Content="Download CSV templates for comparing with&#10;your defaultSecurityDescriptors:" Margin="05,20,00,00" />
                                                                    <Button x:Name="btnDownloadCSVDefSD" Content="Download CSV Templates" HorizontalAlignment="Left" Width="140" Height="19" Margin="05,05,00,00" IsEnabled="True"/>
                                                        </StackPanel>
                                                    </GroupBox>
                                                </StackPanel>
                                            </StackPanel>
                                        </Grid>
                                    </TabItem>
                                </TabControl>
                                <TabControl x:Name="tabFilterTop" Background="AliceBlue"  HorizontalAlignment="Left" Height="550" Margin="4,0,0,0" VerticalAlignment="Top" Width="300">
                                    <TabItem x:Name="tabCompare" Header="Compare">
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="34*"/>
                                                <ColumnDefinition Width="261*"/>
                                            </Grid.ColumnDefinitions>
                                            <StackPanel Orientation="Vertical" Margin="0,0" HorizontalAlignment="Left" Grid.ColumnSpan="2">

                                                <CheckBox x:Name="chkBoxCompare" Content="Enable Compare" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top"/>
                                                <Label x:Name="lblCompareDescText" Content="You can compare the current state with  &#10;a previously created CSV file." />
                                                <Label x:Name="lblCompareTemplate" Content="CSV Template File" />
                                                <TextBox x:Name="txtCompareTemplate" Margin="2,0,0,0" Width="275" IsEnabled="False"/>
                                                <Button x:Name="btnGetCompareInput" Content="Select Template" HorizontalAlignment="Right" Height="19" Margin="65,00,00,00" IsEnabled="False"/>
                                                <StackPanel Orientation="Vertical">
                                                    <CheckBox x:Name="chkBoxTemplateNodes" Content="Use nodes from template." HorizontalAlignment="Left" Width="160" Margin="2,5,00,00" IsEnabled="False" />
                                                    <CheckBox x:Name="chkBoxScanUsingUSN" Content="Faster compare using USNs of the&#10;NTSecurityDescriptor. This requires that your &#10;template to contain USNs.Requires SD Modified&#10;date selected when creating the template." HorizontalAlignment="Left"  Width="280" Margin="2,5,00,00" IsEnabled="False" />                                                        
                                                </StackPanel>
                                                <Label x:Name="lblReplaceDN" Content="Replace DN in file with current domain DN.&#10;E.g. DC=contoso,DC=com&#10;Type the old DN to be replaced:" />
                                                <TextBox x:Name="txtReplaceDN" Margin="2,0,0,0" Width="250" IsEnabled="False"/>
                                                <Label x:Name="lblReplaceNetbios" Content="Replace principals prefixed domain name with&#10;current domain. E.g. CONTOSO&#10;Type the old NETBIOS name to be replaced:" />
                                                <TextBox x:Name="txtReplaceNetbios" Margin="2,0,0,0" Width="250" IsEnabled="False"/>
                                                        <Label x:Name="lblDownloadCSVDefACLs" Content="Download CSV templates for comparing with&#10;your environment:" Margin="05,20,00,00" />
                                                        <Button x:Name="btnDownloadCSVDefACLs" Content="Download CSV Templates" HorizontalAlignment="Left" Width="140" Height="19" Margin="05,05,00,00" IsEnabled="True"/>
                                                    </StackPanel>
                                        </Grid>
                                    </TabItem>
                                    <TabItem x:Name="tabFilter" Header="Filter">
                                        <Grid>
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <CheckBox x:Name="chkBoxFilter" Content="Enable Filter" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top"/>
                                                <Label x:Name="lblAccessCtrl" Content="Filter by Access Type:(example: Allow)" />
                                                <StackPanel Orientation="Horizontal" Margin="0,0">
                                                    <CheckBox x:Name="chkBoxType" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                    <ComboBox x:Name="combAccessCtrl" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="False"/>
                                                </StackPanel>
                                                <Label x:Name="lblFilterExpl" Content="Filter by Object:(example: user)" />
                                                <StackPanel Orientation="Horizontal" Margin="0,0">
                                                    <CheckBox x:Name="chkBoxObject" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                    <ComboBox x:Name="combObjectFilter" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="False"/>
                                                </StackPanel>
                                                <Label x:Name="lblGetObj" Content="The list box contains a few  number of standard &#10;objects. To load all objects from schema &#10;press Load." />
                                                <StackPanel  Orientation="Horizontal" Margin="0,0">

                                                    <Label x:Name="lblGetObjExtend" Content="This may take a while!" />
                                                    <Button x:Name="btnGetObjFullFilter" Content="Load" IsEnabled="False" Width="50" />
                                                </StackPanel>
                                                <Label x:Name="lblFilterTrusteeExpl" Content="Filter by Trustee:&#10;Examples:&#10;CONTOSO\User&#10;CONTOSO\JohnDoe*&#10;*Smith&#10;*Doe*" />
                                                <StackPanel Orientation="Horizontal" Margin="0,0">
                                                    <CheckBox x:Name="chkBoxTrustee" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                    <TextBox x:Name="txtFilterTrustee" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="False"/>
                                                </StackPanel>
                                            </StackPanel>
                                        </Grid>
                                    </TabItem>
                                    <TabItem x:Name="tabEffectiveR" Header="Effective Rights">
                                        <Grid >
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <CheckBox x:Name="chkBoxEffectiveRights" Content="Enable Effective Rights" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top"/>
                                                <Label x:Name="lblEffectiveDescText" Content="Effective Access allows you to view the effective &#10;permissions for a user, group, or device account." />
                                                <Label x:Name="lblEffectiveText" Content="Type the account name (samAccountName) for a &#10;user, group or computer" />
                                                <Label x:Name="lblSelectPrincipalDom" Content=":" />
                                                <TextBox x:Name="txtBoxSelectPrincipal" IsEnabled="False"  />
                                                <StackPanel  Orientation="Horizontal" Margin="0,0">
                                                    <Button x:Name="btnGetSPAccount" Content="Get Account" Margin="5,0,0,0" IsEnabled="False"/>
                                                    <Button x:Name="btnListLocations" Content="Locations..." Margin="50,0,0,0" IsEnabled="False"/>
                                                </StackPanel>
                                                <StackPanel  Orientation="Vertical" Margin="0,0"   >
                                                    <GroupBox x:Name="gBoxEffectiveSelUser" Header="Selected Security Principal:" HorizontalAlignment="Left" Height="50" Margin="2,2,0,0" VerticalAlignment="Top" Width="290">
                                                        <StackPanel Orientation="Vertical" Margin="0,0">
                                                            <Label x:Name="lblEffectiveSelUser" Content="" />
                                                        </StackPanel>
                                                    </GroupBox>
                                                    <Button x:Name="btnGETSPNReport" HorizontalAlignment="Left" Content="View Account" Margin="5,2,0,0" IsEnabled="False" Width="110"/>
                                                </StackPanel>
                                            </StackPanel>
                                        </Grid>
                                    </TabItem>

                                </TabControl>
                            </StackPanel>
                            <Button x:Name="btnScan" Content="Run Scan" HorizontalAlignment="Left" Height="19" Margin="500,5,0,0" VerticalAlignment="Top" Width="66"/>
                                    </StackPanel>
                        </Grid>
                    </TabItem>
                </TabControl>
            </StackPanel>
            <StackPanel >

                <Label x:Name="lblSelectedNode" Content="Selected Object:" HorizontalAlignment="Left" Height="26" Margin="0,0,0,0" VerticalAlignment="Top" Width="158"/>

                <StackPanel Orientation="Horizontal" >
                    <TextBox x:Name="txtBoxSelected" HorizontalAlignment="Left" Height="20" Margin="0,0,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="710"/>
                    <Button x:Name="btnExit" Content="Exit" HorizontalAlignment="Left" Margin="150,0,0,0" VerticalAlignment="Top" Width="75"/>
                </StackPanel>
                <Label x:Name="lblExcludeddNode" Content="Excluded Path (matching string in distinguishedName):" HorizontalAlignment="Left" Height="26" Margin="0,0,0,0" VerticalAlignment="Top" Width="300"/>
                <StackPanel Orientation="Horizontal">
                    <TextBox x:Name="txtBoxExcluded" HorizontalAlignment="Left" Height="20" Margin="0,0,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="710" />
                    <Button x:Name="btnClearExcludedBox" Content="Clear"  Height="21" Margin="10,0,0,0" IsEnabled="true" Width="100"/>
                </StackPanel>
                <Label x:Name="lblStatusBar" Content="Log:" HorizontalAlignment="Left" Height="26" Margin="0,0,0,0" VerticalAlignment="Top" Width="158"/>
                    <StackPanel Orientation="Horizontal" >
                <ListBox x:Name="TextBoxStatusMessage" DisplayMemberPath="Message" SelectionMode="Extended" HorizontalAlignment="Left" Height="100" Margin="0,0,0,0" VerticalAlignment="Top" Width="710" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                    <ListBox.ItemContainerStyle>
                        <Style TargetType="{x:Type ListBoxItem}">
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding Path=Type}" Value="Error">
                                    <Setter Property="ListBoxItem.Foreground" Value="Red" />
                                    <Setter Property="ListBoxItem.Background" Value="LightGray" />
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Path=Type}" Value="Warning">
                                    <Setter Property="ListBoxItem.Foreground" Value="Yellow" />
                                    <Setter Property="ListBoxItem.Background" Value="Gray" />
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Path=Type}" Value="Info">
                                    <Setter Property="ListBoxItem.Foreground" Value="Black" />
                                    <Setter Property="ListBoxItem.Background" Value="White" />
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </ListBox.ItemContainerStyle>
                </ListBox>
                    <StackPanel Orientation="Horizontal" Margin="62,0,0,0">
                    <StackPanel Orientation="Vertical">
                        <Label x:Name="lblStyleVersion3" Content="L" HorizontalAlignment="Left" Height="38" Margin="0,0,0,0" VerticalAlignment="Top"  Width="40" Background="#FF00AEEF" FontFamily="Webdings" FontSize="36" VerticalContentAlignment="Center" HorizontalContentAlignment="Center" Padding="2,0,0,0"/>
                        <Label x:Name="lblStyleVersion4" Content="d" HorizontalAlignment="Left" Height="38" Margin="0,3,0,0" VerticalAlignment="Top"  Width="40" Background="#FFFF5300" FontFamily="Webdings" FontSize="36" VerticalContentAlignment="Center" HorizontalContentAlignment="Center" Padding="2,0,0,0" />
                    </StackPanel>
                    <StackPanel Orientation="Vertical" >
                        <Label x:Name="lblStyleVersion1" Content="AD ACL Scanner &#10;5.4.2" HorizontalAlignment="Left" Height="40" Margin="0,0,0,0" VerticalAlignment="Top" Width="159" Foreground="#FFF4F0F0" Background="#FF004080" FontWeight="Bold"/>
                        <Label x:Name="lblStyleVersion2" Content="written by &#10;robin.granberg@microsoft.com" HorizontalAlignment="Left" Height="40" Margin="0,0,0,0" VerticalAlignment="Top" Width="159" Foreground="#FFF4F0F0" Background="#FF004080" FontSize="10"/>
                        <Button x:Name="btnSupport" Height="23" Tag="Support Statement"  Margin="0,0,0,0" Foreground="#FFF6F6F6" HorizontalAlignment="Right">
                            <TextBlock TextDecorations="Underline" Text="{Binding Path=Tag, RelativeSource={RelativeSource Mode=FindAncestor, AncestorType={x:Type Button}}}" />
                            <Button.Template>
                                <ControlTemplate TargetType="{x:Type Button}">
                                    <ContentPresenter />
                                </ControlTemplate>
                            </Button.Template>
                        </Button>

                    </StackPanel>
                </StackPanel>
            </StackPanel>
        </StackPanel>
        </StackPanel>

    </Grid>
    </ScrollViewer>
</Window>

"@

$xamlForm1.Window.RemoveAttribute("x:Class")  

$reader=(New-Object System.Xml.XmlNodeReader  $xamlForm1)
$ADACLGui.Window=[Windows.Markup.XamlReader]::Load( $reader )


$tabAdv = $ADACLGui.Window.FindName("tabAdv")
$xmlprov_adp = $ADACLGui.Window.FindName("xmlprov")
$chkBoxTemplateNodes = $ADACLGui.Window.FindName("chkBoxTemplateNodes")
$chkBoxScanUsingUSN = $ADACLGui.Window.FindName("chkBoxScanUsingUSN")
$rdbDACL = $ADACLGui.Window.FindName("rdbDACL")
$rdbSACL = $ADACLGui.Window.FindName("rdbSACL")
$lblSelectPrincipalDom = $ADACLGui.Window.FindName("lblSelectPrincipalDom")
$lblEffectiveSelUser = $ADACLGui.Window.FindName("lblEffectiveSelUser")
$chkBoxEffectiveRights = $ADACLGui.Window.FindName("chkBoxEffectiveRights")
$chkBoxEffectiveRightsColor = $ADACLGui.Window.FindName("chkBoxEffectiveRightsColor")
$chkBoxSkipProgressBar = $ADACLGui.Window.FindName("chkBoxSkipProgressBar")
$chkBoxGetOUProtected = $ADACLGui.Window.FindName("chkBoxGetOUProtected")
$chkBoxGetOwner = $ADACLGui.Window.FindName("chkBoxGetOwner")
$chkBoxReplMeta = $ADACLGui.Window.FindName("chkBoxReplMeta")
$chkBoxACLSize = $ADACLGui.Window.FindName("chkBoxACLSize")
$chkBoxType = $ADACLGui.Window.FindName("chkBoxType")
$chkBoxObject = $ADACLGui.Window.FindName("chkBoxObject")
$chkBoxTrustee = $ADACLGui.Window.FindName("chkBoxTrustee")
$btnGETSPNReport = $ADACLGui.Window.FindName("btnGETSPNReport")
$btnGetSPAccount = $ADACLGui.Window.FindName("btnGetSPAccount")
$btnGetObjFullFilter = $ADACLGui.Window.FindName("btnGetObjFullFilter")
$btnViewLegend = $ADACLGui.Window.FindName("btnViewLegend")
$combObjectFilter = $ADACLGui.Window.FindName("combObjectFilter")
$combAccessCtrl = $ADACLGui.Window.FindName("combAccessCtrl")
$txtFilterTrustee = $ADACLGui.Window.FindName("txtFilterTrustee")
$chkBoxFilter = $ADACLGui.Window.FindName("chkBoxFilter")
$txtBoxSelectPrincipal = $ADACLGui.Window.FindName("txtBoxSelectPrincipal")
$txtTempFolder = $ADACLGui.Window.FindName("txtTempFolder")
$txtCompareTemplate = $ADACLGui.Window.FindName("txtCompareTemplate")
$TextBoxStatusMessage = $ADACLGui.Window.FindName("TextBoxStatusMessage")
$rdbCustomNC = $ADACLGui.Window.FindName("rdbCustomNC")
$rdbOneLevel = $ADACLGui.Window.FindName("rdbOneLevel")
$rdbSubtree = $ADACLGui.Window.FindName("rdbSubtree")
$rdbDSdef = $ADACLGui.Window.FindName("rdbDSdef")
$rdbDSConf = $ADACLGui.Window.FindName("rdbDSConf")
$rdbDSSchm = $ADACLGui.Window.FindName("rdbDSSchm")
$btnDSConnect = $ADACLGui.Window.FindName("btnDSConnect")
$btnListDdomain = $ADACLGui.Window.FindName("btnListDdomain")
$btnListLocations = $ADACLGui.Window.FindName("btnListLocations")
$txtCSVImport = $ADACLGui.Window.FindName("txtCSVImport")
$rdbBase = $ADACLGui.Window.FindName("rdbBase")
$chkInheritedPerm = $ADACLGui.Window.FindName("chkInheritedPerm")
$chkBoxDefaultPerm = $ADACLGui.Window.FindName("chkBoxDefaultPerm")
$txtCustomFilter = $ADACLGui.Window.FindName("txtCustomFilter")
$rdbScanOU = $ADACLGui.Window.FindName("rdbScanOU")
$rdbScanContainer = $ADACLGui.Window.FindName("rdbScanContainer")
$rdbScanAll = $ADACLGui.Window.FindName("rdbScanAll")
$rdbScanFilter = $ADACLGui.Window.FindName("rdbScanFilter")
$txtCustomFilter = $ADACLGui.Window.FindName("txtCustomFilter")
$rdbHTAandCSV = $ADACLGui.Window.FindName("rdbHTAandCSV")
$rdbOnlyHTA = $ADACLGui.Window.FindName("rdbOnlyHTA")
$rdbOnlyCSV = $ADACLGui.Window.FindName("rdbOnlyCSV")
$txtBoxSelected = $ADACLGui.Window.FindName("txtBoxSelected")
$txtBoxDomainConnect = $ADACLGui.Window.FindName("txtBoxDomainConnect")
$rdbBrowseAll = $ADACLGui.Window.FindName("rdbBrowseAll")
$btnScan = $ADACLGui.Window.FindName("btnScan")
$lblHeader = $ADACLGui.Window.FindName("lblHeader")
$treeView1 = $ADACLGui.Window.FindName("treeView1")
$chkBoxCompare = $ADACLGui.Window.FindName("chkBoxCompare")
$btnGetTemplateFolder = $ADACLGui.Window.FindName("btnGetTemplateFolder")
$btnGetCompareInput = $ADACLGui.Window.FindName("btnGetCompareInput")
$btnExit = $ADACLGui.Window.FindName("btnExit")
$btnGetCSVFile = $ADACLGui.Window.FindName("btnGetCSVFile")
$btnCreateHTML = $ADACLGui.Window.FindName("btnCreateHTML")
$chkBoxTranslateGUID = $ADACLGui.Window.FindName("chkBoxTranslateGUID")
$chkBoxTranslateGUIDinCSV = $ADACLGui.Window.FindName("chkBoxTranslateGUIDinCSV")
$btnSupport = $ADACLGui.Window.FindName("btnSupport")
$txtBoxExcluded = $ADACLGui.Window.FindName("txtBoxExcluded")
$btnClearExcludedBox = $ADACLGui.Window.FindName("btnClearExcludedBox")
$chkBoxSkipProtectedPerm = $ADACLGui.Window.FindName("chkBoxSkipProtectedPerm")
$txtReplaceDN = $ADACLGui.Window.FindName("txtReplaceDN")
$txtReplaceNetbios = $ADACLGui.Window.FindName("txtReplaceNetbios")
$chkBoxObjType = $ADACLGui.Window.FindName("chkBoxObjType")
$combObjectDefSD = $ADACLGui.Window.FindName("combObjectDefSD")
$btnScanDefSD = $ADACLGui.Window.FindName("btnScanDefSD")
$btnGetSchemaClass = $ADACLGui.Window.FindName("btnGetSchemaClass")
$rdbDefSD_SDDL = $ADACLGui.Window.FindName("rdbDefSD_SDDL")
$btnGetForestInfo = $ADACLGui.Window.FindName("btnGetForestInfo")
$txtBoxExSchema = $ADACLGui.Window.FindName("txtBoxExSchema")
$txtBoxLyncSchema = $ADACLGui.Window.FindName("txtBoxLyncSchema")
$txtBoxADSchema = $ADACLGui.Window.FindName("txtBoxADSchema")
$txtBoxDFL = $ADACLGui.Window.FindName("txtBoxDFL")
$txtBoxFFL = $ADACLGui.Window.FindName("txtBoxFFL")
$rdbDefSD_SDDL = $ADACLGui.Window.FindName("rdbDefSD_SDDL")
$txtBdoxDSServerPort = $ADACLGui.Window.FindName("txtBdoxDSServerPort")
$txtBdoxDSServer = $ADACLGui.Window.FindName("txtBdoxDSServer")
$chkBoxCreds = $ADACLGui.Window.FindName("chkBoxCreds")
$chkBoxShowDel = $ADACLGui.Window.FindName("chkBoxShowDel")
$btnGetCompareDefSDInput = $ADACLGui.Window.FindName("btnGetCompareDefSDInput")
$txtCompareTemplate = $ADACLGui.Window.FindName("txtCompareTemplate")
$txtCompareDefSDTemplate = $ADACLGui.Window.Findname("txtCompareDefSDTemplate")
$btnCompDefSD = $ADACLGui.Window.Findname("btnCompDefSD")
$btnExportDefSD = $ADACLGui.Window.Findname("btnExportDefSD")
$chkModifedDefSD = $ADACLGui.Window.Findname("chkModifedDefSD")
$txtDC = $ADACLGui.Window.Findname("txtDC")
$txtdefaultnamingcontext = $ADACLGui.Window.Findname("txtdefaultnamingcontext")
$txtconfigurationnamingcontext = $ADACLGui.Window.Findname("txtconfigurationnamingcontext")
$txtschemanamingcontext = $ADACLGui.Window.Findname("txtschemanamingcontext")
$txtrootdomainnamingcontext = $ADACLGui.Window.Findname("txtrootdomainnamingcontext")
$btnDownloadCSVDefSD = $ADACLGui.Window.Findname("btnDownloadCSVDefSD")
$txtListObjectMode = $ADACLGui.Window.Findname("txtListObjectMode")
$btnDownloadCSVDefACLs = $ADACLGui.Window.Findname("btnDownloadCSVDefACLs")
$chkBoxRAWSDDL = $ADACLGui.Window.Findname("chkBoxRAWSDDL")
$rdbEXcel = $ADACLGui.Window.Findname("rdbEXcel")


$txtTempFolder.Text = $CurrentFSPath
$global:bolConnected = $false
$global:strPinDomDC = ""
$global:strPrinDomAttr = ""
$global:strPrinDomDir = ""
$global:strPrinDomFlat = ""
$global:strPrincipalDN =""
 $global:strDomainPrinDNName = ""
$global:strEffectiveRightSP = ""
$global:strEffectiveRightAccount = ""
$global:strSPNobjectClass = ""
$global:tokens = New-Object System.Collections.ArrayList
$global:tokens.Clear()
$global:strDommainSelect = "rootDSE"
$global:bolTempValue_InhertiedChkBox = $false
[void]$combAccessCtrl.Items.Add("Allow")
[void]$combAccessCtrl.Items.Add("Deny")
[void]$combObjectDefSD.Items.Add("All Objects")
$combObjectDefSD.SelectedValue="All Objects"
$tabAdv.IsSelected= $true
###################
#TODO: Place custom script here


$code = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;

namespace System
{
	public class IconExtractor
	{

	 public static Icon Extract(string file, int number, bool largeIcon)
	 {
	  IntPtr large;
	  IntPtr small;
	  ExtractIconEx(file, number, out large, out small, 1);
	  try
	  {
	   return Icon.FromHandle(largeIcon ? large : small);
	  }
	  catch
	  {
	   return null;
	  }

	 }
	 [DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
	 private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion, out IntPtr piSmallVersion, int amountIcons);

	}
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing


$ADACLGui.Window.Add_Loaded({
    $Global:observableCollection = New-Object System.Collections.ObjectModel.ObservableCollection[System.Object]
    $TextBoxStatusMessage.ItemsSource = $Global:observableCollection
})

if ($PSVersionTable.PSVersion -gt "2.0") 
{
if($psversiontable.clrversion.Major -ge 4)
{
try
{
Add-Type @"

    public class DelegateCommand : System.Windows.Input.ICommand

    {

        private System.Action<object> _action;

        public DelegateCommand(System.Action<object> action)

        {

            _action = action;

        }



        public bool CanExecute(object parameter)

        {

            return true;

        }



        public event System.EventHandler CanExecuteChanged = delegate { };



        public void Execute(object parameter)

        {

            _action(parameter);

        }

    }

"@
}catch
{}
}
}



Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class SFW {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
"@

Add-Type -AssemblyName System.Windows.Forms | Out-Null


$chkBoxShowDel.add_Checked({
$global:bolShowDeleted= $true
})

$chkBoxShowDel.add_UnChecked({
$global:bolShowDeleted= $false
})

$btnDownloadCSVDefACLs.add_Click({
GenerateTemplateDownloader
})

$btnDownloadCSVDefSD.add_Click({
GenerateTemplateDownloaderSchemaDefSD
})
$rdbScanOU.add_Click({
$txtCustomFilter.IsEnabled = $false

})
$rdbScanContainer.add_Click({
$txtCustomFilter.IsEnabled = $false

}) 
$rdbScanAll.add_Click({
$txtCustomFilter.IsEnabled = $false

})
$rdbScanFilter.add_Click({
$txtCustomFilter.IsEnabled = $true

})


$rdbEXcel.add_Click({
if(!$(get-module ImportExcel))
{ 
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Checking for ImportExcel PowerShell Module..."  -strType "Info" -DateStamp ))
    if(!$(get-module -ListAvailable | Where-Object name -eq "ImportExcel"))
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "You need to install the PowerShell module ImportExcel found in the PSGallery"  -strType "Error" -DateStamp ))
        $rdbOnlyHTA.IsChecked = $true
    }
    else
    {
        Import-Module ImportExcel
    }

}

})
$btnGetForestInfo.add_Click({

    if ($global:bolConnected -eq $true)
    {
        Get-SchemaData $global:CREDS
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Information collected!" -strType "Info" -DateStamp ))
    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }  
})

$btnClearExcludedBox.add_Click({
$txtBoxExcluded.text = ""

})
$btnGetSchemaClass.add_Click(
{

    if ($global:bolConnected -eq $true)
    {
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(objectClass=classSchema)", "Subtree")
        [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
        $request.Controls.Add($pagedRqc) | Out-Null
        [void]$request.Attributes.Add("name")

        $arrSchemaObjects = New-Object System.Collections.ArrayList
        while ($true)
        {
            $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
            #for paged search, the response for paged search result control - we will need a cookie from result later
            if($global:PageSize -gt 0) {
                [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
                if ($response.Controls.Length -gt 0)
                {
                    foreach ($ctrl in $response.Controls)
                    {
                        if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                        {
                            $prrc = $ctrl;
                            break;
                        }
                    }
                }
                if($null -eq $prrc) {
                    #server was unable to process paged search
                    throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                }
            }
            #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
            $colResults = $response.Entries
	        foreach ($objResult in $colResults)
	        {             
		        [void]$arrSchemaObjects.Add($objResult.attributes.name[0])


            }
            if($global:PageSize -gt 0) {
                if ($prrc.Cookie.Length -eq 0) {
                    #last page --> we're done
                    break;
                }
                #pass the search cookie back to server in next paged request
                $pagedRqc.Cookie = $prrc.Cookie;
            } else {
                #exit the processing for non-paged search
                break;
            }
        }#End While
        $arrSchemaObjects.Sort()
        foreach ($object in $arrSchemaObjects)
        {
            [void]$combObjectDefSD.Items.Add($object)
        }
        $global:observableCollection.Insert(0,(LogMessage -strMessage "All classSchema collected!" -strType "Info" -DateStamp ))
        $object = $null
        Remove-Variable object
        $arrSchemaObjects = $null
        Remove-Variable arrSchemaObjects
    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }  
})



$btnExportDefSD.add_Click(
{
    $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
    if ($global:bolConnected -eq $true)
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Scanning..." -strType "Info" -DateStamp ))
        $strFileCSV = $txtTempFolder.Text + "\" +$global:strDomainShortName + "_DefaultSecDescriptor" + $date + ".csv" 
        Write-DefaultSDCSV $strFileCSV
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))
    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }  

})

$btnCompDefSD.add_Click(
{
    $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
    if ($global:bolConnected -eq $true)
    {
 
        if ($txtCompareDefSDTemplate.Text -eq "")
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "No Template CSV file selected!" -strType "Error" -DateStamp ))
        }
        else
        {
            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
            $global:bolDefaultSDCSVLoaded = $false
            $strDefaultSDCompareFile = $txtCompareDefSDTemplate.Text
            &{#Try
                $global:bolDefaultSDCSVLoaded = $true
                $global:csvdefSDTemplate = import-Csv $strDefaultSDCompareFile 
            }
            Trap [SystemException]
            {
                $strCSVErr = $_.Exception.Message
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to load CSV. $strCSVErr" -strType "Error" -DateStamp ))
                $global:bolDefaultSDCSVLoaded = $false
                continue
            }
            if($bolDefaultSDCSVLoaded)
            {
                if(TestCSVColumnsDefaultSD $global:csvdefSDTemplate)            
                {
                    $strSelectedItem = $combObjectDefSD.SelectedItem
                    if($strSelectedItem -eq "All Objects")
                    {
                        $strSelectedItem = "*"
                    }
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Scanning..." -strType "Info" -DateStamp ))
                    Get-DefaultSDCompare $strSelectedItem $strDefaultSDCompareFile
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "CSV file got wrong format! File:  $strDefaultSDCompareFile" -strType "Error" -DateStamp ))
                } #End if test column names exist 
            }
        }#end if txtCompareDefSDTemplate.Text is empty

    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    } 
})

$btnScanDefSD.add_Click(
{
    $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked

    if ($global:bolConnected -eq $true)
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Scanning..." -strType "Info" -DateStamp ))

        $strSelectedItem = $combObjectDefSD.SelectedItem
        if($strSelectedItem -eq "All Objects")
        {
            $strSelectedItem = "*"
        }
        Get-DefaultSD $strSelectedItem $chkModifedDefSD.IsChecked $rdbDefSD_SDDL.IsChecked
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))

    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }        
   


})
$btnGETSPNReport.add_Click(
{
        If(($global:strEffectiveRightSP -ne "") -and  ($global:tokens.count -gt 0))
    {
        
        $strFileSPNHTA = $env:temp + "\"+$global:SPNHTMLFileName+".hta" 
	    $strFileSPNHTM = $env:temp + "\"+"$global:strEffectiveRightAccount"+".htm" 
        CreateServicePrincipalReportHTA $global:strEffectiveRightSP $strFileSPNHTA $strFileSPNHTM $CurrentFSPath
        CreateSPNHTM $global:strEffectiveRightSP $strFileSPNHTM
        InitiateSPNHTM $strFileSPNHTA 
        $strColorTemp = 1
        WriteSPNHTM $global:strEffectiveRightSP $global:tokens $global:strSPNobjectClass $($global:tokens.count-1) $strColorTemp $strFileSPNHTA $strFileSPNHTM
        Invoke-Item $strFileSPNHTA 
    }
    else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "No service principal selected!" -strType "Error" -DateStamp ))

    }
})

$btnViewLegend.add_Click(
{
    
        $strFileLegendHTA = $env:temp + "\"+$global:LegendHTMLFileName+".hta"

        CreateColorLegenedReportHTA $strFileLegendHTA 
        Invoke-Item $strFileLegendHTA 

})

$btnGetSPAccount.add_Click(
{

    if ($global:bolConnected -eq $true)
    {

        If (!($txtBoxSelectPrincipal.Text -eq ""))
        {
            GetEffectiveRightSP $txtBoxSelectPrincipal.Text $global:strDomainPrinDNName
        }
        else
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Enter a principal name!" -strType "Error" -DateStamp ))
        }
    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }
})



$btnListDdomain.add_Click(
{

GenerateDomainPicker

$txtBoxDomainConnect.Text = $global:strDommainSelect

})

$btnListLocations.add_Click(
{

    if ($global:bolConnected -eq $true)
    {
        GenerateTrustedDomainPicker
    }
        else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }
})


$chkBoxScanUsingUSN.add_Click(
{
    If($chkBoxScanUsingUSN.IsChecked)
    {
        $global:bolTempValue_chkBoxReplMeta = $chkBoxReplMeta.IsChecked
        $chkBoxReplMeta.IsChecked = $true
        
    }
    else
    {
        if ($null -ne $global:bolTempValue_chkBoxReplMeta)
        {
         $chkBoxReplMeta.IsChecked = $global:bolTempValue_chkBoxReplMeta
        }
      
    }
})

$chkBoxCompare.add_Click(
{
    If($chkBoxCompare.IsChecked)
    {
        if ($null -ne $global:bolTempValue_InhertiedChkBox)
        {
        $chkInheritedPerm.IsChecked = $global:bolTempValue_InhertiedChkBox
        }
       
        if ($null -ne $global:bolTempValue_chkBoxGetOwner)
        {
        $chkBoxGetOwner.IsChecked = $global:bolTempValue_chkBoxGetOwner
        }

        $chkInheritedPerm.IsEnabled = $true
        $chkBoxGetOwner.IsEnabled = $true
        #Activate Compare Objects
        $txtCompareTemplate.IsEnabled = $true
        $chkBoxTemplateNodes.IsEnabled = $true
        $chkBoxScanUsingUSN.IsEnabled = $true
        $btnGetCompareInput.IsEnabled = $true
        $txtReplaceDN.IsEnabled = $true
        $txtReplaceNetbios.IsEnabled = $true

        #Deactivate Effective Rights and Filter objects
        $chkBoxFilter.IsChecked = $false
        $chkBoxEffectiveRights.IsChecked = $false
        $txtBoxSelectPrincipal.IsEnabled = $false
        $btnGetSPAccount.IsEnabled = $false
        $btnListLocations.IsEnabled = $false
        $btnGETSPNReport.IsEnabled = $false
        $chkBoxType.IsEnabled = $false
        $chkBoxObject.IsEnabled = $false
        $chkBoxTrustee.IsEnabled =  $false
        $chkBoxType.IsChecked = $false
        $chkBoxObject.IsChecked = $false
        $chkBoxTrustee.IsChecked =  $false
        $combObjectFilter.IsEnabled = $false
        $txtFilterTrustee.IsEnabled = $false
        $combAccessCtrl.IsEnabled = $false
        $btnGetObjFullFilter.IsEnabled = $false
        
    }
    else
    {
        #Deactivate Compare Objects
        $txtCompareTemplate.IsEnabled = $false
        $chkBoxTemplateNodes.IsEnabled = $false
        $chkBoxScanUsingUSN.IsEnabled = $false
        $btnGetCompareInput.IsEnabled = $false
        $txtReplaceDN.IsEnabled = $false
        $txtReplaceNetbios.IsEnabled = $false        
    }

})
$chkBoxEffectiveRights.add_Click(
{
    If($chkBoxEffectiveRights.IsChecked)
    {
    
        $global:bolTempValue_InhertiedChkBox = $chkInheritedPerm.IsChecked
        $global:bolTempValue_chkBoxGetOwner = $chkBoxGetOwner.IsChecked
        $chkBoxFilter.IsChecked = $false

        #Deactivate Compare Objects
        $chkBoxCompare.IsChecked = $false
        $txtCompareTemplate.IsEnabled = $false
        $chkBoxTemplateNodes.IsEnabled = $false
        $chkBoxScanUsingUSN.IsEnabled = $false
        $btnGetCompareInput.IsEnabled = $false
        $txtReplaceDN.IsEnabled = $false
        $txtReplaceNetbios.IsEnabled = $false        

        $txtBoxSelectPrincipal.IsEnabled = $true
        $btnGetSPAccount.IsEnabled = $true
        $btnListLocations.IsEnabled = $true
        $btnGETSPNReport.IsEnabled = $true
        $chkInheritedPerm.IsEnabled = $false
        $chkInheritedPerm.IsChecked = $true
        $chkBoxGetOwner.IsEnabled = $false
        $chkBoxGetOwner.IsChecked= $true
  
        $chkBoxType.IsEnabled = $false
        $chkBoxObject.IsEnabled = $false
        $chkBoxTrustee.IsEnabled =  $false
        $chkBoxType.IsChecked = $false
        $chkBoxObject.IsChecked = $false
        $chkBoxTrustee.IsChecked =  $false
        $combObjectFilter.IsEnabled = $false
        $txtFilterTrustee.IsEnabled = $false
        $combAccessCtrl.IsEnabled = $false
        $btnGetObjFullFilter.IsEnabled = $false
        
    }
    else
    {

     $txtBoxSelectPrincipal.IsEnabled = $false
     $btnGetSPAccount.IsEnabled = $false
     $btnListLocations.IsEnabled = $false
     $btnGETSPNReport.IsEnabled = $false
     $chkInheritedPerm.IsEnabled = $true
     $chkInheritedPerm.IsChecked = $global:bolTempValue_InhertiedChkBox
    $chkBoxGetOwner.IsEnabled = $true
    $chkBoxGetOwner.IsChecked = $global:bolTempValue_chkBoxGetOwner
    }

})


$chkBoxFilter.add_Click(
{


    If($chkBoxFilter.IsChecked -eq $true)
    {
        #Deactivate Compare Objects
        $chkBoxCompare.IsChecked = $false
        $txtCompareTemplate.IsEnabled = $false
        $chkBoxTemplateNodes.IsEnabled = $false
        $chkBoxScanUsingUSN.IsEnabled = $false
        $btnGetCompareInput.IsEnabled = $false
        $txtReplaceDN.IsEnabled = $false
        $txtReplaceNetbios.IsEnabled = $false  

        $chkBoxEffectiveRights.IsChecked = $false
        $chkBoxType.IsEnabled = $true
        $chkBoxObject.IsEnabled = $true
        $chkBoxTrustee.IsEnabled =  $true
        $combObjectFilter.IsEnabled = $true
        $txtFilterTrustee.IsEnabled = $true
        $combAccessCtrl.IsEnabled = $true
        $btnGetObjFullFilter.IsEnabled = $true
        $txtBoxSelectPrincipal.IsEnabled = $false
        $btnGetSPAccount.IsEnabled = $false
        $btnListLocations.IsEnabled = $false
        $btnGETSPNReport.IsEnabled = $false
        $chkInheritedPerm.IsEnabled = $true
        $chkInheritedPerm.IsChecked = $global:bolTempValue_InhertiedChkBox
        $chkBoxGetOwner.IsEnabled = $true
        if ($null -ne $global:bolTempValue_chkBoxGetOwner)
        {
            $chkBoxGetOwner.IsChecked = $global:bolTempValue_chkBoxGetOwner
        }
       
    }
    else
    {
        $chkBoxType.IsEnabled = $false
        $chkBoxObject.IsEnabled = $false
        $chkBoxTrustee.IsEnabled =  $false
        $chkBoxType.IsChecked = $false
        $chkBoxObject.IsChecked = $false
        $chkBoxTrustee.IsChecked =  $false
        $combObjectFilter.IsEnabled = $false
        $txtFilterTrustee.IsEnabled = $false
        $combAccessCtrl.IsEnabled = $false
        $btnGetObjFullFilter.IsEnabled = $false
}
})

$rdbDSSchm.add_Click(
{
    If($rdbCustomNC.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.IsEnabled = $true
        $btnListDdomain.IsEnabled = $false
        if (($txtBoxDomainConnect.Text -eq "rootDSE") -or ($txtBoxDomainConnect.Text -eq "config") -or ($txtBoxDomainConnect.Text -eq "schema"))
        {
        $txtBoxDomainConnect.Text = ""
        }
    }
    else
    {
    $btnListDdomain.IsEnabled = $false
     If($rdbDSdef.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = $global:strDommainSelect
        $btnListDdomain.IsEnabled = $true
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false

    }
     If($rdbDSConf.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "config"
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false
    

    }
     If($rdbDSSchm.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "schema"
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false

    }
    $txtBoxDomainConnect.IsEnabled = $false
    }



})

$rdbDSConf.add_Click(
{
    If($rdbCustomNC.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.IsEnabled = $true
        $btnListDdomain.IsEnabled = $false
        if (($txtBoxDomainConnect.Text -eq "rootDSE") -or ($txtBoxDomainConnect.Text -eq "config") -or ($txtBoxDomainConnect.Text -eq "schema"))
        {
        $txtBoxDomainConnect.Text = ""
        }
    }
    else
    {
    $btnListDdomain.IsEnabled = $false
     If($rdbDSdef.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = $global:strDommainSelect
        $btnListDdomain.IsEnabled = $true
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false

    }
     If($rdbDSConf.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "config"
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false
    

    }
     If($rdbDSSchm.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "schema"
        $txtBdoxDSServerPort.IsEnabled = $false
        $txtBdoxDSServer.IsEnabled = $false


    }
    $txtBoxDomainConnect.IsEnabled = $false
    }



})



$rdbDSdef.add_Click(
{
    If($rdbCustomNC.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.IsEnabled = $true
        $btnListDdomain.IsEnabled = $false
        if (($txtBoxDomainConnect.Text -eq "rootDSE") -or ($txtBoxDomainConnect.Text -eq "config") -or ($txtBoxDomainConnect.Text -eq "schema"))
        {
            $txtBoxDomainConnect.Text = ""
        }
    }
    else
    {
        $btnListDdomain.IsEnabled = $false
         If($rdbDSdef.IsChecked -eq $true)
        {
            $txtBdoxDSServerPort.IsEnabled = $false
            $txtBdoxDSServer.IsEnabled = $false
            $txtBoxDomainConnect.Text = $global:strDommainSelect
            $btnListDdomain.IsEnabled = $true


        }
         If($rdbDSConf.IsChecked -eq $true)
        {
            $txtBoxDomainConnect.Text = "config"
    

        }
         If($rdbDSSchm.IsChecked -eq $true)
        {
            $txtBoxDomainConnect.Text = "schema"


        }
        $txtBoxDomainConnect.IsEnabled = $false
    }



})


$rdbCustomNC.add_Click(
{
    If($rdbCustomNC.IsChecked -eq $true)
    {
        $txtBdoxDSServerPort.IsEnabled = $true
        $txtBdoxDSServer.IsEnabled = $true
        $txtBoxDomainConnect.IsEnabled = $true
        $btnListDdomain.IsEnabled = $false
        if (($txtBoxDomainConnect.Text -eq "rootDSE") -or ($txtBoxDomainConnect.Text -eq "config") -or ($txtBoxDomainConnect.Text -eq "schema"))
        {
        $txtBoxDomainConnect.Text = ""
        }
    }
    else
    {
    $btnListDdomain.IsEnabled = $false
     If($rdbDSdef.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = $global:strDommainSelect
        $btnListDdomain.IsEnabled = $true

    }
     If($rdbDSConf.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "config"
    

    }
     If($rdbDSSchm.IsChecked -eq $true)
    {
        $txtBoxDomainConnect.Text = "schema"


    }
    $txtBoxDomainConnect.IsEnabled = $false
    }



})

$btnGetTemplateFolder.add_Click( 
{
  
$strFolderPath = Select-Folder   
$txtTempFolder.Text = $strFolderPath


})

$btnGetCompareDefSDInput.add_Click( 
{

$strFilePath = Select-File 

$txtCompareDefSDTemplate.Text = $strFilePath


})
$btnGetCompareInput.add_Click( 
{

$strFilePath = Select-File 
$txtCompareTemplate.Text = $strFilePath


})
$btnGetCSVFile.add_Click( 
{

$strFilePath = Select-File 

$txtCSVImport.Text = $strFilePath


})
$btnDSConnect.add_Click(
{
if($chkBoxCreds.IsChecked)
{

$global:CREDS = Get-Credential -Message "Type User Name and Password"
$ADACLGui.Window.Activate()

}
$global:bolRoot = $true

$NCSelect = $false
$global:DSType = ""
$global:strDC = ""
$global:strDomainDNName = ""
$global:ConfigDN = ""
$global:SchemaDN = ""
$global:ForestRootDomainDN = ""
$global:IS_GC = ""
$txtDC.text = ""
$txtdefaultnamingcontext.text = ""
$txtconfigurationnamingcontext.text = ""
$txtschemanamingcontext.text = ""
$txtrootdomainnamingcontext.text = ""

	If ($rdbDSdef.IsChecked)
	{

       if (!($txtBoxDomainConnect.Text -eq "rootDSE"))
        {
            if ($null -eq $global:TempDC)
            {
                $strNamingContextDN = $txtBoxDomainConnect.Text
                If(CheckDNExist $strNamingContextDN "")
                {
                $root = New-Object system.directoryservices.directoryEntry("LDAP://"+$strNamingContextDN)
                $global:strDomainDNName = $root.distinguishedName.tostring()
                $global:strDomainPrinDNName = $global:strDomainDNName
                $global:strDomainLongName = $global:strDomainDNName.Replace("DC=","")
                $global:strDomainLongName = $global:strDomainLongName.Replace(",",".")
                $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strDomainLongName )
                $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                $global:strDC = $($ojbDomain.FindDomainController()).name
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                [void]$request.Attributes.Add("dnshostname")
                [void]$request.Attributes.Add("supportedcapabilities")
                [void]$request.Attributes.Add("namingcontexts")
                [void]$request.Attributes.Add("defaultnamingcontext")
                [void]$request.Attributes.Add("schemanamingcontext")
                [void]$request.Attributes.Add("configurationnamingcontext")
                [void]$request.Attributes.Add("rootdomainnamingcontext")
                [void]$request.Attributes.Add("isGlobalCatalogReady")
                                
                try
	            {
                    $response = $LDAPConnection.SendRequest($request)
                    $global:bolLDAPConnection = $true
	            }
	            catch
	            {
		            $global:bolLDAPConnection = $false
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	            }
                if($global:bolLDAPConnection -eq $true)
                {
                    $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                }

                $global:DirContext = Get-DirContext $global:strDC $global:CREDS

                $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
                $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                $NCSelect = $true
                $strNamingContextDN = $global:strDomainDNName
            }
               else
                {
                   $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
                   $global:bolConnected = $false
                }
            }
            else
            {
                $strNamingContextDN = $txtBoxDomainConnect.Text
                If(CheckDNExist $strNamingContextDN "$global:TempDC")
                {
                $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:TempDC )
                $global:TempDC = $null
                $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                $global:strDC = $($ojbDomain.FindDomainController()).name
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                [void]$request.Attributes.Add("dnshostname")
                [void]$request.Attributes.Add("supportedcapabilities")
                [void]$request.Attributes.Add("namingcontexts")
                [void]$request.Attributes.Add("defaultnamingcontext")
                [void]$request.Attributes.Add("schemanamingcontext")
                [void]$request.Attributes.Add("configurationnamingcontext")
                [void]$request.Attributes.Add("rootdomainnamingcontext")
                [void]$request.Attributes.Add("isGlobalCatalogReady")
                
                
                try
	            {
                    $response = $LDAPConnection.SendRequest($request)
                    $global:bolLDAPConnection = $true
	            }
	            catch
	            {
		            $global:bolLDAPConnection = $false
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	            }
                if($global:bolLDAPConnection -eq $true)
                {
                    $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                }

                $global:DirContext = Get-DirContext $global:strDC $global:CREDS

                $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
                $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                $NCSelect = $true
                $strNamingContextDN = $global:strDomainDNName
                }
               else
                {
                   $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
                   $global:bolConnected = $false
                }
            }
        }
        else
        {

            if ($global:bolRoot -eq $true)
            {
                $LDAPConnection = $null
                $request = $null
                $response = $null
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("")
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                [void]$request.Attributes.Add("defaultnamingcontext")
                try
	            {
                    $response = $LDAPConnection.SendRequest($request)
                    $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                    $global:bolLDAPConnection = $true
	            }
	            catch
	            {
		            $global:bolLDAPConnection = $false
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	            }

                if($global:bolLDAPConnection)
                {
                    $global:strDomainPrinDNName = $global:strDomainDNName
                    $global:strDomainLongName = $global:strDomainDNName.Replace("DC=","")
                    $global:strDomainLongName = $global:strDomainLongName.Replace(",",".")
                    $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strDomainLongName )
                    $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                    $global:strDC = $($ojbDomain.FindDomainController()).name
                    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                    $LDAPConnection.SessionOptions.ReferralChasing = "None"
                    $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                    [void]$request.Attributes.Add("dnshostname")
                    [void]$request.Attributes.Add("supportedcapabilities")
                    [void]$request.Attributes.Add("namingcontexts")
                    [void]$request.Attributes.Add("defaultnamingcontext")
                    [void]$request.Attributes.Add("schemanamingcontext")
                    [void]$request.Attributes.Add("configurationnamingcontext")
                    [void]$request.Attributes.Add("rootdomainnamingcontext")
                    [void]$request.Attributes.Add("isGlobalCatalogReady")
                    
                    try
    	            {
                        $response = $LDAPConnection.SendRequest($request)
                        $global:bolLDAPConnection = $true
    	            }
    	            catch
    	            {
    		            $global:bolLDAPConnection = $false
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
    	            }
                    if($global:bolLDAPConnection -eq $true)
                    {
                        $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
                        $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
                        $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
                        $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                        $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                    }

                    $global:DirContext = Get-DirContext $global:strDC $global:CREDS
                    $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                    $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                    $global:DSType = "AD DS"
                    $global:bolADDSType = $true
                    $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                    $NCSelect = $true
                    $strNamingContextDN = $global:strDomainDNName
                }
            }
        }
	}
    #Connect to Config Naming Context
	If ($rdbDSConf.IsChecked)
	{


        if ($global:bolRoot -eq $true)
        {
            $LDAPConnection = $null
            $request = $null
            $response = $null
            $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("")
            $LDAPConnection.SessionOptions.ReferralChasing = "None"
            $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
            [void]$request.Attributes.Add("defaultnamingcontext")
            try
	        {
                $response = $LDAPConnection.SendRequest($request)
                $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                $global:bolLDAPConnection = $true
	        }
	        catch
	        {
		        $global:bolLDAPConnection = $false
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
            }

            if($global:bolLDAPConnection)
            {
                $global:strDomainPrinDNName = $global:strDomainDNName
                $global:strDomainLongName = $global:strDomainDNName.Replace("DC=","")
                $global:strDomainLongName = $global:strDomainLongName.Replace(",",".")
                $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strDomainLongName )
                $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                $global:strDC = $($ojbDomain.FindDomainController()).name
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                [void]$request.Attributes.Add("dnshostname")
                [void]$request.Attributes.Add("supportedcapabilities")
                [void]$request.Attributes.Add("namingcontexts")
                [void]$request.Attributes.Add("defaultnamingcontext")
                [void]$request.Attributes.Add("schemanamingcontext")
                [void]$request.Attributes.Add("configurationnamingcontext")
                [void]$request.Attributes.Add("rootdomainnamingcontext")
                [void]$request.Attributes.Add("isGlobalCatalogReady")

                try
    	        {
                    $response = $LDAPConnection.SendRequest($request)
                    $global:bolLDAPConnection = $true
    	        }
    	        catch
    	        {
    		        $global:bolLDAPConnection = $false
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
    	        }
                if($global:bolLDAPConnection -eq $true)
                {
                    $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                }

                $global:DirContext = Get-DirContext $global:strDC $global:CREDS
                $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
                $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                $NCSelect = $true
                $strNamingContextDN = $global:ConfigDN
            }
        }
	}
    #Connect to Schema Naming Context
	If ($rdbDSSchm.IsChecked)
	{

        if ($global:bolRoot -eq $true)
        {
            $LDAPConnection = $null
            $request = $null
            $response = $null
            $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("")
            $LDAPConnection.SessionOptions.ReferralChasing = "None"
            $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
            [void]$request.Attributes.Add("defaultnamingcontext")
            try
	        {
                $response = $LDAPConnection.SendRequest($request)
                $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                $global:bolLDAPConnection = $true
	        }
	        catch
	        {
		        $global:bolLDAPConnection = $false
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
            }

            if($global:bolLDAPConnection)
            {
                $global:strDomainPrinDNName = $global:strDomainDNName
                $global:strDomainLongName = $global:strDomainDNName.Replace("DC=","")
                $global:strDomainLongName = $global:strDomainLongName.Replace(",",".")
                $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strDomainLongName )
                $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                $global:strDC = $($ojbDomain.FindDomainController()).name
                $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                $LDAPConnection.SessionOptions.ReferralChasing = "None"
                $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
                [void]$request.Attributes.Add("dnshostname")
                [void]$request.Attributes.Add("supportedcapabilities")
                [void]$request.Attributes.Add("namingcontexts")
                [void]$request.Attributes.Add("defaultnamingcontext")
                [void]$request.Attributes.Add("schemanamingcontext")
                [void]$request.Attributes.Add("configurationnamingcontext")
                [void]$request.Attributes.Add("rootdomainnamingcontext")
                [void]$request.Attributes.Add("isGlobalCatalogReady")
                                    
                try
    	        {
                    $response = $LDAPConnection.SendRequest($request)
                    $global:bolLDAPConnection = $true
    	        }
    	        catch
    	        {
    		        $global:bolLDAPConnection = $false
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
    	        }
                if($global:bolLDAPConnection -eq $true)
                {
                    $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                }

                $global:DirContext = Get-DirContext $global:strDC $global:CREDS
                $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
                $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                $NCSelect = $true
                $strNamingContextDN = $global:SchemaDN
            }
        }
	}
    #Connect to Custom Naming Context	
    If ($rdbCustomNC.IsChecked)
	{   
        if (($txtBoxDomainConnect.Text.Length -gt 0) -or ($txtBdoxDSServer.Text.Length -gt 0) -or ($txtBdoxDSServerPort.Text.Length -gt 0))
        {
                $strNamingContextDN = $txtBoxDomainConnect.Text
                if($txtBdoxDSServer.Text -eq "")
                {
                    if($txtBdoxDSServerPort.Text -eq "")
                    {                    
                        $global:strDC = ""
                    }
                    else
                    {
                        $global:strDC = "localhost:" +$txtBdoxDSServerPort.text
                    }
                }
                else
                {
                    $global:strDC = $txtBdoxDSServer.Text +":" +$txtBdoxDSServerPort.text
                    if($txtBdoxDSServerPort.Text -eq "")
                    {                    
                        $global:strDC = $txtBdoxDSServer.Text
                    }
                    else
                    {
                        $global:strDC = $txtBdoxDSServer.Text +":" +$txtBdoxDSServerPort.text     
                    }
                }
                    $global:bolLDAPConnection = $false
                    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
                    $LDAPConnection.SessionOptions.ReferralChasing = "None"
                    $request = New-Object System.directoryServices.Protocols.SearchRequest("", "(objectClass=*)", "base")
                    if($global:bolShowDeleted)
                    {
                        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
                        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
                    }
                    [void]$request.Attributes.Add("dnshostname")
                    [void]$request.Attributes.Add("supportedcapabilities")
                    [void]$request.Attributes.Add("namingcontexts")
                    [void]$request.Attributes.Add("defaultnamingcontext")
                    [void]$request.Attributes.Add("schemanamingcontext")
                    [void]$request.Attributes.Add("configurationnamingcontext")
                    [void]$request.Attributes.Add("rootdomainnamingcontext")
                    [void]$request.Attributes.Add("isGlobalCatalogReady")                        
    
	                try
	                {
                        $response = $LDAPConnection.SendRequest($request)
                        $global:bolLDAPConnection = $true

	                }
	                catch
	                {
		                $global:bolLDAPConnection = $false
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	                }
                    if($global:bolLDAPConnection -eq $true)
                    {
                        $strPrimaryCapability= $response.Entries[0].attributes.supportedcapabilities[0]
                        Switch ($strPrimaryCapability)
                        {
                            "1.2.840.113556.1.4.1851"
                            {
                                $global:DSType = "AD LDS"
                                $global:bolADDSType = $false
                                $global:strDomainDNName = $response.Entries[0].Attributes.namingcontexts[-1]
                                $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                                $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                                if($txtBdoxDSServerPort.Text -eq "")
                                {                    
                                    if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                                    {
                                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                                    }
                                }
                                else
                                {
                                    if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                                    {
                                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" +$txtBdoxDSServerPort.text     
                                    }
                                }

                            }
                            "1.2.840.113556.1.4.800"
                            {
                                $global:DSType = "AD DS"
                                $global:bolADDSType = $true
                                $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                                $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                                $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                                $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                                $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]

                                if($txtBdoxDSServerPort.Text -eq "")
                                {                    
                                    if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                                    {
                                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                                    }
                                }
                                else
                                {
                                    if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                                    {
                                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" +$txtBdoxDSServerPort.text     
                                    }
                                    
                                }
                                $global:strDomainPrinDNName = $global:strDomainDNName
                                $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                                $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                                $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                            }
                            default
                            {
                                $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                                $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                                $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                                $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                                $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]

                                 if($txtBdoxDSServerPort.Text -eq "")
                                {                    
                                    $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                                }
                                else
                                {
                                    $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" +$txtBdoxDSServerPort.text     
                                }
                            }
                        }  
                        if($strNamingContextDN -eq "")
                        {
                            $strNamingContextDN = $global:strDomainDNName
                        }
                        If(CheckDNExist $strNamingContextDN $global:strDC)
                        {
                            $NCSelect = $true
                        }
                        else
                        {
                            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
                            $global:bolConnected = $false
                        }
   
                    }#bolLDAPConnection
                


            
        }
        else
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! No naming context or server specified!" -strType "Error" -DateStamp ))
            $global:bolConnected = $false  
        }
	}  
    If ($NCSelect -eq $true)  
    {
	    If (!($strLastCacheGuidsDom -eq $global:strDomainDNName))
	    {
	        $global:dicRightsGuids = @{"Seed" = "xxx"}
	        CacheRightsGuids 
	        $strLastCacheGuidsDom = $global:strDomainDNName
        
        
	    }
        #Check Directory Service type
        $global:DSType = ""
        $global:bolADDSType = $false
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest("", "(objectClass=*)", "base")
        $response = $LDAPConnection.SendRequest($request)
        $strPrimaryCapability= $response.Entries[0].attributes.supportedcapabilities[0]
        Switch ($strPrimaryCapability)
        {
            "1.2.840.113556.1.4.1851"
            {
                $global:DSType = "AD LDS"
            }
            "1.2.840.113556.1.4.800"
            {
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
            }
            default
            {
                $global:DSType = "Unknown"
            }
        }    
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Connected to directory service  $global:DSType" -strType "Info" -DateStamp ))
        #Plaing with AD LDS Locally
        $global:TreeViewRootPath = $strNamingContextDN

        $xml = Get-XMLDomainOUTree $global:TreeViewRootPath
            # Change XML Document, XPath and Refresh
        $xmlprov_adp.Document = $xml
        $xmlProv_adp.XPath = "/DomainRoot"
        $xmlProv_adp.Refresh()

        $global:bolConnected = $true

        If (!(Test-Path ($env:temp + "\OU.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 0, $true)).ToBitMap()).Save($env:temp + "\OU.png")
        }
        If (!(Test-Path ($env:temp + "\Expand.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 6, $true)).ToBitMap()).Save($env:temp + "\Expand.png")
        }
        If (!(Test-Path ($env:temp + "\User.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 58, $true)).ToBitMap()).Save($env:temp + "\User.png")
        }
        If (!(Test-Path ($env:temp + "\Group.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 59, $true)).ToBitMap()).Save($env:temp + "\Group.png")
        }
        If (!(Test-Path ($env:temp + "\Computer.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 60, $true)).ToBitMap()).Save($env:temp + "\Computer.png")
        }
        If (!(Test-Path ($env:temp + "\Container.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 66, $true)).ToBitMap()).Save($env:temp + "\Container.png")
        }
        If (!(Test-Path ($env:temp + "\DomainDNS.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 95, $true)).ToBitMap()).Save($env:temp + "\DomainDNS.png")
        }
        If (!(Test-Path ($env:temp + "\Other.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 126, $true)).ToBitMap()).Save($env:temp + "\Other.png")    
        }
        If (!(Test-Path ($env:temp + "\refresh.png")))
        {
        (([System.IconExtractor]::Extract("mmcndmgr.dll", 46, $true)).ToBitMap()).Save($env:temp + "\refresh.png")
        }
        If (!(Test-Path ($env:temp + "\refresh2.png")))
        {
        (([System.IconExtractor]::Extract("shell32.dll", 238, $true)).ToBitMap()).Save($env:temp + "\refresh2.png")
        }
        If (!(Test-Path ($env:temp + "\exclude.png")))
        {
        (([System.IconExtractor]::Extract("shell32.dll", 234, $true)).ToBitMap()).Save($env:temp + "\exclude.png")
        }
        #Test PS Version DeleteCommand requries PS 3.0 and above
        if ($PSVersionTable.PSVersion -gt "2.0") 
        {
            if($psversiontable.clrversion.Major -ge 4)
            {    
                $TreeView1.ContextMenu.Items[0].Command = New-Object DelegateCommand( { Add-RefreshChild } )
                $TreeView1.ContextMenu.Items[1].Command = New-Object DelegateCommand( { Add-ExcludeChild } )
            }    
            else
            {

                $global:observableCollection.Insert(0,(LogMessage -strMessage "(common language runtime) CLRVersion = $($psversiontable.clrversion.Major)" -strType "Warning" -DateStamp ))
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Some GUI functions requrie .NET Framework run-time environment (common language runtime) 4.0!" -strType "Warning" -DateStamp ))
                if((Get-HighestNetFrameWorkVer) -ge 4.0)
                {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Installed .NET Framework version = $(Get-HighestNetFrameWorkVer)" -strType "Info" -DateStamp ))
                }
            }
        }
        else 
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "(common language runtime) CLRVersion = $($psversiontable.clrversion.Major)" -strType "Warning" -DateStamp ))
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Some GUI functions requrie PowerShell 3.0 and .NET Framework run-time environment (common language runtime) 4.0!" -strType "Warning" -DateStamp ))
            if((Get-HighestNetFrameWorkVer) -ge 4.0)
            {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Installed .NET Framework version = $(Get-HighestNetFrameWorkVer)" -strType "Info" -DateStamp ))
            }
        }
        #Update Connection Info
        $txtDC.text = $global:strDC
        $txtdefaultnamingcontext.text = $global:strDomainDNName
        $txtconfigurationnamingcontext.text = $global:ConfigDN
        $txtschemanamingcontext.text = $global:SchemaDN
        $txtrootdomainnamingcontext.text = $global:ForestRootDomainDN

    }#End If NCSelect
    
#Get Forest Root Domain ObjectSID
if ($global:DSType -eq "AD DS")
{
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:strDomainDNName, "(objectClass=*)", "base")
    [void]$request.Attributes.Add("objectsid")
                
    try
	{
        $response = $LDAPConnection.SendRequest($request)
        $global:bolLDAPConnection = $true
	}
	catch
	{
		$global:bolLDAPConnection = $false
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	}
    if($global:bolLDAPConnection -eq $true)
    {
        $global:DomainSID = GetSidStringFromSidByte $response.Entries[0].attributes.objectsid[0]

    }
     
    if($global:ForestRootDomainDN -ne $global:strDomainDNName)
    {
        $global:strForestDomainLongName = $global:ForestRootDomainDN.Replace("DC=","")
        $global:strForestDomainLongName = $global:strForestDomainLongName.Replace(",",".")
        if($global:CREDS.UserName)
        {
            $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strForestDomainLongName,$global:CREDS.UserName,$global:CREDS.GetNetworkCredential().Password) 
        }
        else
        {
            $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$global:strForestDomainLongName) 
        }
        $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
        $global:strForestDC = $($ojbDomain.FindDomainController()).name

        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strForestDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest($global:ForestRootDomainDN, "(objectClass=*)", "base")
        [void]$request.Attributes.Add("objectsid")
                
        try
	    {
            $response = $LDAPConnection.SendRequest($request)
            $global:bolLDAPConnection = $true
	    }
	    catch
	    {
		    $global:bolLDAPConnection = $false
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
	    }
        if($global:bolLDAPConnection -eq $true)
        {
            $global:ForestRootDomainSID = GetSidStringFromSidByte $response.Entries[0].attributes.objectsid[0]

        }
    }
    else
    {
        $global:strForestDC = $global:strDC
        $global:ForestRootDomainSID = $global:DomainSID
    }

    
}

})

$chkBoxCreds.add_UnChecked({
$global:CREDS = $null
})

$btnScan.add_Click( 
{

    If($chkBoxCompare.IsChecked)
    {
        RunCompare
    }
    else
    {
        RunScan
    }



})

$btnCreateHTML.add_Click(
{
if ($txtCSVImport.Text -eq "")
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "No Template CSV file selected!" -strType "Error" -DateStamp ))
}
else
{
    #if ($global:bolConnected -eq $true)
    #{
        ConvertCSVtoHTM $txtCSVImport.Text $chkBoxTranslateGUIDinCSV.isChecked
    #}
    #else
    #{
    #$global:observableCollection.Insert(0,(LogMessage -strMessage "You need to connect to a directory first!" -strType "Error" -DateStamp ))
    #}
}

})

$btnSupport.add_Click(
{
GenerateSupportStatement
})

$btnExit.add_Click( 
{
#TODO: Place custom script here

#$ErrorActionPreference = "SilentlyContinue"
$bolConnected= $null
$bolTempValue_InhertiedChkBox= $null
$dicDCSpecialSids= $null
$dicNameToSchemaIDGUIDs= $null
$dicRightsGuids= $null
$dicSchemaIDGUIDs= $null
$dicSidToName= $null
$dicWellKnownSids= $null
$myPID= $null
$observableCollection= $null
$strDomainPrinDNName= $null
$strDommainSelect= $null
$strEffectiveRightAccount= $null
$strEffectiveRightSP= $null
$strPinDomDC= $null
$strPrincipalDN= $null
$strPrinDomAttr= $null
$strPrinDomDir= $null
$strPrinDomFlat= $null
$strSPNobjectClass= $null
$tokens= $null
$strDC = $null
$strDomainDNName = $null
$strDomainLongName = $null
$strDomainShortName = $null
$strOwner = $null
remove-variable -name "bolConnected" -Scope Global
remove-variable -name "bolTempValue_InhertiedChkBox" -Scope Global
remove-variable -name "dicDCSpecialSids" -Scope Global
remove-variable -name "dicNameToSchemaIDGUIDs" -Scope Global
remove-variable -name "dicRightsGuids" -Scope Global
remove-variable -name "dicSchemaIDGUIDs" -Scope Global
remove-variable -name "dicSidToName" -Scope Global
remove-variable -name "dicWellKnownSids" -Scope Global
remove-variable -name "myPID" -Scope Global
remove-variable -name "observableCollection" -Scope Global
remove-variable -name "strDomainPrinDNName" -Scope Global
remove-variable -name "strDommainSelect" -Scope Global
remove-variable -name "strEffectiveRightAccount" -Scope Global
remove-variable -name "strEffectiveRightSP" -Scope Global
remove-variable -name "strPinDomDC" -Scope Global
remove-variable -name "strPrincipalDN" -Scope Global
remove-variable -name "strPrinDomAttr" -Scope Global
remove-variable -name "strPrinDomDir" -Scope Global
remove-variable -name "strPrinDomFlat" -Scope Global
remove-variable -name "strSPNobjectClass" -Scope Global
remove-variable -name "tokens" -Scope Global


$ErrorActionPreference = "SilentlyContinue"
    &{#Try
        $xmlDoc = $null
        remove-variable -name "xmlDoc" -Scope Global
    }
    Trap [SystemException]
    {

     SilentlyContinue
    }

$ErrorActionPreference = "Continue"

$ADACLGui.Window.close()

})


$btnGetObjFullFilter.add_Click( 
{
    if ($global:bolConnected -eq $true)
    {
        GetSchemaObjectGUID  -Domain $global:strDomainDNName
        $global:observableCollection.Insert(0,(LogMessage -strMessage "All schema objects and attributes listed!" -strType "Info" -DateStamp ))
    }
    else
    {
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Connect to your naming context first!" -strType "Error" -DateStamp ))
    }
})



foreach ($ldapDisplayName in $global:dicSchemaIDGUIDs.values)
{


   [void]$combObjectFilter.Items.Add($ldapDisplayName)
   
}

$treeView1.add_SelectedItemChanged({

$txtBoxSelected.Text = (Get-XMLPath -xmlElement ($this.SelectedItem))


if ($this.SelectedItem.Tag -eq "NotEnumerated") 
{ 

    $xmlNode = $global:xmlDoc
     
    $NodeDNPath = $($this.SelectedItem.ParentNode.Text.toString())
    [void]$this.SelectedItem.ParentNode.removeChild($this.SelectedItem);
    $Mynodes = $xmlNode.SelectNodes("//OU[@Text='$NodeDNPath']")

    $treeNodePath = $NodeDNPath
       
    # Initialize and Build Domain OU Tree 
    ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath #-nodeCount 0 
    # Set tag to show this node is already enumerated 
    $this.SelectedItem.Tag  = "Enumerated" 
	
}


})


<######################################################################

    Functions to Build Domains OU Tree XML Document

######################################################################>
#region 
function RunCompare
{
If ($txtBoxSelected.Text -or $chkBoxTemplateNodes.IsChecked )
{
    #If the DC string is changed during the compre ti will be restored to it's orgi value 
    $global:ResetDCvalue = ""
    $global:ResetDCvalue = $global:strDC

    $allSubOU = New-Object System.Collections.ArrayList
    $allSubOU.Clear()
    if ($txtCompareTemplate.Text -eq "")
    {
    	$global:observableCollection.Insert(0,(LogMessage -strMessage "No Template CSV file selected!" -strType "Error" -DateStamp ))
    }
    else
    {
            if ($(Test-Path $txtCompareTemplate.Text) -eq $true)
            {
            if (($chkBoxEffectiveRights.isChecked -eq $true) -or ($chkBoxFilter.isChecked -eq $true))
            {
                if ($chkBoxEffectiveRights.isChecked)
                {
    	            $global:observableCollection.Insert(0,(LogMessage -strMessage "Can't compare while Effective Rights enabled!" -strType "Error" -DateStamp ))
                }
                if ($chkBoxFilter.isChecked)
                {
    	            $global:observableCollection.Insert(0,(LogMessage -strMessage "Can't compare while Filter  enabled!" -strType "Error" -DateStamp ))
                }
            }
            else
            {
                $global:bolCSVLoaded = $false
                $strCompareFile = $txtCompareTemplate.Text
                &{#Try
                    $global:bolCSVLoaded = $true
                    $global:csvHistACLs = import-Csv $strCompareFile 
                }
                Trap [SystemException]
                {
                    $strCSVErr = $_.Exception.Message
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to load CSV. $strCSVErr" -strType "Error" -DateStamp ))
                    $global:bolCSVLoaded = $false
                    continue
                }   
               #Verify that a successful CSV import is performed before continue            
               if($global:bolCSVLoaded)
               {
                    #Test CSV file format
                   if(TestCSVColumns $global:csvHistACLs)
                                                                                                                                                                                                                                                                                                       {
                                       
	               $global:observableCollection.Insert(0,(LogMessage -strMessage "Scanning..." -strType "Info" -DateStamp ))
	               $BolSkipDefPerm = $chkBoxDefaultPerm.IsChecked
                   $BolSkipProtectedPerm =  $chkBoxSkipProtectedPerm.IsChecked
                   $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
	               if ($chkBoxTemplateNodes.IsChecked -eq $false)
                    {
                        $sADobjectName = $txtBoxSelected.Text.ToString()
                        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC,$global:CREDS)
                        $LDAPConnection.SessionOptions.ReferralChasing = "None"
                        $request = New-Object System.directoryServices.Protocols.SearchRequest
                        if($global:bolShowDeleted)
                        {
                            [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
                            [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
                        }
                        $request.DistinguishedName = $sADobjectName
                        $request.Filter = "(name=*)"
                        $request.Scope = "Base"
                        [void]$request.Attributes.Add("name")
                        $response = $LDAPConnection.SendRequest($request)
                        $ADobject = $response.Entries[0]
                        if($null -ne $ADobject.Attributes.name)
                        {
                            $strNode = fixfilename $ADobject.attributes.name[0]
                        }
                        else
                        {
                                $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not read object $($txtBoxSelected.Text.ToString()). Enough permissions?" -strType "Error" -DateStamp ))
                        }
                       
                    }
                    else
                    {
                        #Set the bolean to true so connection will be performed unless an error occur
                        $bolContinue = $true

                        $strOUcol = $global:csvHistACLs[0].OU

                        if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

                        }

                        if($strOUcol.Contains("<ROOT-DN>") -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)

                            if($global:strDomainDNName -ne $global:ForestRootDomainDN)
                            {
                                if($global:IS_GC -eq "TRUE")
                                {
                                    $MsgBox = [System.Windows.Forms.MessageBox]::Show("You are not connected to the forest root domain: $global:ForestRootDomainDN.`n`nYour DC is a Global Catalog.`nDo you want to use Global Catalog and  continue?",”Information”,3,"Warning")
                                    if($MsgBox -eq "Yes")
                                    {
                                        if($global:strDC.contains(":"))
                                        {
                                            $global:strDC = $global:strDC.split(":")[0] + ":3268"
                                        }
                                        else
                                        {
                                            $global:strDC = $global:strDC + ":3268"
                                        }
                                       
                                    }
                                    else
                                    {
                                        $bolContinue = $false
                                    }

                                }
                                else
                                {
                                    $MsgBox = [System.Windows.Forms.MessageBox]::Show("You are not connected to the forest root domain: $global:ForestRootDomainDN.",”Information”,0,"Warning")
                                    $bolContinue = $false
                                }
                            }

                        }
                        

                        if($txtReplaceDN.text.Length -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text,$global:strDomainDNName)

                        }
                        $sADobjectName = $strOUcol
                        #Verify if the connection can be done
                        if($bolContinue)
                        {
                            $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC,$global:CREDS)
                            $LDAPConnection.SessionOptions.ReferralChasing = "None"
                            $request = New-Object System.directoryServices.Protocols.SearchRequest
                            if($global:bolShowDeleted)
                            {
                                [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
                                [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
                            }
                            $request.DistinguishedName = $sADobjectName
                            $request.Filter = "(name=*)"
                            $request.Scope = "Base"
                            [void]$request.Attributes.Add("name")
                            
                            $response = $LDAPConnection.SendRequest($request)

                            $ADobject = $response.Entries[0]
                            $strNode = fixfilename $ADobject.attributes.name[0]
                        }
                        else
                        {
                            #Set the node to empty , no connection will be done
                            $strNode = ""
                        }
                    }
                    #if not is empty continue
                    if($strNode -ne "")
                    {
                        $strFileHTA = $env:temp + "\"+$global:ACLHTMLFileName+".hta" 
                        $strFileHTM = $env:temp + "\"+"$global:strDomainShortName-$strNode-$global:SessionID"+".htm" 
                        CreateHTM "$global:strDomainShortName-$strNode" $strFileHTM					
                        CreateHTA "$global:strDomainShortName-$strNode" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC

           
                        InitiateHTM $strFileHTA $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $chkBoxGetOUProtected.IsChecked $chkBoxEffectiveRightsColor.IsChecked $true $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked
                        InitiateHTM $strFileHTM $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $chkBoxGetOUProtected.IsChecked $chkBoxEffectiveRightsColor.IsChecked $true $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked
                        $bolTranslateGUIDStoObject = $false
                        If (($txtBoxSelected.Text.ToString().Length -gt 0) -or (($chkBoxTemplateNodes.IsChecked -eq $true)))
                        {
                            #Select type of scope
		                    If ($rdbBase.IsChecked -eq $False)
		                    {
                                If ($rdbSubtree.IsChecked -eq $true)
		                        {
			                        $allSubOU = GetAllChildNodes $txtBoxSelected.Text "subtree"
                                }
                                else
                                {
                                    $allSubOU = GetAllChildNodes $txtBoxSelected.Text "onelevel"
                                }	    
                            }
		                    else
		                    {
			                    $allSubOU =  @($txtBoxSelected.Text)
		                    }
                            $Format = "HTM"
                            #if any objects found compare ACLs
                            if($allSubOU.count -gt 0)
                            {			        
                                Get-PermCompare $allSubOU $BolSkipDefPerm $BolSkipProtectedPerm $chkBoxReplMeta.IsChecked $chkBoxGetOwner.IsChecked $chkBoxGetOUProtected.IsChecked $chkBoxACLsize.IsChecked $bolTranslateGUIDStoObject $Format
                            }	
                            else
                            {
                                $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects returned!" -strType "Error" -DateStamp ))
                            }
		                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))
	                   }# End If txtBoxSelected or chkBoxTemplateNodes
                    }
                    else
                    {
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not connect to $sADobjectName" -strType "Error" -DateStamp ))
                    }#End if not is empty
                }#else if test column names exist
                    else
                    {
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "CSV file got wrong format! File:  $strCompareFile" -strType "Error" -DateStamp ))
                    } #End if test column names exist 
                } # End If Verify that a successful CSV import is performed before continue 
           }#End If $chkBoxEffectiveRights.isChecked  -or $chkBoxFilter.isChecked
    
        }#End If Test-Path
        else
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "CSV file not found!" -strType "Error" -DateStamp ))
        }#End If Test-Path Else
    }# End If          

    #Restore the DC string to its original
    $global:strDC = $global:ResetDCvalue
}
else
{
        $global:observableCollection.Insert(0,(LogMessage -strMessage "No object selected!" -strType "Error" -DateStamp ))
}
$allSubOU = ""
$strFileCSV = ""
$strFileHTA = ""
$strFileHTM = ""
$sADobjectName = ""
$date= ""
}
function RunScan
{

$bolPreChecks = $true
If ($txtBoxSelected.Text)
{
    If(($chkBoxFilter.IsChecked -eq $true) -and  (($chkBoxType.IsChecked -eq $false) -and ($chkBoxObject.IsChecked -eq $false) -and ($chkBoxTrustee.IsChecked -eq  $false)))
    {
                   
                   $global:observableCollection.Insert(0,(LogMessage -strMessage "Filter Enabled , but no filter is specified!" -strType "Error" -DateStamp ))
                   $bolPreChecks = $false
    }
    else
    {
        If(($chkBoxFilter.IsChecked -eq $true) -and  (($combAccessCtrl.SelectedIndex -eq -1) -and ($combObjectFilter.SelectedIndex -eq -1) -and ($txtFilterTrustee.Text -eq  "")))
        {
                       
                       $global:observableCollection.Insert(0,(LogMessage -strMessage "Filter Enabled , but no filter is specified!" -strType "Error" -DateStamp ))
                       $bolPreChecks = $false
        }
    }
    
        If(($chkBoxEffectiveRights.IsChecked -eq $true) -and  ($global:tokens.count -eq 0))
    {
                    
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Effective rights enabled , but no service principal selected!" -strType "Error" -DateStamp ))
                    $bolPreChecks = $false
    }
    $global:intShowCriticalityLevel = 0
    if ($bolPreChecks -eq $true)
    {
        $strCompareFile = ""
        $allSubOU = New-Object System.Collections.ArrayList
        $allSubOU.Clear()
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Scanning..." -strType "Info" -DateStamp ))
	    $BolSkipDefPerm = $chkBoxDefaultPerm.IsChecked
        $BolSkipProtectedPerm =  $chkBoxSkipProtectedPerm.IsChecked
        $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
	    $bolCSV = $rdbHTAandCSV.IsChecked

        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC,$global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest
        if($global:bolShowDeleted)
        {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
            [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
        }
        $request.DistinguishedName = $txtBoxSelected.Text.ToString()
        $request.Filter = "(name=*)"
        $request.Scope = "Base"
        [void]$request.Attributes.Add("name")
        
        $response = $LDAPConnection.SendRequest($request)
        $ADobject = $response.Entries[0]
        #Verify that attributes can be read
        if($null -ne $ADobject.distinguishedName)
        {
	        if($null -ne $ADobject.Attributes.name)
            {
                $strNode = $ADobject.Attributes.name[0]
            }
            else
            {
                $strNode = $ADobject.distinguishedName
            }
            $bolTranslateGUIDStoObject = $false
            $date= get-date -uformat %Y%m%d_%H%M%S
            $strNode = fixfilename $strNode
	        $strFileCSV = $txtTempFolder.Text + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".csv" 
            $strFileEXCEL = $txtTempFolder.Text + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".xlsx" 
	        $strFileHTA = $env:temp + "\"+$global:ACLHTMLFileName+".hta" 
	        $strFileHTM = $env:temp + "\"+"$global:strDomainShortName-$strNode-$global:SessionID"+".htm" 	
            if(!($rdbOnlyCSV.IsChecked))
            {		
                if(!($rdbEXcel.IsChecked))
                {		            	
                    if ($chkBoxFilter.IsChecked)
                    {
		                CreateHTA "$global:strDomainShortName-$strNode Filtered" $strFileHTA  $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
		                CreateHTM "$global:strDomainShortName-$strNode Filtered" $strFileHTM	
                    }
                    else
                    {
                        CreateHTA "$global:strDomainShortName-$strNode" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
		                CreateHTM "$global:strDomainShortName-$strNode" $strFileHTM	
                    }

	                InitiateHTM $strFileHTA $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $chkBoxGetOUProtected.IsChecked $chkBoxEffectiveRightsColor.IsChecked $false $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked
	                InitiateHTM $strFileHTM $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $chkBoxGetOUProtected.IsChecked $chkBoxEffectiveRightsColor.IsChecked $false $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked
                    $Format = "HTM"
                }
                else
                {
                    $Format = "EXCEL"
                }
            }			
	        If ($txtBoxSelected.Text.ToString().Length -gt 0)
            {
                #Select type of scope
		        If ($rdbBase.IsChecked -eq $False)
		        {
                    If ($rdbSubtree.IsChecked -eq $true)
		            {
			            $allSubOU = GetAllChildNodes $txtBoxSelected.Text "subtree"
                    }
                    else
                    {
                        $allSubOU = GetAllChildNodes $txtBoxSelected.Text "onelevel"
                    }	    
                }
		        else
		        {
			        $allSubOU = GetAllChildNodes $txtBoxSelected.Text "base"
		        }
                #if any objects found read ACLs
                if($allSubOU.count -gt 0)
                {			        
                    Get-Perm $allSubOU $global:strDomainShortName $BolSkipDefPerm $BolSkipProtectedPerm $chkBoxFilter.IsChecked $chkBoxGetOwner.IsChecked $bolCSV $rdbOnlyCSV.IsChecked $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $chkBoxEffectiveRights.IsChecked $chkBoxGetOUProtected.IsChecked $bolTranslateGUIDStoObject $true $Format
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects returned! Does your filter relfect the objects you are searching for?" -strType "Error" -DateStamp ))
                }                		        
	        }
        }
        else
        {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not read object $($txtBoxSelected.Text.ToString()). Enough permissions?" -strType "Error" -DateStamp ))
        }
    }
}
else
{
        $global:observableCollection.Insert(0,(LogMessage -strMessage "No object selected!" -strType "Error" -DateStamp ))
}
$global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))

$allSubOU = ""
$strFileCSV = ""
$strFileHTA = ""
$strFileHTM = ""
$sADobjectName = ""
$date= ""

}
function Get-XMLPath
{
Param($xmlElement)
    $Path = ""

    $FQDN = $xmlElement.Text

    return $FQDN
}

function AddXMLAttribute
{
    Param([ref]$node, $szName, $value)
	$attribute = $global:xmlDoc.createAttribute($szName);
	[void]$node.value.setAttributeNode($attribute);
	$node.value.setAttribute($szName, $value);
	#return $node;
}

function Add-ExcludeChild
{

    # Test if any node is selected
    if($txtBoxSelected.Text.Length -gt 0)
    {
        if($txtBoxExcluded.Text.Length -gt 0)
        {
            $txtBoxExcluded.Text = $txtBoxExcluded.Text + ";" + $txtBoxSelected.Text 
        }
        else
        {
            $txtBoxExcluded.Text =  $txtBoxSelected.Text
        }

    }

}

function Add-RefreshChild
{

    # Test if any node is selected
    if($txtBoxSelected.Text.Length -gt 0)
    {
        $xmlNode = $global:xmlDoc
        $NodeDNPath = $txtBoxSelected.Text

        if($global:TreeViewRootPath -eq $NodeDNPath)
        {
            $Mynodes = $xmlNode.SelectSingleNode("//DomainRoot[@Text='$NodeDNPath']")
            # Make sure a node was found
            if($Mynodes.Name.Length -gt 0)
            {
                $Mynodes.IsEmpty = $true
                $treeNodePath = $NodeDNPath
       
                # Initialize and Build Domain OU Tree 

                ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath #-nodeCount 0 
                # Set tag to show this node is already enumerated 

            }
        }
        else
        {
            $Mynodes = $xmlNode.SelectSingleNode("//OU[@Text='$NodeDNPath']")
            # Make sure a node was found
            if($Mynodes.Name.Length -gt 0)
            {
                $Mynodes.IsEmpty = $true
                $treeNodePath = $NodeDNPath
       
                # Initialize and Build Domain OU Tree 
                ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath #-nodeCount 0 
                # Set tag to show this node is already enumerated 

            }
        }
    }

}

#  Processes an OU tree

function ProcessOUTree
{

	Param($node, $ADSObject)

	# Increment the node count to indicate we are done with the domain level

 
	$strFilterOUCont = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)))"
	$strFilterAll = "(objectClass=*)"

    
    


    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null    
    
    if($global:bolShowDeleted)
    {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
    }
    $request.DistinguishedName = $ADSObject


    # Single line Directory searcher
    # set a filter



	If ($rdbBrowseAll.IsChecked -eq $true)
	{
	$request.Filter = $strFilterAll
		
	}
	else
	{
 	$request.Filter = $strFilterOUCont
	}
    # set search scope
    $request.Scope = "OneLevel"

    [void]$request.Attributes.Add("name")
    [void]$request.Attributes.Add("objectclass")
    
	# Now walk the list and recursively process each child
        while ($true)
        {
            $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
            #for paged search, the response for paged search result control - we will need a cookie from result later
            if($global:PageSize -gt 0) {
                [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
                if ($response.Controls.Length -gt 0)
                {
                    foreach ($ctrl in $response.Controls)
                    {
                        if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                        {
                            $prrc = $ctrl;
                            break;
                        }
                    }
                }
                if($null -eq $prrc) {
                    #server was unable to process paged search
                    throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                }
            }
            #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
            $colResults = $response.Entries
	        foreach ($objResult in $colResults)
	        {             
		    
                if ($objResult.attributes.Count -ne 0)
                {
		            $NewOUNode = $global:xmlDoc.createElement("OU");
            
                    # Add an Attribute for the Name

                    if (($null -ne $($objResult.attributes.name[0])))
		            {

                        # Add an Attribute for the Name
                        $OUName = "$($objResult.attributes.name[0])"
        
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Name" -value $OUName
                        $DNName = $objResult.distinguishedname
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Text" -value $DNName
                             Switch ($objResult.attributes.objectclass[$objResult.attributes.objectclass.count-1])
                            {
                            "domainDNS"
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\DomainDNS.png"
                            }
                            "OrganizationalUnit"
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\OU.png"
                            }
                            "user"
                            {
                             AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\User.png"
                            }
                            "group"
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Group.png"
                            }
                            "computer"
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Computer.png"
                            }
                            "container"
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Container.png"
                            }
                            default
                            {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Other.png"
                            }
                        }
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Tag" -value "Enumerated"
                        $child = $node.appendChild($NewOUNode);
                        ProcessOUTreeStep2OnlyShow -node $NewOUNode -DNName $DNName
                           }
                    else
                    {
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not read object $($objResult.distinguishedname)" -strType "Error" -DateStamp ))
                    }
                }
                else
                {
                 if ($null -ne $objResult.distinguishedname)
		            {

                        # Add an Attribute for the Name
                        $DNName = $objResult.distinguishedname
                        $OUName = $DNName.toString().Split(",")[0]
                        if($OUName -match "=")
                        {
                        $OUName = $OUName.Split("=")[1]
                        }
        
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Name" -value $OUName
                
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Text" -value $DNName
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Container.png"
                        AddXMLAttribute -node ([ref]$NewOUNode) -szName "Tag" -value "Enumerated"
                        $child = $node.appendChild($NewOUNode);
                        ProcessOUTreeStep2OnlyShow -node $NewOUNode -DNName $DNName
                    }

                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not read object $($objResult.distinguishedname). Enough permissions?" -strType "Warning" -DateStamp ))
                }

            }
            if($global:PageSize -gt 0) {
                if ($prrc.Cookie.Length -eq 0) {
                    #last page --> we're done
                    break;
                }
                #pass the search cookie back to server in next paged request
                $pagedRqc.Cookie = $prrc.Cookie;
            } else {
                #exit the processing for non-paged search
                break;
            }
        }


}
function ProcessOUTreeStep2OnlyShow
{
    Param($node, $DNName)

	# Increment the node count to indicate we are done with the domain level

    $strFilterOUCont = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)))"
	$strFilterAll = "(&(name=*))"

    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    #$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(objectClass=classSchema)", "Subtree")
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.distinguishedName = $DNName 
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    if($global:bolShowDeleted)
    {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
    }
    # Single line Directory searcher
    # set a filter

	If ($rdbBrowseAll.IsChecked -eq $true)
	{
	$request.Filter = $strFilterAll
		
	}
	else
	{
 	$request.Filter = $strFilterOUCont
	}

    # set search scope
    $request.Scope = "oneLevel"

    [void]$request.Attributes.Add("name")

    $arrSchemaObjects = New-Object System.Collections.ArrayList
    $intStop = 0
    while ($true)
    {
        $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
        #for paged search, the response for paged search result control - we will need a cookie from result later
        if($global:PageSize -gt 0) 
        {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
            if ($response.Controls.Length -gt 0)
            {
                foreach ($ctrl in $response.Controls)
                {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                    {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
	    foreach ($objResult in $colResults)
	    {             
            if($intStop -eq 0)
            {
                $global:DirSrchResults = $objResult 
                if ($null -ne $global:DirSrchResults.attributes)
                {
		    

                    # Add an Attribute for the Name
                    $NewOUNode = $global:xmlDoc.createElement("OU");
                    # Add an Attribute for the Name
                
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Name" -value "Click ..."
            
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Text" -value "Click ..."
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Expand.png"
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Tag" -value "NotEnumerated"

		            [void]$node.appendChild($NewOUNode);
          
                }
                else
                {
              
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "At least one child object could not be accessed: $DNName" -strType "Warning" -DateStamp ))
                    # Add an Attribute for the Name
                    $NewOUNode = $global:xmlDoc.createElement("OU");
                    # Add an Attribute for the Name
                
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Name" -value "Click ..."
            
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Text" -value "Click ..."
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Img" -value "$env:temp\Expand.png"
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName "Tag" -value "NotEnumerated"

		            [void]$node.appendChild($NewOUNode);
                }
            }
            $intStop++
        }

        if($global:PageSize -gt 0) {
            if ($prrc.Cookie.Length -eq 0) {
                #last page --> we're done
                break;
            }
            #pass the search cookie back to server in next paged request
            $pagedRqc.Cookie = $prrc.Cookie;
        } else {
            #exit the processing for non-paged search
            break;
        }
    }#End While
}
function Get-XMLDomainOUTree
{

    param
    (
        $szDomainRoot
    )



    $treeNodePath = $szDomainRoot

   
    # Initialize and Build Domain OU Tree 
    
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    if($global:bolShowDeleted)
    {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
    }

    $request.distinguishedName = $treeNodePath 
    $request.filter = "(name=*)"
    $request.Scope = "base"
    [void]$request.Attributes.Add("name")
    [void]$request.Attributes.Add("objectclass")

    $response = $LDAPConnection.SendRequest($request)
    $DomainRoot = $response.Entries[0]
    if($DomainRoot.attributes.count -ne 0)
    {
        $DNName = $DomainRoot.distinguishedname
        if($null -ne $DomainRoot.Attributes.objectclass)
        {                
            $strObClass = $DomainRoot.Attributes.objectclass[$DomainRoot.Attributes.objectclass.count-1]
        }
        else
        {
            $strObClass = "unknown"
        }
    }
    else
    {
        $DNName = $DomainRoot.distinguishedname
        $strObClass = "container"

        $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not read object $DNName . Enough permissions?" -strType "Error" -DateStamp ))
    }
    $global:xmlDoc = New-Object -TypeName System.Xml.XmlDocument
    $global:xmlDoc.PreserveWhitespace = $false

    $RootNode = $global:xmlDoc.createElement("DomainRoot")
    AddXMLAttribute -Node ([ref]$RootNode) -szName "Name" -value $szDomainRoot
    AddXMLAttribute -node ([ref]$RootNode) -szName "Text" -value $DNName
    AddXMLAttribute -node ([ref]$RootNode) -szName "Icon" -value "$env:temp\refresh2.png"
    AddXMLAttribute -node ([ref]$RootNode) -szName "Icon2" -value "$env:temp\exclude.png"

     Switch ($strObClass)
                {
                "domainDNS"
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\DomainDNS.png"
                }
                "OrganizationalUnit"
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\OU.png"
                }
                "user"
                {
                 AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\User.png"
                }
                "group"
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\Group.png"
                }
                "computer"
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\Computer.png"
                }
                "container"
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\Container.png"
                }
                default
                {
                AddXMLAttribute -node ([ref]$RootNode) -szName "Img" -value "$env:temp\Other.png"
                }
            }
    [void]$global:xmlDoc.appendChild($RootNode)
    
    $node = $global:xmlDoc.documentElement;

    #Process the OU tree
    ProcessOUTree -node $node -ADSObject $treeNodePath  #-nodeCount 0

    return $global:xmlDoc
}







$global:dicRightsGuids = @{"Seed" = "xxx"}
$global:dicSidToName = @{"Seed" = "xxx"} 
$global:dicDCSpecialSids =@{"BUILTIN\Incoming Forest Trust Builders"="S-1-5-32-557";`
"BUILTIN\Account Operators"="S-1-5-32-548";`
"BUILTIN\Server Operators"="S-1-5-32-549";`
"BUILTIN\Pre-Windows 2000 Compatible Access"="S-1-5-32-554";`
"BUILTIN\Terminal Server License Servers"="S-1-5-32-561";`
"BUILTIN\Windows Authorization Access Group"="S-1-5-32-560"}
$global:dicWellKnownSids = @{"S-1-0"="Null Authority";`
"S-1-0-0"="Nobody";`
"S-1-1"="World Authority";`
"S-1-1-0"="Everyone";`
"S-1-2"="Local Authority";`
"S-1-2-0"="Local ";`
"S-1-2-1"="Console Logon ";`
"S-1-3"="Creator Authority";`
"S-1-3-0"="Creator Owner";`
"S-1-3-1"="Creator Group";`
"S-1-3-2"="Creator Owner Server";`
"S-1-3-3"="Creator Group Server";`
"S-1-3-4"="Owner Rights";`
"S-1-4"="Non-unique Authority";`
"S-1-5"="NT Authority";`
"S-1-5-1"="Dialup";`
"S-1-5-2"="Network";`
"S-1-5-3"="Batch";`
"S-1-5-4"="Interactive";`
"S-1-5-6"="Service";`
"S-1-5-7"="Anonymous";`
"S-1-5-8"="Proxy";`
"S-1-5-9"="Enterprise Domain Controllers";`
"S-1-5-10"="Principal Self";`
"S-1-5-11"="Authenticated Users";`
"S-1-5-12"="Restricted Code";`
"S-1-5-13"="Terminal Server Users";`
"S-1-5-14"="Remote Interactive Logon";`
"S-1-5-15"="This Organization";`
"S-1-5-17"="IUSR";`
"S-1-5-18"="Local System";`
"S-1-5-19"="NT Authority";`
"S-1-5-20"="NT Authority";`
"S-1-5-22"="ENTERPRISE READ-ONLY DOMAIN CONTROLLERS BETA";`
"S-1-5-32-544"="Administrators";`
"S-1-5-32-545"="Users";`
"S-1-5-32-546"="Guests";`
"S-1-5-32-547"="Power Users";`
"S-1-5-32-548"="BUILTIN\Account Operators";`
"S-1-5-32-549"="Server Operators";`
"S-1-5-32-550"="Print Operators";`
"S-1-5-32-551"="Backup Operators";`
"S-1-5-32-552"="Replicator";`
"S-1-5-32-554"="BUILTIN\Pre-Windows 2000 Compatible Access";`
"S-1-5-32-555"="BUILTIN\Remote Desktop Users";`
"S-1-5-32-556"="BUILTIN\Network Configuration Operators";`
"S-1-5-32-557"="BUILTIN\Incoming Forest Trust Builders";`
"S-1-5-32-558"="BUILTIN\Performance Monitor Users";`
"S-1-5-32-559"="BUILTIN\Performance Log Users";`
"S-1-5-32-560"="BUILTIN\Windows Authorization Access Group";`
"S-1-5-32-561"="BUILTIN\Terminal Server License Servers";`
"S-1-5-32-562"="BUILTIN\Distributed COM Users";`
"S-1-5-32-568"="BUILTIN\IIS_IUSRS";`
"S-1-5-32-569"="BUILTIN\Cryptographic Operators";`
"S-1-5-32-573"="BUILTIN\Event Log Readers ";`
"S-1-5-32-574"="BUILTIN\Certificate Service DCOM Access";`
"S-1-5-32-575"="BUILTIN\RDS Remote Access Servers";`
"S-1-5-32-576"="BUILTIN\RDS Endpoint Servers";`
"S-1-5-32-577"="BUILTIN\RDS Management Servers";`
"S-1-5-32-578"="BUILTIN\Hyper-V Administrators";`
"S-1-5-32-579"="BUILTIN\Access Control Assistance Operators";`
"S-1-5-32-580"="BUILTIN\Remote Management Users";`
"S-1-5-33"="Write Restricted Code";`
"S-1-5-64-10"="NTLM Authentication";`
"S-1-5-64-14"="SChannel Authentication";`
"S-1-5-64-21"="Digest Authentication";`
"S-1-5-65-1"="This Organization Certificate";`
"S-1-5-80"="NT Service";`
"S-1-5-84-0-0-0-0-0"="User Mode Drivers";`
"S-1-5-113"="Local Account";`
"S-1-5-114"="Local Account And Member Of Administrators Group";`
"S-1-5-1000"="Other Organization";`
"S-1-15-2-1"="All App Packages";`
"S-1-16-0"="Untrusted Mandatory Level";`
"S-1-16-4096"="Low Mandatory Level";`
"S-1-16-8192"="Medium Mandatory Level";`
"S-1-16-8448"="Medium Plus Mandatory Level";`
"S-1-16-12288"="High Mandatory Level";`
"S-1-16-16384"="System Mandatory Level";`
"S-1-16-20480"="Protected Process Mandatory Level";`
"S-1-16-28672"="Secure Process Mandatory Level";`
"S-1-18-1"="Authentication Authority Asserted Identityl";`
"S-1-18-2"="Service Asserted Identity"}

#==========================================================================
# Function		: Test-ResolveDNS 
# Arguments     : DNS Name, DNS Server
# Returns   	: boolean
# Description   : This function try to resolve a dns record and retruns true or false
# 
#==========================================================================
Function Test-ResolveDNS
{
param
(
$strDNS,
$strDNSServer = ""
)
    $bolResolved = $false
    $global:bolDNSSuccess = $true
    $global:DNSrslt = $null
    try
    {
        if($strDNSServer-eq "")
        {
            $global:DNSrslt = Resolve-DnsName -Type ALL -Name $strDNS -ErrorAction Stop
        }
        else
        {
            $global:DNSrslt = Resolve-DnsName -Type ALL -Name $strDNS -ErrorAction Stop -Server $strDNSServer
        }
    }
    catch
    {
        $global:bolDNSSuccess = $false
    }
    if($global:bolDNSSuccess)
    {
        if(($global:DNSrslt)[0].IPAddress -ne $null)
        {
            $bolResolved = $true
        }


    }
    Remove-Variable bolDNSSuccess -Scope global
    Remove-Variable DNSrslt -Scope global
    return $bolResolved
}
#==========================================================================
# Function		: LogMessage 
# Arguments     : Type of message, message, date stamping
# Returns   	: Custom psObject with two properties, type and message
# Description   : This function creates a custom object that is used as input to an ListBox for logging purposes
# 
#==========================================================================
function LogMessage 
{ 
     param ( 
         [Parameter(  
             Mandatory = $true
          )][String[]] $strType ,
        
        [Parameter(  
             Mandatory = $true 
          )][String[]]  $strMessage ,

       [Parameter(  
             Mandatory = $false
         )][switch]$DateStamp
     )
     
     process {

                if ($DateStamp)
                {

                    $newMessageObject = New-Object PSObject -Property @{Type="$strType";Message="[$(get-date)] $strMessage"}
                }
                else
                {

                    $newMessageObject = New-Object PSObject -Property @{Type="$strType";Message="$strMessage"}
                }

         
                return $newMessageObject
            }
 } 

#==========================================================================
# Function		: ConvertTo-ObjectArrayListFromPsCustomObject  
# Arguments     : Defined Object
# Returns   	: Custom Object List
# Description   : Convert a defined object to a custom, this will help you  if you got a read-only object 
# 
#==========================================================================
function ConvertTo-ObjectArrayListFromPsCustomObject 
{ 
     param ( 
         [Parameter(  
             Position = 0,   
             Mandatory = $true,   
             ValueFromPipeline = $true,  
             ValueFromPipelineByPropertyName = $true  
         )] $psCustomObject
     ); 
     
     process {
 
        $myCustomArray = New-Object System.Collections.ArrayList
     
         foreach ($myPsObject in $psCustomObject) { 
             $hashTable = @{}; 
             $myPsObject | Get-Member -MemberType *Property | ForEach-Object { 
                 $hashTable.($_.name) = $myPsObject.($_.name); 
             } 
             $Newobject = new-object psobject -Property  $hashTable
             [void]$myCustomArray.add($Newobject)
         } 
         return $myCustomArray
     } 
 }
 #==========================================================================
# Function		: GenerateTemplateDownloaderSchemaDefSD
# Arguments     : -
# Returns   	: -
# Description   : Generates a form for download links
#==========================================================================
Function GenerateTemplateDownloaderSchemaDefSD
{
[xml]$xamlTemplateDownloaderSchemaDefSD =@"
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="CSV Templates" WindowStartupLocation = "CenterScreen"
        Width = "380" Height = "250" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" >
    <Window.Resources>
    
        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Blue"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <TextBlock TextDecorations="Underline" 
                            Text="{TemplateBinding Content}"
                            Background="{TemplateBinding Background}"/>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Foreground" Value="Red"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
         </Style>
    </Window.Resources>
<ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
        <Grid>
        <StackPanel Orientation="Vertical">
            <Label x:Name="lblDownloadLinks" Content="Download links for defaultSecuritydescriptor CSV templates:" Margin="10,05,00,00"/>
                <GroupBox x:Name="gBoxTemplate" Header="Templates" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFileSchema2016" Content="Windows Server 2016" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2012R2" Content="Windows Server 2012 R2" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2012" Content="Windows Server 2012" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2008R2" Content="Windows Server 2008 R2" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2003SP1" Content="Windows Server 2003 SP1" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2003" Content="Windows Server 2003" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2000SP4" Content="Windows 2000 Server SP4" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/> 
                    </StackPanel>       
                </GroupBox>            
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
            </StackPanel>
        </StackPanel>
        </Grid>
 </ScrollViewer>
</Window>

"@

$xamlTemplateDownloaderSchemaDefSD.Window.RemoveAttribute("x:Class") 

$reader=(New-Object System.Xml.XmlNodeReader $xamlTemplateDownloaderSchemaDefSD)
$TemplateDownloaderSchemaDefSDGui=[Windows.Markup.XamlReader]::Load( $reader )
$btnOK = $TemplateDownloaderSchemaDefSDGui.FindName("btnOK")
$btnDownloadCSVFileSchema2016 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2016")
$btnDownloadCSVFileSchema2012R2 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2012R2")
$btnDownloadCSVFileSchema2012 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2012")
$btnDownloadCSVFileSchema2008R2 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2008R2")
$btnDownloadCSVFileSchema2003SP1 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2003SP1")
$btnDownloadCSVFileSchema2003 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2003")
$btnDownloadCSVFileSchema2000SP4 = $TemplateDownloaderSchemaDefSDGui.FindName("btnDownloadCSVFileSchema2000SP4")


$btnOK.add_Click({
$TemplateDownloaderSchemaDefSDGui.Close()
})


$btnDownloadCSVFileSchema2016.add_Click({
 [System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21173&authkey=!ANmZFP4r67-yvGs&ithint=file%2ccsv")
 })
$btnDownloadCSVFileSchema2012R2.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!108&authkey=!AH2bxltG5s-l3YY&ithint=file%2ccsv")
})
$btnDownloadCSVFileSchema2012.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!111&authkey=!APeksydtWJ9B1Fc&ithint=file%2ccsv")
})
$btnDownloadCSVFileSchema2008R2.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!110&authkey=!AKYYkARRfsC7IyM&ithint=file%2ccsv")
})
$btnDownloadCSVFileSchema2003SP1.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21164&authkey=AI5D2Q7kmGI_17Q&ithint=file%2ccsv")
})
$btnDownloadCSVFileSchema2003.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!109&authkey=!AKZcScjykAZr9sw&ithint=file%2ccsv")
})
$btnDownloadCSVFileSchema2000SP4.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!112&authkey=!ACo2xB2BHPYSkOE&ithint=file%2ccsv")
})



$TemplateDownloaderSchemaDefSDGui.ShowDialog()

}
#==========================================================================
# Function		: GenerateTemplateDownloader
# Arguments     : -
# Returns   	: -
# Description   : Generates a form for download links
#==========================================================================
Function GenerateTemplateDownloader
{
[xml]$xamlTemplateDownloader =@"
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="CSV Templates" WindowStartupLocation = "CenterScreen"
        Width = "650" Height = "400" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" >
    <Window.Resources>
    
        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Blue"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <TextBlock TextDecorations="Underline" 
                            Text="{TemplateBinding Content}"
                            Background="{TemplateBinding Background}"/>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Foreground" Value="Red"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
         </Style>
    </Window.Resources>
<ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
        <Grid>
        <StackPanel Orientation="Vertical">
            <Label x:Name="lblDownloadLinks" Content="Download links for operating system default DACL templates:" Margin="10,05,00,00"/>
            <StackPanel Orientation="Horizontal" Margin="0,0">
                <GroupBox x:Name="gBox2016" Header="Windows Server 2016" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2016" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2016AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>
                <GroupBox x:Name="gBox2012R2" Header="Windows Server 2012 R2" HorizontalAlignment="Left"  Margin="2,1,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2012R2" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012R2AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>     
                <GroupBox x:Name="gBox2012" Header="Windows Server 2012" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2012" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2012AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>  
                </StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,0">    
                <GroupBox x:Name="gBox2008R2" Header="Windows Server 2008 R2" HorizontalAlignment="Left"  Margin="2,0,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2008R2" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2008R2AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>
                <GroupBox x:Name="gBox2003" Header="Windows Server 2003" HorizontalAlignment="Left" Margin="2,0,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2003" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2003AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>
                <GroupBox x:Name="gBox2000SP4" Header="Windows 2000 Server SP4" HorizontalAlignment="Left" Margin="2,0,0,0" VerticalAlignment="Top" Width="210">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFile2000SP4" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2000SP4Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2000SP4Config" Content="Configration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2000SP4Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFile2000SP4AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                    </StackPanel>
                </GroupBox>                               
            </StackPanel>            
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
            </StackPanel>
        </StackPanel>
        </Grid>
 </ScrollViewer>
</Window>

"@

$xamlTemplateDownloader.Window.RemoveAttribute("x:Class") 

$reader=(New-Object System.Xml.XmlNodeReader $xamlTemplateDownloader)
$TemplateDownloaderGui=[Windows.Markup.XamlReader]::Load( $reader )
$btnOK = $TemplateDownloaderGui.FindName("btnOK")
$btnDownloadCSVFile2016 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016")
$btnDownloadCSVFile2016Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016Domain")
$btnDownloadCSVFile2016Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016Config")
$btnDownloadCSVFile2016Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016Schema")
$btnDownloadCSVFile2016DomainDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016DomainDNS")
$btnDownloadCSVFile2016ForestDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016ForestDNS")
$btnDownloadCSVFile2016AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2016AllFiles")
$btnDownloadCSVFile2012R2 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2")
$btnDownloadCSVFile2012R2Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2Domain")
$btnDownloadCSVFile2012R2Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2Config")
$btnDownloadCSVFile2012R2Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2Schema")
$btnDownloadCSVFile2012R2DomainDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2DomainDNS")
$btnDownloadCSVFile2012R2ForestDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2ForestDNS")
$btnDownloadCSVFile2012R2AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012R2AllFiles")
$btnDownloadCSVFile2012 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012")
$btnDownloadCSVFile2012Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012Domain")
$btnDownloadCSVFile2012Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012Config")
$btnDownloadCSVFile2012Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012Schema")
$btnDownloadCSVFile2012DomainDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012DomainDNS")
$btnDownloadCSVFile2012ForestDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012ForestDNS")
$btnDownloadCSVFile2012AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2012AllFiles")
$btnDownloadCSVFile2008R2 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2")
$btnDownloadCSVFile2008R2Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2Domain")
$btnDownloadCSVFile2008R2Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2Config")
$btnDownloadCSVFile2008R2Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2Schema")
$btnDownloadCSVFile2008R2DomainDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2DomainDNS")
$btnDownloadCSVFile2008R2ForestDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2ForestDNS")
$btnDownloadCSVFile2008R2AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2008R2AllFiles")
$btnDownloadCSVFile2003 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003")
$btnDownloadCSVFile2003Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003Domain")
$btnDownloadCSVFile2003Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003Config")
$btnDownloadCSVFile2003Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003Schema")
$btnDownloadCSVFile2003DomainDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003DomainDNS")
$btnDownloadCSVFile2003ForestDNS = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003ForestDNS")
$btnDownloadCSVFile2003AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2003AllFiles")
$btnDownloadCSVFile2000SP4 = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2000SP4")
$btnDownloadCSVFile2000SP4Domain = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2000SP4Domain")
$btnDownloadCSVFile2000SP4Config = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2000SP4Config")
$btnDownloadCSVFile2000SP4Schema = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2000SP4Schema")
$btnDownloadCSVFile2000SP4AllFiles = $TemplateDownloaderGui.FindName("btnDownloadCSVFile2000SP4AllFiles")

$btnOK.add_Click({
$TemplateDownloaderGui.Close()
})


## START 2016
$btnDownloadCSVFile2016.add_Click({
 #[System.Diagnostics.Process]::Start("https://1drv.ms/u/s!Aqm6M_BmY8U_gSlxzW6CZ2_noQUX")
 [System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21169&authkey=!AHHNboJnb-ehBRc&ithint=file%2ccsv")
 
})
$btnDownloadCSVFile2016Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21167&authkey=!APh1fzUu8ndLvho&ithint=file%2ccsv")
})
$btnDownloadCSVFile2016Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21171&authkey=!AG5nGAGqOAAZ3kg&ithint=file%2ccsv")
})
$btnDownloadCSVFile2016Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21170&authkey=!AM7EwzODPD7wlrM&ithint=file%2ccsv")
})
$btnDownloadCSVFile2016DomainDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21168&authkey=!AI4FI10Y20fOMXY&ithint=file%2ccsv")
})
$btnDownloadCSVFile2016ForestDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21166&authkey=!APGNhnXbQ1nMlmY&ithint=file%2ccsv")
})
$btnDownloadCSVFile2016AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9%21172&authkey=!AHHbU-CV7iYSqCM&ithint=file%2czip")
})
## END 2016
## START 2012 R2
$btnDownloadCSVFile2012R2.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!118&authkey=!AEsPNFM4NNDs-NY&ithint=file%2ccsv")
})

$btnDownloadCSVFile2012R2Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!117&authkey=!ACGO_auHv7nVuFA&ithint=file%2ccsv")
})

$btnDownloadCSVFile2012R2Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!120&authkey=!AAUMJ01QN18vWz0&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012R2Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!119&authkey=!ACZnOYr_JsYL_1A&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012R2DomainDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!115&authkey=!ABibK0uHLccRXXE&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012R2ForestDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!116&authkey=!AN76snGTmVRqYUg&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012R2AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!134&authkey=!AJ9zhCQSjhPCiA4&ithint=file%2czip")
})
## END 2012 R2
## START 2012
$btnDownloadCSVFile2012.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!132&authkey=!AA1HBqNDu3g07YA&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!127&authkey=!AFOrTjNj77zbe5M&ithint=file%2ccsv")
})

$btnDownloadCSVFile2012Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!128&authkey=!AIoukl1--XMqH0o&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!129&authkey=!APUXZph0_yhzXns&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012DomainDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!130&authkey=!ABuBOH9pXKlgUo0&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012ForestDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!131&authkey=!AHmopj2Fc9L7pS4&ithint=file%2ccsv")
})
$btnDownloadCSVFile2012AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!133&authkey=!AJhM8XTSi_eboFs&ithint=file%2czip")
})
## END 2012
## START 2008 R2
$btnDownloadCSVFile2008R2.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!157&authkey=!APMwORrenMZF2Dw&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!140&authkey=!ALgAYQdynKvUZLs&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!158&authkey=!ACm5uljC8HQGU00&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!158&authkey=!ACm5uljC8HQGU00&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2DomainDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!136&authkey=!AD_CYsd2dEM7Pf8&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2ForestDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!137&authkey=!AKXfX52VtuirzFw&ithint=file%2ccsv")
})
$btnDownloadCSVFile2008R2AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!159&authkey=!AE4AIrkTKhM-Xcg&ithint=file%2czip")
})
## END 2008 R2
## START 2003

$btnDownloadCSVFile2003.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!150&authkey=!AF98uOT5coGagCQ&ithint=file%2ccsv")
})
$btnDownloadCSVFile2003Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!147&authkey=!AA5j_FLH3sfAk5Q&ithint=file%2ccsv")
})

$btnDownloadCSVFile2003Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!148&authkey=!AE1-jkVztfOqIJw&ithint=file%2ccsv")
})
$btnDownloadCSVFile2003Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!145&authkey=!AFa88cyZdDJsYVk&ithint=file%2ccsv")
})
$btnDownloadCSVFile2003DomainDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!146&authkey=!AJ6CtlNI0he9OgM&ithint=file%2ccsv")
})
$btnDownloadCSVFile2003ForestDNS.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!144&authkey=!AKoTCcfQnKHYpMc&ithint=file%2ccsv")
})
$btnDownloadCSVFile2003AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!160&authkey=!AEiUpr6LOCkiQ94&ithint=file%2czip")
})
## END 2003

## START 2000 SP4

$btnDownloadCSVFile2000SP4.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!152&authkey=!AKO49fQePeRrCKY&ithint=file%2ccsv")
})

$btnDownloadCSVFile2000SP4Domain.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!155&authkey=!AFGHVo-wCZoWXYw&ithint=file%2ccsv")
})

$btnDownloadCSVFile2000SP4Config.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!156&authkey=!AEoB4RiacNQci4s&ithint=file%2ccsv")
})
$btnDownloadCSVFile2000SP4Schema.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!154&authkey=!AHy8rar_9lJ8KQo&ithint=file%2ccsv")
})

$btnDownloadCSVFile2000SP4AllFiles.add_Click({
[System.Diagnostics.Process]::Start("https://onedrive.live.com/download?resid=3FC56366F033BAA9!153&authkey=!AKsmuhvoig_CKfs&ithint=file%2czip")
})
## END 2000


$TemplateDownloaderGui.ShowDialog()

}
#==========================================================================
# Function		: GenerateTrustedDomainPicker
# Arguments     : -
# Returns   	: Domain DistinguishedName
# Description   : Windows Form List AD Domains in Forest 
#==========================================================================
Function GenerateTrustedDomainPicker
{
[xml]$TrustedDomainPickerXAML =@"
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Locations" WindowStartupLocation = "CenterScreen"
        Width = "400" Height = "200" ShowInTaskbar = "True" ResizeMode="NoResize" WindowStyle="ToolWindow" Opacity="0.9">
    <Window.Background>
        <LinearGradientBrush>
            <LinearGradientBrush.Transform>
                <ScaleTransform x:Name="Scaler" ScaleX="1" ScaleY="1"/>
            </LinearGradientBrush.Transform>
            <GradientStop Color="#CC064A82" Offset="1"/>
            <GradientStop Color="#FF6797BF" Offset="0.7"/>
            <GradientStop Color="#FF6797BF" Offset="0.3"/>
            <GradientStop Color="#FFD4DBE1" Offset="0"/>
        </LinearGradientBrush>
    </Window.Background>
    <Grid>
        <StackPanel Orientation="Vertical">
            <Label x:Name="lblDomainPciker" Content="Select the location you want to search." Margin="10,05,00,00"/>
        <ListBox x:Name="objListBoxDomainList" HorizontalAlignment="Left" Height="78" Margin="10,05,0,0" VerticalAlignment="Top" Width="320"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
            <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
            <Button x:Name="btnCancel" Content="Cancel" Margin="10,05,00,00" Width="50" Height="20"/>
        </StackPanel>
        </StackPanel>
    </Grid>
</Window>

"@

$TrustedDomainPickerXAML.Window.RemoveAttribute("x:Class") 

$reader=(New-Object System.Xml.XmlNodeReader $TrustedDomainPickerXAML)
$TrustedDomainPickerGui=[Windows.Markup.XamlReader]::Load( $reader )
$btnOK = $TrustedDomainPickerGui.FindName("btnOK")
$btnCancel = $TrustedDomainPickerGui.FindName("btnCancel")
$objListBoxDomainList = $TrustedDomainPickerGui.FindName("objListBoxDomainList")



$btnCancel.add_Click(
{
$TrustedDomainPickerGui.Close()
})

$btnOK.add_Click({
$global:strDomainPrinDNName=$objListBoxDomainList.SelectedItem

if ( $global:strDomainPrinDNName -eq $global:strDomainLongName )
{
    $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
}
else
{
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", "(&(trustPartner=$global:strDomainPrinDNName))", "Onelevel")
    [void]$request.Attributes.Add("trustdirection")
    [void]$request.Attributes.Add("trustattributes")
    [void]$request.Attributes.Add("flatname")
    $response = $LDAPConnection.SendRequest($request)
    $colResults = $response.Entries[0]

    if($null -ne $colResults)
    {
            $global:strPrinDomDir = $colResults.attributes.trustdirection[0]
            $global:strPrinDomAttr = "{0:X2}" -f [int]  $colResults.attributes.trustattributes[0]
            $global:strPrinDomFlat = $colResults.attributes.flatname[0].ToString()
            $lblSelectPrincipalDom.Content = $global:strPrinDomFlat+":"

    }

}
$TrustedDomainPickerGui.Close()
})
 

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", "(&(cn=*)(objectClass=trustedDomain))", "Onelevel") 
[void]$request.Attributes.Add("trustpartner")
$response = $LDAPConnection.SendRequest($request)
$colResults = $response.Entries

foreach ($objResult in $colResults)
{
    [void] $objListBoxDomainList.Items.Add($objResult.attributes.trustpartner[0])
}



[void] $objListBoxDomainList.Items.Add($global:strDomainLongName)

$TrustedDomainPickerGui.ShowDialog()

}
#==========================================================================
# Function		: GenerateSupportStatement 
# Arguments     : -
# Returns   	: Support 
# Description   : Generate Support Statement 
#==========================================================================
Function GenerateSupportStatement
{
[xml]$SupportStatementXAML =@"
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Support Statement" WindowStartupLocation = "CenterScreen"
        Width = "400" Height = "500" ShowInTaskbar = "True" ResizeMode="NoResize" WindowStyle="ToolWindow"  Background="#FFF0F0F0">
    <Grid HorizontalAlignment="Center">
        <StackPanel Orientation="Vertical"  Margin="0,0,00,0" HorizontalAlignment="Center">
            <Label x:Name="lblSupportHeader" Content="Carefully read and understand the support statement." Height="25" Width="350" FontSize="12" />
            <Label x:Name="lblSupportStatement" Content="" Height="380"  Width="370" FontSize="12" Background="White" BorderBrush="#FFC9C9CA" BorderThickness="1,1,1,1" FontWeight="Bold"/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                <Button x:Name="btnOK" Content="OK" Margin="00,10,00,00" Width="50" Height="20"/>
            </StackPanel>
        </StackPanel>
    </Grid>
</Window>

"@

$SupportStatementXAML.Window.RemoveAttribute("x:Class") 
$reader=(New-Object System.Xml.XmlNodeReader $SupportStatementXAML)
$SuportGui=[Windows.Markup.XamlReader]::Load( $reader )


$btnOK = $SuportGui.FindName("btnOK")
$lblSupportStatement = $SuportGui.FindName("lblSupportStatement")
$txtSupoprt = @"
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT 
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR
A PARTICULAR PURPOSE.

This sample is not supported under any Microsoft standard 
support program or service. The script is provided AS IS
without warranty of any kind. Microsoft further disclaims
all implied warranties including, without limitation, any
implied warranties of merchantability or of fitness for a
particular purpose.
The entire risk arising out of the use or performance of the
sample and documentation remains with you. In no event
shall Microsoft, its authors,or anyone else involved in the 
creation, production, or delivery of the script be liable 
for any damages whatsoever (including, without limitation,
damages for loss of business profits, business interruption,
loss of business information, or other pecuniary loss) 
arising out of the use of or inability to use the sample or
documentation, even if Microsoft has been advised of the 
possibility of such damages.
"@
$lblSupportStatement.Content = $txtSupoprt

$btnOK.add_Click(
{
$SuportGui.Close()
})




$SuportGui.ShowDialog()

}
#==========================================================================
# Function		: GenerateDomainPicker 
# Arguments     : -
# Returns   	: Domain DistinguishedName
# Description   : Windows Form List AD Domains in Forest 
#==========================================================================
Function GenerateDomainPicker
{
[xml]$DomainPickerXAML =@"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Select a domain" WindowStartupLocation = "CenterScreen"
        Width = "400" Height = "200" ShowInTaskbar = "True" ResizeMode="NoResize" WindowStyle="ToolWindow" Opacity="0.9">
    <Window.Background>
        <LinearGradientBrush>
            <LinearGradientBrush.Transform>
                <ScaleTransform x:Name="Scaler" ScaleX="1" ScaleY="1"/>
            </LinearGradientBrush.Transform>
            <GradientStop Color="#CC064A82" Offset="1"/>
            <GradientStop Color="#FF6797BF" Offset="0.7"/>
            <GradientStop Color="#FF6797BF" Offset="0.3"/>
            <GradientStop Color="#FFD4DBE1" Offset="0"/>
        </LinearGradientBrush>
    </Window.Background>
    <Grid>
        <StackPanel Orientation="Vertical">
        <Label x:Name="lblDomainPciker" Content="Please select a domain:" Margin="10,05,00,00"/>
        <ListBox x:Name="objListBoxDomainList" HorizontalAlignment="Left" Height="78" Margin="10,05,0,0" VerticalAlignment="Top" Width="320"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
            <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
            <Button x:Name="btnCancel" Content="Cancel" Margin="10,05,00,00" Width="50" Height="20"/>
        </StackPanel>
        </StackPanel>
    </Grid>
</Window>
"@

$DomainPickerXAML.Window.RemoveAttribute("x:Class") 

$reader=(New-Object System.Xml.XmlNodeReader $DomainPickerXAML)
$DomainPickerGui=[Windows.Markup.XamlReader]::Load( $reader )
$btnOK = $DomainPickerGui.FindName("btnOK")
$btnCancel = $DomainPickerGui.FindName("btnCancel")
$objListBoxDomainList = $DomainPickerGui.FindName("objListBoxDomainList")

$btnCancel.add_Click(
{
$DomainPickerGui.Close()
})

$btnOK.add_Click(
{
$strSelectedDomain = $objListBoxDomainList.SelectedItem
if ($strSelectedDomain)
{
    if($strSelectedDomain.Contains("."))
    {
        $global:TempDC = $strSelectedDomain
        $strSelectedDomain  = "DC=" + $strSelectedDomain.Replace(".",",DC=")
    }
    $global:strDommainSelect = $strSelectedDomain
}
$DomainPickerGui.Close()
})
$arrPartitions = New-Object System.Collections.ArrayList
$arrPartitions.Clear()

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("")
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
[void]$request.Attributes.Add("dnshostname")
[void]$request.Attributes.Add("supportedcapabilities")
[void]$request.Attributes.Add("namingcontexts")
[void]$request.Attributes.Add("defaultnamingcontext")
[void]$request.Attributes.Add("schemanamingcontext")
[void]$request.Attributes.Add("configurationnamingcontext")
[void]$request.Attributes.Add("rootdomainnamingcontext")
[void]$request.Attributes.Add("isGlobalCatalogReady")                
try
{
    $response = $LDAPConnection.SendRequest($request)
    $global:bolLDAPConnection = $true
}
catch
{
	$global:bolLDAPConnection = $false
    #$global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
}
if($global:bolLDAPConnection -eq $true)
{
    $global:ForestRootDomainDN = $response.Entries[0].attributes.rootdomainnamingcontext[0]
    $global:SchemaDN = $response.Entries[0].attributes.schemanamingcontext[0]
    $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
    $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]
    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
}

#Get all NC and Domain partititons
$request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,$global:ConfigDN ", "(&(cn=*)(systemFlags:1.2.840.113556.1.4.803:=3))", "Onelevel")
[void]$request.Attributes.Add("ncname")
[void]$request.Attributes.Add("dnsroot")

try
{
    $response = $LDAPConnection.SendRequest($request)
    
}
catch
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
}
#If connection established list partitions
if($response)
{
    $colResults = $response.Entries
    foreach ($objResult in $colResults)
    {
        [void] $arrPartitions.add($objResult.attributes.dnsroot[0])
        [void] $objListBoxDomainList.Items.Add($objResult.attributes.ncname[0])
    }
}

#Get all incoming and bidirectional trusts
$request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", "(&(cn=*)(objectClass=trustedDomain)(|(trustDirection:1.2.840.113556.1.4.803:=1)(trustDirection:1.2.840.113556.1.4.803:=3)))", "Onelevel")
[void]$request.Attributes.Add("trustpartner")
try
{
    $response = $LDAPConnection.SendRequest($request)
    
}
catch
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
}
#If connection established list partitions
if($response)
{

    $colResults = $response.Entries
    foreach ($objResult in $colResults)
    {

        $bolPartitionMatch = $false
        foreach ($strPartition in $arrPartitions)
        {
            if($strPartition -eq $objResult.attributes.trustpartner[0])
            {
                $bolPartitionMatch = $true
            }
        }
        if(!($bolPartitionMatch))
        {
            [void] $objListBoxDomainList.Items.Add($objResult.attributes.trustpartner[0])
        }


    }
}



if($objListBoxDomainList.Items.count -gt 0)
{
    $DomainPickerGui.ShowDialog()
}

}
#==========================================================================
# Function		: Get-SchemaData 
# Arguments     : 
# Returns   	: string
# Description   : Returns Schema Version
#==========================================================================
function Get-SchemaData
{
Param([System.Management.Automation.PSCredential] $SchemaCREDS)

	# Retrieve schema

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $SchemaCREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(CN=ms-Exch-Schema-Version-Pt)", "onelevel")
[void]$request.Attributes.Add("rangeupper")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		[int] $ExchangeVersion = $entry.Attributes.rangeupper[0]
					
		if ( $global:SchemaHashExchange.ContainsKey($ExchangeVersion) )
		{
			$txtBoxExSchema.Text = $global:SchemaHashExchange[$ExchangeVersion]
		}
		else
		{
			$txtBoxExSchema.Text = "Unknown"
		}
	}
	catch
	{
		$txtBoxExSchema.Text = "Not Found"
	}

}
}
else
{
	$txtBoxExSchema.Text = "Not Found"
}
$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(CN=ms-RTC-SIP-SchemaVersion)", "onelevel")
[void]$request.Attributes.Add("rangeupper")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		[int] $LyncVersion = $entry.Attributes.rangeupper[0]
					
		if ( $global:SchemaHashLync.ContainsKey($LyncVersion) )
		{
			$txtBoxLyncSchema.Text = $global:SchemaHashLync[$LyncVersion]
		}
		else
		{
			$txtBoxLyncSchema.Text = "Unknown"
		}
	}
	catch
	{
		$txtBoxLyncSchema.Text = "Not Found"
	}

}
}
else
{
	$txtBoxLyncSchema.Text = "Not Found"
}
$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(CN=*)", "Base")
[void]$request.Attributes.Add("objectversion")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		$ADSchemaVersion = $entry.Attributes.objectversion[0]
					
		if ( $global:SchemaHashAD.ContainsKey([int]$ADSchemaVersion) )
		{
			$txtBoxADSchema.Text = $global:SchemaHashAD[[int]$ADSchemaVersion]
		}
		else
		{
			$txtBoxADSchema.Text = $ADSchemaVersion
		}
	}
	catch
	{
		$txtBoxADSchema.Text = "Not Found"
	}

}
}
else
{
	$txtBoxADSchema.Text = "Not Found"
}

$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:strDomainDNName", "(name=*)", "Base")
[void]$request.Attributes.Add("msds-behavior-version")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		$ADDFL = $entry.Attributes.'msds-behavior-version'[0]
					
		if ( $global:DomainFLHashAD.ContainsKey([int]$ADDFL) )
		{
			$txtBoxDFL.Text = $global:DomainFLHashAD[[int]$ADDFL]
		}
		else
		{
			$txtBoxDFL.Text = "Unknown"
		}
	}
	catch
	{
		$txtBoxDFL.Text = "Not Found"
	}

}
}
else
{
	$txtBoxDFL.Text = "Not Found"
}
$request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,CN=Configuration,$global:ForestRootDomainDN", "(name=*)", "Base")
[void]$request.Attributes.Add("msds-behavior-version")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		$ADFFL = $entry.Attributes.'msds-behavior-version'[0]
					
		if ( $global:ForestFLHashAD.ContainsKey([int]$ADFFL) )
		{
			$txtBoxFFL.Text = $global:ForestFLHashAD[[int]$ADFFL]
		}
		else
		{
			$txtBoxFFL.Text = "Unknown"
		}
	}
	catch
	{
		$txtBoxFFL.Text = "Not Found"
	}

}
}
else
{
	$txtBoxFFL.Text = "Not Found"
}
$request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$global:ForestRootDomainDN", "(dSHeuristics=*)", "Base")
[void]$request.Attributes.Add("dsheuristics")
$response = $LDAPConnection.SendRequest($request)
$adObject = $response.Entries

if(($null -ne $adObject) -and ($adobject.Count -ne 0 ))
{
foreach ($entry  in $response.Entries)
{
 
   
	try
	{
		$DSHeuristics = $entry.Attributes.dsheuristics[0]
					
		if ($DSHeuristics.Substring(2,1) -eq "1")
		{
			$txtListObjectMode.Text = "Enabled"
		}
		else
		{
			$txtListObjectMode.Text = "Disabled"
		}
	}
	catch
	{
		$txtListObjectMode.Text = "Not Found"
	}

}
}
else
{
	$txtListObjectMode.Text = "Disabled"
}
}
#==========================================================================
# Function		: Get-HighestNetFrameWorkVer 
# Arguments     : 
# Returns   	: string
# Description   : Returns Highest .Net Framework Version
#==========================================================================
Function Get-HighestNetFrameWorkVer
{
$arrDotNetFrameWorkVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
Get-ItemProperty -name Version,Release -EA 0 |
Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
Select-Object Version 
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 4.6} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 4.5} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 4.0} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 3.5} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 3.0} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 2.0} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 1.1} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
else{
$DotNetVer = $arrDotNetFrameWorkVersions | where-object{$_.version -ge 1.0} | Select-Object -Last 1
if($DotNetVer){$HighestDotNetFrmVer = $DotNetVer.Version}
}}}}}}}

Remove-variable DotNetVer,arrDotNetFrameWorkVersions

return $HighestDotNetFrmVer

}
#==========================================================================
# Function		: GetDomainController 
# Arguments     : Domain FQDN,bol using creds, PSCredential
# Returns   	: Domain Controller
# Description   : Locate a domain controller in a specified domain
#==========================================================================
Function GetDomainController
{
Param([string] $strDomainFQDN,
[bool] $bolCreds,
[parameter(Mandatory=$false)]
[System.Management.Automation.PSCredential] $DCCREDS)

$strDomainController = ""

if ($bolCreds -eq $true)
{

        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$strDomainFQDN,$DCCREDS.UserName,$DCCREDS.GetNetworkCredential().Password)
        $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
        $strDomainController = $($ojbDomain.FindDomainController()).name
}
else
{

        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$strDomainFQDN )
        $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
        $strDomainController = $($ojbDomain.FindDomainController()).name
}

return $strDomainController

}

#==========================================================================
# Function		: Get-DirContext 
# Arguments     : string domain controller,credentials
# Returns   	: Directory context
# Description   : Get Directory Context
#==========================================================================
function Get-DirContext
{
Param($DomainController,
[System.Management.Automation.PSCredential] $DIRCREDS)

	if($global:CREDS)
		{
		$Context = new-object DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$DomainController,$DIRCREDS.UserName,$DIRCREDS.GetNetworkCredential().Password)
	}
	else
	{
		$Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$DomainController)
	}
	

    return $Context
}
#==========================================================================
# Function		: TestCreds 
# Arguments     : System.Management.Automation.PSCredential
# Returns   	: Boolean
# Description   : Check If username and password is valid
#==========================================================================
Function TestCreds
{
Param([System.Management.Automation.PSCredential] $psCred)

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

if ($psCred.UserName -match "\\")
{
    If ($psCred.UserName.split("\")[0] -eq "")
    {
        [directoryservices.directoryEntry]$root = (New-Object system.directoryservices.directoryEntry)

        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $root.name) 
    }
    else
    {
    
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $psCred.UserName.split("\")[0]) 
    }
    $bolValid = $ctx.ValidateCredentials($psCred.UserName.split("\")[1],$psCred.GetNetworkCredential().Password)
}
else
{
    [directoryservices.directoryEntry]$root = (New-Object system.directoryservices.directoryEntry)

    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $root.name) 

    $bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)
}    

return $bolValid
}
#==========================================================================
# Function		: GetTokenGroups
# Arguments     : Principal DistinguishedName string
# Returns   	: ArrayList of groups names
# Description   : Group names of all sids in tokenGroups
#==========================================================================
Function GetTokenGroups
{
Param($PrincipalDomDC,$PrincipalDN,
[bool] $bolCreds,
[parameter(Mandatory=$false)]
[System.Management.Automation.PSCredential] $GetTokenCreds)


$script:bolErr = $false
$tokenGroups =  New-Object System.Collections.ArrayList

$tokenGroups.Clear()
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($PrincipalDomDC,$GetTokenCreds)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
$request.DistinguishedName = $PrincipalDN
$request.Filter = "(name=*)"
$request.Scope = "Base"
[void]$request.Attributes.Add("tokengroups")
[void]$request.Attributes.Add("tokengroupsglobalanduniversal")
[void]$request.Attributes.Add("objectsid")
$response = $LDAPConnection.SendRequest($request)
$ADobject = $response.Entries[0]

if ( $global:strDomainPrinDNName -eq $global:strDomainDNName )
{
    $SIDs = $ADobject.Attributes.tokengroups
}
else
{
    $SIDs = $ADobject.Attributes.tokengroupsglobalanduniversal
}
#Get selected principal SID
$strOwnerSIDs = [string]$($ADobject.Attributes.objectsid)
$ownerSIDs = New-Object System.Security.Principal.SecurityIdentifier $ADobject.Attributes.objectsid[0], 0
# Add selected principal SID to tokenGroups
[void]$tokenGroups.Add($ownerSIDs.Value)

$arrForeignSecGroups = FindForeignSecPrinMemberships $(GenerateSearchAbleSID $strOwnerSIDs) $global:CREDS

foreach ($ForeignMemb in $arrForeignSecGroups)
{
       if($null -ne  $ForeignMemb)
        {
            if($ForeignMemb.tostring().length -gt 0 )
            {
            [void]$tokenGroups.add($ForeignMemb)
            }
        }
} 

# Populate hash table with security group memberships. 
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($PrincipalDomDC,$GetTokenCreds)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
$request.DistinguishedName = "CN=ForeignSecurityPrincipals,$global:strDomainDNName"
$request.Filter = "(CN=S-1-5-11)"
$request.Scope = "onelevel"
[void]$request.Attributes.Add("objectsid")
$response = $LDAPConnection.SendRequest($request)
$colResults = $response.Entries
foreach ($objResult in $colResults)
{             
	$ForeignDefaultWellKnownSIDs = [string]$($objResult.Attributes.objectsid)

    $arrForeignSecGroups = FindForeignSecPrinMemberships $(GenerateSearchAbleSID $ForeignDefaultWellKnownSIDs) $global:CREDS

    foreach ($ForeignMemb in $arrForeignSecGroups)
    {
           if($null -ne  $ForeignMemb)
            {
                if($ForeignMemb.tostring().length -gt 0 )
                {
                [void]$tokenGroups.add($ForeignMemb)
                }
            }
    } 
} 
#Add SID string to tokenGroups
ForEach ($Value In $SIDs)
{
    $SID = New-Object System.Security.Principal.SecurityIdentifier $Value, 0

    [void]$tokenGroups.Add($SID.Value)
}
#Add Everyone  
[void]$tokenGroups.Add("S-1-1-0")
#Add Authenticated Users 
[void]$tokenGroups.Add("S-1-5-11")
if(($global:strPrinDomAttr -eq 14) -or ($global:strPrinDomAttr -eq 18) -or ($global:strPrinDomAttr -eq "5C") -or ($global:strPrinDomAttr -eq "1C") -or ($global:strPrinDomAttr -eq "44")  -or ($global:strPrinDomAttr -eq "54")  -or ($global:strPrinDomAttr -eq "50"))         
{
    #Add Other Organization 
    [void]$tokenGroups.Add("S-1-5-1000")
}
else
{
    #Add This Organization 
    [void]$tokenGroups.Add("S-1-5-15")
}
#Remove duplicate
$tokenGroups = $tokenGroups | Select-Object -Unique
Return $tokenGroups

}


#==========================================================================
# Function		: GenerateSearchAbleSID
# Arguments     : SID Decimal form Value as string
# Returns   	: SID in String format for LDAP searcheds
# Description   : Convert SID from decimal to hex with "\" for searching with LDAP
#==========================================================================
Function GenerateSearchAbleSID
{
Param([String] $SidValue)

$SidDec =$SidValue.tostring().split("")
Foreach ($intSID in $SIDDec)
{
[string] $SIDHex = "{0:X2}" -f [int] $intSID
$strSIDHextString = $strSIDHextString + "\" + $SIDHex

}

return $strSIDHextString
}
#==========================================================================
# Function		: FindForeignSecPrinMemberships
# Arguments     : SID Decimal form Value as string
# Returns   	: Group names
# Description   : Searching for ForeignSecurityPrinicpals and return memberhsip
#==========================================================================
Function FindForeignSecPrinMemberships
{
Param([string] $strSearchAbleSID,
[System.Management.Automation.PSCredential] $ForeignCREDS)

$arrForeignMembership = New-Object System.Collections.ArrayList
[void]$arrForeignMembership.clear()

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $ForeignCREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
$request.DistinguishedName = "CN=ForeignSecurityPrincipals,$global:strDomainDNName"
$request.Filter = "(&(objectSID=$strSearchAbleSID))"
$request.Scope = "Subtree"
[void]$request.Attributes.Add("memberof")
$response = $LDAPConnection.SendRequest($request)

Foreach ( $obj in $response.Entries)
{
    
  $index = 0
    while($index -le $obj.Attributes.memberof.count -1) 
    {
        $member = $obj.Attributes.memberof[$index]
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC,$ForeignCREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest

        $request.DistinguishedName = $member
        $request.Filter = "(name=*)"
        $request.Scope = "Base"
        [void]$request.Attributes.Add("objectsid")
        $response = $LDAPConnection.SendRequest($request)
        $ADobject = $response.Entries[0]
        $strPrinName = New-Object System.Security.Principal.SecurityIdentifier $($ADobject.Attributes.objectsid), 0
        [void]$arrForeignMembership.add($strPrinName.Value)
        $index++
    }
}            


return $arrForeignMembership
}
#==========================================================================
# Function		: GetSidStringFromSidByte
# Arguments     : SID Value in Byte[]
# Returns   	: SID in String format
# Description   : Convert SID from Byte[] to String
#==========================================================================
Function GetSidStringFromSidByte
{
Param([byte[]] $SidByte)

    $objectSid = [byte[]]$SidByte
    $sid = New-Object System.Security.Principal.SecurityIdentifier($objectSid,0)  
    $sidString = ($sid.value).ToString() 
    return $sidString
}
#==========================================================================
# Function		: GetSecPrinDN
# Arguments     : samAccountName
# Returns   	: DistinguishedName
# Description   : Search Security Principal and Return DistinguishedName
#==========================================================================
Function GetSecPrinDN
{
Param([string] $samAccountName,
[string] $strDomainDC,
[bool] $bolCreds,
[parameter(Mandatory=$false)]
[System.Management.Automation.PSCredential] $SecPrinDNREDS)


$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($strDomainDC,$SecPrinDNREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
$request.Filter = "(name=*)"
$request.Scope = "Base"
$response = $LDAPConnection.SendRequest($request)
$strPrinDomDC = $response.Entries[0].Attributes.dnshostname[0]
$strPrinDomDefNC = $response.Entries[0].Attributes.defaultnamingcontext[0]
if($strDomainDC -match ":")
{
    $strPrinDomDC = $strPrinDomDC + ":" + $strDomainDC.split(":")[1]
}
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($strPrinDomDC,$SecPrinDNREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
$request.DistinguishedName = $strPrinDomDefNC
$request.Filter = "(&(samAccountName=$samAccountName))"
$request.Scope = "Subtree"
[void]$request.Attributes.Add("name")

$response = $LDAPConnection.SendRequest($request)
$ADobject = $response.Entries[0]


if($ADobject.Attributes.Count -gt 0)
{

	$global:strPrincipalDN = $ADobject.distinguishedname
}
else
{
    $global:strPrincipalDN = ""
}

return $global:strPrincipalDN

}


#==========================================================================
# Function		: GetSchemaObjectGUID
# Arguments     : Object Guid or Rights Guid
# Returns   	: LDAPDisplayName or DisplayName
# Description   : Searches in the dictionaries(Hash) dicRightsGuids and $global:dicSchemaIDGUIDs  and in Schema 
#				for the name of the object or Extended Right, if found in Schema the dicRightsGuids is updated.
#				Then the functions return the name(LDAPDisplayName or DisplayName).
#==========================================================================
Function GetSchemaObjectGUID
{
Param([string] $Domain)
	[string] $strOut =""
	[string] $strLDAPname = ""
    
    [void]$combObjectFilter.Items.Clear()
    BuildSchemaDic
    foreach ($ldapDisplayName in $global:dicSchemaIDGUIDs.values)
    {
        [void]$combObjectFilter.Items.Add($ldapDisplayName)
    }

    
    
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(&(schemaIDGUID=*))", "Subtree")
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add("ldapdisplayname")
    [void]$request.Attributes.Add("schemaidguid")
    while ($true)
    {
        $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
        #for paged search, the response for paged search result control - we will need a cookie from result later
        if($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
            if ($response.Controls.Length -gt 0)
            {
                foreach ($ctrl in $response.Controls)
                {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                    {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
	    foreach ($objResult in $colResults)
	    {             
		    $strLDAPname = $objResult.attributes.ldapdisplayname[0]
		    $guidGUID = [System.GUID] $objResult.attributes.schemaidguid[0]
            $strGUID = $guidGUID.toString().toUpper()
		    If (!($global:dicSchemaIDGUIDs.ContainsKey($strGUID)))
            {
                $global:dicSchemaIDGUIDs.Add($strGUID,$strLDAPname)
                $global:dicNameToSchemaIDGUIDs.Add($strLDAPname,$strGUID)
                [void]$combObjectFilter.Items.Add($strLDAPname)
            }
				
	    }
        if($global:PageSize -gt 0) {
            if ($prrc.Cookie.Length -eq 0) {
                #last page --> we're done
                break;
            }
            #pass the search cookie back to server in next paged request
            $pagedRqc.Cookie = $prrc.Cookie;
        } else {
            #exit the processing for non-paged search
            break;
        }
    }

	          
        
	return $strOut
}


#==========================================================================
# Function		: CheckDNExist 
# Arguments     : string distinguishedName, string directory server
# Returns   	: Boolean
# Description   : Check If distinguishedName exist
#==========================================================================
function CheckDNExist
{
Param (
  $sADobjectName,
  $strDC
  )

    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($strDC, $global:CREDS)
    #$LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    if($global:bolShowDeleted)
    {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
    }
    $request.DistinguishedName = $sADobjectName
    $request.Filter = "(name=*)"
    $request.Scope = "Base"
	try
	{
        $response = $LDAPConnection.SendRequest($request)
	}
	catch
	{
		return $false
	}
    if($response.Entries.count -gt 0)
    {
        $ADobject = $response.Entries[0]
        If($null -eq $ADobject.distinguishedname)
        {return $false}
        else
        {return $true}
    }
}


#==========================================================================
# Function		: TestCSVColumnsDefaultSD
# Arguments     : CSV import for Default Security descriptor
# Returns   	: Boolean
# Description   : Search for all requried column names in CSV and return true or false
#==========================================================================
function TestCSVColumnsDefaultSD
{
param($CSVImport)
$bolColumExist = $false
$colHeaders = ( $CSVImport | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
$bolName = $false
$boldistinguishedName = $false
$bolVersion = $false
$bolModifiedDate = $false
$bolSDDL = $false

Foreach ($ColumnName in $colHeaders )
{

    if($ColumnName.Trim() -eq "Name")
    {
        $bolName = $true
    }
    if($ColumnName.Trim() -eq "distinguishedName")
    {
        $boldistinguishedName = $true
    }
    if($ColumnName.Trim() -eq "Version")
    {
        $bolVersion = $true
    }
    if($ColumnName.Trim() -eq "ModifiedDate")
    {
        $bolModifiedDate = $true
    }
    if($ColumnName.Trim() -eq "SDDL")
    {
        $bolSDDL = $true
    }
    

}
#if test column names exist
if($bolName -and $boldistinguishedName -and $bolVersion -and $bolModifiedDate -and $bolSDDL)
{
    $bolColumExist = $true
}
return $bolColumExist
}
#==========================================================================
# Function		: TestCSVColumns
# Arguments     : CSV import 
# Returns   	: Boolean
# Description   : Search for all requried column names in CSV and return true or false
#==========================================================================
function TestCSVColumns
{
param($CSVImport)
$bolColumExist = $false
$colHeaders = ( $CSVImport | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
$bolAccessControlType = $false
$bolActiveDirectoryRights = $false
$bolIdentityReference = $false
$bolInheritanceFlags = $false
$bolInheritanceType = $false
$bolInheritedObjectType = $false
$bolInvocationID = $false
$bolIsInherited = $false
$bolLegendText = $false
$bolObjectFlags= $false
$bolObjectType = $false
$bolOrgUSN= $false
$bolOU = $false
$bolPropagationFlags = $false
$bolSDDate = $false
Foreach ($ColumnName in $colHeaders )
{

    if($ColumnName.Trim() -eq "AccessControlType")
    {
        $bolAccessControlType = $true
    }
    if($ColumnName.Trim() -eq "ActiveDirectoryRights")
    {
        $bolActiveDirectoryRights = $true
    }
    if($ColumnName.Trim() -eq "IdentityReference")
    {
        $bolIdentityReference = $true
    }
    if($ColumnName.Trim() -eq "InheritanceFlags")
    {
        $bolInheritanceFlags = $true
    }
    if($ColumnName.Trim() -eq "InheritanceType")
    {
        $bolInheritanceType = $true
    }
    if($ColumnName.Trim() -eq "InheritedObjectType")
    {
        $bolInheritedObjectType = $true
    }
    if($ColumnName.Trim() -eq "InvocationID")
    {
        $bolInvocationID = $true
    }
    if($ColumnName.Trim() -eq "IsInherited")
    {
        $bolIsInherited = $true
    }        
    if($ColumnName.Trim() -eq "LegendText")
    {
        $bolLegendText = $true
    }    
   
    if($ColumnName.Trim() -eq "ObjectFlags")
    {
        $bolObjectFlags= $true
    }    
    if($ColumnName.Trim() -eq "ObjectType")
    {
        $bolObjectType = $true
    }   
    if($ColumnName.Trim() -eq "OrgUSN")
    {
        $bolOrgUSN= $true
    }   
    if($ColumnName.Trim() -eq "OU")
    {
        $bolOU = $true
    }   
    if($ColumnName.Trim() -eq "PropagationFlags")
    {
        $bolPropagationFlags = $true
    }        
    if($ColumnName.Trim() -eq "SDDate")
    {
        $bolSDDate = $true
    }     

}
#if test column names exist
if($bolAccessControlType -and $bolActiveDirectoryRights -and $bolIdentityReference -and $bolInheritanceFlags -and $bolInheritanceType -and $bolInheritedObjectType `
    -and $bolInvocationID -and $bolIsInherited -and $bolLegendText -and $bolObjectFlags -and $bolObjectType -and $bolOrgUSN -and $bolOU -and $bolPropagationFlags`
    -and $bolSDDate)
{
    $bolColumExist = $true
}
return $bolColumExist
}

#==========================================================================
# Function		: ReverseDNList
# Arguments     : array of distinguishedname
# Returns   	: List of reversed distinguishedname
# Description   : List of reversed distinguishedname
#==========================================================================
function ReverseDNList {
    param (
        [Parameter(Mandatory=$True)]
        [System.Array]$stringlist
    )

    $stringlistReversed = @()

    foreach ($string in $stringlist) {
        $stringSplitted = $string.Split(',')
        $Counter = $stringSplitted.Count
        $stringReversed = ''
        while ($Counter -gt 0) {
            $stringReversed += $stringSplitted[$Counter-1]
            $Counter = $Counter-1
            if ($Counter -gt 0) {
                $stringReversed += ','
            }
        }
        $stringlistReversed += $stringReversed
    }

    return $stringlistReversed
}
#==========================================================================
# Function		: GetAllChildNodes
# Arguments     : Node distinguishedName 
# Returns   	: List of Nodes
# Description   : Search for a Node and returns distinguishedName
#==========================================================================
function GetAllChildNodes
{
param (
# Search base
[Parameter(Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0,
            ParameterSetName='Default')]
[ValidateNotNull()]
[ValidateNotNullOrEmpty()]
[String] 
$firstnode,
# Scope
[Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=1,
            ParameterSetName='Default')]
[ValidateSet("base", "onelevel", "subtree")]
[ValidateNotNull()]
[ValidateNotNullOrEmpty()]
[String] 
$Scope,
# Search filter (Optional)
[Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=3,
            ParameterSetName='Default')]
[string]
$CustomFilter=""
)
$nodelist = New-Object System.Collections.ArrayList
$nodelist.Clear()
[boolean]$global:SearchFailed = $false

# Add all Children found as Sub Nodes to the selected TreeNode 

$strFilterAll = "(objectClass=*)"
$strFilterContainer = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=DomainDNS)(objectClass=dMD)))"
$strFilterOU = "(|(objectClass=organizationalUnit)(objectClass=domainDNS))"
$ReqFilter = ""

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null

if($global:bolShowDeleted)
{
    [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
}


$request.DistinguishedName = $firstnode
If ($rdbScanAll.IsChecked -eq $true) 
{
	$ReqFilter = $strFilterAll

}
If ($rdbScanOU.IsChecked -eq $true) 
{
	$ReqFilter = $strFilterOU
}
If ($rdbScanContainer.IsChecked -eq $true) 
{
	$ReqFilter = $strFilterContainer
}
If ($rdbScanFilter.IsChecked -eq $true) 
{
    if($txtCustomFilter.text.Length -gt 0)
    {
        $ReqFilter = $txtCustomFilter.Text
    }
}
if($CustomFilter -ne"")
{
    $ReqFilter = $CustomFilter
}

# Set search scope
$request.Scope = $Scope



#if the seaching using a scope of onelevel we add the base node to the results
if ($Scope -eq "onelevel")
{
    # Test the filter against the first node
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request2 = New-Object System.directoryServices.Protocols.Searchrequest($firstnode, $ReqFilter, "base")
    [void]$request2.Attributes.Add("name")               
    try
    {
        $response2 = $LDAPConnection.Sendrequest($request2)
    }
    catch
    {
        if($_.Exception.Message.tostring() -match "The search filter is invalid")
        {
            $global:SearchFailed = $true
            if($global:bolCMD)
            {
                Write-host "The search filter is invalid"
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "The search filter is invalid" -strType "Error" -DateStamp ))
            }
            break
        }
    }   
    #if the filter catch the first node add it to list
    If ($response2.Entries.Count -gt 0) 
    {
        if($txtBoxExcluded.text.Length -gt 0)
        {
            $bolInclude = $true
            Foreach( $strExcludeDN in $arrExcludedDN)
            {
                if(!($objResult.distinguishedName -notmatch $strExcludeDN ))
                {
                    $bolInclude = $false
                    break
                }
            }
            if($bolInclude)
            {
                #Reverse string to be able to sort output    
                try
                {   
                    $nodelist += $firstnode     
                }
                catch
                {}
                $intNomatch++
                
            }
        }
        else
        {   
            $nodelist += $firstnode    
        }
    }
}#End if Scope = onelevel
$request.filter =  $ReqFilter
if($txtBoxExcluded.text.Length -gt 0)
{
    $arrExcludedDN = $txtBoxExcluded.text.split(";")
    while ($true)
    {
        try
        {
            $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
        }
        catch
        {
            if($_.Exception.Message.tostring() -match "The search filter is invalid")
            {
                $global:SearchFailed = $true
                if($global:bolCMD)
                {
                    Write-host "The search filter is invalid"
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "The search filter is invalid" -strType "Error" -DateStamp ))
                }
                break
            }
        }          
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
    $colResults = $response.Entries
    $intTotalSearch =  $colResults.Count
    $intNomatch = 0
	foreach ($objResult in $colResults)
	{
        $bolInclude = $true
        Foreach( $strExcludeDN in $arrExcludedDN)
        {
          if(!($objResult.distinguishedName -notmatch $strExcludeDN ))
          {
              $bolInclude = $false
              break
          }
        }
        #Add objects with distinguihsedname not matching string
        if($bolInclude)
        {
            #Reverse string to be able to sort output
            $nodelist += $objResult.distinguishedName
            $intNomatch++
        }
        
    }
        if($global:PageSize -gt 0) {
            if ($prrc.Cookie.Length -eq 0) {
                #last page --> we're done
                break;
            }
            #pass the search cookie back to server in next paged request
            $pagedRqc.Cookie = $prrc.Cookie;
        } else {
            #exit the processing for non-paged search
            break;
        }
    } #End While

    #Caclulate number of objects exluded in search
    $global:intObjExluced = $intTotalSearch - $intNomatch
    # Log information about skipped objects
    if($global:bolCMD)
    {
        Write-host "Number of objects excluded: $global:intObjExluced"
    }
    else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Number of objects excluded: $global:intObjExluced" -strType "Info" -DateStamp ))
    }
}
# If no string in Excluded String box 
else
{

    $colResults = @()
    while ($true)
    {
        try
        {
        $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
        }
        catch
        {
            if($_.Exception.Message.tostring() -match "The search filter is invalid")
            {
                $global:SearchFailed = $true
                if($global:bolCMD)
                {
                    Write-host "The search filter is invalid" 
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "The search filter is invalid" -strType "Error" -DateStamp ))
                }
                break
            }
        } 
        #for paged search, the response for paged search result control - we will need a cookie from result later
        if($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
            if ($response.Controls.Length -gt 0)
            {
                foreach ($ctrl in $response.Controls)
                {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                    {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults += $response.Entries

        if($global:PageSize -gt 0) {
            if ($prrc.Cookie.Length -eq 0) {
                #last page --> we're done
                break;
            }
            #pass the search cookie back to server in next paged request
            $pagedRqc.Cookie = $prrc.Cookie;
        } else {
            #exit the processing for non-paged search
            break;
        }
    }
    if($colResults.count -gt 0)
    {
        $nodelist += $colResults.DistinguishedName
    }

}

if($nodelist.count -gt 0)
{
    $nodelist = ReverseDNList $nodelist
    $nodelist = $nodelist | sort
    $nodelist = ReverseDNList $nodelist
}
return $nodelist

}
#==========================================================================
# Function		: GetDomainShortName
# Arguments     : domain name 
# Returns   	: N/A
# Description   : Search for short domain name
#==========================================================================
function GetDomainShortName
{ 
Param($strDomain,
[string]$strConfigDN)

    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,$strConfigDN", "(&(objectClass=crossRef)(nCName=$strDomain))", "Subtree")
    [void]$request.Attributes.Add("netbiosname")
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries[0]

    if($null -ne $adObject)
    {

        $ReturnShortName = $adObject.Attributes.netbiosname[0]
	}
	else
	{
		$ReturnShortName = ""
	}
 
return $ReturnShortName
}

#==========================================================================
# Function		: Get-ProtectedPerm
# Arguments     : 
# Returns   	: ArrayList
# Description   : Creates the Security Descriptor with the Protect object from accidental deleations ACE
#==========================================================================
Function Get-ProtectedPerm
{

$sdProtectedDeletion =  New-Object System.Collections.ArrayList
$sdProtectedDeletion.clear()

$protectedDeletionsACE1 = New-Object PSObject -Property @{ActiveDirectoryRights="DeleteChild";InheritanceType="None";ObjectType ="00000000-0000-0000-0000-000000000000";`
InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="None";AccessControlType="Deny";IdentityReference="Everyone";IsInherited="False";`
InheritanceFlags="None";PropagationFlags="None"}

[void]$sdProtectedDeletion.insert(0,$protectedDeletionsACE)


$protectedDeletionsACE2 = New-Object PSObject -Property @{ActiveDirectoryRights="DeleteChild, DeleteTree, Delete";InheritanceType="None";ObjectType ="00000000-0000-0000-0000-000000000000";`
InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Deny";IdentityReference="Everyone";IsInherited="False";`
InheritanceFlags="None";PropagationFlags="None"}

$protectedDeletionsACE3 = New-Object PSObject -Property @{ActiveDirectoryRights="DeleteTree, Delete";InheritanceType="None";ObjectType ="00000000-0000-0000-0000-000000000000";`
InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="None";AccessControlType="Deny";IdentityReference="Everyone";IsInherited="False";`
InheritanceFlags="None";PropagationFlags="None"}

[void]$sdProtectedDeletion.insert(0,@($protectedDeletionsACE1,$protectedDeletionsACE2,$protectedDeletionsACE3))




return $sdProtectedDeletion

}
#==========================================================================
# Function		: Get-PermDef
# Arguments     : Object Class, Trustee Name
# Returns   	: ArrayList
# Description   : Fetch the Default Security Descriptor with the Default
#==========================================================================
Function Get-PermDef
{
Param($strObjectClass,
[string]$strTrustee)


$sdOUDef =  New-Object System.Collections.ArrayList
$sdOUDef.clear()



$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(ldapdisplayname=$strObjectClass)", "Subtree")
[void]$request.Attributes.Add("defaultsecuritydescriptor")
$response = $LDAPConnection.SendRequest($request)
$colResults = $response.Entries

foreach ($entry  in $response.Entries)
{          
    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $defSD = ""
    if($null -ne $entry.Attributes.defaultsecuritydescriptor)
    {
        $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
    }
    $defSD = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])   
    $sec = $null
}


if($null -ne $defSD){

$(ConvertTo-ObjectArrayListFromPsCustomObject  $defSD)| ForEach-Object{[void]$sdOUDef.add($_)}
$defSD = $null
if ($strObjectClass -eq "computer")
{
  if($global:intObjeComputer -eq 0)
    {

        $global:additionalComputerACE1 = New-Object PSObject -Property @{ActiveDirectoryRights="DeleteTree, ExtendedRight, Delete, GenericRead";InheritanceType="None";ObjectType ="00000000-0000-0000-0000-000000000000";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="None";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}
        
        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


        $global:additionalComputerACE2 = New-Object PSObject -Property @{ActiveDirectoryRights="WriteProperty";InheritanceType="None";ObjectType ="4c164200-20c0-11d0-a768-00aa006e0529";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


        $global:additionalComputerACE3 = New-Object PSObject -Property @{ActiveDirectoryRights="WriteProperty";InheritanceType="None";ObjectType ="3e0abfd0-126a-11d0-a060-00aa006c33ed";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


        $global:additionalComputerACE4 = New-Object PSObject -Property @{ActiveDirectoryRights="WriteProperty";InheritanceType="None";ObjectType ="bf967953-0de6-11d0-a285-00aa003049e2";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}
        
        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)

        $global:additionalComputerACE5 = New-Object PSObject -Property @{ActiveDirectoryRights="WriteProperty";InheritanceType="None";ObjectType ="bf967950-0de6-11d0-a285-00aa003049e2";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)

        $global:additionalComputerACE6 = New-Object PSObject -Property @{ActiveDirectoryRights="WriteProperty";InheritanceType="None";ObjectType ="5f202010-79a5-11d0-9020-00c04fc2d4cf";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)
        

        $global:additionalComputerACE7 = New-Object PSObject -Property @{ActiveDirectoryRights="Self";InheritanceType="None";ObjectType ="f3a64788-5306-11d1-a9c5-0000f80367c1";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        #[void]$sdOUDef.insert(0,$global:additionalComputerACE)    
            
        $global:additionalComputerACE8 = New-Object PSObject -Property @{ActiveDirectoryRights="Self";InheritanceType="None";ObjectType ="72e39547-7b18-11d1-adef-00c04fd8d5cd";`
        InheritedObjectType="00000000-0000-0000-0000-000000000000";ObjectFlags="ObjectAceTypePresent";AccessControlType="Allow";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        [void]$sdOUDef.insert(0,@($global:additionalComputerACE1,$global:additionalComputerACE2,$global:additionalComputerACE3,$global:additionalComputerACE4,$global:additionalComputerACE5,$global:additionalComputerACE6,$global:additionalComputerACE7,$global:additionalComputerACE8))
    }
    else
    {
        [void]$sdOUDef.insert(0,@($global:additionalComputerACE1,$global:additionalComputerACE2,$global:additionalComputerACE3,$global:additionalComputerACE4,$global:additionalComputerACE5,$global:additionalComputerACE6,$global:additionalComputerACE7,$global:additionalComputerACE8))
    }
    $global:intObjeComputer++
}# End if Computer
}



return $sdOUDef

}
#==========================================================================
# Function		: CacheRightsGuids
# Arguments     : none
# Returns   	: nothing
# Description   : Enumerates all Extended Rights and put them in a Hash dicRightsGuids
#==========================================================================
Function CacheRightsGuids
{
	
        
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $searcher = New-Object System.directoryServices.Protocols.SearchRequest
        $searcher.DistinguishedName = $global:ConfigDN

        [void]$searcher.Attributes.Add("cn")
        [void]$searcher.Attributes.Add("name")                        
        [void]$searcher.Attributes.Add("rightsguid")
        [void]$searcher.Attributes.Add("validaccesses")
        [void]$searcher.Attributes.Add("displayname")
		$searcher.filter = "(&(objectClass=controlAccessRight))"

        $searcherSent = $LDAPConnection.SendRequest($searcher)
        $colResults = $searcherSent.Entries        
 		$intCounter = 0
	
	foreach ($objResult in $colResults)
	{

		    $strRightDisplayName = $objResult.Attributes.displayname[0]
		    $strRightGuid = $objResult.Attributes.rightsguid[0]
		    $strRightGuid = $($strRightGuid).toString()

            #Expecting to fail at lest once since two objects have the same rightsguid
            &{#Try

		        $global:dicRightsGuids.Add($strRightGuid,$strRightDisplayName)	
            }
            Trap [SystemException]
            {
                #Write-host "Failed to add CAR:$strRightDisplayName" -ForegroundColor red
                continue
            }

		$intCounter++
    }
			 

}
#==========================================================================
# Function		: MapGUIDToMatchingName
# Arguments     : Object Guid or Rights Guid
# Returns   	: LDAPDisplayName or DisplayName
# Description   : Searches in the dictionaries(Hash) dicRightsGuids and $global:dicSchemaIDGUIDs  and in Schema 
#				for the name of the object or Extended Right, if found in Schema the dicRightsGuids is updated.
#				Then the functions return the name(LDAPDisplayName or DisplayName).
#==========================================================================
Function MapGUIDToMatchingName
{
Param([string] $strGUIDAsString,[string] $Domain)
	[string] $strOut =""
	[string] $strLDAPname = ""

	If ($strGUIDAsString -eq "") 
	{

	 Break
	 }
	$strGUIDAsString = $strGUIDAsString.toUpper()
	$strOut =""
	if ($global:dicRightsGuids.ContainsKey($strGUIDAsString))
	{
		$strOut =$global:dicRightsGuids.Item($strGUIDAsString)
	}

	If ($strOut -eq "")
	{  #Didn't find a match in extended rights
		If ($global:dicSchemaIDGUIDs.ContainsKey($strGUIDAsString))
		{
			$strOut =$global:dicSchemaIDGUIDs.Item($strGUIDAsString)
		}
		else
		{
		
		 if ($strGUIDAsString -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$"))
		 {
		 	
			$ConvertGUID = ConvertGUID($strGUIDAsString)
		            
            $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
            $LDAPConnection.SessionOptions.ReferralChasing = "None"
            $searcher = New-Object System.directoryServices.Protocols.SearchRequest
            $searcher.DistinguishedName = $global:SchemaDN

            [void]$searcher.Attributes.Add("cn")
    
            [void]$searcher.Attributes.Add("name")                        
            [void]$searcher.Attributes.Add("ldapdisplayname")
			$searcher.filter = "(&(schemaIDGUID=$ConvertGUID))"

            $searcherSent = $LDAPConnection.SendRequest($searcher)
            $objSchemaObject = $searcherSent.Entries[0]

			 if ($objSchemaObject)
			 {
				$strLDAPname =$objSchemaObject.attributes.ldapdisplayname[0]
				$global:dicSchemaIDGUIDs.Add($strGUIDAsString.toUpper(),$strLDAPname)
				$strOut=$strLDAPname
				
			 }
		}
	  }
	}
    
	return $strOut
}
#==========================================================================
# Function		: ConvertGUID
# Arguments     : Object Guid or Rights Guid
# Returns   	: AD Searchable GUID String
# Description   : Convert a GUID to a string

#==========================================================================
Function ConvertGUID
 {
    Param($guid)

	 $test = "(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})"
	 $pattern = '"\$4\$3\$2\$1\$6\$5\$8\$7\$9\$10\$11\$12\$13\$14\$15\$16"'
	 $ConvertGUID = [regex]::Replace($guid.replace("-",""), $test, $pattern).Replace("`"","")
	 return $ConvertGUID
}
#==========================================================================
# Function		: fixfilename
# Arguments     : Text for naming text file
# Returns   	: Text with replace special characters
# Description   : Replace characters that be contained in a file name.

#==========================================================================
function fixfilename
{
    Param([string] $strFileName)
    $strFileName = $strFileName.Replace("*","#")
    $strFileName = $strFileName.Replace("/","#")
    $strFileName = $strFileName.Replace("\","#")
    $strFileName = $strFileName.Replace(":","#")
    $strFileName = $strFileName.Replace("<","#")
    $strFileName = $strFileName.Replace(">","#")
    $strFileName = $strFileName.Replace("|","#")
    $strFileName = $strFileName.Replace('"',"#")
    $strFileName = $strFileName.Replace('?',"#")

    return $strFileName
}
#==========================================================================
# Function		: WritePermCSV
# Arguments     : Security Descriptor, OU distinguishedName, Ou put text file
# Returns   	: n/a
# Description   : Writes the SD to a text file.
#==========================================================================
function WritePermCSV
{
    Param($sd,[string]$ou,[string]$objType,[string] $fileout, [bool] $ACLMeta,[string]  $strACLDate,[string] $strInvocationID,[string] $strOrgUSN)
$sd  | foreach {
        #Convert SID to Names for lookups
        $strPrincipalName = $_.IdentityReference.toString()
	    If ($strPrincipalName -match "S-1-")
	    {
	        $strPrincipalName = ConvertSidToName -server $global:strDomainLongName -Sid $strPrincipalName

	    }
        # Add Translated object GUID information to output
        if($chkBoxTranslateGUID.isChecked -eq $true)
        {
	        if($($_.InheritedObjectType.toString()) -ne "00000000-0000-0000-0000-000000000000" )
            {
            
                $strTranslatedInheritObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.InheritedObjectType.toString() -Domain $global:strDomainDNName) 
            }
            else
            {
                $strTranslatedInheritObjType = "None" #$($_.InheritedObjectType.toString())
            }
	        if($($_.ObjectType.toString()) -ne "00000000-0000-0000-0000-000000000000" )
            {
            
                $strTranslatedObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.ObjectType.toString() -Domain $global:strDomainDNName) 
            }
            else
            {
                $strTranslatedObjType = "None" #$($_.ObjectType.toString())
            }
        }
        else
        {
            $strTranslatedInheritObjType = $($_.InheritedObjectType.toString())
            $strTranslatedObjType = $($_.ObjectType.toString())
        }
        # Add Meta data info to output
        If ($ACLMeta -eq $true)
        {
            $strMetaData = $strACLDate.toString()+[char]34+","+[char]34+$strInvocationID.toString()+[char]34+","+[char]34+ $strOrgUSN.toString()+[char]34+","
	        
        }
        else
        {
            $strMetaData = [char]34+","+[char]34+[char]34+","+[char]34+[char]34+","

        }
        if($chkBoxEffectiveRightsColor.IsChecked -eq $true)
        {
            $intCriticalityValue = GetCriticality $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString()
            Switch ($intCriticalityValue)
            {
                0 {$strLegendText = "Info"+[char]34 +","}
                1 {$strLegendText = "Low"+[char]34 +","}
                2 {$strLegendText = "Medium"+[char]34 +","}
                3 {$strLegendText = "Warning"+[char]34 +","}
                4 {$strLegendText = "Critical"+[char]34 +","}
            }
        }
        else
        {
            $strLegendText = [char]34 +","
        }



        [char]34+$ou+[char]34+","+[char]34+`
        $objType+[char]34+","+[char]34+`
        $_.IdentityReference.toString()+[char]34+","+[char]34+`
	    $strPrincipalName+[char]34+","+[char]34+`
	    $_.ActiveDirectoryRights.toString()+[char]34+","+[char]34+`
	    $_.InheritanceType.toString()+[char]34+","+[char]34+`
	    $strTranslatedObjType+[char]34+","+[char]34+`
	    $strTranslatedInheritObjType+[char]34+","+[char]34+`
	    $_.ObjectFlags.toString()+[char]34+","+[char]34+`
        $(if($null -ne $_.AccessControlType)
        {
        $_.AccessControlType.toString()+[char]34+","+[char]34
        }
        else
        {
        $_.AuditFlags.toString()+[char]34+","+[char]34
        })+`
	    $_.IsInherited.toString()+[char]34+","+[char]34+`
	    $_.InheritanceFlags.toString()+[char]34+","+[char]34+`
        $_.PropagationFlags.toString()+[char]34+","+[char]34+`
        $strMetaData+[char]34+`
         $strLegendText | Out-File -Append -FilePath $fileout 



    } 
}
#==========================================================================
# Function		: ConvertSidToName
# Arguments     : SID string
# Returns   	: Friendly Name of Security Object
# Description   : Try to translate the SID if it fails it try to match a Well-Known.
#==========================================================================
function ConvertSidToName
{
    Param($server,$sid)
$global:strAccNameTranslation = ""     
$ID = New-Object System.Security.Principal.SecurityIdentifier($sid)

&{#Try
	$User = $ID.Translate( [System.Security.Principal.NTAccount])
	$global:strAccNameTranslation = $User.Value
}
Trap [SystemException]
{
	If ($global:dicWellKnownSids.ContainsKey($sid))
	{
		$global:strAccNameTranslation = $global:dicWellKnownSids.Item($sid)
		return $global:strAccNameTranslation
	}
	;Continue
}

if ($global:strAccNameTranslation -eq "")
{

    If ($global:dicSidToName.ContainsKey($sid))
    {
	    $global:strAccNameTranslation =$global:dicSidToName.Item($sid)
    }
    else
    {

        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC,$global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest
        if($global:bolShowDeleted)
        {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
            [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
        }
        $request.DistinguishedName = "<SID=$sid>"
        $request.Filter = "(name=*)"
        $request.Scope = "Base"
        [void]$request.Attributes.Add("samaccountname")
        
        $response = $LDAPConnection.SendRequest($request)
        $result = $response.Entries[0]
        try
        {
	        $global:strAccNameTranslation =  $global:strDomainShortName + "\" + $result.attributes.samaccountname[0]
        }
        catch
        {
             
        }

	    if(!($global:strAccNameTranslation))
        {
            $global:strAccNameTranslation =  $result.distinguishedname
        }
        $global:dicSidToName.Add($sid,$global:strAccNameTranslation)
    }

}

If (($global:strAccNameTranslation -eq $nul) -or ($global:strAccNameTranslation -eq ""))
{
	$global:strAccNameTranslation =$sid
}

return $global:strAccNameTranslation
}
#==========================================================================
# Function		: GetCriticality
# Arguments     : $objRights,$objAccess,$objFlags,$objInheritanceType
# Returns   	: Integer
# Description   : Check criticality and returns number for rating
#==========================================================================
Function GetCriticality
{
    Param($objIdentity,$objRights,$objAccess,$objFlags,$objInheritanceType,$objObjectType,$objInheritedObjectType)

$intCriticalityLevel = 0

Switch ($objRights)
{
    "ListChildren"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 0
        }
    }
    "Modify permissions"
    {
        $intCriticalityLevel = 4
    }
    "DeleteChild, DeleteTree, Delete"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
        }
    }
    "Delete"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
        }
    }
    "GenericRead"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 1
    	}
    }
    "CreateChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "DeleteChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "ExtendedRight"
    {
        If ($objAccess -eq "Allow")
        {
            Switch ($objObjectType)
            {
                # User-Change-Password = 1
                "ab721a53-1e2f-11d0-9819-00aa0040529b"
                {
                    $intCriticalityLevel = 1
                }
                # DS-Query-Self-Quota = 1
                "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"
                {
                    $intCriticalityLevel = 1
                }
                # Enable-Per-User-Reversibly-Encrypted-Password = 1
                "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
                {
                    $intCriticalityLevel = 1
                }
                # Update-Password-Not-Required-Bit = 1
                "280f369c-67c7-438e-ae98-1d46f3c6f541"
                {
                    $intCriticalityLevel = 1
                }
                # Unexpire-Password = 1
                "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"
                {
                    $intCriticalityLevel = 1
                }
                # Apply-Group-Policy = 1
                "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
                {
                    $intCriticalityLevel = 1
                }
                # SAM-Enumerate-Entire-Domain = 1
                "91d67418-0135-4acc-8d79-c08e857cfbec"
                {
                    $intCriticalityLevel = 1
                }
                # Send-TO = 1
                "ab721a55-1e2f-11d0-9819-00aa0040529b"
                {
                    $intCriticalityLevel = 1
                }
                # Send-As = 3
                "ab721a54-1e2f-11d0-9819-00aa0040529b"
                {
                    #If it SELF then = 1
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 3
                    }
                }
                # Receive-As = 3
                "ab721a56-1e2f-11d0-9819-00aa0040529b"
                {
                   #If it SELF then = 1
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 3
                    }
                }
                # DS-Replication-Get-Changes = 3
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                {
                    $intCriticalityLevel = 3
                }
                default
                {
                    $intCriticalityLevel = 4
                }
            }
            
        }
    }
    "GenericAll"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 4
    	}
    }
    "CreateChild, DeleteChild"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 3
    	}
    }
    "ReadProperty"
    {
        If ($objAccess -eq "Allow")
        {
            $intCriticalityLevel = 1
    	}
        Switch ($objInheritanceType) 
    	{
    	 	"None"
    	 	{
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #       
                #        $objRights = "Read"	
                #    }
                #       	                
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Read"	
                #    }
                #    default
                #    {$objRights = "Read All Properties"	}
                #}#End switch
                $intCriticalityLevel = 1
            }
            "Children"
    	    {
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #        $objRights = "Read"	
                #    }
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Read"	
                #    }
                #    default
                #    {$objRights = "Read All Properties"	}
                #}#End switch
                 
            }
            "Descendents"
            {
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #        $objRights = "Read"	
                #    }
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Read"	
                #    }
                #    default
                #    {$objRights = "Read All Properties"	}
                #}#End switch
                                  
            }
    	    default
    	    {
                #$objRights = "Read All Properties"	
            }
        }#End switch
    }
    "ReadProperty, WriteProperty, ExtendedRight" 
    {
        If ($objAccess -eq "Allow")
        {
            Switch ($objObjectType)
            {
                # Privat-Information = 3
                "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
                {
                    #If it SELF then = 1
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 3
                    }
                }
                default
                {
                $intCriticalityLevel = 4
                }
            }
        }

    }
    "ReadProperty, WriteProperty" 
    {
        If ($objAccess -eq "Allow")
        {
           Switch ($objObjectType)
            {
                # Email-Information = 0
                "E45795B2-9455-11d1-AEBD-0000F80367C1"
                {
                    $intCriticalityLevel = 0
                }
                # Web-Information = 2
                "E45795B3-9455-11d1-AEBD-0000F80367C1"
                {
                    #If it SELF then = 1
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 2
                    }
                }
                # Personal-Information = 2
                "77B5B886-944A-11d1-AEBD-0000F80367C1"
                {
                    #If it SELF then = 1
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 2
                    }
                }
                default
                {
                    $intCriticalityLevel = 2
                }
            }
    	}
        #$objRights = "Read All Properties;Write All Properties"			
    }
    "WriteProperty" 
    {
        If ($objAccess -eq "Allow")
        {
           Switch ($objObjectType)
            {
                # Personal-Information = 2
                "77B5B886-944A-11d1-AEBD-0000F80367C1"
                {
                    if($objIdentity -eq "NT AUTHORITY\SELF")
                    {
                        $intCriticalityLevel = 1
                    }
                    else
                    {
                        $intCriticalityLevel = 2
                    }
                }
                default
                {
                    $intCriticalityLevel = 2
                }
            }
            
    	}
        #Switch ($objInheritanceType) 
    	#{
    	# 	"None"
    	# 	{
     
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #    default
                #    {
                #        $objRights = "Write All Properties"	
                #    }
                #}#End switch
        #    }
        #    "Children"
        #    {
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #               	                
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #    default
                #    {
                #        $objRights = "Write All Properties"	
                #    }
                #}#End switch
        #    }
        #    "Descendents"
        #    {
                #Switch ($objFlags)
                #{ 
                #    "ObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                #    {
                #        $objRights = "Write"	
                #    }
                #    default
                #    {
                #        $objRights = "Write All Properties"	
                #    }
                #}#End switch
        #    }
        #    default
        #    {
        #        #$objRights = "Write All Properties"
        #    }
        #}#End switch		
    }
    default
    {
        If ($objAccess -eq "Allow")
        {
            if($objRights -match "Write")
            {
                $intCriticalityLevel = 2
            }         
            if($objRights -match "Create")
            {
                $intCriticalityLevel = 3
            }        
            if($objRights -match "Delete")
            {
                $intCriticalityLevel = 3
            }
            if($objRights -match "ExtendedRight")
            {
                $intCriticalityLevel = 3
            }             
            if($objRights -match "WriteDacl")
            {
                $intCriticalityLevel = 4
            }
            if($objRights -match "WriteOwner")
            {
                $intCriticalityLevel = 4
            }       
        }     
    }
}# End Switch

Return $intCriticalityLevel

}
#==========================================================================
# Function		: WriteOUT
# Arguments     : Security Descriptor, OU dn string, Output htm file or other format
# Returns   	: n/a
# Description   : Wites the SD info to a HTM table or other format, it appends info if the file exist
#==========================================================================
function WriteOUT
{
    Param([bool] $bolACLExist,$sd,[string]$DSObject,[bool] $OUHeader,[string] $strColorTemp,[string] $htmfileout,[bool] $CompareMode,[bool] $FilterMode,[bool]$boolReplMetaDate,[string]$strReplMetaDate,[bool]$boolACLSize,[string]$strACLSize,[bool]$boolOUProtected,[bool]$bolOUPRotected,[bool]$bolCriticalityLevel,[bool]$bolTranslateGUID,[string]$strObjClass,[bool]$bolObjClass,[string]$xlsxout,[string]$Type)
if($Type -eq "HTM")
{
$htm = $true
$fileout = $htmfileout
}
if($Type -eq "EXCEL")
{
$EXCEL = $true
$fileout = $xlsxout
}
if($HTM)
{
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
if ($bolCriticalityLevel -eq $true)
{
$strLegendColor =@"
bgcolor="#A4A4A4"
"@
}
else
{
$strLegendColor = ""
}
$strLegendColorInfo=@"
bgcolor="#A4A4A4"
"@
$strLegendColorLow =@"
bgcolor="#0099FF"
"@
$strLegendColorMedium=@"
bgcolor="#FFFF00"
"@
$strLegendColorWarning=@"
bgcolor="#FFCC00"
"@
$strLegendColorCritical=@"
bgcolor="#DF0101"
"@
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontRights =@"
<FONT size="1" face="verdana, hevetica, arial">
"@ 
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@
If ($OUHeader -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $DSObject</b>
"@

if ($bolObjClass -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $strObjClass</b>
"@
}
if ($boolReplMetaDate -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $strReplMetaDate</b>
"@
}
if ($boolACLSize -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $strACLSize bytes</b>
"@
}
if ($boolOUProtected -eq $true)
{
    if ($bolOUProtected -eq $true)
    {
$strHTMLText =@"
$strHTMLText
<TD bgcolor="FF0000"><b>$strFontOU $bolOUProtected</b>
"@
    }
    else
    {
$strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $bolOUProtected</b>
"@
    }
}

$strHTMLText =@"
$strHTMLText
</TR>
"@
}


Switch ($strColorTemp) 
{

"1"
	{
	$strColor = "DDDDDD"
	$strColorTemp = "2"
	}
"2"
	{
	$strColor = "AAAAAA"
	$strColorTemp = "1"
	}		
"3"
	{
	$strColor = "FF1111"
}
"4"
	{
	$strColor = "00FFAA"
}     
"5"
	{
	$strColor = "FFFF00"
}          
	}# End Switch
}#End if HTM
if ($bolACLExist) 
{
	$sd  | foreach{


    if($null  -ne  $_.AccessControlType)
    {
        $objAccess = $($_.AccessControlType.toString())
    }
    else
    {
        $objAccess = $($_.AuditFlags.toString())
    }
	$objFlags = $($_.ObjectFlags.toString())
	$objType = $($_.ObjectType.toString())
    $objIsInheried = $($_.IsInherited.toString())
	$objInheritedType = $($_.InheritedObjectType.toString())
	$objRights = $($_.ActiveDirectoryRights.toString())
    $objInheritanceType = $($_.InheritanceType.toString())
    


    if($chkBoxEffectiveRightsColor.IsChecked -eq $false)
    {
    	Switch ($objRights)
    	{
   		    "Self"
    		{
                #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                 $objRights = ""
            }
    		"DeleteChild, DeleteTree, Delete"
    		{
    			$objRights = "DeleteChild, DeleteTree, Delete"

    		}
    		"GenericRead"
    		{
    			$objRights = "Read Permissions,List Contents,Read All Properties,List"
            }
    		"CreateChild"
    		{
    			$objRights = "Create"	
    		}
    		"DeleteChild"
    		{
    			$objRights = "Delete"		
    		}
    		"GenericAll"
    		{
    			$objRights = "Full Control"		
    		}
    		"CreateChild, DeleteChild"
    		{
    			$objRights = "Create/Delete"		
    		}
    		"ReadProperty"
    		{
    	        Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch



                        }
                                  	 	        "Children"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch
                                }
                        	 	        "Descendents"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch
                                }
    	 	        default
    	 	        {$objRights = "Read All Properties"	}
                }#End switch

    			           	
    		}
    		"ReadProperty, WriteProperty" 
    		{
    			$objRights = "Read All Properties;Write All Properties"			
    		}
    		"WriteProperty" 
    		{
    	        Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch



                        }
                                  	 	        "Children"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch
                                }
                        	 	        "Descendents"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch
                                }
    	 	        default
    	 	        {$objRights = "Write All Properties"	}
                }#End switch		
    		}
    	}# End Switch
    }
    else
    {
 
    	Switch ($objRights)
    	{
    		"Self"
    		{
                #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                 $objRights = ""
            }
    		"GenericRead"
    		{
                 $objRights = "Read Permissions,List Contents,Read All Properties,List"
            }
    		"CreateChild"
    		{
                 $objRights = "Create"	
    		}
    		"DeleteChild"
    		{
                $objRights = "Delete"		
    		}
    		"GenericAll"
    		{
                $objRights = "Full Control"		
    		}
    		"CreateChild, DeleteChild"
    		{
                $objRights = "Create/Delete"		
    		}
    		"ReadProperty"
    		{
                Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        Switch ($objFlags)
    	    	        { 
    		      	        "ObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
    		      	        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
                            default
    	 	                {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                     "Children"
    	 	        {
                     
                        Switch ($objFlags)
    	    	        { 
    		      	        "ObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
    		      	        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
                            default
    	 	                {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                    "Descendents"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                            $objRights = "Read"	
                            }
                       	                
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                            $objRights = "Read"	
                            }
                            default
                            {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                    default
                    {$objRights = "Read All Properties"	}
                }#End switch
    		}
    		"ReadProperty, WriteProperty" 
    		{
                $objRights = "Read All Properties;Write All Properties"			
    		}
    		"WriteProperty" 
    		{
                Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                               $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                               $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    "Children"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    "Descendents"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    default
                    {
                        $objRights = "Write All Properties"
                    }
                }#End switch		
    		}
            default
            {
  
            }
    	}# End Switch  

        $intCriticalityValue = GetCriticality $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString()
        
        Switch ($intCriticalityValue)
        {
            0 {$strLegendText = "Info";$strLegendColor = $strLegendColorInfo}
            1 {$strLegendText = "Low";$strLegendColor = $strLegendColorLow}
            2 {$strLegendText = "Medium";$strLegendColor = $strLegendColorMedium}
            3 {$strLegendText = "Warning";$strLegendColor = $strLegendColorWarning}
            4 {$strLegendText = "Critical";$strLegendColor = $strLegendColorCritical}
        }
        $strLegendTextVal = $strLegendText
        if($intCriticalityValue -gt $global:intShowCriticalityLevel)
        {
            $global:intShowCriticalityLevel = $intCriticalityValue
        }
        
    }#End IF else

	$IdentityReference = $($_.IdentityReference.toString())
    
    If ($IdentityReference.contains("S-1-"))
	{
	 $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $IdentityReference

	}
   
    Switch ($strColorTemp) 
    {

    "1"
	{
	$strColor = "DDDDDD"
	$strColorTemp = "2"
	}
	"2"
	{
	$strColor = "AAAAAA"
	$strColorTemp = "1"
	}		
    "3"
	{
	$strColor = "FF1111"
    }
    "4"
	{
	$strColor = "00FFAA"
    }     
    "5"
	{
	$strColor = "FFFF00"
    }          
	}# End Switch

	 Switch ($objInheritanceType) 
	 {
	 	"All"
	 	{
	 		Switch ($objFlags) 
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo =  "This object and all child objects"
                    $strPerm =  "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
		      	}    	
		      	"ObjectAceTypePresent"
		      	{
		      		$strApplyTo =  "This object and all child objects"
                    $strPerm =  "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo =  "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
                    $strPerm =  "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 	      	
		      	"None"
		      	{
		      		$strApplyTo ="This object and all child objects"
                    $strPerm = "$objRights"
		      	} 
		      		default
	 		    {
		      		$strApplyTo = "Error"
                    $strPerm = "Error: Failed to display permissions 1K"
		      	} 	 
	
		    }# End Switch
	 		
	 	}
	 	"Descendents"
	 	{
	
	 		Switch ($objFlags)
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      	    $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
                    $strPerm = "$objRights"
		      	}
		      	"None"
		      	{
		      		$strApplyTo = "Child Objects Only"
                    $strPerm = "$objRights"
		      	} 	      	
		      	"ObjectAceTypePresent"
		      	{
		      		$strApplyTo = "Child Objects Only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo =	"$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
                    $strPerm =	"$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	}
		      	default
	 			{
		      		$strApplyTo = "Error"
                    $strPerm = "Error: Failed to display permissions 2K"
		      	} 	 
	
		    } 		
	 	}
	 	"None"
	 	{
	 		Switch ($objFlags)
	    	{ 
		      	"ObjectAceTypePresent"
		      	{
		      		$strApplyTo = "This Object Only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 
		      	"None"
		      	{
		      		$strApplyTo = "This Object Only"
                    $strPerm = "$objRights"
		      	} 
		      		default
	 		    {
		      		$strApplyTo = "Error"
                    $strPerm = "Error: Failed to display permissions 4K"
		      	} 	 
	
			}
	 	}
	 	"SelfAndChildren"
	 	{
	 	 		Switch ($objFlags)
	    	{ 
		      	"ObjectAceTypePresent"
	      		{
		      		$strApplyTo = "This object and all child objects within this conatainer only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	}
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo = "Children within this conatainer only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
		      	} 

		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo =  "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
                    $strPerm =  "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 	      	
		      	"None"
		      	{
		      		$strApplyTo = "This object and all child objects"
                    $strPerm = "$objRights"
		      	}                                  	   
		      	default
	 		    {
		      		$strApplyTo = "Error"
                    $strPerm = "Error: Failed to display permissions 5K"
		      	} 	 
	
			}   	
	 	} 	
	 	"Children"
	 	{
	 	 		Switch ($objFlags)
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strApplyTo = "Children within this conatainer only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
		      	} 
		      	"None"
		      	{
		      		$strApplyTo = "Children  within this conatainer only"
                    $strPerm = "$objRights"
		      	} 	      	
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
	      		{
		      		$strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})"
                    $strPerm = "$(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName}) $objRights"
		      	} 	
		      	"ObjectAceTypePresent"
	      		{
		      		$strApplyTo = "Children within this conatainer only"
                    $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})"
		      	} 		      	
		      	default
	 			{
		      		$strApplyTo = "Error"
                    $strPerm = "Error: Failed to display permissions 6K"
		      	} 	 
	
	 		}
	 	}
	 	default
	 	{
		    $strApplyTo = "Error"
            $strPerm = "Error: Failed to display permissions 7K"
		} 	 
	}# End Switch

##

If($Excel)
{
    $objhashtableACE = [pscustomobject][ordered]@{    Object = $DSObject ;`    ObjectClass = $strObjClass ;`    IdentityReference = $IdentityReference ;`    Trustee = $strNTAccount ;`    Access = $objAccess ;`
    Inhereted = $objIsInheried ;`
    'Apply To' = $strApplyTo ;`
    Permission = $strPerm}

    [VOID]$global:ArrayAllACE.Add($objhashtableACE)
}

If($HTM)
{
$strACLHTMLText =@"
$strACLHTMLText
<TR bgcolor="$strColor"><TD>$strFont $DSObject</TD>
"@

if ($bolObjClass -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strObjClass</TD>
"@
}
if ($boolReplMetaDate -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
}

if ($boolACLSize -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
}

if ($boolOUProtected -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
}
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont <a href="#web" onclick="GetGroupDN('$strNTAccount')">$strNTAccount</a></TD>
<TD>$strFont $objAccess</TD>
<TD>$strFont $objIsInheried </TD>
<TD>$strFont $strApplyTo</TD>
<TD $strLegendColor>$strFontRights $strPerm</TD>
"@


if($CompareMode)
{

$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $($_.color.toString())</TD>
"@
}
if ($bolCriticalityLevel -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@

}
}#End If HTM
}# End Foreach

	
}
else
{
if($HTM)
{
if ($OUHeader -eq $false)
{
if ($FilterMode)
{



if ($boolReplMetaDate -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
}

if ($boolACLSize -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
}

if ($boolOUProtected -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
}
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Matching Permissions Set</TD>
"@



if ($bolCriticalityLevel -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
}
}
else
{


if ($boolReplMetaDate -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
}

if ($boolACLSize -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
}

if ($boolOUProtected -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
}

$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Permissions Set</TD>
"@


if ($bolCriticalityLevel -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
}

}# End If
}#end If OUHeader false
}#End if HTM
} #End if bolACLExist
if($HTM)
{
$strACLHTMLText =@"
$strACLHTMLText
</TR>
"@

    #end ifelse OUHEader
    $strHTMLText = $strHTMLText + $strACLHTMLText

    Out-File -InputObject $strHTMLText -Append -FilePath $fileout 
    Out-File -InputObject $strHTMLText -Append -FilePath $strFileHTM

    $strHTMLText = $null
    $strACLHTMLText = $null
    Remove-Variable -Name "strHTMLText"
    Remove-Variable -Name "strACLHTMLText"
}#End if HTM

}
#==========================================================================
# Function		: WriteDefSDAccessHTM
# Arguments     : Security Descriptor, OU dn string, Output htm file
# Returns   	: n/a
# Description   : Wites the SD info to a HTM table, it appends info if the file exist
#==========================================================================
function WriteDefSDAccessHTM
{
    Param($sd, $strObjectClass, $strColorTemp,$htmfileout, $strFileHTM, $OUHeader, $boolReplMetaDate, $strReplMetaVer, $strReplMetaDate, $bolCriticalityLevel,
    [boolean]$CompareMode)

$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
if ($bolCriticalityLevel -eq $true)
{
$strLegendColor =@"
bgcolor="#A4A4A4"
"@
}
else
{
$strLegendColor = ""
}
$strLegendColorInfo=@"
bgcolor="#A4A4A4"
"@
$strLegendColorLow =@"
bgcolor="#0099FF"
"@
$strLegendColorMedium=@"
bgcolor="#FFFF00"
"@
$strLegendColorWarning=@"
bgcolor="#FFCC00"
"@
$strLegendColorCritical=@"
bgcolor="#DF0101"
"@
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontRights =@"
<FONT size="1" face="verdana, hevetica, arial">
"@ 
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@
If ($OUHeader -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $strObjectClass</b>
"@
if ($boolReplMetaDate -eq $true)
{
$strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $strReplMetaDate</b>
<TD><b>$strFontOU $strReplMetaVer</b>
"@
}



$strHTMLText =@"
$strHTMLText
</TR>
"@
}


Switch ($strColorTemp) 
{

"1"
	{
	$strColor = "DDDDDD"
	$strColorTemp = "2"
	}
	"2"
	{
	$strColor = "AAAAAA"
	$strColorTemp = "1"
	}		
"3"
	{
	$strColor = "FF1111"
}
"4"
	{
	$strColor = "00FFAA"
}     
"5"
	{
	$strColor = "FFFF00"
}          
	}# End Switch


	$sd  | foreach{
    if($null  -ne  $_.AccessControlType)
    {
        $objAccess = $($_.AccessControlType.toString())
    }
    else
    {
        $objAccess = $($_.AuditFlags.toString())
    }
	$objFlags = $($_.ObjectFlags.toString())
	$objType = $($_.ObjectType.toString())
	$objInheritedType = $($_.InheritedObjectType.toString())
	$objRights = $($_.ActiveDirectoryRights.toString())
    $objInheritanceType = $($_.InheritanceType.toString())
    


    if($chkBoxEffectiveRightsColor.IsChecked -eq $false)
    {
    	Switch ($objRights)
    	{
   		    "Self"
    		{
                #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                 $objRights = ""
            }
    		"DeleteChild, DeleteTree, Delete"
    		{
    			$objRights = "DeleteChild, DeleteTree, Delete"

    		}
    		"GenericRead"
    		{
    			$objRights = "Read Permissions,List Contents,Read All Properties,List"
            }
    		"CreateChild"
    		{
    			$objRights = "Create"	
    		}
    		"DeleteChild"
    		{
    			$objRights = "Delete"		
    		}
    		"GenericAll"
    		{
    			$objRights = "Full Control"		
    		}
    		"CreateChild, DeleteChild"
    		{
    			$objRights = "Create/Delete"		
    		}
    		"ReadProperty"
    		{
    	        Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch



                        }
                                  	 	        "Children"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch
                                }
                        	 	        "Descendents"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Read"	
                    }
                      default
    	 	                        {$objRights = "Read All Properties"	}
                                }#End switch
                                }
    	 	        default
    	 	        {$objRights = "Read All Properties"	}
                }#End switch

    			           	
    		}
    		"ReadProperty, WriteProperty" 
    		{
    			$objRights = "Read All Properties;Write All Properties"			
    		}
    		"WriteProperty" 
    		{
    	        Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch



                        }
                                  	 	        "Children"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch
                                }
                        	 	        "Descendents"
    	 	        {
                     
                        	 		Switch ($objFlags)
    	    	                { 
    		      	                "ObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                       	                
    		      	                "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                    {
                       $objRights = "Write"	
                    }
                      default
    	 	                        {$objRights = "Write All Properties"	}
                                }#End switch
                                }
    	 	        default
    	 	        {$objRights = "Write All Properties"	}
                }#End switch		
    		}
    	}# End Switch
    }
    else
    {
 
    	Switch ($objRights)
    	{
   		    "Self"
    		{
                #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                 $objRights = ""
            }
    		"GenericRead"
    		{
                 $objRights = "Read Permissions,List Contents,Read All Properties,List"
            }
    		"CreateChild"
    		{
                 $objRights = "Create"	
    		}
    		"DeleteChild"
    		{
                $objRights = "Delete"		
    		}
    		"GenericAll"
    		{
                $objRights = "Full Control"		
    		}
    		"CreateChild, DeleteChild"
    		{
                $objRights = "Create/Delete"		
    		}
    		"ReadProperty"
    		{
                Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                     
                        Switch ($objFlags)
    	    	        { 
    		      	        "ObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
    		      	        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
                            default
    	 	                {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                     "Children"
    	 	        {
                     
                        Switch ($objFlags)
    	    	        { 
    		      	        "ObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
    		      	        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Read"	
                            }
                            default
    	 	                {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                    "Descendents"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                            $objRights = "Read"	
                            }
                       	                
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                            $objRights = "Read"	
                            }
                            default
                            {$objRights = "Read All Properties"	}
                        }#End switch
                    }
                    default
                    {$objRights = "Read All Properties"	}
                }#End switch
    		}
    		"ReadProperty, WriteProperty" 
    		{
                $objRights = "Read All Properties;Write All Properties"			
    		}
    		"WriteProperty" 
    		{
                Switch ($objInheritanceType) 
    	        {
    	 	        "None"
    	 	        {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                               $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                               $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    "Children"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    "Descendents"
                    {
                        Switch ($objFlags)
                        { 
                            "ObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                            {
                                $objRights = "Write"	
                            }
                            default
                            {
                                $objRights = "Write All Properties"	
                            }
                        }#End switch
                    }
                    default
                    {
                        $objRights = "Write All Properties"
                    }
                }#End switch		
    		}
            default
            {
  
            }
    	}# End Switch  

        $intCriticalityValue = GetCriticality $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString()
        
        Switch ($intCriticalityValue)
        {
            0 {$strLegendText = "Info";$strLegendColor = $strLegendColorInfo}
            1 {$strLegendText = "Low";$strLegendColor = $strLegendColorLow}
            2 {$strLegendText = "Medium";$strLegendColor = $strLegendColorMedium}
            3 {$strLegendText = "Warning";$strLegendColor = $strLegendColorWarning}
            4 {$strLegendText = "Critical";$strLegendColor = $strLegendColorCritical}
        }
        $strLegendTextVal = $strLegendText
        if($intCriticalityValue -gt $global:intShowCriticalityLevel)
        {
            $global:intShowCriticalityLevel = $intCriticalityValue
        }
        
    }#End IF else

	$strNTAccount = $($_.IdentityReference.toString())
    
	If ($strNTAccount.contains("S-1-"))
	{
	 $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	}
    else
    {
        $strCurrentDom = $env:USERDOMAIN
	    If ($strNTAccount.contains($strCurrentDom+"\"))
	    {
            $strNTAccount =  $strNTAccount.Replace($strCurrentDom+"\",$global:strDomainShortName+"\")
	    }
    }
   
    Switch ($strColorTemp) 
    {

    "1"
	{
	$strColor = "DDDDDD"
	$strColorTemp = "2"
	}
	"2"
	{
	$strColor = "AAAAAA"
	$strColorTemp = "1"
	}		
    "3"
	{
	$strColor = "FF1111"
    }
    "4"
	{
	$strColor = "00FFAA"
    }     
    "5"
	{
	$strColor = "FFFF00"
    }          
	}# End Switch

	 Switch ($objInheritanceType) 
	 {
	 	"All"
	 	{
	 		Switch ($objFlags) 
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strPerm =  "$strFont This object and all child objects</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD>"
		      	}    	
		      	"ObjectAceTypePresent"
		      	{
		      		$strPerm =  "$strFont This object and all child objects</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	} 
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strPerm =  "$strFont $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	} 	      	
		      	"None"
		      	{
		      		$strPerm ="$strFont This object and all child objects</TD><TD $strLegendColor>$strFontRights $objRights</TD>"
		      	} 
		      		default
	 		    {
		      		$strPerm = "Error: Failed to display permissions 1K"
		      	} 	 
	
		    }# End Switch
	 		
	 	}
	 	"Descendents"
	 	{
	
	 		Switch ($objFlags)
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      	$strPerm = "$strFont $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD><TD $strLegendColor>$strFontRights $objRights</TD>"
		      	}
		      	"None"
		      	{
		      		$strPerm ="$strFont Child Objects Only</TD><TD $strLegendColor>$strFontRights $objRights</TD>"
		      	} 	      	
		      	"ObjectAceTypePresent"
		      	{
		      		$strPerm = "$strFont Child Objects Only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	} 
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strPerm =	"$strFont $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	}
		      	default
	 			{
		      		$strPerm = "Error: Failed to display permissions 2K"
		      	} 	 
	
		    } 		
	 	}
	 	"None"
	 	{
	 		Switch ($objFlags)
	    	{ 
		      	"ObjectAceTypePresent"
		      	{
		      		$strPerm = "$strFont This Object Only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName}) </TD>"
		      	} 
		      	"None"
		      	{
		      		$strPerm ="$strFont This Object Only</TD><TD $strLegendColor>$strFontRights $objRights </TD>"
		      	} 
		      		default
	 		{
		      		$strPerm = "Error: Failed to display permissions 4K"
		      	} 	 
	
			}
	 	}
	 	"SelfAndChildren"
	 	{
	 	 		Switch ($objFlags)
	    	{ 
		      	"ObjectAceTypePresent"
	      		{
		      		$strPerm = "$strFont This object and all child objects within this conatainer only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	}
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strPerm = "$strFont Children within this conatainer only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD>"
		      	} 

		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
		      	{
		      		$strPerm =  "$strFont $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	} 	      	
		      	"None"
		      	{
		      		$strPerm ="$strFont This object and all child objects</TD><TD $strLegendColor>$strFontRights $objRights</TD>"
		      	}                                  	   
		      	default
	 		    {
		      		$strPerm = "Error: Failed to display permissions 5K"
		      	} 	 
	
			}   	
	 	} 	
	 	"Children"
	 	{
	 	 		Switch ($objFlags)
	    	{ 
		      	"InheritedObjectAceTypePresent"
		      	{
		      		$strPerm = "$strFont Children within this conatainer only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD>"
		      	} 
		      	"None"
		      	{
		      		$strPerm = "$strFont Children  within this conatainer only</TD><TD $strLegendColor>$strFontRights $objRights</TD>"
		      	} 	      	
		      	"ObjectAceTypePresent, InheritedObjectAceTypePresent"
	      		{
		      		$strPerm = "$strFont $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName})</TD><TD>$strFont $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName}) $objRights</TD>"
		      	} 	
		      	"ObjectAceTypePresent"
	      		{
		      		$strPerm = "$strFont Children within this conatainer only</TD><TD $strLegendColor>$strFontRights $objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName})</TD>"
		      	} 		      	
		      	default
	 			{
		      		$strPerm = "Error: Failed to display permissions 6K"
		      	} 	 
	
	 		}
	 	}
	 	default
	 		{
		      		$strPerm = "Error: Failed to display permissions 7K"
		    } 	 
	}# End Switch

##

$strACLHTMLText =@"
$strACLHTMLText
<TR bgcolor="$strColor"><TD>$strFont $strObjectClass</TD>
"@

if ($boolReplMetaDate -eq $true)
{
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
<TD>$strFont $strReplMetaVer</TD>
"@
}
$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strNTAccount</TD>
<TD>$strFont $(if($null -ne $_.AccessControlType){$_.AccessControlType.toString()}else{$_.AuditFlags.toString()}) </TD>
<TD>$strFont $($_.IsInherited.toString())</TD>
<TD>$strPerm</TD>
"@

if($CompareMode)
{

$strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $($_.color.toString())</TD>
"@
}


}# End Foreach

	

$strACLHTMLText =@"
$strACLHTMLText
</TR>
"@

#end ifelse OUHEader
$strHTMLText = $strHTMLText + $strACLHTMLText

Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
Out-File -InputObject $strHTMLText -Append -FilePath $strFileHTM

$strHTMLText = $null
$strACLHTMLText = $null
Remove-Variable -Name "strHTMLText"
Remove-Variable -Name "strACLHTMLText"

}
#==========================================================================
# Function		: InitiateDefSDAccessHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function InitiateDefSDAccessHTM
{
    Param([string] $htmfileout,
    [string]$strStartingPoint,
    $RepMetaDate,
    [bool]$bolCompare,
    [string] $strComparefile)

$strACLTypeHeader = "Access"
If($bolCompare)
{
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor COMPARE REPORT - $($strStartingPoint.ToUpper())</h1>
<h3 style="color: #191010;text-align: center;">
Template: $strComparefile
</h3>
"@ 
}
else
{
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor REPORT - $($strStartingPoint.ToUpper())</h1>
"@ 
}

$strHTMLText =@"
$strHTMLText
<TABLE BORDER=1>
"@ 
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH ObjectClass</font></th>
"@
if ($RepMetaDate -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Security Descriptor Modified</font><th bgcolor="$strTHColor">$strFontTH Version</font>
"@
}
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Trustee</font></th><th bgcolor="$strTHColor">$strFontTH $strACLTypeHeader</font></th><th bgcolor="$strTHColor">$strFontTH Inherited</font></th><th bgcolor="$strTHColor">$strFontTH Apply To</font></th><th bgcolor="$strTHColor">$strFontTH Permission</font></th>
"@

if ($bolCompare -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH State</font></th>
"@
}




Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
$strHTMLText = $null
$strTHOUColor = $null
$strTHColor = $null
Remove-Variable -Name "strHTMLText"
Remove-Variable -Name "strTHOUColor"
Remove-Variable -Name "strTHColor"


}

#==========================================================================
# Function		: InitiateHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function InitiateHTM
{
    Param([string] $htmfileout,[string]$strStartingPoint,[string]$strDN,[bool]$RepMetaDate ,[bool]$ACLSize,[bool]$bolACEOUProtected,[bool]$bolCirticaltiy,[bool]$bolCompare,[bool]$SkipDefACE,[bool]$SkipProtectDelACE,[string]$strComparefile,[bool]$bolFilter,[bool]$bolEffectiveRights,[bool]$bolObjType)
If($rdbSACL.IsChecked)
{
$strACLTypeHeader = "Audit"
}
else
{
$strACLTypeHeader = "Access"
}
If($bolCompare)
{
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">COMPARE REPORT - $($strStartingPoint.ToUpper())</h1>
<h3 style="color: #191010;text-align: center;">
Template: $strComparefile
</h3>
"@ 
}
else
{
If($bolFilter)
{
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">FILTERED REPORT - $($strStartingPoint.ToUpper())</h1>
"@
}
else
{
If($bolEffectiveRights)
{

$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">EFFECTIVE RIGHTS REPORT <br>
Service Principal: $($global:strEffectiveRightAccount.ToUpper())</h1>
"@ 
}
else
{
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">ACL REPORT - $($strStartingPoint.ToUpper())</h1>
"@ 
}
}
}
If($bolCirticaltiy)
{
$strHTMLText =@"
$strHTMLText
<div style="text-align: center;font-weight: bold}">
<FONT size="6"  color= "#79A0E0">Highest Criticality Level:</FONT> 20141220T021111056594002014122000</FONT>
</div>
"@ 
}
$strHTMLText =@"
$strHTMLText
<h3 style="color: #191010;text-align: center;">$strDN<br>
Report Created: $(get-date -uformat "%Y-%m-%d %H:%M:%S")</h3>
"@ 
If($SkipDefACE)
{
$strHTMLText =@"
$strHTMLText
<h3 style="color: #191010;text-align: center;">Default permissions excluced</h3>
"@ 
}
If($SkipProtectDelACE)
{
$strHTMLText =@"
$strHTMLText
<h3 style="color: #191010;text-align: center;">Protected against accidental deletions permissions excluced</h3>
"@ 
}
$strHTMLText =@"
$strHTMLText
<TABLE BORDER=1>
"@ 
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Object</font></th>
"@
if ($bolObjType -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH ObjectClass</font>
"@
}
if ($RepMetaDate -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Security Descriptor Modified</font>
"@
}
if ($ACLSize -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH DACL Size</font>
"@
}
if ($bolACEOUProtected -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Inheritance Disabled</font>
"@
}
$strHTMLText =@"
$strHTMLText
</th><th bgcolor="$strTHColor">$strFontTH Trustee</font></th><th bgcolor="$strTHColor">$strFontTH $strACLTypeHeader</font></th><th bgcolor="$strTHColor">$strFontTH Inherited</font></th><th bgcolor="$strTHColor">$strFontTH Apply To</font></th><th bgcolor="$strTHColor">$strFontTH Permission</font></th>
"@

if ($bolCompare -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH State</font></th>
"@
}


if ($bolCirticaltiy -eq $true)
{
$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Criticality Level</font></th>
"@
}



Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
$strHTMLText = $null
$strTHOUColor = $null
$strTHColor = $null
Remove-Variable -Name "strHTMLText"
Remove-Variable -Name "strTHOUColor"
Remove-Variable -Name "strTHColor"


}

#==========================================================================
# Function		: CreateHTA
# Arguments     : OU Name, Ou put HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateHTA
{
    Param([string]$NodeName,[string]$htafileout,[string]$htmfileout,[string] $folder,[string] $strDomainDN,[string] $strDC)
$strHTAText =@"
<html>
<head>
<hta:Application ID="hta"
ApplicationName="Report">
<title>Report on $NodeName</title>
<script type="text/vbscript">

Dim i
Dim strGroupMemberList
Dim dicSeenGroupMember
Dim strBGColor
Dim strBG1
Dim strBG2
Dim MaxResult
MaxResult = 500

set dicSeenGroupMember = CreateObject("Scripting.Dictionary")
i=0
strBG1 = "bgcolor=#AAAAAA"
strBG2 = "bgcolor=#DDDDDD"

Function ListMembers (strGroupADsPath, dicSeenGroupMember, strRDN)

Dim objGroup, objMember
set objGroup = GetObject(strGroupADsPath)

for each objMember In objGroup.Members
    if i < MaxResult Then
	    If strGroupMemberList = "" Then
		    strBGColor = strBG1
		    strGroupMemberList = "<TR "&strBGColor&"><TD>" & objMember.Get("cn") & "</TD><TD>" & objMember.Get("distinguishedname") & "</TD></TR>"
	    Else
		    If strBGColor = strBG1 Then
			    strBGColor = strBG2
		    Else
			    strBGColor = strBG1
		    End If
	    strGroupMemberList = strGroupMemberList & vbCrlf & "<TR "&strBGColor&"><TD>" & objMember.Get("cn") & "</TD><TD>" & objMember.Get("distinguishedname") & "</TD></	TR>"
	    End If
        i = i + 1
        if objMember.Class = "group" then

            if dicSeenGroupMember.Exists(objMember.ADsPath) then

            else
            dicSeenGroupMember.Add objMember.ADsPath, 1
            ListMembers objMember.ADsPath, dicSeenGroupMember, strRDN
            end if

        end if
    else
        if Not i > MaxResult Then
        strGroupMemberList = strGroupMemberList & vbCrlf & "<TR "&strBGColor&"><TD>Reached Max Results: MaxResult</TD><TD>Reached Max Results: MaxResult</TD></	TR>"
        end if
        i = i + 1
        exit for
    end if
    
next
End Function
Sub DisplayMembers(strMemberTable,strGroupName,strGroupDN)
On Error Resume Next
Dim objDialogWindow
dim wshShell
Set objDialogWindow = window.Open("about:blank","AboutWindow","height=400,width=800,left=100,top=100,addressbar=no,status=no,titlebar=no,toolbar=no,menubar=no,location=no,scrollbars=yes,resizable=yes") 
objDialogWindow.Focus()
strHTML = "<html><title>Direct Members</title>" &_
"<body>" &_
"<h1 style='color: #79A0E0;text-align: center;'>" & strGroupName &"</h1>" &_
"<h3 style='color: #191010;text-align: center;'>" & strGroupDN &"</h3>" 
if Not strMemberTable = "" Then
strHTML = strHTML & "<TABLE BORDER=1>" &_
"<th bgcolor=#EFAC00> Member</th><th  bgcolor=#EFAC00>DN</th>" &_
strMemberTable &_
"</table></body></html>"
else
strHTML = strHTML &"<img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABYAAAAZCAYAAAA14t7uAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAADrSURBVEhL7ZVBCsIwEEV7FS/gUhAP6c6FegPBpRs3giBeQEGliHoAabVWaszoD1QnNE0txpV9MGTSTl5DGRJPCEG/CE9KSS6ARxPjYa29+jo4+IhTMc8r8Su3ips9n8b+iRIh1Yi5qQ7BPcAqnu4iVZQyP1yMdQhOYVdEyV0VpmDnpjoEp1Bcdsc8t4pbfZ8m27MqxIi5qQ4BeG4VlwnuAUZxvbOhwSKg8Kr/42MsaLgMqNHN7hzw3CgerUP1Mo/ZPsqsATw3iuOb/cR7NkdmDSe3Kz7BtqY63bT8z8UpzrtCu6VhdwE8b7GgB+EAjr6jfR4GAAAAAElFTkSuQmCC' />" &_
"</body></html>"
end if
objDialogWindow.document.write strHTML
End Sub

Function GetGroupDN(strRDN)
Dim oConnection
Dim oRecordset
Dim oCmd
Dim strQuery

Set oConnection = CreateObject("ADODB.Connection")
Set oRecordset = CreateObject("ADODB.Recordset")
Set oCmd = CReateObject("ADODB.Command")
oConnection.Provider = "ADsDSOObject"
oConnection.Open "ADs Provider"
Set oCmd.ActiveConnection = oConnection
oCmd.Properties("Page Size") = 20


strGroupText = Split(strRDN,"\")
If (ubound(strGroupText) > 0) Then
	strRDN = strGroupText(1)
End IF


strQuery = "<LDAP://$strDC/$strDomainDN>;(&(samaccountname="&strRDN&")(|(objectClass=group)(objectClass=user)));samAccountName,distinguishedName,member,objectclass;Subtree"
oCmd.CommandText = strQuery
Set oRecordSet = oCmd.Execute
If oRecordset.EOF And oRecordset.BOF Then

 		MsgBox "Could not find group"
Else
 	While Not oRecordset.EOF
 		GetGroupDN =  oRecordset.Fields("distinguishedName")
        Set objGroupAD = GetObject("LDAP://" & GetGroupDN)

		oRecordset.MoveNext
        i = 0
        strGroupMemberList = ""
        if objGroupAD.Class =  "group" Then
            strRDN = "MEMBERS OF - " & strRDN
            ListMembers "LDAP://" & GetGroupDN, dicSeenGroupMember, strRDN
            If Not i = 0 Then
	            DisplayMembers strGroupMemberList,strRDN,GetGroupDN
            Else
                strGroupMemberList = "<TR "&strBGColor&"><TD>Group Empty</TD><TD></TD></TR>"
                DisplayMembers strGroupMemberList,strRDN,GetGroupDN
            End IF	
        else
            strRDN = "User Object - " & strRDN
	        DisplayMembers strGroupMemberList,strRDN,GetGroupDN
        end if

	Wend

End If
Set oConnection = Nothing
Set oRecordset = Nothing
Set oCmd = Nothing
End Function


Sub ExportToCSV()
Dim objFSO,objFile,objNewFile,oShell,oEnv
Set oShell=CreateObject("wscript.shell")
Set oEnv=oShell.Environment("System")
strTemp=oShell.ExpandEnvironmentStrings("%USERPROFILE%")
strTempFile="$htmfileout"
strOutputFolder="$folder"
strFile=SaveAs("$NodeName.htm",strOutputFolder)
If strFile="" Then Exit Sub
Set objFSO=CreateObject("Scripting.FileSystemObject")
objFSO.CopyFile strTempFile,strFile, true
MsgBox "Finished exporting to " & strFile,vbOKOnly+vbInformation,"Export"
End Sub
Function SaveAs(strFile,strOutFolder)
Dim objDialog
SaveAs=InputBox("Enter the filename and path."&vbCrlf&vbCrlf&"Example: "&strOutFolder&"\CONTOSO-contoso.htm","Export",strOutFolder&"\"&strFile)
End Function
</script>
</head>
<body>
<input type="button" value="Export" onclick="ExportToCSV" tabindex="9">
<input id="print_button" type="button" value="Print" name="Print_button" class="Hide" onClick="Window.print()">
<input type="button" value="Exit" onclick=self.close name="B3" tabindex="1" class="btn">
"@
Out-File -InputObject $strHTAText -Force -FilePath $htafileout 
}
#==========================================================================
# Function		: WriteSPNHTM
# Arguments     : Security Principal Name,  Output htm file
# Returns   	: n/a
# Description   : Wites the account membership info to a HTM table, it appends info if the file exist
#==========================================================================
function WriteSPNHTM
{
    Param([string] $strSPN,$tokens,[string]$objType,[int]$intMemberOf,[string] $strColorTemp,[string] $htafileout,[string] $htmfileout)
#$strHTMLText ="<TABLE BORDER=1>" 
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@

$strHTMLText =@"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $strSPN</b><TD><b>$strFontOU $objType</b><TD><b>$strFontOU $intMemberOf</b></TR>
"@
$strHTMLText =@"
$strHTMLText
<TR bgcolor="$strTHColor"><TD><b>$strFontTH Groups</b></TD><TD></TD><TD></TD></TR>
"@


$tokens  | foreach{
If ($_.contains("S-1-"))
{
	$strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $_

}
if ($($strNTAccount.toString()) -ne $strSPN)
{
Switch ($strColorTemp) 
{

"1"
	{
	$strColor = "DDDDDD"
	$strColorTemp = "2"
	}
"2"
	{
	$strColor = "AAAAAA"
	$strColorTemp = "1"
	}		
"3"
	{
	$strColor = "FF1111"
}
"4"
	{
	$strColor = "00FFAA"
}     
"5"
	{
	$strColor = "FFFF00"
}          
	}# End Switch
$strGroupText=$strGroupText+@"
<TR bgcolor="$strColor"><TD>
$strFont $($strNTAccount.toString())</TD></TR>
"@
}
}
$strHTMLText = $strHTMLText + $strGroupText


Out-File -InputObject $strHTMLText -Append -FilePath $htafileout
Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout

$strHTMLText = ""

}
#==========================================================================
# Function		: CreateColorLegenedReportHTA
# Arguments     : OU Name, Ou put HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateColorLegenedReportHTA
{
    Param([string]$htafileout)
$strHTAText =@"
<html>
<head>
<hta:Application ID="hta"
ApplicationName="Legend">
<title>Color Code</title>
<script type="text/vbscript">
Sub Window_Onload

 	self.ResizeTo 500,500
End sub
</script>
</head>
<body>

<input type="button" value="Exit" onclick=self.close name="B3" tabindex="1" class="btn">
"@

$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@
$strLegendColorInfo=@"
bgcolor="#A4A4A4"
"@
$strLegendColorLow =@"
bgcolor="#0099FF"
"@
$strLegendColorMedium=@"
bgcolor="#FFFF00"
"@
$strLegendColorWarning=@"
bgcolor="#FFCC00"
"@
$strLegendColorCritical=@"
bgcolor="#DF0101"
"@

$strHTAText =@"
$strHTAText
<h4>Use colors in report to identify criticality level of permissions.<br>This might help you in implementing <B>Least-Privilege</B> Administrative Models.</h4>
<TABLE BORDER=1>
<th bgcolor="$strTHColor">$strFontTH Permissions</font></th><th bgcolor="$strTHColor">$strFontTH Criticality</font></th>
<TR><TD> $strFontTH <B>Deny Permissions<TD $strLegendColorInfo> Info</TR>
<TR><TD> $strFontTH <B>List<TD $strLegendColorInfo>Info</TR>
<TR><TD> $strFontTH <B>Read Properties<TD $strLegendColorLow>Low</TR>
<TR><TD> $strFontTH <B>Read Object<TD $strLegendColorLow>Low</TR>
<TR><TD> $strFontTH <B>Read Permissions<TD $strLegendColorLow>Low</TR>
<TR><TD> $strFontTH <B>Write Propeties<TD $strLegendColorMedium>Medium</TR>
<TR><TD> $strFontTH <B>Create Object<TD $strLegendColorWarning>Warning</TR>
<TR><TD> $strFontTH <B>Delete Object<TD $strLegendColorWarning>Warning</TR>
<TR><TD> $strFontTH <B>ExtendedRight<TD $strLegendColorWarning>Warning</TR>
<TR><TD> $strFontTH <B>Modify Permisions<TD $strLegendColorCritical>Critical</TR>
<TR><TD> $strFontTH <B>Full Control<TD $strLegendColorCritical>Critical</TR>

"@


##
Out-File -InputObject $strHTAText -Force -FilePath $htafileout 
}
#==========================================================================
# Function		: WriteDefSDSDDLHTM
# Arguments     : Security Principal Name,  Output htm file
# Returns   	: n/a
# Description   : Wites the account membership info to a HTM table, it appends info if the file exist
#==========================================================================
function WriteDefSDSDDLHTM
{
    Param([string] $strColorTemp,[string] $htafileout,[string] $htmfileout,[string]$strObjectClass,[string]$strDefSDVer,[string]$strDefSDDate,[string]$strSDDL)
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@

$strHTMLText =@"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $strObjectClass</b>
<TD><b>$strFontOU $strDefSDVer</b>
<TD><b>$strFontOU $strDefSDDate</b>
"@




$strHTMLText =@"
$strHTMLText
</TR>
"@

Switch ($strColorTemp) 
{

    "1"
	    {
	    $strColor = "DDDDDD"
	    $strColorTemp = "2"
	    }
    "2"
	    {
	    $strColor = "AAAAAA"
	    $strColorTemp = "1"
	    }		
    "3"
	    {
	    $strColor = "FF1111"
    }
    "4"
	    {
	    $strColor = "00FFAA"
    }     
    "5"
	    {
	    $strColor = "FFFF00"
    }          
}# End Switch

$strGroupText=$strGroupText+@"
<TR bgcolor="$strColor"><TD> $strFont $strObjectClass</TD><TD> $strFont $strDefSDVer</TD><TD> $strFont $strDefSDDate</TD><TD> $strFont $strSDDL</TD></TR>
"@


$strHTMLText = $strHTMLText + $strGroupText


Out-File -InputObject $strHTMLText -Append -FilePath $htafileout
Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout

$strHTMLText = ""

}

#==========================================================================
# Function		: CreateDefaultSDReportHTA
# Arguments     : Forest Name, Output HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateDefaultSDReportHTA
{
    Param([string]$Forest,[string]$htafileout,[string]$htmfileout,[string] $folder)
$strHTAText =@"
<html>
<head>
<hta:Application ID="hta"
ApplicationName="Report">
<title>defaultSecurityDescriptor Report on $Forest</title>
<script type="text/vbscript">
Sub ExportToCSV()
Dim objFSO,objFile,objNewFile,oShell,oEnv
Set oShell=CreateObject("wscript.shell")
Set oEnv=oShell.Environment("System")
strTemp=oShell.ExpandEnvironmentStrings("%USERPROFILE%")
strTempFile="$htmfileout"
strOutputFolder="$folder"
strFile=SaveAs("$($Forest.Split("\")[-1]).htm",strOutputFolder)
If strFile="" Then Exit Sub
Set objFSO=CreateObject("Scripting.FileSystemObject")
objFSO.CopyFile strTempFile,strFile, true
MsgBox "Finished exporting to " & strFile,vbOKOnly+vbInformation,"Export"
End Sub
Function SaveAs(strFile,strOutFolder)
Dim objDialog
SaveAs=InputBox("Enter the filename and path."&vbCrlf&vbCrlf&"Example: "&strOutFolder&"\CONTOSO-contoso.htm","Export",strOutFolder&"\"&strFile)
End Function
</script>
</head>
<body>
<input type="button" value="Export" onclick="ExportToCSV" tabindex="9">
<input id="print_button" type="button" value="Print" name="Print_button" class="Hide" onClick="Window.print()">
<input type="button" value="Exit" onclick=self.close name="B3" tabindex="1" class="btn">
"@
Out-File -InputObject $strHTAText -Force -FilePath $htafileout 
}
#==========================================================================
# Function		: CreateSPNHTM
# Arguments     : OU Name, Ou put HTM file
# Returns   	: n/a
# Description   : Initiates a base HTM file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateDefSDHTM
{
    Param([string]$SPN,[string]$htmfileout)
$strHTAText =@"
<html>
<head[string]$SPN
<title>Default Security Descritor Report on $SPN</title>
"@
Out-File -InputObject $strHTAText -Force -FilePath $htmfileout 

}
#==========================================================================
# Function		: InitiateSPNHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function InitiateDefSDHTM
{
    Param([string] $htmfileout,[string] $strStartingPoint)
$strHTMLText =@"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor REPORT - $($strStartingPoint.ToUpper())</h1>
"@ 
$strHTMLText =$strHTMLText +"<TABLE BORDER=1>" 
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@


$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Object</font></th><th bgcolor="$strTHColor">$strFontTH Version</font></th><th bgcolor="$strTHColor">$strFontTH Modified Date</font><th bgcolor="$strTHColor">$strFontTH SDDL</font></th>
"@



Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
}
#==========================================================================
# Function		: CreateServicePrincipalReportHTA
# Arguments     : OU Name, Ou put HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateServicePrincipalReportHTA
{
    Param([string]$SPN,[string]$htafileout,[string]$htmfileout,[string] $folder)
$strHTAText =@"
<html>
<head>
<hta:Application ID="hta"
ApplicationName="Report">
<title>Membership Report on $SPN</title>
<script type="text/vbscript">
Sub ExportToCSV()
Dim objFSO,objFile,objNewFile,oShell,oEnv
Set oShell=CreateObject("wscript.shell")
Set oEnv=oShell.Environment("System")
strTemp=oShell.ExpandEnvironmentStrings("%USERPROFILE%")
strTempFile="$htmfileout"
strOutputFolder="$folder"
strFile=SaveAs("$($SPN.Split("\")[-1]).htm",strOutputFolder)
If strFile="" Then Exit Sub
Set objFSO=CreateObject("Scripting.FileSystemObject")
objFSO.CopyFile strTempFile,strFile, true
MsgBox "Finished exporting to " & strFile,vbOKOnly+vbInformation,"Export"
End Sub
Function SaveAs(strFile,strOutFolder)
Dim objDialog
SaveAs=InputBox("Enter the filename and path."&vbCrlf&vbCrlf&"Example: "&strOutFolder&"\CONTOSO-contoso.htm","Export",strOutFolder&"\"&strFile)
End Function
</script>
</head>
<body>
<input type="button" value="Export" onclick="ExportToCSV" tabindex="9">
<input id="print_button" type="button" value="Print" name="Print_button" class="Hide" onClick="Window.print()">
<input type="button" value="Exit" onclick=self.close name="B3" tabindex="1" class="btn">
"@
Out-File -InputObject $strHTAText -Force -FilePath $htafileout 
}
#==========================================================================
# Function		: CreateSPNHTM
# Arguments     : OU Name, Ou put HTM file
# Returns   	: n/a
# Description   : Initiates a base HTM file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateSPNHTM
{
    Param([string]$SPN,[string]$htmfileout)
$strHTAText =@"
<html>
<head[string]$SPN
<title>Membership Report on $SPN</title>
"@
Out-File -InputObject $strHTAText -Force -FilePath $htmfileout 

}
#==========================================================================
# Function		: InitiateSPNHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function InitiateSPNHTM
{
    Param([string] $htmfileout)
$strHTMLText ="<TABLE BORDER=1>" 
$strTHOUColor = "E5CF00"
$strTHColor = "EFAC00"
$strFont =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontOU =@"
<FONT size="1" face="verdana, hevetica, arial">
"@
$strFontTH =@"
<FONT size="2" face="verdana, hevetica, arial">
"@


$strHTMLText =@"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Account Name</font></th><th bgcolor="$strTHColor">$strFontTH Object Type</font></th><th bgcolor="$strTHColor">$strFontTH Number of Groups</font></th>
"@



Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
}
#==========================================================================
# Function		: CreateHTM
# Arguments     : OU Name, Ou put HTM file
# Returns   	: n/a
# Description   : Initiates a base HTM file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateHTM
{
    Param([string]$NodeName,[string]$htmfileout)
$strHTAText =@"
<html>
<head>
<title>Report on $NodeName</title>
"@

Out-File -InputObject $strHTAText -Force -FilePath $htmfileout 
}


#==========================================================================
# Function		: Select-File
# Arguments     : n/a
# Returns   	: folder path
# Description   : Dialogbox for selecting a file
#==========================================================================
function Select-File
{
    param (
        [System.String]$Title = "Select Template File", 
        [System.String]$InitialDirectory = $CurrentFSPath, 
        [System.String]$Filter = "All Files(*.csv)|*.csv"
    )
    
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = $filter
    $dialog.InitialDirectory = $initialDirectory
    $dialog.ShowHelp = $true
    $dialog.Title = $title
    $result = $dialog.ShowDialog($owner)

    if ($result -eq "OK")
    {
        return $dialog.FileName
    }
    else
    {
        return ""

    }
}
#==========================================================================
# Function		: Select-Folder
# Arguments     : n/a
# Returns   	: folder path
# Description   : Dialogbox for selecting a folder
#==========================================================================
function Select-Folder
{  
    Param($message='Select a folder', $path = 0)
    $object = New-Object -comObject Shell.Application   
      
    $folder = $object.BrowseForFolder(0, $message, 0, $path)  
    if ($null -ne $folder) {  
        $folder.self.Path  
    }  
} 
#==========================================================================
# Function		: Get-Perm
# Arguments     : List of OU Path
# Returns   	: All Permissions on a speficied object
# Description   : Enumerates all access control entries on a speficied object
#==========================================================================
Function Get-Perm
{
    Param([System.Collections.ArrayList]$ALOUdn,[string]$DomainNetbiosName,[boolean]$SkipDefaultPerm,[boolean]$SkipProtectedPerm,[boolean]$FilterEna,[boolean]$bolGetOwnerEna,[boolean]$bolCSV,[boolean]$bolCSVOnly,[boolean]$bolReplMeta, [boolean]$bolACLsize,[boolean]$bolEffectiveR,[boolean] $bolGetOUProtected,[boolean] $bolGUIDtoText,[boolean]$Show,[string] $OutType)
$SDResult = $false
$bolCompare = $false
$bolACLExist = $true
$global:strOwner = ""
$strACLSize = ""
$bolOUProtected = $false
$aclcount = 0
$sdOUProtect = ""
$global:ArrayAllACE = New-Object System.Collections.ArrayList

If ($bolCSV)
{
	If ((Test-Path $strFileCSV) -eq $true)
	{
	Remove-Item $strFileCSV
	}
}

$count = 0
$i = 0
$intCSV = 0
if($global:bolCMD)
{
    $intTot = 0
    #calculate percentage
    $intTot = $ALOUdn.count
}
else
{
    if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
    {
        $intTot = 0
        #calculate percentage
        $intTot = $ALOUdn.count
        if ($intTot -gt 0)
        {
        LoadProgressBar
   
        }
    }
}

while($count -le $ALOUdn.count -1)
{
$ADObjDN = $($ALOUdn[$count])
$global:secd = ""
$bolACLExist = $true
$global:GetSecErr = $false
if($global:bolCMD)
{

    $i++
    [int]$pct = ($i/$intTot)*100
    Write-Progress -Activity "Collecting objects" -Status "Currently scanning $i of $intTot objects" -Id 0 -CurrentOperation "Reading ACL on: $ADObjDN" -PercentComplete $pct 
}
else
{
    if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
    {
        $i++
        [int]$pct = ($i/$intTot)*100
        #Update the progress bar
    
        while(($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20))
        {
                    Start-Sleep -Milliseconds 1
                    $cc++
        }
        if ($global:ProgressBarWindow.Window.IsInitialized -eq $true)
        {
            Update-ProgressBar "Currently scanning $i of $intTot objects" $pct 
        }    
    
    }
}

$sd =  New-Object System.Collections.ArrayList
$GetOwnerEna = $bolGetOwnerEna
   
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest("$ADObjDN", "(name=*)", "base")
if($global:bolShowDeleted)
{
    [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
}
[void]$request.Attributes.Add("objectclass")
[void]$request.Attributes.Add("ntsecuritydescriptor")
        
  
    
if ($rdbDACL.IsChecked)
{
    $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
    $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
    [void]$request.Controls.Add($control)
    $response = $LDAPConnection.SendRequest($request)
    $DSobject = $response.Entries[0]
    #Check if any NTsecuritydescr
    if($null -ne $DSobject.Attributes.ntsecuritydescriptor)
    {
        if($null -ne $DSobject.Attributes.objectclass)
        {                
            $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count-1]
        }
        else
        {
            $strObjectClass = "unknown"
        }

        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
        if($chkBoxRAWSDDL.IsChecked)
        {
            $secSDDL = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $objSd =  $DSobject.Attributes.ntsecuritydescriptor[0]
            if ($objSD -is [Byte[]]) {
                    $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd, 0)
                } elseif ($objSD -is [string]) {
                    $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd)
                }
            $strSDDL = $SDDLSec.GetSddlForm('Access,Owner')

            $arrSplitedSDDL = $strSDDL.Split("(")
            $intI = 0
            Foreach ($strSDDLPart in $arrSplitedSDDL)
            {
                if($intI -gt 0)
                {
                    if($sec.Owner -eq $null)
                    {
                        $sec.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                    }
                    else
                    {
                        if(!($chkInheritedPerm.IsChecked))
                        {
                            if(($strSDDLPart.split(";")[1] -ne "CIID") -and ($strSDDLPart.split(";")[1] -ne "CIIOID"))
                            {
                                $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                $sec.AddAccessRule($secSDDL.Access[0]) 
                            }
                        }
                        else
                        {
                            $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                            $sec.AddAccessRule($secSDDL.Access[0])
                        }
                    }
                }
                $intI++
            }
        }
        else
        {
            $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
        }

        &{#Try
            $global:secd = $sec.GetAccessRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])

        }
        Trap [SystemException]
        { 
            if($bolCMD)
            {
                Write-host "Failed to translate identity:$ADObjDN" -ForegroundColor red
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType "Warning" -DateStamp ))
            }
            $global:GetSecErr = $true
            Continue
        }              

    }
    else
    {
        #Fail futher scan when NTsecurityDescriptor is null
        $global:GetSecErr = $true
    }
}
else
{
    $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
    $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
    [void]$request.Controls.Add($control)
    $response = $LDAPConnection.SendRequest($request)
    $DSobject = $response.Entries[0]
    if($null -ne $DSobject.Attributes.objectclass)
    {                
        $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count-1]
    }
    else
    {
        $strObjectClass = "unknown"
    }
    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
    &{#Try
        $global:secd = $sec.GetAuditRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
    }
    Trap [SystemException]
    { 
        if($bolCMD)
        {
            Write-host "Failed to translate identity:$ADObjDN" -ForegroundColor red
        }
        else
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType "Warning" -DateStamp ))
        }       
        $global:GetSecErr = $true
        Continue
    }
}

if(($global:GetSecErr -ne $true) -or ($global:secd -ne ""))
{
    $sd.clear()
    if($null -ne $global:secd){
        $(ConvertTo-ObjectArrayListFromPsCustomObject  $global:secd)| ForEach-Object{[void]$sd.add($_)}
    }
    If ($GetOwnerEna -eq $true)
    {
    
        &{#Try
            $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
        }
   
        Trap [SystemException]
        { 
            if($global:bolADDSType)
            {
                if($bolCMD)
                {
                    Write-host "Failed to translate owner identity:$ADObjDN" -ForegroundColor red
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType "Warning" -DateStamp ))
                }
            }
            Continue
        }

        $newSdOwnerObject = New-Object PSObject -Property @{ActiveDirectoryRights="Read permissions, Modify permissions";InheritanceType="None";ObjectType ="None";`
        InheritedObjectType="None";ObjectFlags="None";AccessControlType="Owner";IdentityReference=$global:strOwner;IsInherited="False";`
        InheritanceFlags="None";PropagationFlags="None"}

        [void]$sd.insert(0,$newSdOwnerObject)
 
    }
 	If ($SkipDefaultPerm)
	{
        If ($GetOwnerEna -eq $false)
            {
    
            &{#Try
                $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
            }
   
            Trap [SystemException]
            { 
                if($bolCMD)
                {
                    Write-host "Failed to translate owner identity:$ADObjDN" -ForegroundColor red
                }
                else
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType "Error" -DateStamp ))
                }
                Continue
            }
        } 

    }

    if ($bolACLsize -eq $true) 
    {
        $strACLSize = $sec.GetSecurityDescriptorBinaryForm().length
    }
    if ($bolGetOUProtected -eq $true)
    {
        $bolOUProtected = $sec.AreAccessRulesProtected
    }
    if ($bolReplMeta -eq $true)
    {
    
        $AclChange = $(GetACLMeta  $global:strDC $ADObjDN)
        $objLastChange = $AclChange.split(";")[0]
        $strOrigInvocationID = $AclChange.split(";")[1]
        $strOrigUSN = $AclChange.split(";")[2]
    }
    

    If (($FilterEna -eq $true) -and ($bolEffectiveR -eq $false))
    {
        If ($chkBoxType.IsChecked)
        {
            if ($combAccessCtrl.SelectedIndex -gt -1)
            {
            $sd = @($sd | Where-Object{$_.AccessControlType -eq $combAccessCtrl.SelectedItem})
            }
        }    
        If ($chkBoxObject.IsChecked)
        {
            if ($combObjectFilter.SelectedIndex -gt -1)
            {

                $sd = @($sd | Where-Object{($_.ObjectType -eq $global:dicNameToSchemaIDGUIDs.Item($combObjectFilter.SelectedItem)) -or ($_.InheritedObjectType -eq $global:dicNameToSchemaIDGUIDs.Item($combObjectFilter.SelectedItem))})
            }
        }
        If ($chkBoxTrustee.IsChecked)
        {
            if ($txtFilterTrustee.Text.Length -gt 0)
            {
                $sd = @($sd | Where-Object{if($_.IdentityReference -like "S-1-*"){`
                $(ConvertSidToName -server $global:strDomainLongName -Sid $_.IdentityReference) -like $txtFilterTrustee.Text}`
                else{$_.IdentityReference -like $txtFilterTrustee.Text}})

            }
        }

    }


    if ($bolEffectiveR -eq $true)
    {

            if ($global:tokens.count -gt 0)
            {

                $sdtemp2 =  New-Object System.Collections.ArrayList
            
                if ($global:strPrincipalDN -eq $ADObjDN)
                {
                        $sdtemp = ""
                        $sdtemp = $sd | Where-Object{$_.IdentityReference -eq "S-1-5-10"}
                        if($sdtemp)
                        {
                            $sdtemp2.Add( $sdtemp)
                        }
                }
                foreach ($tok in $global:tokens) 
	            {
 
                        $sdtemp = ""
                        $sdtemp = $sd | Where-Object{$_.IdentityReference -eq $tok}
                        if($sdtemp)
                        {
                            $sdtemp2.Add( $sdtemp)
                        }
                  
             
                }
                    $sd = $sdtemp2
            }

    }
    $intSDCount =  $sd.count
  
    if (!($null -eq $sd))
    {
		$index=0
		$permcount = 0

        if ($intSDCount -gt 0)
        {        
    
		    while($index -le $sd.count -1) 
		    {
                    $bolMatchDef = $false
                    $bolMatchprotected = $false
                    $strNTAccount = $sd[$index].IdentityReference.ToString()
	                If ($strNTAccount.contains("S-1-"))
	                {
	                    $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount
	                }  
                    #Remove Default Permissions if SkipDefaultPerm selected
                    if($SkipDefaultPerm)
                    {
                        if($strObjectClass  -ne $strTemoObjectClass)
                        {
                            $sdOUDef = Get-PermDef $strObjectClass $strNTAccount
                        }
                        $strTemoObjectClass = $strObjectClass
                        $indexDef=0
                        while($indexDef -le $sdOUDef.count -1)
                        {
			                if (($sdOUDef[$indexDef].IdentityReference -eq $strNTAccount) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sd[$index].ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sd[$index].AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sd[$index].ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sd[$index].InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sd[$index].InheritedObjectType))
			                {
			                    $bolMatchDef = $true
			                } #End If
                            $indexDef++
                        } #End While
                    }

                    if($bolMatchDef)
				    {
				    }
				    else
				    {
                        #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                        if($SkipProtectedPerm)
                                                                                {
                        if($sdOUProtect -eq "")
                        {
                            $sdOUProtect = Get-ProtectedPerm
                        }
                        $indexProtected=0
                        while($indexProtected -le $sdOUProtect.count -1)
                        {
			                if (($sdOUProtect[$indexProtected].IdentityReference -eq $strNTAccount) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sd[$index].ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sd[$index].AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sd[$index].ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sd[$index].InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sd[$index].InheritedObjectType))
			                {
			                    $bolMatchprotected = $true
			                }#End If
                            $indexProtected++
                        } #End While
                    }

                        if($bolMatchprotected)
				        {
				        }
				        else
				                                                                                                                                            {
					    If ($bolCSV -or $bolCSVOnly)
					    {
                            if($intCSV -eq 0)
                            {

                            $strCSVHeader | Out-File -FilePath $strFileCSV
                            }
                            $intCSV++
				 		    WritePermCSV $sd[$index] $DSobject.distinguishedname.toString() $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN

				 	    }# End If
                        If (!($bolCSVOnly))
                        {
					        If ($strColorTemp -eq "1")
					        {
						        $strColorTemp = "2"
					        }# End If
					        else
					        {
						        $strColorTemp = "1"
					        }# End If				 	
				 	        if ($permcount -eq 0)
				 	        {
                                $bolOUHeader = $true    
				 		        WriteOUT $bolACLExist $sd[$index] $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $FilterEna $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType

				 	        }
				 	        else
				 	        {
                                    $bolOUHeader = $false 
				 		        WriteOUT $bolACLExist $sd[$index] $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $FilterEna $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType

				 	        }# End If
                        }
                        $aclcount++
					    $permcount++
				    }# End If SkipProtectedPerm
                    }# End If SkipDefaultPerm
				    $index++
		    }# End while

        }
        else
        {
            If (!($bolCSVOnly))
            {            
			    If ($strColorTemp -eq "1")
			    {
			    $strColorTemp = "2"
			    }
			    else
			    {
			    $strColorTemp = "1"
			    }		
		 	    if ($permcount -eq 0)
		 	    {
                    $bolOUHeader = $true 
		 		    WriteOUT $bolACLExist $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $FilterEna $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType

                   
		 	    }
		 	    else
		 	    {
                    $bolOUHeader = $false 
                    $GetOwnerEna = $false
                    WriteOUT $bolACLExist $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $FilterEna $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                    #$aclcount++
		 	    }
            }

            $permcount++
        }#End if array        
    
        If (!($bolCSVOnly))
        {
            $bolACLExist = $false
            if (($permcount -eq 0) -and ($index -gt 0))
            {
                $bolOUHeader = $true 
	            WriteOUT $bolACLExist $sd $DSobject.distinguishedname.toString() $bolOUHeader "1" $strFileHTA $bolCompare $FilterEna $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                $aclcount++
            }# End If
        }# End if bolCSVOnly
    }
}#End $global:GetSecErr
	$count++
}# End while
    

if (($count -gt 0))
{
if ($aclcount -eq 0)
{
    if($bolCMD)
    {
        Write-host "No Permissions found!" -ForegroundColor red
    }
    else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "No Permissions found!" -strType "Error" -DateStamp ))
        if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
        {
            $global:ProgressBarWindow.Window.Dispatcher.invoke([action]{$global:ProgressBarWindow.Window.Close()},"Normal")
            $ProgressBarWindow = $null
            Remove-Variable -Name "ProgressBarWindow" -Scope Global
        } 
    }
}  
else
{
    if($chkBoxEffectiveRightsColor.IsChecked)
    {
        Switch ($global:intShowCriticalityLevel)
        {
            0
            {
            (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
            (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
            }
            1
            {
            (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
            (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
            }
            2
            {
            (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
            (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
            }
            3
            {
            (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
            (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
            }
            4
            {
            (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
            (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
            }
        }
    }
    if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
    {
        
            $global:ProgressBarWindow.Window.Dispatcher.invoke([action]{$global:ProgressBarWindow.Window.Close()},"Normal")
            #Remove-Variable -Name "ProgressBarWindow" -Scope Global
    } 
    If ($bolCSVOnly)
    {
        if($bolCMD)
        {
            Write-host "Report saved in $strFileCSV" -ForegroundColor Yellow
        }
        else
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileCSV" -strType "Warning" -DateStamp ))
        }
    }
    else
    {
        if($bolCSV)
        {
            if($bolCMD)
            {
                Write-host "Report saved in $strFileCSV" -ForegroundColor Yellow
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileCSV" -strType "Warning" -DateStamp ))
            }
        }
        #If excel output
        if($OutType -eq "EXCEL")
        {
            $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname "ACL" -BoldTopRow -TableStyle Medium2 -TableName "acltbl" -NoLegend -AutoSize -FreezeTopRow
            
            if($bolCMD)
            {
                Write-host "Report saved in $strFileEXCEL" -ForegroundColor Yellow
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileEXCEL" -strType "Warning" -DateStamp ))
            }
        }#End if EXCEL
        else
        {
            #If Get-Perm was called with Show then open the HTA file.
            if($Show)
            {
	            Invoke-Item $strFileHTA
            }
        }
    }

    }# End If
}
else
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects found!" -strType "Error" -DateStamp ))
}
$i = $null
Remove-Variable -Name "i"
$secd = $null


return $SDResult

}

#==========================================================================
# Function		: Get-PermCompare
# Arguments     : OU Path 
# Returns   	: N/A
# Description   : Compare Permissions on node with permissions in CSV file
#==========================================================================
Function Get-PermCompare
{
    Param([System.Collections.ArrayList]$ALOUdn,[boolean]$SkipDefaultPerm,[boolean]$SkipProtectedPerm,[boolean]$bolReplMeta,[boolean]$bolGetOwnerEna,[boolean]$bolGetOUProtected,[boolean]$bolACLsize,[boolean] $bolGUIDtoText,[string] $OutType)
$Error
&{#Try
$arrOUList = New-Object System.Collections.ArrayList
$bolCompare = $true
$bolCompareDelegation = $false
$bolFilter = $false
$bolOUPRotected = $false
$strACLSize = ""
$bolAClMeta = $false
$strOwner = ""
$count = 0
$aclcount = 0
$SDUsnCheck = $false
$ExitCompare = $false
$sdOUProtect = ""
if ($chkBoxTemplateNodes.IsChecked -eq $true)
{

    $index = 0
    #Enumerate all Nodes in CSV
    while($index -le $global:csvHistACLs.count -1) 
    {
        $arrOUList.Add($global:csvHistACLs[$index].OU)
        $index++
    }
    $arrOUListUnique = $arrOUList | Select-Object -Unique


    #Replace any existing strings matching <DOMAIN-DN>
    $arrOUListUnique = $arrOUListUnique -replace "<DOMAIN-DN>",$global:strDomainDNName
    
    #Replace any existing strings matching <ROOT-DN>
    $arrOUListUnique = $arrOUListUnique -replace "<ROOT-DN>",$global:ForestRootDomainDN
    #If the user entered any text replace matching string from CSV

    if($txtReplaceDN.text.Length -gt 0)
    {

        $arrOUListUnique = $arrOUListUnique -replace $txtReplaceDN.text,$global:strDomainDNName

    }
    $ALOUdn = @($arrOUListUnique)
}

If ($bolReplMeta -eq $true)
{
        If ($global:csvHistACLs[0].SDDate.length -gt 1)
        {
        $bolAClMeta = $true
        }
        $arrUSNCheckList = $global:csvHistACLs | Select-Object -Property OU,OrgUSN -Unique
}
#Verify that USN exist in file and that Meta data will be retreived
if($chkBoxScanUsingUSN.IsChecked -eq $true)
{
    if($bolAClMeta -eq $true)
    {
        $SDUsnCheck = $true
    }
    else
    {
        If ($bolReplMeta -eq $true)
        {
            $MsgBox = [System.Windows.Forms.MessageBox]::Show("Could not compare using USN.`nDid not find USNs in template.`nDo you want to continue?",”Information”,3,"Warning")
            Switch ($MsgBOx)
            {
                "YES"
                {$ExitCompare = $false}
                "NO"
                {$ExitCompare = $true}
                Default
                {$ExitCompare = $true}
            }
        }
        else
        {
            $MsgBox = [System.Windows.Forms.MessageBox]::Show("Could not compare using USN.`nMake sure scan option SD Modified is selected.`nDo you want to continue?",”Information”,3,"Warning")
            Switch ($MsgBOx)
            {
                "YES"
                {$ExitCompare = $false}
                "NO"
                {$ExitCompare = $true}
                Default
                {$ExitCompare = $true}
            }
        }
    }
}
if(!($ExitCompare))
{
$i = 0
if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
{
    $intTot = 0
    #calculate percentage
    $intTot = $ALOUdn.count
    if ($intTot -gt 0)
    {
    LoadProgressBar
    
    }
}

while($count -le $ALOUdn.count -1)
{
    $global:GetSecErr = $false
    $global:secd = ""
    if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
    {
        $i++
        [int]$pct = ($i/$intTot)*100
        #Update the progress bar
        while(($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20))
        {
                    Start-Sleep -Milliseconds 1
                    $cc++
        }
        if ($global:ProgressBarWindow.Window.IsInitialized -eq $true)
        {
            Update-ProgressBar "Currently scanning $i of $intTot objects" $pct 
        }  
        
    }


    $OUMatchResultOverall = $false

    $sd =  New-Object System.Collections.ArrayList
    $GetOwnerEna = $bolGetOwnerEna
    $ADObjDN = $($ALOUdn[$count])
    $OUdnorgDN = $ADObjDN 

    #Counter used for fitlerout Nodes with only defaultpermissions configured
    $intAclOccurence = 0

    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$ADObjDN", "(name=*)", "base")
    if($global:bolShowDeleted)
    {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
        [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
    }
    [void]$request.Attributes.Add("objectclass")
    [void]$request.Attributes.Add("ntsecuritydescriptor")
    
    $response = $null
     $DSobject = $null
    ##
    if ($rdbDACL.IsChecked)
    {
        $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
        $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
        [void]$request.Controls.Add($control)
        $response = $LDAPConnection.SendRequest($request)
        $DSobject = $response.Entries[0]
        #Check if any NTsecuritydescr
        if($null -ne $DSobject.Attributes.ntsecuritydescriptor)
        {
            if($null -ne $DSobject.Attributes.objectclass)
            {                
                $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count-1]
            }
            else
            {
                $strObjectClass = "unknown"
            }
            $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity

            if($chkBoxRAWSDDL.IsChecked)
            {
            #### Behind the curtain ###
                $secSDDL = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $objSd =  $DSobject.Attributes.ntsecuritydescriptor[0]
                if ($objSD -is [Byte[]]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd, 0)
                    } elseif ($objSD -is [string]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd)
                    }
                $strSDDL = $SDDLSec.GetSddlForm('Access,Owner')

                $arrSplitedSDDL = $strSDDL.Split("(")
                $intI = 0
                Foreach ($strSDDLPart in $arrSplitedSDDL)
                {
                    if($intI -gt 0)
                    {
                        if($sec.Owner -eq $null)
                        {
                            $sec.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                        }
                        else
                        {
                            if(!($chkInheritedPerm.IsChecked))
                            {
                                if(($strSDDLPart.split(";")[1] -ne "CIID") -and ($strSDDLPart.split(";")[1] -ne "CIIOID"))
                                {
                                    $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                    $sec.AddAccessRule($secSDDL.Access[0]) 
                                }
                            }
                            else
                            {
                                $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                $sec.AddAccessRule($secSDDL.Access[0])
                            }
                        }
                    }
                    $intI++
                }
                #### Behind the curtain ###
            }
            else
            {
                $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
            }
            &{#Try
                $global:secd = $sec.GetAccessRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.NTAccount])

            }
            Trap [SystemException]
            { 
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType "Warning" -DateStamp ))
                &{#Try
                    $global:secd = $sec.GetAccessRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
                }
                Trap [SystemException]
                { 
                    $global:GetSecErr = $true
                    Continue
                }
                Continue
            }
        }
        else
        {
            #Fail futher scan when NTsecurityDescriptor is null
            $global:GetSecErr = $true
        }
     
    }
    else
    {
        $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
        $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
        [void]$request.Controls.Add($control)
        $response = $LDAPConnection.SendRequest($request)
        $DSobject = $response.Entries[0]
        if($null -ne $DSobject.Attributes.objectclass)
        {                
            $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count-1]
        }
        else
        {
            $strObjectClass = "unknown"
        }
        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
        &{#Try
            #$DSobject.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner' -bor [System.DirectoryServices.SecurityMasks]'Group'-bor [System.DirectoryServices.SecurityMasks]'Dacl' -bor [System.DirectoryServices.SecurityMasks]'Sacl'
            $global:secd = $sec.GetAuditRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.NTAccount])
        }
        Trap [SystemException]
        { 
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType "Warning" -DateStamp ))
            &{#Try
                $global:secd = $sec.GetAuditRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
            }
            Trap [SystemException]
            { 
                $global:GetSecErr = $true
                Continue
            }
            Continue
        }
    }
    if($DSobject.attributes.count -gt 0)
    {
    if(($global:GetSecErr -ne $true) -or ($global:secd -ne ""))
    {
        $sd.clear()
        if($null -ne $global:secd){
            $(ConvertTo-ObjectArrayListFromPsCustomObject  $global:secd)| ForEach-Object{[void]$sd.add($_)}
        }
        If ($GetOwnerEna -eq $true)
        {
    
            &{#Try
                $global:strOwner = $sec.GetOwner([System.Security.Principal.NTAccount]).value
            }
   
            Trap [SystemException]
            { 
                if($global:bolADDSType)
                {
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType "Warning" -DateStamp ))
                }
                $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                Continue
            }


            $newSdOwnerObject = New-Object PSObject -Property @{ActiveDirectoryRights="Read permissions, Modify permissions";InheritanceType="None";ObjectType ="None";`
            InheritedObjectType="None";ObjectFlags="None";AccessControlType="Owner";IdentityReference=$global:strOwner;IsInherited="False";`
            InheritanceFlags="None";PropagationFlags="None"}

            [void]$sd.insert(0,$newSdOwnerObject)
 
        }
 	    If ($SkipDefaultPerm)
	    {
            If ($GetOwnerEna -eq $false)
                {
    
                &{#Try
                    $global:strOwner = $sec.GetOwner([System.Security.Principal.NTAccount]).value
                }
   
                Trap [SystemException]
                { 
                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType "Error" -DateStamp ))
                    $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                    Continue
                }
            } 
        }

        if ($bolACLsize -eq $true) 
        {
            #$strACLSize = $sec.GetSecurityDescriptorBinaryForm().length
            $strACLSize = $SDDLSec.BinaryLength
        }
        if ($bolGetOUProtected -eq $true)
        {
            $bolOUProtected = $sec.AreAccessRulesProtected
        }
        if ($bolReplMeta -eq $true)
        {
    
            $AclChange = $(GetACLMeta  $global:strDC $ADObjDN)
            $objLastChange = $AclChange.split(";")[0]
            $strOrigInvocationID = $AclChange.split(";")[1]
            $strOrigUSN = $AclChange.split(";")[2]
        }

  
    
        $rar = @($($sd | select-Object -Property *))


        $index = 0
        $SDResult = $false
        $OUMatchResult = $false
            

        $SDUsnNew = $true
        if ($SDUsnCheck -eq $true)
        {

               	       

                    while($index -le $arrUSNCheckList.count -1) 
                    {
                        $SDHistResult = $false

                        $strOUcol = $arrUSNCheckList[$index].OU
                        if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

                        }
                        if($strOUcol.Contains("<ROOT-DN>") -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)

                        }
                        if($txtReplaceDN.text.Length -gt 0)
                        {
		                    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text,$global:strDomainDNName)

                        }     
			            if ($OUdnorgDN -eq $strOUcol )
			            {
                            $OUMatchResult = $true
                            $SDResult = $true

                            if($strOrigUSN -eq $arrUSNCheckList[$index].OrgUSN)
                            {
                                $aclcount++
                                foreach($sdObject in $rar)
            	                {

                
                                    if($null  -ne $sdObject.AccessControlType)
                                    {
                                        $ACEType = $sdObject.AccessControlType
                                    }
                                    else
                                    {
                                        $ACEType = $sdObject.AuditFlags
                                    }
                                    $strNTAccount = $sdObject.IdentityReference
	                                If ($strNTAccount.contains("S-1-"))
	                                {
	                                    $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	                                }
                                    $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$sdObject.ActiveDirectoryRights;InheritanceType=$sdObject.InheritanceType;ObjectType=$sdObject.ObjectType;`
                                    InheritedObjectType=$sdObject.InheritedObjectType;ObjectFlags=$sdObject.ObjectFlags;AccessControlType=$ACEType;IdentityReference=$strNTAccount;IsInherited=$sdObject.IsInherited;`
                                    InheritanceFlags=$sdObject.InheritanceFlags;PropagationFlags=$sdObject.PropagationFlags;Color="Match"}

                                    $OUMatchResultOverall = $true
                                    if ($intAclOccurence -eq 0)
                                    {
                                        $intAclOccurence++
                                        $bolOUHeader = $true 
                                        WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        
                                    }
                                    $bolOUHeader = $false 
                                    WriteOUT $true $newSdObject $DSobject.distinguishedname.toString() $bolOUHeader "4" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                                }
                                $SDUsnNew = $false
                                break
                            }
                            else
                            {
                                $aclcount++

                                $SDUsnNew = $true
                                break
                            }

                        }
                        $index++
                    }
                
               
        } 

        If (($SDUsnCheck -eq $false) -or ($SDUsnNew -eq $true))
        { 
	        foreach($sdObject in $rar)
	        {
                $bolMatchDef = $false
                $bolMatchprotected = $false
                $strNTAccount = $sdObject.IdentityReference.toString()
	            If ($strNTAccount.contains("S-1-"))
	            {
	                $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	            }
                #Remove Default Permissions if SkipDefaultPerm selected
                if($SkipDefaultPerm)
                {
                    if($strObjectClass  -ne $strTemoObjectClass)
                    {
                        $sdOUDef = Get-PermDef $strObjectClass $strNTAccount
                    }
                    $strTemoObjectClass = $strObjectClass
                    $indexDef=0
                    while($indexDef -le $sdOUDef.count -1) {
			                    if (($sdOUDef[$indexDef].IdentityReference -eq $strNTAccount) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sdObject.ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sdObject.InheritedObjectType))
			                    {
			                        $bolMatchDef = $true
			                    }#} #End If
                        $indexDef++
                    } #End While
                }

                if($bolMatchDef)
				{
				}
                else
                {
                    #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                    if($SkipProtectedPerm)
                    {
                        if($sdOUProtect -eq "")
                        {
                            $sdOUProtect = Get-ProtectedPerm
                        }
                        $indexProtected=0
                        while($indexProtected -le $sdOUProtect.count -1)
                        {
			                if (($sdOUProtect[$indexProtected].IdentityReference -eq $strNTAccount) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sdObject.ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sdObject.InheritedObjectType))
			                {
			                    $bolMatchprotected = $true
			                }#End If
                            $indexProtected++
                        } #End While
                    }

                    if($bolMatchprotected)
				    {
				    }
				    else
				    {

		                $index = 0
		                $SDResult = $false
                        $OUMatchResult = $false
                        $aclcount++
                        if($null  -ne $sdObject.AccessControlType)
                        {
                            $ACEType = $sdObject.AccessControlType
                        }
                        else
                        {
                            $ACEType = $sdObject.AuditFlags
                        }

                        $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$sdObject.ActiveDirectoryRights;InheritanceType=$sdObject.InheritanceType;ObjectType=$sdObject.ObjectType;`
                        InheritedObjectType=$sdObject.InheritedObjectType;ObjectFlags=$sdObject.ObjectFlags;AccessControlType=$ACEType;IdentityReference=$strNTAccount;IsInherited=$sdObject.IsInherited;`
                        InheritanceFlags=$sdObject.InheritanceFlags;PropagationFlags=$sdObject.PropagationFlags;Color="Match"}

		                while($index -le $global:csvHistACLs.count -1) 
		                {
                            $strOUcol = $global:csvHistACLs[$index].OU

                            if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
                            {
		                        $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

                            }
                            if($strOUcol.Contains("<ROOT-DN>") -gt 0)
                            {
		                        $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)

                            }
                            if($txtReplaceDN.text.Length -gt 0)
                            {
		                        $strOUcol = ($strOUcol -Replace $txtReplaceDN.text,$global:strDomainDNName)

                            }
			                if ($OUdnorgDN -eq $strOUcol )
			                {
                                $OUMatchResult = $true
                                $OUMatchResultOverall = $true
				                $strIdentityReference = $global:csvHistACLs[$index].IdentityReference
                                if($strIdentityReference.Contains("<DOMAIN-NETBIOS>"))
                                {
		                            $strIdentityReference = ($strIdentityReference -Replace "<DOMAIN-NETBIOS>",$global:strDomainShortName)

                                }
                                if($strIdentityReference.Contains("<ROOT-NETBIOS>"))
                                {
		                            $strIdentityReference = ($strIdentityReference -Replace "<ROOT-NETBIOS>",$global:strRootDomainShortName)

                                }
                                if($strIdentityReference.Contains("<DOMAINSID>"))
                                {
		                            $strIdentityReference = ($strIdentityReference -Replace "<DOMAINSID>",$global:DomainSID)

                                }
                                if($strIdentityReference.Contains("<ROOTDOMAINSID>"))
                                {
		                            $strIdentityReference = ($strIdentityReference -Replace "<ROOTDOMAINSID>",$global:ForestRootDomainSID)

                                }
	                            If ($strIdentityReference.contains("S-1-"))
	                            {
	                                $strIdentityReference = ConvertSidToName -server $global:strDomainLongName -Sid $strIdentityReference

	                            }
                                if($txtReplaceNetbios.text.Length -gt 0)
                                {
		                            $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text,$global:strDomainShortName)

                                }
				                $strTmpActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights				
				                $strTmpInheritanceType = $global:csvHistACLs[$index].InheritanceType			
				                $strTmpObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
				                $strTmpInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
				                $strTmpAccessControlType = $global:csvHistACLs[$index].AccessControlType
                                if ($strTmpAccessControlType -eq "Owner" )
                                {
                                    $global:strOwnerTemplate = $strIdentityReference
                                }

                                If (($newSdObject.IdentityReference -eq $strIdentityReference) -and ($newSdObject.ActiveDirectoryRights -eq $strTmpActiveDirectoryRights) -and ($newSdObject.AccessControlType -eq $strTmpAccessControlType) -and ($newSdObject.ObjectType -eq $strTmpObjectTypeGUID) -and ($newSdObject.InheritanceType -eq $strTmpInheritanceType) -and ($newSdObject.InheritedObjectType -eq $strTmpInheritedObjectTypeGUID))
		 		                {
					                $SDResult = $true
		 		                }
 		 	                }
			                $index++
		                }# End While
         
                    if ($SDResult)
                    {
                        if ($intAclOccurence -eq 0)
                        {
                            $intAclOccurence++
                            $bolOUHeader = $true 
                            WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        
                        }
                        $bolOUHeader = $false 
                        WriteOUT $true $newSdObject $DSobject.distinguishedname.toString() $bolOUHeader "4" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                    
                    }
		            If ($OUMatchResult -And !($SDResult))
		            {
                        if ($intAclOccurence -eq 0)
                        {
                            $intAclOccurence++
                            $bolOUHeader = $true 
                            WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        }   
                        $newSdObject.Color = "New"
                        $bolOUHeader = $false 
                        WriteOUT $true $newSdObject $DSobject.distinguishedname.toString() $bolOUHeader "5" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
            
                     }
                }# End If SkipProtectedPerm
            }# End If SkipDefaultPerm
	    }
            } # if $SDUsnCheck -eq $true

        If (($SDUsnCheck -eq $false) -or ($SDUsnNew -eq $true))
        {
            $index = 0

            while($index -le $global:csvHistACLs.count -1) 
            {
                $SDHistResult = $false

                $strOUcol = $global:csvHistACLs[$index].OU
                if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
                {
		            $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

                }
                if($strOUcol.Contains("<ROOT-DN>") -gt 0)
                {
		            $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)

                }
                if($txtReplaceDN.text.Length -gt 0)
                {
		            $strOUcol = ($strOUcol -Replace $txtReplaceDN.text,$global:strDomainDNName)

                }     
			    if ($OUdnorgDN -eq $strOUcol )
			    {
                    $OUMatchResult = $true
				    $strIdentityReference = $global:csvHistACLs[$index].IdentityReference

                    if($strIdentityReference.Contains("<DOMAIN-NETBIOS>"))
                    {
		                $strIdentityReference = ($strIdentityReference -Replace "<DOMAIN-NETBIOS>",$global:strDomainShortName)

                    }
                    if($strIdentityReference.Contains("<ROOT-NETBIOS>"))
                    {
		                $strIdentityReference = ($strIdentityReference -Replace "<ROOT-NETBIOS>",$global:strRootDomainShortName)

                    }
                    if($strIdentityReference.Contains("<DOMAINSID>"))
                    {
		                $strIdentityReference = ($strIdentityReference -Replace "<DOMAINSID>",$global:DomainSID)

                    }
                    if($strIdentityReference.Contains("<ROOTDOMAINSID>"))
                    {
		                $strIdentityReference = ($strIdentityReference -Replace "<ROOTDOMAINSID>",$global:ForestRootDomainSID)

                    }
	                If ($strIdentityReference.contains("S-1-"))
	                {
	                 $strIdentityReference = ConvertSidToName -server $global:strDomainLongName -Sid $strIdentityReference

	                }
                    if($txtReplaceNetbios.text.Length -gt 0)
                    {
		                $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text,$global:strDomainShortName)

                    }
				    $strTmpActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights			
				    $strTmpInheritanceType = $global:csvHistACLs[$index].InheritanceType				
				    $strTmpObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
				    $strTmpInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
				    $strTmpAccessControlType = $global:csvHistACLs[$index].AccessControlType
                    if ($strTmpAccessControlType -eq "Owner" )
                    {
                        $global:strOwnerTemplate = $strIdentityReference
                    }

                
                    $rarHistCheck = @($($sd | select-object -Property *))

	                foreach($sdObject in $rarHistCheck)
	                {
                        $bolMatchDef = $false
                        $strNTAccount = $sdObject.IdentityReference.toString()
	                    If ($strNTAccount.contains("S-1-"))
	                    {
	                     $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	                    }
                        #Remove Default Permissions if SkipDefaultPerm selected
                        if($SkipDefaultPerm)
                        {
                            if($strObjectClass  -ne $strTemoObjectClass)
                            {
                                $sdOUDef = Get-PermDef $strObjectClass $strNTAccount
                            }
                            $strTemoObjectClass = $strObjectClass
                            $indexDef=0
                            while($indexDef -le $sdOUDef.count -1) {
			                            if (($sdOUDef[$indexDef].IdentityReference -eq $strNTAccount) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sdObject.ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sdObject.InheritedObjectType))
			                            {
			                                $bolMatchDef = $true
			                            }#} #End If
                                $indexDef++
                            } #End While
                        }

                        if($bolMatchDef)
				        {
				        }
                        else
                        {     
                            #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                            if($SkipProtectedPerm)
                            {
                                if($sdOUProtect -eq "")
                                {
                                    $sdOUProtect = Get-ProtectedPerm
                                }
                                $indexProtected=0
                                while($indexProtected -le $sdOUProtect.count -1)
                                {
			                        if (($sdOUProtect[$indexProtected].IdentityReference -eq $strNTAccount) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sdObject.ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sdObject.InheritedObjectType))
			                        {
			                            $bolMatchprotected = $true
			                        }#End If
                                    $indexProtected++
                                } #End While
                            }

                            if($bolMatchprotected)
				            {
				            }
				            else
				            {                     
                                if($null  -ne $sdObject.AccessControlType)
                                {
                                    $ACEType = $sdObject.AccessControlType
                                }
                                else
                                {
                                    $ACEType = $sdObject.AuditFlags
                                }                                          
           
                                $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$sdObject.ActiveDirectoryRights;InheritanceType=$sdObject.InheritanceType;ObjectType=$sdObject.ObjectType;`
                                InheritedObjectType=$sdObject.InheritedObjectType;ObjectFlags=$sdObject.ObjectFlags;AccessControlType=$ACEType;IdentityReference=$strNTAccount;IsInherited=$sdObject.IsInherited;`
                                InheritanceFlags=$sdObject.InheritanceFlags;PropagationFlags=$sdObject.PropagationFlags}

                                If (($newSdObject.IdentityReference -eq $strIdentityReference) -and ($newSdObject.ActiveDirectoryRights -eq $strTmpActiveDirectoryRights) -and ($newSdObject.AccessControlType -eq $strTmpAccessControlType) -and ($newSdObject.ObjectType -eq $strTmpObjectTypeGUID) -and ($newSdObject.InheritanceType -eq $strTmpInheritanceType) -and ($newSdObject.InheritedObjectType -eq $strTmpInheritedObjectTypeGUID))
                                {
                                    $SDHistResult = $true
                                }#End If $newSdObject
                            }# End If SkipProtectedPerm
                        }# End If SkipDefaultPerm
                    }# End foreach 

                    #If OU exist in CSV but no matching ACE found
                    If ($OUMatchResult -And !($SDHistResult))
                    {

                        $strIdentityReference = $global:csvHistACLs[$index].IdentityReference
                        if($strIdentityReference.Contains("<DOMAIN-NETBIOS>"))
                        {
		                    $strIdentityReference = ($strIdentityReference -Replace "<DOMAIN-NETBIOS>",$global:strDomainShortName)

                        }
                        if($strIdentityReference.Contains("<ROOT-NETBIOS>"))
                        {
		                    $strIdentityReference = ($strIdentityReference -Replace "<ROOT-NETBIOS>",$global:strRootDomainShortName)

                        }
                        if($strIdentityReference.Contains("<DOMAINSID>"))
                        {
		                    $strIdentityReference = ($strIdentityReference -Replace "<DOMAINSID>",$global:DomainSID)

                        }
                        if($strIdentityReference.Contains("<ROOTDOMAINSID>"))
                        {
		                    $strIdentityReference = ($strIdentityReference -Replace "<ROOTDOMAINSID>",$global:ForestRootDomainSID)

                        }
                        if($txtReplaceNetbios.text.Length -gt 0)
                        {
		                    $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text,$global:strDomainShortName)

                        }                  
	                    If ($strIdentityReference.contains("S-1-"))
	                    {
	                     $strIdentityReference = ConvertSidToName -server $global:strDomainLongName -Sid $strIdentityReference

	                    }
                        $histSDObject = New-Object PSObject -Property @{ActiveDirectoryRights=$global:csvHistACLs[$index].ActiveDirectoryRights;InheritanceType=$global:csvHistACLs[$index].InheritanceType;ObjectType=$global:csvHistACLs[$index].ObjectType;`
                        InheritedObjectType=$global:csvHistACLs[$index].InheritedObjectType;ObjectFlags=$global:csvHistACLs[$index].ObjectFlags;AccessControlType=$global:csvHistACLs[$index].AccessControlType;IdentityReference=$strIdentityReference;IsInherited=$global:csvHistACLs[$index].IsInherited;`
                        InheritanceFlags=$global:csvHistACLs[$index].InheritanceFlags;PropagationFlags=$global:csvHistACLs[$index].PropagationFlags;Color="Missing"}
                    
                        if ($intAclOccurence -eq 0)
                        {
                            $intAclOccurence++
                            $bolOUHeader = $true 
                            WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        }
                        $bolOUHeader = $false               
                        WriteOUT $true $histSDObject $DSobject.distinguishedname.toString() $bolOUHeader "3" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        $histSDObject = ""
                    }# End If $OUMatchResult
                }# End if $OUdn
			    $index++
		    }# End While

        } #End If If ($SDUsnCheck -eq $false)

        #If the OU was not found in the CSV
        If (!$OUMatchResultOverall)        
        {

	        foreach($sdObject in $rar)
            {
                $bolMatchDef = $false
                if($sdObject.IdentityReference.value)
                {
                    $strNTAccount = $sdObject.IdentityReference.value
                }
                else
                {
                   $strNTAccount = $sdObject.IdentityReference
                }
	            If ($strNTAccount.contains("S-1-"))
	            {
	             $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	            }

                #Remove Default Permissions if SkipDefaultPerm selected
                if($SkipDefaultPerm -or $bolCompareDelegation) 
                {
                    if($strObjectClass  -ne $strTemoObjectClass)
                    {
                        $sdOUDef = Get-PermDef $strObjectClass $strNTAccount
                    }
                    $strTemoObjectClass = $strObjectClass
                    $indexDef=0
                    while($indexDef -le $sdOUDef.count -1) {
			                    if (($sdOUDef[$indexDef].IdentityReference -eq $strNTAccount) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sd[$index].ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sd[$index].AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sd[$index].ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sd[$index].InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sd[$index].InheritedObjectType))
			                    {
			                        $bolMatchDef = $true
			                    }#} #End If
                        $indexDef++
                    } #End While
                }

                if($bolMatchDef)
			    {
			    }
                else
                {   
                    if($SkipDefaultPerm -or $bolCompareDelegation) 
                    {
                        $strDelegationNotation = "Out of Policy"


                        If (($strNTAccount -eq $global:strOwnerTemplate) -and ($sdObject.ActiveDirectoryRights -eq "Read permissions, Modify permissions") -and ($sdObject.AccessControlType -eq "Owner") -and ($sdObject.ObjectType -eq "None") -and ($sdObject.InheritanceType -eq "None") -and ($sdObject.InheritedObjectType -eq "None"))
                        {
                                
                        }#End If $newSdObject
                        else
                        {

                            $MissingOUSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$sdObject.ActiveDirectoryRights;InheritanceType=$sdObject.InheritanceType;ObjectType=$sdObject.ObjectType;`
                            InheritedObjectType=$sdObject.InheritedObjectType;ObjectFlags=$sdObject.ObjectFlags;AccessControlType=$sdObject.AccessControlType;IdentityReference=$strNTAccount;IsInherited=$sdObject.IsInherited;`
                            InheritanceFlags=$sdObject.InheritanceFlags;PropagationFlags=$sdObject.PropagationFlags;Color=$strDelegationNotation}

                            if ($intAclOccurence -eq 0)
                            {
                                $intAclOccurence++
                                $bolOUHeader = $true 
                                WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                            }
                            $bolOUHeader = $false 
                            WriteOUT $true $MissingOUSdObject $OUdn $bolOUHeader "5" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        }
                    }
                    else
                    {
                        if($SDUsnCheck -eq $false)
                        {
                            $strDelegationNotation = "Node not in file"
            

                            $MissingOUSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$sdObject.ActiveDirectoryRights;InheritanceType=$sdObject.InheritanceType;ObjectType=$sdObject.ObjectType;`
                            InheritedObjectType=$sdObject.InheritedObjectType;ObjectFlags=$sdObject.ObjectFlags;AccessControlType=$sdObject.AccessControlType;IdentityReference=$strNTAccount;IsInherited=$sdObject.IsInherited;`
                            InheritanceFlags=$sdObject.InheritanceFlags;PropagationFlags=$sdObject.PropagationFlags;Color=$strDelegationNotation}
 
                            if ($intAclOccurence -eq 0)
                            {
                                $intAclOccurence++
                                $bolOUHeader = $true 
                                WriteOUT $false $sd $DSobject.distinguishedname.toString() $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                            }
                            $bolOUHeader = $false                  
                            WriteOUT $true $MissingOUSdObject $DSobject.distinguishedname.toString() $bolOUHeader "5" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
                        }
                    }
                }#Skip Default or bolComparedelegation
            }#End Forech $rar
        } #End If not OUMatchResultOverall
      }#End Global:GetSecErr
  }#else if adobject missing name
  else
  {
  $index = 0
     while($index -le $global:csvHistACLs.count -1) 
     {
        $SDHistResult = $false

        $strOUcol = $global:csvHistACLs[$index].OU

        if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
        {
		    $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

        }
        if($strOUcol.Contains("<ROOT-DN>") -gt 0)
        {
		    $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)

        }
        if($txtReplaceDN.text.Length -gt 0)
        {
		    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text,$global:strDomainDNName)

        }           
	    if ($OUdnorgDN -eq $strOUcol )
	    {

            $strIdentityReference = $global:csvHistACLs[$index].IdentityReference
            if($strIdentityReference.Contains("<DOMAIN-NETBIOS>"))
            {
		        $strIdentityReference = ($strIdentityReference -Replace "<DOMAIN-NETBIOS>",$global:strDomainShortName)

            }
            if($strIdentityReference.Contains("<ROOT-NETBIOS>"))
            {
		        $strIdentityReference = ($strIdentityReference -Replace "<ROOT-NETBIOS>",$global:strRootDomainShortName)

            }
            if($strIdentityReference.Contains("<DOMAINSID>"))
            {
		        $strIdentityReference = ($strIdentityReference -Replace "<DOMAINSID>",$global:DomainSID)

            }
            if($strIdentityReference.Contains("<ROOTDOMAINSID>"))
            {
		        $strIdentityReference = ($strIdentityReference -Replace "<ROOTDOMAINSID>",$global:ForestRootDomainSID)

            }
            if($txtReplaceNetbios.text.Length -gt 0)
            {
		        $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text,$global:strDomainShortName)

            }    
	        If ($strIdentityReference.contains("S-1-"))
	        {
	         $strIdentityReference = ConvertSidToName -server $global:strDomainLongName -Sid $strIdentityReference

	        }
            $histSDObject = New-Object PSObject -Property @{ActiveDirectoryRights=$global:csvHistACLs[$index].ActiveDirectoryRights;InheritanceType=$global:csvHistACLs[$index].InheritanceType;ObjectType=$global:csvHistACLs[$index].ObjectType;`
            InheritedObjectType=$global:csvHistACLs[$index].InheritedObjectType;ObjectFlags=$global:csvHistACLs[$index].ObjectFlags;AccessControlType=$global:csvHistACLs[$index].AccessControlType;IdentityReference=$strIdentityReference;IsInherited=$global:csvHistACLs[$index].IsInherited;`
            InheritanceFlags=$global:csvHistACLs[$index].InheritanceFlags;PropagationFlags=$global:csvHistACLs[$index].PropagationFlags;Color="Node does not exist in AD"}
                    
            if ($intAclOccurence -eq 0)
            {
                $intAclOccurence++
                $bolOUHeader = $true 
                WriteOUT $false $histSDObject $strOUcol $bolOUHeader $strColorTemp $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
            }
            $bolOUHeader = $false               
            WriteOUT $true $histSDObject $strOUcol $bolOUHeader "3" $strFileHTA $bolCompare $bolFilter $bolReplMeta $objLastChange $bolACLsize $strACLSize $bolGetOUProtected $bolOUProtected $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $chkBoxObjType.IsChecked $strFileEXCEL $OutType
            $histSDObject = ""
        }
        $index++
    }
  }#End if adobject missing name
  $count++
}# End While $ALOUdn.count

if (($count -gt 0))
{
    if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
    {
                
            $global:ProgressBarWindow.Window.Dispatcher.invoke([action]{$global:ProgressBarWindow.Window.Close()},"Normal")
    } 
       
    if ($aclcount -eq 0)
    {
    [System.Windows.Forms.MessageBox]::Show("No Permissions found!" , "Status") 
    }  
    else
    {
        if($chkBoxEffectiveRightsColor.IsChecked)
        {
            Switch ($global:intShowCriticalityLevel)
            {
                0
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
                }
                1
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
                }
                2
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
                }
                3
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
                }
                4
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
                }
            }
        }
        if ($bolCSVOnly)
        {

            [System.Windows.Forms.MessageBox]::Show("Done!" , "Status") 
        }
        else
        {
	        Invoke-Item $strFileHTA
        }

    }# End If
}
else
{
[System.Windows.Forms.MessageBox]::Show("No objects found!" , "Status") 


}
}#End if ExitCompare
}# End Try
 Trap [SystemException]
 {
#

Invoke-Item $strFileHTA
;Continue
 }  

$histSDObject = ""
$sdObject = ""   
$MissingOUSdObject = ""
$newSdObject = ""
$DSobject = ""
$global:strOwner = ""
$global:csvHistACLs = ""
  

$secd = $null
Remove-Variable -Name "secd" -Scope Global
}

#==========================================================================
# Function		:  ConvertCSVtoHTM
# Arguments     : Fle Path 
# Returns   	: N/A
# Description   : Convert CSV file to HTM Output
#==========================================================================
Function ConvertCSVtoHTM
{
    Param($CSVInput,[boolean] $bolGUIDtoText)
$OutType = "HTM"
$bolReplMeta = $false
If(Test-Path $CSVInput)
{

    $fileName = $(Get-ChildItem $CSVInput).BaseName
	$strFileHTA = $env:temp + "\"+$global:ACLHTMLFileName+".hta" 
	$strFileHTM = $env:temp + "\"+"$fileName"+".htm" 	

    $global:csvHistACLs = import-Csv $CSVInput
    #Test CSV file format



    if(TestCSVColumns $global:csvHistACLs)
    {
        If ($global:csvHistACLs[0].SDDate.length -gt 1)
        {
            $bolReplMeta = $true
        }

        $colHeaders = ( $global:csvHistACLs| Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
        $bolObjType = $false
        Foreach ($ColumnName in $colHeaders )
        {

            if($ColumnName.Trim() -eq "ObjectClass")
            {
                $bolObjType = $true
            }
        }

        CreateHTM $fileName $strFileHTM
        CreateHTA $fileName $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
	
        InitiateHTM $strFileHTM $fileName $fileName $bolReplMeta $false $false $chkBoxEffectiveRightsColor.IsChecked $false $false $false $strCompareFile $false $false $bolObjType
	    InitiateHTM $strFileHTA $fileName $fileName $bolReplMeta $false $false $chkBoxEffectiveRightsColor.IsChecked $false $false $false $strCompareFile $false $false $bolObjType
    
   

        $tmpOU = ""
        $index = 0
        while($index -le $global:csvHistACLs.count -1)
        {
	    
            $strOUcol = $global:csvHistACLs[$index].OU
        
            if($strOUcol.Contains("<DOMAIN-DN>") -gt 0)
            {
		        $strOUcol = ($strOUcol -Replace "<DOMAIN-DN>",$global:strDomainDNName)

            }

            if($strOUcol.Contains("<ROOT-DN>") -gt 0)
            {
		        $strOUcol = ($strOUcol -Replace "<ROOT-DN>",$global:ForestRootDomainDN)	
            }


            If ($bolReplMeta -eq $true)
            {

		        $strOU = $strOUcol
		        $strTrustee = $global:csvHistACLs[$index].IdentityReference
		        $strRights = $global:csvHistACLs[$index].ActiveDirectoryRights				
		        $strInheritanceType = $global:csvHistACLs[$index].InheritanceType				
		        $strObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
		        $strInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
		        $strObjectFlags = $global:csvHistACLs[$index].ObjectFlags
		        $strAccessControlType = $global:csvHistACLs[$index].AccessControlType
		        $strIsInherited = $global:csvHistACLs[$index].IsInherited
		        $strInheritedFlags = $global:csvHistACLs[$index].InheritanceFlags
		        $strPropFlags = $global:csvHistACLs[$index].PropagationFlags
                $strTmpACLDate = $global:csvHistACLs[$index].SDDate

            }
            else
            {

		        $strOU = $strOUcol
		        $strTrustee = $global:csvHistACLs[$index].IdentityReference
		        $strRights = $global:csvHistACLs[$index].ActiveDirectoryRights				
		        $strInheritanceType = $global:csvHistACLs[$index].InheritanceType				
		        $strObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
		        $strInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
		        $strObjectFlags = $global:csvHistACLs[$index].ObjectFlags
		        $strAccessControlType = $global:csvHistACLs[$index].AccessControlType
		        $strIsInherited = $global:csvHistACLs[$index].IsInherited
		        $strInheritedFlags = $global:csvHistACLs[$index].InheritanceFlags
		        $strPropFlags = $global:csvHistACLs[$index].PropagationFlags

            }                                
            
            If ($bolObjType -eq $true)
            {

		        $strObjectClass = $global:csvHistACLs[$index].ObjectClass
            }
            if($strTrustee.Contains("<DOMAIN-NETBIOS>"))
            {
		        $strTrustee = ($strTrustee -Replace "<DOMAIN-NETBIOS>",$global:strDomainShortName)

            }
            if($strTrustee.Contains("<ROOT-NETBIOS>"))
            {
		        $strTrustee = ($strTrustee -Replace "<ROOT-NETBIOS>",$global:strRootDomainShortName)

            }
            if($strTrustee.Contains("<DOMAINSID>"))
            {
		        $strTrustee = ($strTrustee -Replace "<DOMAINSID>",$global:DomainSID)

            }
            if($strTrustee.Contains("<ROOTDOMAINSID>"))
            {
		        $strTrustee = ($strTrustee -Replace "<ROOTDOMAINSID>",$global:ForestRootDomainSID)

            }
            $txtSdObject = New-Object PSObject -Property @{ActiveDirectoryRights=$strRights;InheritanceType=$strInheritanceType;ObjectType=$strObjectTypeGUID;`
            InheritedObjectType=$strInheritedObjectTypeGUID;ObjectFlags=$strObjectFlags;AccessControlType=$strAccessControlType;IdentityReference=$strTrustee;IsInherited=$strIsInherited;`
            InheritanceFlags=$strInheritedFlags;PropagationFlags=$strPropFlags}

	        If ($strColorTemp -eq "1")
	        {
		        $strColorTemp = "2"
	        }# End If
	        else
	        {
		        $strColorTemp = "1"
	        }# End If                  
            if ($tmpOU -ne $strOU)      
            {
  
                $bolOUHeader = $true   
                WriteOUT $true $txtSdObject $strOU $bolOUHeader $strColorTemp $strFileHTA $false $false $bolReplMeta $strTmpACLDate $false $strACLSize $false $false $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $bolObjType $strFileEXCEL $OutType
   
    
                $tmpOU = $strOU
            }
            else
            {
                $bolOUHeader = $false   
                WriteOUT $true $txtSdObject $strOU $bolOUHeader $strColorTemp $strFileHTA $false $false $bolReplMeta $strTmpACLDate  $false $strACLSize $false $false $chkBoxEffectiveRightsColor.IsChecked $bolGUIDtoText $strObjectClass $bolObjType $strFileEXCEL $OutType


            }
			
            $index++
				
        }#End While


        if($chkBoxEffectiveRightsColor.IsChecked)
        {
            Switch ($global:intShowCriticalityLevel)
            {
                0
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
                }
                1
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
                }
                2
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
                }
                3
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
                }
                4
                {
                (Get-Content $strFileHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
                }
            }
        }

        Invoke-Item $strFileHTA
    }#else if test column names exist
    else
    {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "CSV file got wrong format! File:  $CSVInput" -strType "Error" -DateStamp ))
    } #End if test column names exist 
}
else
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! $CSVInput does not exist!" -strType "Error" -DateStamp ))
}

}# End Function


#==========================================================================
# Function		: GetACLMeta
# Arguments     : Domain Controller, AD Object DN 
# Returns   	: Semi-colon separated string
# Description   : Get AD Replication Meta data LastOriginatingChange, LastOriginatingDsaInvocationID
#                  usnOriginatingChange and returns as string
#==========================================================================
Function GetACLMeta
{
    Param($DomainController,$objDN)

$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($objDN, "(name=*)", "base")
$SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
$control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
[void]$request.Controls.Add($control)
[void]$request.Attributes.Add("ntsecuritydescriptor")
[void]$request.Attributes.Add("name")

[void]$request.Attributes.Add("msDS-ReplAttributeMetaData")
$response = $LDAPConnection.SendRequest($request)

foreach ($entry  in $response.Entries)
{
    
    $index = 0
    while($index -le $entry.attributes.'msds-replattributemetadata'.count -1) 
         {
            $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
            $childMember = $childMember.replace("$($childMember[-1])","")
            If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq "nTSecurityDescriptor")
            {
                $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                $strInvocationID = $([xml]$childMember).DS_REPL_ATTR_META_DATA.uuidLastOriginatingDsaInvocationID
                $strOriginatingChange = $([xml]$childMember).DS_REPL_ATTR_META_DATA.usnOriginatingChange
            }
            $index++
         }    
}
if ($strLastChangeDate -eq $nul)
{
    $ACLdate = $(get-date "1601-01-01" -UFormat "%Y-%m-%d %H:%M:%S")
    $strInvocationID = "00000000-0000-0000-0000-000000000000"
    $strOriginatingChange = "000000"
}
else
{
$ACLdate = $(get-date $strLastChangeDate -UFormat "%Y-%m-%d %H:%M:%S")
}
  return "$ACLdate;$strInvocationID;$strOriginatingChange"
}

#==========================================================================
# Function		: Get-DefaultSD
# Arguments     : string ObjectClass
# Returns   	: 
# Description   : Create report of default Security Descriptor 
#==========================================================================
Function Get-DefaultSD
{
    Param( [String[]] $strObjectClass,[bool] $bolChangedDefSD,[bool]$bolSDDL)
$strFileDefSDHTA = $env:temp + "\"+$global:ModifiedDefSDAccessFileName+".hta" 
$strFileDefSDHTM = $env:temp + "\"+$global:ModifiedDefSDAccessFileName+".htm" 
$bolOUHeader = $true 
$bolReplMeta = $true    
$bolCompare = $false 
$intNumberofDefSDFound = 0
if($bolSDDL -eq $true)
{
        CreateDefaultSDReportHTA $global:strDomainLongName $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath
        CreateDefSDHTM $global:strDomainLongName $strFileDefSDHTM
        InitiateDefSDHTM $strFileDefSDHTM $strObjectClass
        InitiateDefSDHTM $strFileDefSDHTA $strObjectClass
}
else
{
    CreateHTM "strObjectClass" $strFileDefSDHTM					
    CreateHTA "$strObjectClass" $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath $global:strDomainDNName $global:strDC
    InitiateDefSDAccessHTM $strFileDefSDHTA $strObjectClass $bolReplMeta $false ""
    InitiateDefSDAccessHTM $strFileDefSDHTM $strObjectClass $bolReplMeta $false ""
}

$strColorTemp = 1 




$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", "Subtree")
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null
[void]$request.Attributes.Add("defaultsecuritydescriptor")
[void]$request.Attributes.Add("name")
[void]$request.Attributes.Add("msds-replattributemetadata")

$CountadObject = 0
while ($true)
{
    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

    $CountadObject = $CountadObject + $response.Entries.Count

    if($global:PageSize -gt 0) 
    {
        if ($prrc.Cookie.Length -eq 0)
        {
            #last page --> we're done
            break;
        }
        #pass the search cookie back to server in next paged request
        $pagedRqc.Cookie = $prrc.Cookie;
    }
    else
    {
        #exit the processing for non-paged search
        break;
    }
}#End While

#Load Progressbar
if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
{
    $intTot = 0
    #calculate percentage
    $intTot = $CountadObject
    if ($intTot -gt 0)
    {
    LoadProgressBar
    
    }
}

$response = $null




$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", "Subtree")
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null
[void]$request.Attributes.Add("defaultsecuritydescriptor")
[void]$request.Attributes.Add("name")
[void]$request.Attributes.Add("msds-replattributemetadata")
while ($true)
{
    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

    foreach ($entry  in $response.Entries)
    {
        #Update Progressbar
        if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
        {
            $i++
            [int]$pct = ($i/$intTot)*100
            #Update the progress bar
            while(($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20))
            {
                        Start-Sleep -Milliseconds 1
                        $cc++
            }
            if ($global:ProgressBarWindow.Window.IsInitialized -eq $true)
            {
                Update-ProgressBar "Currently scanning $i of $intTot objects" $pct 
            }  
        
        } 
        $index = 0
        while($index -le $entry.attributes.'msds-replattributemetadata'.count -1) 
            {
            $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
            $childMember = $childMember.replace("$($childMember[-1])","")
            If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq "defaultSecurityDescriptor")
            {
                $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                if ($strLastChangeDate -eq $nul)
                {
                    $strLastChangeDate = $(get-date "1601-01-01" -UFormat "%Y-%m-%d %H:%M:%S")
     
                }
                else
                {
                $strLastChangeDate = $(get-date $strLastChangeDate -UFormat "%Y-%m-%d %H:%M:%S")
                }             
            }
            $index++
            }   

        if($bolChangedDefSD -eq $true)
        {
               
            if($strVersion -gt 1)
            {
                $strObjectClassName = $entry.Attributes.name[0]
                $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity

              if($bolSDDL -eq $true)
              {
                $strSDDL = ""
                if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                {
                    $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
                }  
                #Indicate that a defaultsecuritydescriptor was found
                $intNumberofDefSDFound++
                WriteDefSDSDDLHTM $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $strObjectClassName $strVersion $strLastChangeDate $strSDDL
                Switch ($strColorTemp) 
                {

                    "1"
	                    {
	                    $strColorTemp = "2"
	                    }
                    "2"
	                    {
	                    $strColorTemp = "1"
	                    }	
                }
              }
              else
              {
                $sd = ""
                if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                {
                    $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                }
                $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])   
                #Indicate that a defaultsecuritydescriptor was found
                $intNumberofDefSDFound++  
                WriteDefSDAccessHTM $sd $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
               } 
            
            }
        }
        else
        {
            $strObjectClassName = $entry.Attributes.name[0]
            $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
            if($bolSDDL -eq $true)
            {
                $strSDDL = ""
                if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                {
                    $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
                } 
                #Indicate that a defaultsecuritydescriptor was found
                $intNumberofDefSDFound++                           
                WriteDefSDSDDLHTM $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $strObjectClassName $strVersion $strLastChangeDate $strSDDL
                Switch ($strColorTemp) 
                {

                    "1"
	                    {
	                    $strColorTemp = "2"
	                    }
                    "2"
	                    {
	                    $strColorTemp = "1"
	                    }	
                }
            }
            else
            {
                $sd = ""
                if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                {
                    $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                }
                $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])   
                #Indicate that a defaultsecuritydescriptor was found
                $intNumberofDefSDFound++
                WriteDefSDAccessHTM $sd $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
            }
        }
    }

    if($global:PageSize -gt 0) 
    {
        if ($prrc.Cookie.Length -eq 0)
        {
            #last page --> we're done
            break;
        }
        #pass the search cookie back to server in next paged request
        $pagedRqc.Cookie = $prrc.Cookie;
    }
    else
    {
        #exit the processing for non-paged search
        break;
    }
}#End While

if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
{
    $global:ProgressBarWindow.Window.Dispatcher.invoke([action]{$global:ProgressBarWindow.Window.Close()},"Normal")
    $ProgressBarWindow = $null
    Remove-Variable -Name "ProgressBarWindow" -Scope Global
} 
if($intNumberofDefSDFound  -gt 0)
{
    Invoke-Item $strFileDefSDHTA 
}
else
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "No defaultsecuritydescriptor found!" -strType "Error" -DateStamp ))
}
}

#==========================================================================
# Function		: Get-DefaultSDCompare
# Arguments     : string ObjectClass
# Returns   	: 
# Description   : Compare the default Security Descriptor 
#==========================================================================
Function Get-DefaultSDCompare
{
    Param( [String[]] $strObjectClass="*",
    [string] $strTemplate
    )
$strFileDefSDHTA = $env:temp + "\"+$global:ModifiedDefSDAccessFileName+".hta" 
$strFileDefSDHTM = $env:temp + "\"+$global:ModifiedDefSDAccessFileName+".htm" 
$bolOUHeader = $true 
$bolReplMeta = $true     
$bolCompare = $true
#Indicator that a defaultsecuritydescriptor was found
$intNumberofDefSDFound = 0

CreateHTM "strObjectClass" $strFileDefSDHTM					
CreateHTA "$strObjectClass" $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath $global:strDomainDNName $global:strDC
InitiateDefSDAccessHTM $strFileDefSDHTA $strObjectClass $bolReplMeta $true $strTemplate
InitiateDefSDAccessHTM $strFileDefSDHTM $strObjectClass $bolReplMeta $true $strTemplate

#Default color
$strColorTemp = 1 




$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", "Subtree")
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null
[void]$request.Attributes.Add("defaultsecuritydescriptor")
[void]$request.Attributes.Add("name")
[void]$request.Attributes.Add("msds-replattributemetadata")

$CountadObject = 0
while ($true)
{
    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

    $CountadObject = $CountadObject + $response.Entries.Count

    if($global:PageSize -gt 0) 
    {
        if ($prrc.Cookie.Length -eq 0)
        {
            #last page --> we're done
            break;
        }
        #pass the search cookie back to server in next paged request
        $pagedRqc.Cookie = $prrc.Cookie;
    }
    else
    {
        #exit the processing for non-paged search
        break;
    }
}#End While

#Load Progressbar
if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
{
    $intTot = 0
    #calculate percentage
    $intTot = $CountadObject
    if ($intTot -gt 0)
    {
    LoadProgressBar
    
    }
}





$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", "Subtree")
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null
[void]$request.Attributes.Add("defaultsecuritydescriptor")
[void]$request.Attributes.Add("name")
[void]$request.Attributes.Add("msds-replattributemetadata")

while ($true)
{
    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

    foreach ($entry  in $response.Entries)
    {
        $ObjectMatchResult = $false
        #Update Progressbar
        if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
        {
            $i++
            [int]$pct = ($i/$intTot)*100
            #Update the progress bar
            while(($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20))
            {
                        Start-Sleep -Milliseconds 1
                        $cc++
            }
            if ($global:ProgressBarWindow.Window.IsInitialized -eq $true)
            {
                Update-ProgressBar "Currently scanning $i of $intTot objects" $pct 
            }  
        
        }
        #Counter for Metadata
        $index = 0
        #Get metadata for defaultSecurityDescriptor
        while($index -le $entry.attributes.'msds-replattributemetadata'.count -1) 
        {
            $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
            $childMember = $childMember.replace("$($childMember[-1])","")
            If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq "defaultSecurityDescriptor")
            {
                $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                if ($strLastChangeDate -eq $nul)
                {
                    $strLastChangeDate = $(get-date "1601-01-01" -UFormat "%Y-%m-%d %H:%M:%S")
     
                }
                else
                {
                    $strLastChangeDate = $(get-date $strLastChangeDate -UFormat "%Y-%m-%d %H:%M:%S")
                }             
            }
            $index++
        }
        #Get object name
        $strObjectClassName = $entry.Attributes.name[0]


        #Make sure strSDDL is empty
        $strSDDL = ""
        if($null -ne $entry.Attributes.defaultsecuritydescriptor)
        {
            $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
        }  
        $index = 0 
        #Enumerate template file
        $ObjectMatchResult = $false  
        while($index -le $global:csvdefSDTemplate.count -1) 
	    {
            $strNamecol = $global:csvdefSDTemplate[$index].Name
            #Check for matching object names
		    if ($strObjectClassName -eq $strNamecol )
		    {
                $ObjectMatchResult = $true    
                $strSDDLcol = $global:csvdefSDTemplate[$index].SDDL
                #Replace any <ROOT-DOAMIN> strngs with Forest Root Domain SID
                if($strSDDLcol.Contains("<ROOT-DOMAIN>"))
                {
                    if($global:ForestRootDomainSID -gt "")
                    {
                        $strSDDLcol  = $strSDDLcol.Replace("<ROOT-DOMAIN>",$global:ForestRootDomainSID)
                    }
                }
                #Compare SDDL
                if($strSDDL -eq $strSDDLcol)
                {
                    $sd = ""
                    #Create ad security object
                    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                    {
                        $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                    }
                    $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) 
                    #Count ACE for applying header on fist
                    $intACEcount = 0
                    foreach($ObjectDefSD in $sd)
                    {
                        $strNTAccount = $ObjectDefSD.IdentityReference.toString()
	                    If ($strNTAccount.contains("S-1-"))
	                    {
	                     $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	                    }
                        $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights=$ObjectDefSD.ActiveDirectoryRights;InheritanceType=$ObjectDefSD.InheritanceType;ObjectType=$ObjectDefSD.ObjectType;`
                        InheritedObjectType=$ObjectDefSD.InheritedObjectType;ObjectFlags=$ObjectDefSD.ObjectFlags;AccessControlType=$ObjectDefSD.AccessControlType;IdentityReference=$strNTAccount;IsInherited=$ObjectDefSD.IsInherited;`
                        InheritanceFlags=$ObjectDefSD.InheritanceFlags;PropagationFlags=$ObjectDefSD.PropagationFlags;Color="Match"}

                        #Matching color "green"
                        $strColorTemp = 4
                        #If first ACE add header
                        if ($intACEcount -eq 0)
				 	    {
                            #Indicate that a defaultsecuritydescriptor was found
                            $intNumberofDefSDFound++
                            $bolOUHeader = $true
                            WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                        }
                        else
                        {
                            $bolOUHeader = $false
                            WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                        }
                        #Count ACE to not ad a header
                        $intACEcount++
                    }
                    $newObjectDefSD = $null
                    $sd = $null
                    $sec = $null
                }
                else
                {
                    $sd = ""
                    #Create ad security object
                    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    if($null -ne $entry.Attributes.defaultsecuritydescriptor)
                    {
                        $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                    }
                    $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) 
                    #Count ACE for applying header on fist
                    $intACEcount = 0
                    #Comare DefaultSecurityDesriptor in schema with template looking for matching and new ACE's
                    foreach($ObjectDefSD in $sd)
                    {
                        #Check if matchin ACE exits, FALSE until found 
                        $SDCompareResult = $false

                        $strNTAccount = $ObjectDefSD.IdentityReference.toString()
	                    If ($strNTAccount.contains("S-1-"))
	                    {
	                     $strNTAccount = ConvertSidToName -server $global:strDomainLongName -Sid $strNTAccount

	                    }

                        $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights=$ObjectDefSD.ActiveDirectoryRights;InheritanceType=$ObjectDefSD.InheritanceType;ObjectType=$ObjectDefSD.ObjectType;`
                        InheritedObjectType=$ObjectDefSD.InheritedObjectType;ObjectFlags=$ObjectDefSD.ObjectFlags;AccessControlType=$ObjectDefSD.AccessControlType;IdentityReference=$strNTAccount;IsInherited=$ObjectDefSD.IsInherited;`
                        InheritanceFlags=$ObjectDefSD.InheritanceFlags;PropagationFlags=$ObjectDefSD.PropagationFlags;Color="New"}

                        $sdFile = ""
                        #Create ad security object
                        $secFile = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        if($null -ne $strSDDLcol)
                        {
                            $secFile.SetSecurityDescriptorSddlForm($strSDDLcol)
                        }
                        $sdFile = $secFile.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) 
                        foreach($ObjectDefSDFile in $sdFile)
                        {
                                If (($newObjectDefSD.IdentityReference -eq $ObjectDefSDFile.IdentityReference) -and ($newObjectDefSD.ActiveDirectoryRights -eq $ObjectDefSDFile.ActiveDirectoryRights) -and ($newObjectDefSD.AccessControlType -eq $ObjectDefSDFile.AccessControlType) -and ($newObjectDefSD.ObjectType -eq $ObjectDefSDFile.ObjectType) -and ($newObjectDefSD.InheritanceType -eq $ObjectDefSDFile.InheritanceType) -and ($newObjectDefSD.InheritedObjectType -eq $ObjectDefSDFile.InheritedObjectType))
		 		                {
					                $SDCompareResult = $true
		 		                }
                        }
                        if ($SDCompareResult)
                        {
                            #Change from New to Match
                            $newObjectDefSD.Color = "Match"
                            #Match color "Green"
                            $strColorTemp = 4
                            #If first ACE add header
                            if ($intACEcount -eq 0)
				 	        {
                                #Indicate that a defaultsecuritydescriptor was found
                                $intNumberofDefSDFound++
                                $bolOUHeader = $true
                                WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            else
                            {
                                $bolOUHeader = $false
                                WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            #Count ACE to not ad a header
                            $intACEcount++
                        }
                        else
                        {
                            #New color "Yellow"
                            $strColorTemp = 5
                            #If first ACE add header
                            if ($intACEcount -eq 0)
				 	        {
                                #Indicate that a defaultsecuritydescriptor was found
                                $intNumberofDefSDFound++
                                $bolOUHeader = $true
                                WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            else
                            {
                                $bolOUHeader = $false
                                WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            #Count ACE to not ad a header
                            $intACEcount++        
                        }
                    }
                    $newObjectDefSD = $null
                    #Comare DefaultSecurityDesriptor in template with schema looking for missing ACE's
                    $secFile = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    if($null -ne $strSDDLcol)
                    {
                        $secFile.SetSecurityDescriptorSddlForm($strSDDLcol)
                    }
                    $sdFile = $secFile.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) 
                    foreach($ObjectDefSDFromFile in $sdFile)
                    {
                        #Check if matchin ACE missing, TRUE until found 
                        $SDMissingResult = $true

                        $ObjectDefSDFile = New-Object PSObject -Property @{ActiveDirectoryRights=$ObjectDefSDFromFile.ActiveDirectoryRights;InheritanceType=$ObjectDefSDFromFile.InheritanceType;ObjectType=$ObjectDefSDFromFile.ObjectType;`
                        InheritedObjectType=$ObjectDefSDFromFile.InheritedObjectType;ObjectFlags=$ObjectDefSDFromFile.ObjectFlags;AccessControlType=$ObjectDefSDFromFile.AccessControlType;IdentityReference=$ObjectDefSDFromFile.IdentityReference;IsInherited=$ObjectDefSDFromFile.IsInherited;`
                        InheritanceFlags=$ObjectDefSDFromFile.InheritanceFlags;PropagationFlags=$ObjectDefSDFromFile.PropagationFlags;Color="Missing"}

                        foreach($ObjectDefSD in $sd)
                        {

                            If (($ObjectDefSD.IdentityReference -eq $ObjectDefSDFile.IdentityReference) -and ($ObjectDefSD.ActiveDirectoryRights -eq $ObjectDefSDFile.ActiveDirectoryRights) -and ($ObjectDefSD.AccessControlType -eq $ObjectDefSDFile.AccessControlType) -and ($ObjectDefSD.ObjectType -eq $ObjectDefSDFile.ObjectType) -and ($ObjectDefSD.InheritanceType -eq $ObjectDefSDFile.InheritanceType) -and ($ObjectDefSD.InheritedObjectType -eq $ObjectDefSDFile.InheritedObjectType))
		 		            {
					            $SDMissingResult = $false
		 		            }
                        }
                        if ($SDMissingResult)
                        {
                            #Missig´ng color "Red"
                            $strColorTemp = 3
                            #If first ACE add header
                            if ($intACEcount -eq 0)
				 	        {
                                #Indicate that a defaultsecuritydescriptor was found
                                $intNumberofDefSDFound++
                                $bolOUHeader = $true
                                WriteDefSDAccessHTM $ObjectDefSDFile $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            else
                            {
                                $bolOUHeader = $false
                                WriteDefSDAccessHTM $ObjectDefSDFile $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                            }
                            #Count ACE to not ad a header
                            $intACEcount++
                        }
                    }
                    $secFile = $null
                    $sdFile = $null
                    $ObjectDefSDFile = $null
                    $ObjectDefSDFromFile = $null
                    $ObjectDefSD = $null
                    $sd = $null
                    $sec = $null
                }#End matchin SDDL
            }#End matching object name
            $index++
        }#End while 
        #Check if the schema object does not exist in template
        if($ObjectMatchResult -eq $false)
        {
            $sd = ""
            #Create ad security object
            $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
            if($null -ne $entry.Attributes.defaultsecuritydescriptor)
            {
                $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
            }
            $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) 
            #Count ACE for applying header on fist
            $intACEcount = 0
            foreach($ObjectDefSD in $sd)
            {

                $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights=$ObjectDefSD.ActiveDirectoryRights;InheritanceType=$ObjectDefSD.InheritanceType;ObjectType=$ObjectDefSD.ObjectType;`
                InheritedObjectType=$ObjectDefSD.InheritedObjectType;ObjectFlags=$ObjectDefSD.ObjectFlags;AccessControlType=$ObjectDefSD.AccessControlType;IdentityReference=$ObjectDefSD.IdentityReference;IsInherited=$ObjectDefSD.IsInherited;`
                InheritanceFlags=$ObjectDefSD.InheritanceFlags;PropagationFlags=$ObjectDefSD.PropagationFlags;Color="Missing in file"}

                #Matching color "green"
                $strColorTemp = 5
                #If first ACE add header
                if ($intACEcount -eq 0)
			    {
                    $bolOUHeader = $true
                    #Indicate that a defaultsecuritydescriptor was found
                    $intNumberofDefSDFound++
                    WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                }
                else
                {
                    $bolOUHeader = $false
                    WriteDefSDAccessHTM $newObjectDefSD $strObjectClassName $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $bolOUHeader $bolReplMeta $strVersion $strLastChangeDate $chkBoxEffectiveRightsColor.IsChecked $bolCompare
                }
                #Count ACE to not ad a header
                $intACEcount++
            }
            $newObjectDefSD = $null
            $sd = $null    
        }

    }#End foreach
    if($global:PageSize -gt 0) 
    {
        if ($prrc.Cookie.Length -eq 0)
        {
            #last page --> we're done
            break;
        }
        #pass the search cookie back to server in next paged request
        $pagedRqc.Cookie = $prrc.Cookie;
    }
    else
    {
        #exit the processing for non-paged search
        break;
    }
}#End While
if (($PSVersionTable.PSVersion -ne "2.0") -and ($global:bolProgressBar))
{
    $global:ProgressBarWindow.Window.Dispatcher.invoke([action]{$global:ProgressBarWindow.Window.Close()},"Normal")
    $ProgressBarWindow = $null
    Remove-Variable -Name "ProgressBarWindow" -Scope Global
} 

if($intNumberofDefSDFound  -gt 0)
{
    Invoke-Item $strFileDefSDHTA 
}
else
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "No defaultsecuritydescriptor found!" -strType "Error" -DateStamp ))
}
}
#==========================================================================
# Function		: Write-DefaultSDCSV
# Arguments     : string ObjectClass
# Returns   	: 
# Description   : Write the default Security Descriptor to a CSV
#==========================================================================
Function Write-DefaultSDCSV
{
    Param( [string] $fileout,
    $strObjectClass="*")

#Number of columns in CSV import
$strCSVHeaderDefsd = @"
"Name","distinguishedName","Version","ModifiedDate","SDDL"
"@


If ((Test-Path $fileout) -eq $true)
{
    Remove-Item $fileout
}

$strCSVHeaderDefsd | Out-File -FilePath $fileout




$LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
$LDAPConnection.SessionOptions.ReferralChasing = "None"
$request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", "Subtree")
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null
[void]$request.Attributes.Add("defaultsecuritydescriptor")
[void]$request.Attributes.Add("name")
[void]$request.Attributes.Add("msds-replattributemetadata")
while ($true)
{
    $response = $LdapConnection.SendRequest($request, (new-object System.Timespan(0,0,$global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
    #for paged search, the response for paged search result control - we will need a cookie from result later
    if($global:PageSize -gt 0) {
        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
        if ($response.Controls.Length -gt 0)
        {
            foreach ($ctrl in $response.Controls)
            {
                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                {
                    $prrc = $ctrl;
                    break;
                }
            }
        }
        if($null -eq $prrc) {
            #server was unable to process paged search
            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
        }
    }
    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

    foreach ($entry  in $response.Entries)
    {
        $index = 0
        while($index -le $entry.attributes.'msds-replattributemetadata'.count -1) 
        {
            $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
            $childMember = $childMember.replace("$($childMember[-1])","")
            If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq "defaultSecurityDescriptor")
            {
                $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                if ($strLastChangeDate -eq $nul)
                {
                    $strLastChangeDate = $(get-date "1601-01-01" -UFormat "%Y-%m-%d %H:%M:%S")
     
                }
                else
                {
                $strLastChangeDate = $(get-date $strLastChangeDate -UFormat "%Y-%m-%d %H:%M:%S")
                }             
            }
            $index++
        }   

        $strSDDL = ""
        if($null -ne $entry.Attributes.defaultsecuritydescriptor)
        {
            $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
        }            
        $strName = $entry.Attributes.name[0]
        $strDistinguishedName = $entry.distinguishedname

        #Write to file
        [char]34+$strName+[char]34+","+[char]34+`
        $strDistinguishedName+[char]34+","+[char]34+`
        $strVersion+[char]34+","+[char]34+`
        $strLastChangeDate+[char]34+","+[char]34+`
        $strSDDL+[char]34 | Out-File -Append -FilePath $fileout 

    
    }

    if($global:PageSize -gt 0) 
    {
        if ($prrc.Cookie.Length -eq 0)
        {
            #last page --> we're done
            break;
        }
        #pass the search cookie back to server in next paged request
        $pagedRqc.Cookie = $prrc.Cookie;
    }
    else
    {
        #exit the processing for non-paged search
        break;
    }
}#End While
$global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $fileout" -strType "Warning" -DateStamp ))

}
#==========================================================================
# Function		: GetEffectiveRightSP
# Arguments     : 
# Returns   	: 
# Description   : Rs
#==========================================================================
Function GetEffectiveRightSP
{
    param([string] $strPrincipal,
[string] $strDomainDistinguishedName
)
$global:strEffectiveRightSP = ""
$global:strEffectiveRightAccount = ""
$global:strSPNobjectClass = ""
$global:strPrincipalDN = ""
$strPrinName = ""

if ($global:strPrinDomDir -eq 2)
{
    &{#Try

    $Script:CredsExt = $host.ui.PromptForCredential("Need credentials", "Please enter your user name and password.", "", "$global:strPrinDomFlat")
    $ADACLGui.Window.Activate()
    }
    Trap [SystemException]
    {
    continue
    }
    $h =  (get-process -id $global:myPID).MainWindowHandle # just one notepad must be opened!
    [SFW]::SetForegroundWindow($h)
    if($null -ne $Script:CredsExt.UserName)
    {
        if (TestCreds $CredsExt)
        {    
            $global:strPinDomDC = $(GetDomainController $global:strDomainPrinDNName $true $Script:CredsExt)
            $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $true $Script:CredsExt)
         }
         else
         {
             $global:observableCollection.Insert(0,(LogMessage -strMessage "Bad user name or password!" -strType "Error" -DateStamp ))
             $lblEffectiveSelUser.Content = ""
         }
     }
     else
     {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Faild to insert credentials!" -strType "Error" -DateStamp ))

     }
}
else
{
    if ( $global:strDomainPrinDNName -eq $global:strDomainDNName )
    {
        $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
        $global:strPinDomDC = $global:strDC
        $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $false)
    }
    else
    {
        $global:strPinDomDC = $(GetDomainController $global:strDomainPrinDNName $false)
        $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $false)
    }
}
if ($global:strPrincipalDN -eq "")
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not find $strPrincipal!" -strType "Error" -DateStamp ))
    $lblEffectiveSelUser.Content = ""
}
else
{
    $global:strEffectiveRightAccount = $strPrincipal
    $global:observableCollection.Insert(0,(LogMessage -strMessage "Found security principal" -strType "Info" -DateStamp ))
    if ($global:strPrinDomDir -eq 2)
    {
        [System.Collections.ArrayList] $global:tokens = @(GetTokenGroups $global:strPinDomDC $global:strPrincipalDN $true $Script:CredsExt)
        
        $objADPrinipal = new-object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN",$Script:CredsExt.UserName,$Script:CredsExt.GetNetworkCredential().Password)

        
        $objADPrinipal.psbase.RefreshCache("msDS-PrincipalName")
        $strPrinName = $($objADPrinipal.psbase.Properties.Item("msDS-PrincipalName"))
        $global:strSPNobjectClass = $($objADPrinipal.psbase.Properties.Item("objectClass"))[$($objADPrinipal.psbase.Properties.Item("objectClass")).count-1]
        if (($strPrinName -eq "") -or ($null -eq $strPrinName))
        {
            $strPrinName = "$global:strPrinDomFlat\$($objADPrinipal.psbase.Properties.Item("samAccountName"))"
        }
        $global:strEffectiveRightSP = $strPrinName
        $lblEffectiveSelUser.Content = $strPrinName    
    }
    else
    {
        [System.Collections.ArrayList] $global:tokens = @(GetTokenGroups $global:strPinDomDC $global:strPrincipalDN $false)
        

        $objADPrinipal = new-object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN")

                    
        $objADPrinipal.psbase.RefreshCache("msDS-PrincipalName")
        $strPrinName = $($objADPrinipal.psbase.Properties.Item("msDS-PrincipalName"))
        $global:strSPNobjectClass = $($objADPrinipal.psbase.Properties.Item("objectClass"))[$($objADPrinipal.psbase.Properties.Item("objectClass")).count-1]
        if (($strPrinName -eq "") -or ($null -eq $strPrinName))
        {
            $strPrinName = "$global:strPrinDomFlat\$($objADPrinipal.psbase.Properties.Item("samAccountName"))"
        }
        $global:strEffectiveRightSP = $strPrinName
        $lblEffectiveSelUser.Content = $strPrinName
    }

}

}



function LoadProgressBar
{
$global:ProgressBarWindow = [hashtable]::Synchronized(@{})
$newRunspace =[runspacefactory]::CreateRunspace()
$newRunspace.ApartmentState = "STA"
$newRunspace.ThreadOptions = "ReuseThread"          
$newRunspace.Open()
$newRunspace.SessionStateProxy.SetVariable("global:ProgressBarWindow",$global:ProgressBarWindow)          
$psCmd = [PowerShell]::Create().AddScript({   
    [xml]$xamlProgressBar = @"
<Window x:Class="WpfApplication1.StatusBar"
         xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Scanning..." WindowStartupLocation = "CenterScreen"
        Width = "350" Height = "150" ShowInTaskbar = "True" ResizeMode="NoResize" WindowStyle="ToolWindow" Opacity="0.9" Background="#FF165081" >
    <Grid>
        <StackPanel >
            <Label x:Name="lblProgressBarInfo" Foreground="white" Content="Currently scanning 0 of 0 objects" HorizontalAlignment="Center" Margin="10,20,0,0"  FontWeight="Bold" FontSize="14"/>
            <ProgressBar  x:Name = "ProgressBar" HorizontalAlignment="Left" Height="23" Margin="10,0,0,0" VerticalAlignment="Top" Width="320"   >
                <ProgressBar.Foreground>
                    <LinearGradientBrush EndPoint="1,0.5" StartPoint="0,0.5">
                        <GradientStop Color="#FF237026"/>
                        <GradientStop Color="#FF0BF815" Offset="1"/>
                        <GradientStop Color="#FF0BF815" Offset="1"/>
                    </LinearGradientBrush>
                </ProgressBar.Foreground>
            </ProgressBar>
        </StackPanel>

    </Grid>
</Window>
"@
 
$xamlProgressBar.Window.RemoveAttribute("x:Class")  
    $reader=(New-Object System.Xml.XmlNodeReader $xamlProgressBar)
    $global:ProgressBarWindow.Window=[Windows.Markup.XamlReader]::Load( $reader )
    $global:ProgressBarWindow.lblProgressBarInfo = $global:ProgressBarWindow.window.FindName("lblProgressBarInfo")
    $global:ProgressBarWindow.ProgressBar = $global:ProgressBarWindow.window.FindName("ProgressBar")
    $global:ProgressBarWindow.ProgressBar.Value = 0
    $global:ProgressBarWindow.Window.ShowDialog() | Out-Null
    $global:ProgressBarWindow.Error = $Error
})
$psCmd.Runspace = $newRunspace

[void]$psCmd.BeginInvoke()



}
Function Update-ProgressBar
{
Param ($txtlabel,$valProgress)

        &{#Try
           $global:ProgressBarWindow.ProgressBar.Dispatcher.invoke([action]{ $global:ProgressBarWindow.lblProgressBarInfo.Content = $txtlabel;$global:ProgressBarWindow.ProgressBar.Value = $valProgress},"Normal")
           
        }
        Trap [SystemException]
        {
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Progressbar Failed!" -strType "Error" -DateStamp ))
           
        }

}




#Number of columns in CSV import
$strCSVHeader = @"
"OU","ObjectClass","IdentityReference","PrincipalName","ActiveDirectoryRights","InheritanceType","ObjectType","InheritedObjectType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags","SDDate","InvocationID","OrgUSN","LegendText"
"@

$global:myPID = $PID
$global:csvHistACLs = New-Object System.Collections.ArrayList
$CurrentFSPath = split-path -parent $MyInvocation.MyCommand.Path
$strLastCacheGuidsDom = ""
$sd = ""
$global:intObjeComputer = 0

$null = Add-Type -AssemblyName System.DirectoryServices.Protocols
if($base) 
{
    $global:bolProgressBar = $false
    #Connect to Custom Naming Context
    $global:bolCMD = $true
 
    if ($base.Length -gt 0)
    {
        $strNamingContextDN = $base
        if($Server -eq "")
        {
            if($Port -eq "")
            {                    
                $global:strDC = ""
            }
            else
            {
                $global:strDC = "localhost:" +$Port
            }
        }
        else
        {
            if($Port -eq "")
            {                    
                $global:strDC = $Server
            }
            else
            {
                $global:strDC = $Server + ":" + $Port
            }
        }
        $global:bolLDAPConnection = $false
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest("", "(objectClass=*)", "base")
        if($global:bolShowDeleted)
        {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
            [void]$request.Controls.Add((New-Object "System.DirectoryServices.Protocols.DirectoryControl" -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID",$null,$false,$true ))
        }
        [void]$request.Attributes.Add("dnshostname")
        [void]$request.Attributes.Add("supportedcapabilities")
        [void]$request.Attributes.Add("namingcontexts")
        [void]$request.Attributes.Add("defaultnamingcontext")
        [void]$request.Attributes.Add("schemanamingcontext")
        [void]$request.Attributes.Add("configurationnamingcontext")
        [void]$request.Attributes.Add("rootdomainnamingcontext")
        [void]$request.Attributes.Add("isGlobalCatalogReady")                        
    
	    try
	    {
            $response = $LDAPConnection.SendRequest($request)
            $global:bolLDAPConnection = $true

	    }
	    catch
	    {
		    $global:bolLDAPConnection = $false
            Write-host "Failed! Domain does not exist or can not be connected" -ForegroundColor red
	    }
        if($global:bolLDAPConnection -eq $true)
        {
            $strPrimaryCapability= $response.Entries[0].attributes.supportedcapabilities[0]
            Switch ($strPrimaryCapability)
            {
                "1.2.840.113556.1.4.1851"
                {
                    $global:DSType = "AD LDS"
                    $global:bolADDSType = $false
                    $global:strDomainDNName = $response.Entries[0].Attributes.namingcontexts[-1]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                    if($Port -eq "")
                    {                    
                        if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                        {
                            $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                        }
                    }
                    else
                    {
                        if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                        {
                            $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" + $Port     
                        }
                    }

                }
                "1.2.840.113556.1.4.800"
                {
                    $global:DSType = "AD DS"
                    $global:bolADDSType = $true
                    $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]

                    if($Port -eq "")
                    {                    
                        if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                        {
                            $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                        }
                    }
                    else
                    {
                        if(Test-ResolveDNS $response.Entries[0].Attributes.dnshostname[0])
                        {
                            $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" + $Port
                        }
                                    
                    }
                    $global:strDomainPrinDNName = $global:strDomainDNName
                    $global:strDomainShortName = GetDomainShortName $global:strDomainDNName $global:ConfigDN
                    $global:strRootDomainShortName = GetDomainShortName $global:ForestRootDomainDN $global:ConfigDN
                    $lblSelectPrincipalDom.Content = $global:strDomainShortName+":"
                }
                default
                {
                    $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]

                    if($Port -eq "")
                    {                    
                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                    }
                    else
                    {
                        $global:strDC = $response.Entries[0].Attributes.dnshostname[0] +":" + $Port
                    }
                }
            }  
            if($strNamingContextDN -eq "")
            {
                $strNamingContextDN = $global:strDomainDNName
            }
            If(CheckDNExist $strNamingContextDN $global:strDC)
            {
                $NCSelect = $true
            }
            else
            {
                Write-Output "Failed to connect to $base"
                $global:bolConnected = $false
            }
   
        }#bolLDAPConnection
    } # End If D lenght
    else
    {
        $global:bolConnected = $false  
    }

    If ($NCSelect -eq $true)  
    {
	    If (!($strLastCacheGuidsDom -eq $global:strDomainDNName))
	    {
	        $global:dicRightsGuids = @{"Seed" = "xxx"}
	        CacheRightsGuids 
	        $strLastCacheGuidsDom = $global:strDomainDNName
        
        
	    }
        #Check Directory Service type
        $global:DSType = ""
        $global:bolADDSType = $false
        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection($global:strDC, $global:CREDS)
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest("", "(objectClass=*)", "base")
        $response = $LDAPConnection.SendRequest($request)
        $strPrimaryCapability= $response.Entries[0].attributes.supportedcapabilities[0]
        Switch ($strPrimaryCapability)
        {
            "1.2.840.113556.1.4.1851"
            {
                $global:DSType = "AD LDS"
            }
            "1.2.840.113556.1.4.800"
            {
                $global:DSType = "AD DS"
                $global:bolADDSType = $true
            }
            default
            {
                $global:DSType = "Unknown"
            }
        }    

        $LDAPConnection = New-Object System.DirectoryServices.Protocols.LDAPConnection("")
        $LDAPConnection.SessionOptions.ReferralChasing = "None"
        $request = New-Object System.directoryServices.Protocols.SearchRequest($base, "(objectClass=*)", "base")
        [void]$request.Attributes.Add("name")               
        $response = $LDAPConnection.SendRequest($request)

        #Set search base as the name of the output file
        $Node = fixfilename $response.Entries[0].Attributes.name[0]
        
        #Get current date
        $date= get-date -uformat %Y%m%d_%H%M%S

        
        #Get all LDAP objects to read ACL's on
        $allSubOU = GetAllChildNodes $base $Scope $Filter


        #If more than 0 objects returned send it to Get-Perm to read ACL's
        if($allSubOU.count -gt 0)
        {
            #Set the path for the CSV file name
            if($OutputFolder -gt "")
            {
                #Check if foler exist if not use current folder
                if(Test-Path $OutputFolder)
                {
                    $strFileCSV = $OutputFolder + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date + ".csv" 
                }
                else
                {
                    Write-host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                    $strFileCSV = $CurrentFSPath + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date + ".csv" 
                }
            }
            else
            {
                $strFileCSV = $CurrentFSPath + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date + ".csv" 
            }
            # Check if HTML switch is selected , creates a HTML file
            if($HTML)
            {			
                $strFileHTA = $env:temp + "\"+$global:ACLHTMLFileName+".hta" 
                #Set the path for the HTM file name
                if($OutputFolder -gt "")
                {
                    #Check if foler exist if not use current folder
                    if(Test-Path $OutputFolder)
                    {
                        $strFileHTM = $OutputFolder + "\"+"$global:strDomainShortName-$Node-$global:SessionID"+".htm" 
                    }
                    else
                    {
                        Write-host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                        $strFileHTM = $CurrentFSPath + "\"+"$global:strDomainShortName-$Node-$global:SessionID"+".htm" 
                    }
                }
                else
                {
                    $strFileHTM = $CurrentFSPath + "\"+"$global:strDomainShortName-$Node-$global:SessionID"+".htm"  
                }
                CreateHTA "$global:strDomainShortName-$Node" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                CreateHTM "$global:strDomainShortName-$Node" $strFileHTM	
                InitiateHTM $strFileHTA $Node $Base $false $false $false $false $false $false $false "" $false $false $false
                InitiateHTM $strFileHTM $Node $Base $false $false $false $false $false $false $false "" $false $false $false
                if($Show)
                {
                    $rsl = Get-Perm $allSubOU $global:strDomainShortName $false $false $false $false $false $false $false $false $false $false $false $true "HTM"
                }
                else
                {
                    $rsl = Get-Perm $allSubOU $global:strDomainShortName $false $false $false $false $false $false $false $false $false $false $false $false "HTM"
                }

                Write-host "Report saved in $strFileHTM" -ForegroundColor Yellow
            }
            else 
            {
                if($EXCEL)
                {	
                    $ExcelModuleExist = $true
                    if(!$(get-module ImportExcel))
                    { 
                        Write-Host "Checking for ImportExcel PowerShell Module..." 
                        if(!$(get-module -ListAvailable | Where-Object name -eq "ImportExcel"))
                        {
                            write-host "You need to install the PowerShell module ImportExcel found in the PSGallery" -ForegroundColor red    
                            $ExcelModuleExist = $false 
                        }
                        else
                        {
                            Import-Module ImportExcel
                            $ExcelModuleExist = $true
                        }

                    }
                    if($ExcelModuleExist)
                    {                		
                        #Set the path for the HTM file name
                        if($OutputFolder -gt "")
                        {
                            #Check if foler exist if not use current folder
                            if(Test-Path $OutputFolder)
                            {
                                $strFileEXCEL = $OutputFolder + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".xlsx" 
                            }
                            else
                            {
                                Write-host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                $strFileEXCEL = $CurrentFSPath + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".xlsx" 
                            }
                        }
                        else
                        {
                            $strFileEXCEL = $CurrentFSPath + "\" +$Node + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".xlsx" 
                        }

                        $rsl = Get-Perm $allSubOU $global:strDomainShortName $false $false $false $false $false $false $false $false $false $false $false $false "EXCEL"

                    }
                }
                else # Create CSV file
                {
                    $rsl = Get-Perm $allSubOU $global:strDomainShortName $false $false $false $false $true $true $false $false $false $false $false $false "HTM"
                }
            }
        }
        else
        {
                Write-host "No objects returned! Does your filter relfect the objects you are searching for?" -ForegroundColor red
        }
    }#End if $NCSelect
}# End if D
else # Else GUI will open
{
    if([System.Windows.SystemParameters]::PrimaryScreenHeight -lt $ADACLGui.Window.Height)
    {
    $ADACLGui.Window.Height = [System.Windows.SystemParameters]::PrimaryScreenHeight * 0.94
    }
    $global:bolCMD = $false
    [void]$ADACLGui.Window.ShowDialog()
}