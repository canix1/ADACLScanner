<#
.Synopsis
    ADACLScan.ps1

    AUTHOR: Robin Granberg (robin.granberg@protonmail.com)

    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
    FITNESS FOR A PARTICULAR PURPOSE.

.DESCRIPTION
    A tool with GUI or command linte used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory.
    See https://github.com/canix1/ADACLScanner

.EXAMPLE
    .\ADACLScan.ps1

    Start in GUI mode.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM"

    Returns the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base rootdse

    Returns the ACL of the domain root.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Credentials $CREDS -Server 10.0.0.20

    Returns the permissions of the object CORP using credentials on Domain Controller 10.0.0.20.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Output HTML

    Create a HTML file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Output EXCEL

    Create a Excel file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Output HTML -Show

    Opens the HTML (HTA) file with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Output HTML -Show -SDDate

    Opens the HTML (HTA) file with the permissions of the object CORP including the modified date of the security descriptor.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -OutputFolder C:\Temp

    Create a CSV file in the folder C:\Temp, with the permissions of the object CORP.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree

    Create a CSV file with the permissions of the object CORP and all child objects of type OrganizationalUnit.

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -EffectiveRightsPrincipal joe

    Create a CSV file with the effective permissions of all the objects in the path for the user "joe".

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)"

    Create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)" -Server DC1

    Targeted search against server "DC1" that will create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.EXAMPLE
    .\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -Scope subtree -Filter "(objectClass=user)" -Server DC1 -Port 389

    Targeted search against server "DC1" on port 389 that will create a CSV file with the permissions of all the objects in the path and below that matches the filter (objectClass=user).

.EXAMPLE
    .\ADACLScan.ps1 -Base "ou=mig,dc=contoso,dc=com" -Output CSVTEMPLATE

    This will result in a CSV-file with a format adapted for comparing.

.EXAMPLE
    .\ADACLScan.ps1 -Base "ou=mig,dc=contoso,dc=com" -Template C:\Scripts\mig_CONTOSO_adAclOutput20220722_182746.csv

    The following command will result in an output with the possibility to see the state of each ACE on the object compared with the CSV-template.

.EXAMPLE
    .\ADACLScan.ps1 -Base "ou=mig,dc=contoso,dc=com" -SDDL

    The following command will result in an output with security descriptor in SDDL format.

.OUTPUTS
    The output is an CSV,HTML or EXCEL report.

.LINK
    https://github.com/canix1/ADACLScanner

.NOTES

**Version: 9.0**

**30 September, 2025**

**Features**
* Filter on Properties such as attribute,property lists or extended rights
* Replace the LDAP Connection code
* Added autehntication using UI

**Fixes**
* Fixed type in URL to templates
* Repaired authentication from non-domain joined machines


#>
Param
(
    # DistinguishedName to start your search at or type RootDSE for the domain root. Will be included in the result if your filter matches the object.
    [Alias('b')]
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Base = '',

    # Targets allows you to use a predefined search for specific objects
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        Position = 0,
        ParameterSetName = 'Default')]
    [ValidateSet('RiskyTemplates')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Targets,

    # Filter. Specify your custom filter. Default is OrganizationalUnit.
    [Alias('filter')]
    [Parameter(Mandatory = $false,
        Position = 1,
        ParameterSetName = 'Default')]
    [validatescript({ $_ -like '(*=*)' })]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $LDAPFilter,

    # Scope. Set your scope. Default is base.
    [Parameter(Mandatory = $false,
        Position = 2,
        ParameterSetName = 'Default')]
    [ValidateSet('base', 'onelevel', 'subtree')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Scope = 'base',

    # Server. Specify your specific server to target your search at.
    [Parameter(Mandatory = $false,
        Position = 3,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Server,

    # Port. Specify your custom port.
    [Parameter(Mandatory = $false,
        Position = 4,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Port,

    # Specify the samAccountName of a security principal to check for its effective permissions
    [Parameter(Mandatory = $false,
        Position = 5,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $EffectiveRightsPrincipal,

    # Generates a HTML report, default is a CSV.
    [Parameter(Mandatory = $false,
        Position = 6,
        ParameterSetName = 'Default')]
    [ValidateSet('CSV', 'CSVTEMPLATE', 'HTML', 'EXCEL')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Output = '',

    # Output folder path for where results are written.
    [Parameter(Mandatory = $false,
        Position = 7,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $OutputFolder,

    # Template to compare with.
    # This parameter will allow you compare the current state of a security descriptor with a previos created tempate.
    [Parameter(Mandatory = $false,
        Position = 8,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Template,

    # Filter what to return when comparing with a template.
    # This parameter will allow you to filter the out put on "ALL", "MATCH", "MISSING","NEW"
    # Example 1. -Returns "ALL"
    # Example 2. -Returns "MATCH"
    # Example 3. -Returns "MISSING"
    # Example 4. -Returns "NEW"
    [Parameter(Mandatory = $false,
        Position = 8,
        ParameterSetName = 'Default')]
    [ValidateSet('ALL', 'MATCH', 'MISSING', 'NEW')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $TemplateFilter = 'ALL',

    # User ExcelFile to defined your own path for the excel output
    # This parameter will allow you to type the excel file path.
    # Example 1. -ExcelFile "C:\Temp\ExcelOutput.xlsx"
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $ExcelFile = '',

    # Filter on Criticality.
    # This parameter will filter the result based on a defined criticality level
    [Alias('c')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateSet('Critical', 'Warning', 'Medium', 'Low', 'Info')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Criticality = '',

    # Show color of criticality
    # This parameter will add colors to the report if you selected HTML or EXCEL using the -OUTPUT parameter
    [Alias('color')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $ShowCriticalityColor,

    # Skip default permissions
    # This parameter will skip permissions that match the permissions defined in the schema partition for the object
    [Alias('sd')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $SkipDefaults,

    # Skip protected permissions
    # This parameter will skip permissions that match the permissions set when selecting "protect object from accidental deletaion"
    [Alias('sp')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $SkipProtected,

    # Skip Built-in security principals
    # This parameter will skip permissions that match the built in groups
    [Alias('sb')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $SkipBuiltIn,

    # Filter the trustees on object type.
    # This parameter will filter the result on an object type.
    [Alias('rt')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateSet('user', 'computer', 'group', 'msds-groupmanagedserviceaccount', '*')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $ReturnObjectType = '*',

    # Expand groups
    # This parameter will search any nested groups to show all security prinicpals that have access.
    [Alias('rf')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $RecursiveFind,

    # Filter on RecursiveObjectType.
    # This parameter will filter the nested groups to show only users that have access.
    [Alias('ro')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateSet('User', 'Computer', 'Group', '*')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $RecursiveObjectType = '*',

    # Translate GUIDs
    # This parameter will translate any GUIDs if necessary
    [Alias('tr')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $Translate,

    # Get Group Policy Objects linked
    # This parameter will let you search permissions on group policy objects that are linked to the path you have selected
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $GPO,

    # Open HTML report
    # This parameter will open the out report if you selected one using the -OUTPUT parameter
    [Alias('s')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $Show,

    # Include Security Descriptor modified date in report
    # This parameter will include the date when the security descriptor was last changed
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $SDDate,

    # Include Owner in report
    # This parameter will make the scan to search the owner section in the security descriptor.
    [Alias('o')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $Owner,

    # Include Canonical Names in report
    [Alias('cn')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $CanonicalNames,

    # Include if inheritance is disabled in report
    # This parameter will add information in the report whether the object have disabled it's inheritnace
    [Alias('p')]
    [Parameter(Mandatory = $false,
        ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $Protected,

    # Scan Default Security Descriptor
    # This parameter will make AD ACL Scanner to search the schema partition for security descriptors of all objects.
    [Alias('dsd')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $DefaultSecurityDescriptor,

    # Filter Default Security Descriptor on a schema object
    # This parameter let you select the schema object you would like to see the default security descriptor on.
    # Example 1. -SchemaObjectName "User"
    # Example 2. -SchemaObjectName "Computer"
    [Alias('son')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $SchemaObjectName = '*',

    # Filter Default Security Descriptor on modified with version number higher than 1
    # This parameter will check the metadata of the NTSecurityDescriptor if it have ever been changed, basically have a version number higher than 1.
    [Alias('om')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $OnlyModified,

    # Include inherited permissions
    # By default only explicit permissions are shown
    [Alias('in')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $IncludeInherited,

    # Returns ACE's in the format that .Net presents access permissions
    # Use this option if you would like to create a template for compairson
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $RAW,

    # Returns ACE's in the SDDL format
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $SDDL,

    # Filter ACL for access type
    # Example 1. -AccessType "Allow"
    # Example 2. -AccessType "Deny"
    [Alias('acc')]
    [Parameter(Mandatory = $false)]
    [ValidateSet('Allow', 'Deny')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $AccessType,

    # Filter ACL for a specific permission
    # Example 1. -Permissions "GenericAll"
    # Example 2. -Permissions "WriteProperty|ExtendedRight"
    [Alias('perm')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Permission,

    # Filter ACL ObjectName
    # Example 1. -ApplyTo user
    # Example 2. -ApplyTo "user|computer"
    [Alias('at')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $ApplyTo = '',

    # Filter ACL PropertyFilter
    # Example 1. -PropertyFilter msLAPS-Password
    # Example 2. -PropertyFilter "displayName|AdminCount"
    [Alias('pf')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $PropertyFilter = '',

    # Filter ACL for matching strings in Trustee
    # Example 1 -FilterTrustee "*Domain*"
    # Example 1 -FilterTrustee "contoso\user1"
    [Alias('ft')]
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String]
    $FilterTrustee = '',

    # Show the progressbar in the CLI
    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch]
    $ShowProgressBar,

    # Skip the banner
    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $NoBanner,

    # Set the depth of LDAP Searches, requires -Scope = Onelevel
    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [int] 
    $SearchDepth,

    # Add Credentials to the command by first creating a pscredential object like for example $CREDS = get-credential
    [Parameter(Mandatory = $false)]
    [PSCredential]
    $Credentials

)

[string]$ADACLScanVersion = "-------`nAD ACL Scanner 9.0 , Author: Robin Granberg, @ipcdollar1, Github: github.com/canix1 `n-------"
[string]$global:SessionID = [GUID]::NewGuid().Guid
[string]$global:ACLHTMLFileName = "ACLHTML-$SessionID"
[string]$global:SPNHTMLFileName = "SPNHTML-$SessionID"
[string]$global:ModifiedDefSDAccessFileName = "ModifiedDefSDAccess-$SessionID"
[string]$global:LegendHTMLFileName = "LegendHTML-$SessionID"

if ((-not($base)) -and (-not($DefaultSecurityDescriptor))) {
    if ([threading.thread]::CurrentThread.ApartmentState.ToString() -eq 'MTA') {
        Write-Host -ForegroundColor RED 'RUN PowerShell.exe with -STA switch'
        Write-Host -ForegroundColor RED 'Example:'
        Write-Host -ForegroundColor RED "    PowerShell -STA $PSCommandPath"

        Write-Host 'Press any key to continue ...'
        [VOID]$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

        Exit
    }
}

#Set global value for time out in paged searches
$global:TimeoutSeconds = 120
#Set global value for page size in paged searches
$global:PageSize = 1000
# Hash table for Forest Level
$global:ForestFLHashAD = @{
    0  = 'Windows 2000 Server';
    1  = 'Windows Server 2003/Interim';
    2  = 'Windows Server 2003';
    3  = 'Windows Server 2008';
    4  = 'Windows Server 2008 R2';
    5  = 'Windows Server 2012';
    6  = 'Windows Server 2012 R2';
    7  = 'Windows Server 2016';
    8  = 'Windows Server 2019';
    9  = 'Windows Server 2022';
    10 = 'Windows Server 2025'
}
#Hash table for Domain Level
$global:DomainFLHashAD = @{
    0  = 'Windows 2000 Server';
    1  = 'Windows Server 2003/Interim';
    2  = 'Windows Server 2003';
    3  = 'Windows Server 2008';
    4  = 'Windows Server 2008 R2';
    5  = 'Windows Server 2012';
    6  = 'Windows Server 2012 R2';
    7  = 'Windows Server 2016';
    8  = 'Windows Server 2019';
    9  = 'Windows Server 2022';
    10 = 'Windows Server 2025'
}
$global:SchemaHashAD = @{
    13 = 'Windows 2000 Server';
    30 = 'Windows Server 2003';
    31 = 'Windows Server 2003 R2';
    44 = 'Windows Server 2008';
    47 = 'Windows Server 2008 R2';
    56 = 'Windows Server 2012';
    69 = 'Windows Server 2012 R2';
    72 = 'Windows Server 2016 Technical Preview';
    81 = 'Windows Server 2016 Technical Preview 2';
    82 = 'Windows Server 2016 Technical Preview 3';
    85 = 'Windows Server 2016 Technical Preview 4';
    87 = 'Windows Server 2016';
    88 = 'Windows Server 2019';
    91 = 'Windows Server 2025'
}

# List of Exchange Schema versions
$global:SchemaHashExchange = @{
    4397  = 'Exchange Server 2000';
    4406  = 'Exchange Server 2000 SP3';
    6870  = 'Exchange Server 2003';
    6936  = 'Exchange Server 2003 SP3';
    10628 = 'Exchange Server 2007';
    10637 = 'Exchange Server 2007';
    11116 = 'Exchange Server 2007 SP1';
    14622 = 'Exchange Server 2007 SP2 or Exchange Server 2010';
    14726 = 'Exchange Server 2010 SP1';
    14732 = 'Exchange Server 2010 SP2';
    14734 = 'Exchange Server 2010 SP3';
    15137 = 'Exchange Server 2013 RTM';
    15254 = 'Exchange Server 2013 CU1';
    15281 = 'Exchange Server 2013 CU2';
    15283 = 'Exchange Server 2013 CU3';
    15292 = 'Exchange Server 2013 SP1/CU4';
    15300 = 'Exchange Server 2013 CU5';
    15303 = 'Exchange Server 2013 CU6';
    15312 = 'Exchange Server 2013 CU7';
    15317 = 'Exchange Server 2016';
    15323 = 'Exchange Server 2016 CU1';
    15325 = 'Exchange Server 2016 CU2';
    15326 = 'Exchange Server 2016 CU3-CU5';
    15330 = 'Exchange Server 2016 CU6';
    15332 = 'Exchange Server 2016 CU7-CU18';
    15333 = 'Exchange Server 2016 CU19';
    17000 = 'Exchange Server 2019';
    17001 = 'Exchange Server 2019 CU2-CU7';
    17002 = 'Exchange Server 2019 CU8';
    17003 = 'Exchange Server 2019 CU10'
}

# List of Lync Schema versions
$global:SchemaHashLync = @{
    1006 = 'LCS 2005';
    1007 = 'OCS 2007 R1';
    1008 = 'OCS 2007 R2';
    1100 = 'Lync Server 2010';
    1150 = 'Lync Server 2013/Skype for Business 2015'
}
Function BuildSchemaDic {

    $global:dicSchemaIDGUIDs = @{'BF967ABA-0DE6-11D0-A285-00AA003049E2' = 'user'; `
            'BF967A86-0DE6-11D0-A285-00AA003049E2'                      = 'computer'; `
            'BF967A9C-0DE6-11D0-A285-00AA003049E2'                      = 'group'; `
            'BF967ABB-0DE6-11D0-A285-00AA003049E2'                      = 'volume'; `
            'F30E3BBE-9FF0-11D1-B603-0000F80367C1'                      = 'gPLink'; `
            'F30E3BBF-9FF0-11D1-B603-0000F80367C1'                      = 'gPOptions'; `
            'BF967AA8-0DE6-11D0-A285-00AA003049E2'                      = 'printQueue'; `
            '4828CC14-1437-45BC-9B07-AD6F015E5F28'                      = 'inetOrgPerson'; `
            '5CB41ED0-0E4C-11D0-A286-00AA003049E2'                      = 'contact'; `
            'BF967AA5-0DE6-11D0-A285-00AA003049E2'                      = 'organizationalUnit'; `
            'BF967A0A-0DE6-11D0-A285-00AA003049E2'                      = 'pwdLastSet'
    }


    $global:dicNameToSchemaIDGUIDs = @{'user' = 'BF967ABA-0DE6-11D0-A285-00AA003049E2'; `
            'computer'                        = 'BF967A86-0DE6-11D0-A285-00AA003049E2'; `
            'group'                           = 'BF967A9C-0DE6-11D0-A285-00AA003049E2'; `
            'volume'                          = 'BF967ABB-0DE6-11D0-A285-00AA003049E2'; `
            'gPLink'                          = 'F30E3BBE-9FF0-11D1-B603-0000F80367C1'; `
            'gPOptions'                       = 'F30E3BBF-9FF0-11D1-B603-0000F80367C1'; `
            'printQueue'                      = 'BF967AA8-0DE6-11D0-A285-00AA003049E2'; `
            'inetOrgPerson'                   = '4828CC14-1437-45BC-9B07-AD6F015E5F28'; `
            'contact'                         = '5CB41ED0-0E4C-11D0-A286-00AA003049E2'; `
            'organizationalUnit'              = 'BF967AA5-0DE6-11D0-A285-00AA003049E2'; `
            'pwdLastSet'                      = 'BF967A0A-0DE6-11D0-A285-00AA003049E2'
    }
}

BuildSchemaDic

$CurrentFSPath = $PSScriptRoot

$CREDS = $null
$script:CREDS = $null
$global:bolConnected = $false
$global:strDC = ''
$global:PickedDDomainName = ''
$global:strPinDomDC = ''
$global:strPrinDomAttr = ''
$global:strPrinDomDir = ''
$global:strPrinDomFlat = ''
$global:strPrincipalDN = ''
$global:strDomainPrinDNName = ''
$global:strEffectiveRightSP = ''
$global:strEffectiveRightAccount = ''
$global:strSPNobjectClass = ''
$global:tokens = New-Object System.Collections.ArrayList
$global:tokens.Clear()
$global:strDomainSelect = 'rootDSE'

#### Check if UI should be loaded
if ((!($base) -and (!($GPO)) -and (!($DefaultSecurityDescriptor)) -and (!($Targets)))) {

Add-Type -Assembly PresentationFramework

$xamlBase = @'
<Window x:Class="ADACLScanXAMLProj.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD ACL Scanner"  WindowStartupLocation="CenterScreen" Height="690" Width="1035" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="Black"   >
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
        <Grid HorizontalAlignment="Left" VerticalAlignment="Top" Height="640" Width="1000">
            <StackPanel Orientation="Vertical" Margin="10,0,0,0" >
                <StackPanel Orientation="Horizontal">
                    <StackPanel Orientation="Vertical">
                        <TabControl x:Name="tabConnect"   HorizontalAlignment="Left" Height="245" Margin="0,10,0,0" VerticalAlignment="Top" Width="350">
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
                                        <TextBox x:Name="txtBoxDSServer" HorizontalAlignment="Left" Height="18"  Text="" Width="150" Margin="0,0,0.0,0" IsEnabled="False"/>
                                        <Label x:Name="lblPort" Content="Port:"  HorizontalAlignment="Left" Height="28" Margin="10,0,0,0" Width="35"/>
                                        <TextBox x:Name="txtBoxDSServerPort" HorizontalAlignment="Left" Height="18"  Text="" Width="45" Margin="0,0,0.0,0" IsEnabled="False"/>
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
                        <GroupBox x:Name="gBoxSelectNodeTreeView" Grid.Column="0" Header="Nodes" HorizontalAlignment="Left" Height="330" Margin="0,0,0,0" VerticalAlignment="Top" Width="350"  Foreground="White" BorderThickness="0" BorderBrush="#FF2A3238" >
                            <StackPanel Orientation="Vertical">
                                <TreeView x:Name="treeView1"  Height="300" Width="340"  Margin="0,5,0,0" HorizontalAlignment="Left"
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
                        <StackPanel Orientation="Horizontal" >
                            <StackPanel Orientation="Horizontal" Margin="0,0,0,0">
                                <StackPanel Orientation="Vertical" >
                                    <StackPanel Orientation="Horizontal" >
                                        <Label x:Name="lblStyleVersion1" Content="AD ACL Scanner 9.0" HorizontalAlignment="Left" Height="25" Margin="0,0,0,0" VerticalAlignment="Top" Width="140" Foreground="#FF46724C" Background="{x:Null}" FontWeight="Bold" FontSize="14"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" >
                                        <Label x:Name="lblStyleVersion2" Content="written by Robin Granberg " HorizontalAlignment="Left" Height="27" Margin="0,0,0,0" VerticalAlignment="Top" Width="150" Foreground="White" Background="{x:Null}" FontSize="12"/>
                                        <Image x:Name="imgTwitter" HorizontalAlignment="Left" Height="15" VerticalAlignment="Center" Width="15"  />
                                        <Label x:Name="lblStyleVersion3" Content="@ipcdollar1" HorizontalAlignment="Left" Height="27" Margin="0,0,0,0" VerticalAlignment="Top" Width="72" Foreground="White" Background="{x:Null}" FontSize="12"/>
                                        <Image x:Name="imgGithub" HorizontalAlignment="Left" Height="15" VerticalAlignment="Center" Width="15"  />
                                        <Label x:Name="lblStyleVersion4" Content="@canix1" HorizontalAlignment="Left" Height="27" Margin="0,0,0,0" VerticalAlignment="Top" Width="53" Foreground="White" Background="{x:Null}" FontSize="12"/>
                                    </StackPanel>
                                </StackPanel>
                            </StackPanel>
                        </StackPanel>
                    </StackPanel>
                    <StackPanel Orientation="Vertical">
                        <Label x:Name="lblSelectedNode" Content="Selected Object:" HorizontalAlignment="Left" Height="26" Margin="0,0,0,0" VerticalAlignment="Top" Width="158" Foreground="White" />
                        <StackPanel Orientation="Horizontal" >
                            <TextBox x:Name="txtBoxSelected" HorizontalAlignment="Left" Height="20" Margin="5,0,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="630"/>
                        </StackPanel>
                        <Label x:Name="lblStatusBar" Content="Log:" HorizontalAlignment="Left" Height="26" Margin="0,0,0,0" VerticalAlignment="Top" Width="158" Foreground="White" />
                        <ListBox x:Name="TextBoxStatusMessage" DisplayMemberPath="Message" SelectionMode="Extended" HorizontalAlignment="Left" Height="80" Margin="5,0,0,0" VerticalAlignment="Top" Width="630" ScrollViewer.HorizontalScrollBarVisibility="Auto">
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
                        <TabControl x:Name="tabScanTop"   HorizontalAlignment="Left" Height="405"  VerticalAlignment="Top" Width="630" Margin="5,5,0,0">
                            <TabItem x:Name="tabScan" Header="Scan Options" Width="85">
                                <Grid >
                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                        <StackPanel Orientation="Horizontal" Margin="0,0">
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <GroupBox x:Name="gBoxScanType" Header="Scan Type" HorizontalAlignment="Left" Height="71" Margin="2,1,0,0" VerticalAlignment="Top" Width="290" >
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
                                                <GroupBox x:Name="gBoxScanDepth" Header="Scan Depth" HorizontalAlignment="Left" Height="78" Margin="2,1,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton GroupName="Depth" x:Name="rdbBase" Content="Base" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="61" IsChecked="True"/>
                                                            <RadioButton GroupName="Depth" x:Name="rdbOneLevel" Content="One Level" HorizontalAlignment="Left" Height="18" Margin="20,10,0,0" VerticalAlignment="Top" Width="80"/>
                                                            <RadioButton GroupName="Depth" x:Name="rdbSubtree" Content="Subtree" HorizontalAlignment="Left" Height="18" Margin="20,10,0,0" VerticalAlignment="Top" Width="80"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton GroupName="Depth" x:Name="rdbDepth" Content="Depth (0-999):" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="100"/>
                                                            <TextBox x:Name="txtDepth" Text="0" HorizontalAlignment="Left" Height="18" Width="25" Margin="2,5,0.0,0" IsEnabled="false"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxRdbFile" Header="Output Options" HorizontalAlignment="Left" Height="158" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbOnlyHTA" Content="HTML" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="61" GroupName="rdbGroupOutput" IsChecked="True"/>
                                                            <RadioButton x:Name="rdbOnlyCSV" Content="CSV file" HorizontalAlignment="Left" Height="18" Margin="20,05,0,0" VerticalAlignment="Top" Width="61" GroupName="rdbGroupOutput"/>
                                                            <RadioButton x:Name="rdbOnlyCSVTEMPLATE" Content="CSV Template" HorizontalAlignment="Left" Height="18" Margin="20,05,0,0" VerticalAlignment="Top" Width="91" GroupName="rdbGroupOutput"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbEXcel" Content="Excel file" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="155" GroupName="rdbGroupOutput"/>
                                                        </StackPanel>
                                                        <CheckBox x:Name="chkBoxTranslateGUID" Content="Translate GUID's in CSV output" HorizontalAlignment="Left" Height="18" Margin="5,05,0,0" VerticalAlignment="Top" Width="200"/>
                                                        <Label x:Name="lblTempFolder" Content="CSV file destination" />
                                                        <TextBox x:Name="txtTempFolder" Margin="0,0,02,0"/>
                                                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" >
                                                            <Button x:Name="btnGetTemplateFolder" Content="Change Folder" Width="90" Margin="-100,00,0,0"  />
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                            </StackPanel>
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <GroupBox x:Name="gBoxRdbScan" Header="Objects to scan" HorizontalAlignment="Left" Height="75" Margin="2,0,0,0" VerticalAlignment="Top" Width="310">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbScanOU" Content="OUs" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="61" IsChecked="True" GroupName="rdbGroupFilter"/>
                                                            <RadioButton x:Name="rdbScanContainer" Content="Containers" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="80" GroupName="rdbGroupFilter"/>
                                                            <RadioButton x:Name="rdbScanAll" Content="All Objects" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="80" GroupName="rdbGroupFilter"/>
                                                            <RadioButton x:Name="rdbGPO" Content="GPOs" HorizontalAlignment="Left" Height="18" Margin="5,10,0,0" VerticalAlignment="Top" Width="80" GroupName="rdbGroupFilter"/>
                                                        </StackPanel>
                                                        <StackPanel Orientation="Horizontal">
                                                            <RadioButton x:Name="rdbScanFilter" Content="" HorizontalAlignment="Left" Height="18" Margin="5,5,0,0" VerticalAlignment="Top" Width="15" GroupName="rdbGroupFilter"/>
                                                            <TextBox x:Name="txtCustomFilter" Text="(objectClass=*)" HorizontalAlignment="Left" Height="18" Width="250" Margin="0,0,0.0,0" IsEnabled="False"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                                <GroupBox x:Name="gBoxReportOpt" Header="View in report" HorizontalAlignment="Left" Height="220" Margin="2,0,0,0" VerticalAlignment="Top" Width="310">
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
                                                        <StackPanel Orientation="Vertical"  Margin="0,0,0,0">
                                                            <StackPanel Orientation="Horizontal" Height="19" Margin="0,0,0.2,0">
                                                                <CheckBox x:Name="chkBoxUseCanonicalName" Content="Canonical Name" HorizontalAlignment="Left" Margin="5,05,0,0" VerticalAlignment="Top" Width="120"/>
                                                                <CheckBox x:Name="chkBoxSDDLView" Content="SDDL" HorizontalAlignment="Left" Height="30" Margin="30,05,0,0" VerticalAlignment="Top" Width="90"/>
                                                            </StackPanel>
                                                            <Label x:Name="lblReturnObjectType" Content="Filter report on security principal type:"  Margin="5,0,0,0"/>
                                                            <ComboBox x:Name="combReturnObjectType" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="True"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </GroupBox>
                                            </StackPanel>
                                        </StackPanel>
                                        <GroupBox  x:Name="gBoxExclude" Header="Excluded Path (matching string in distinguishedName):" HorizontalAlignment="Left" Height="75" Margin="2,0,0,0" VerticalAlignment="Top" Width="605">
                                            <StackPanel Orientation="Vertical">
                                                <StackPanel Orientation="Vertical">
                                                    <TextBox x:Name="txtBoxExcluded" HorizontalAlignment="Left" Height="20" Margin="5,10,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="585" />
                                                    <Button x:Name="btnClearExcludedBox" Content="Clear"  Height="21" Margin="10,0,0,0" IsEnabled="true" Width="100"/>
                                                </StackPanel>
                                            </StackPanel>
                                        </GroupBox>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                            <TabItem x:Name="tabFilter" Header="Filter">
                                <Grid>
                                    <StackPanel Orientation="Horizontal">
                                        <StackPanel Orientation="Vertical" Margin="0,0">
                                            <CheckBox x:Name="chkBoxFilter" Content="Enable Filter" HorizontalAlignment="Left" Margin="5,5,0,0" VerticalAlignment="Top"/>
                                            <Label x:Name="lblAccessCtrl" Content="Filter by Access Type:(example: Allow)" />
                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxType" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <ComboBox x:Name="combAccessCtrl" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="False"/>
                                            </StackPanel>
                                            <Label x:Name="lblFilterExpl" Content="Filter by Object:&#10;Examples:&#10;Group &#10;User|Computer" />
                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxObject" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <TextBox x:Name="txtBoxObjectFilter" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="200" IsEnabled="False"/>
                                            </StackPanel>
                                             <Label x:Name="lblFilterPropExpl" Content="Filter by Property:&#10;Examples:&#10;userAccountControl &#10;msLAPS-Password|msLAPS-EncryptedPassword" />
                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxProperty" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <TextBox x:Name="txtBoxPropertyFilter" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="200" IsEnabled="False"/>
                                            </StackPanel>
                                        </StackPanel>
                                        <StackPanel Orientation="Vertical" Margin="5,5,0,0" Width="320">
                                            <Label x:Name="lblPermission" Content="Filter by permissions:&#10;Examples:&#10;GenericAll &#10;WriteProperty|ExtendedRight" />
                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxPermission" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <TextBox x:Name="txtPermission" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="160" IsEnabled="False"/>
                                            </StackPanel>
                                            <Label x:Name="lblFilterTrusteeExpl" Content="Filter by Trustee:&#10;Examples:&#10;CONTOSO\User&#10;CONTOSO\JohnDoe*&#10;*Smith&#10;*Doe*" />
                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxTrustee" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <TextBox x:Name="txtFilterTrustee" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="160" IsEnabled="False"/>
                                            </StackPanel>

                                            <StackPanel Orientation="Horizontal" Margin="0,0">
                                                <CheckBox x:Name="chkBoxFilterBuiltin" Content="" HorizontalAlignment="Left" Margin="5,5,0,0" VerticalAlignment="Top" IsEnabled="False"/>
                                                <Label x:Name="lblFilterBuiltin" Content="Exclude all built-in security principals" />
                                            </StackPanel>
                                        </StackPanel>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                            <TabItem x:Name="tabAssess" Header="Assessment">
                                <Grid >
                                    <StackPanel Orientation="Horizontal">
                                        <StackPanel Orientation="Vertical" Margin="0,0">
                                            <GroupBox x:Name="gBoxdCriticals" Header="Assessment Options" HorizontalAlignment="Left" Height="200" Margin="0,5,0,0" VerticalAlignment="Top" Width="290">
                                                <StackPanel>
                                                    <Label x:Name="lblFilterServerity" Content="Filter by Severity" />
                                                    <StackPanel Orientation="Horizontal" Margin="0,0">
                                                        <CheckBox x:Name="chkBoxSeverity" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="True"/>
                                                        <ComboBox x:Name="combServerity" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="false"/>
                                                    </StackPanel>
                                                    <Label x:Name="lblRecursiveFind" Content="Perform a recursive search and return these objects:" />
                                                    <StackPanel Orientation="Horizontal" Margin="0,0">
                                                        <CheckBox x:Name="chkBoxRecursiveFind" Content="" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" IsEnabled="True"/>
                                                        <ComboBox x:Name="combRecursiveFind" HorizontalAlignment="Left" Margin="5,0,0,0" VerticalAlignment="Top" Width="120" IsEnabled="false"/>
                                                    </StackPanel>
                                                </StackPanel>
                                            </GroupBox>
                                        </StackPanel>
                                        <StackPanel Orientation="Vertical" Margin="5,5">
                                            <GroupBox x:Name="gBoxCriticality" Header="Access Rights Criticality" HorizontalAlignment="Left" Height="150" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                                <StackPanel Orientation="Vertical" Margin="0,0">
                                                    <CheckBox x:Name="chkBoxEffectiveRightsColor" Content="Show color coded criticality" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top" IsEnabled="True"/>
                                                    <Label x:Name="lblEffectiveRightsColor" Content="Use colors in report to identify criticality level of &#10;permissions.This might help you in implementing &#10;Least-Privilege Administrative Models" />
                                                    <Button x:Name="btnViewLegend" Content="View Color Legend" HorizontalAlignment="Left" Margin="5,0,0,0" IsEnabled="True" Width="110"/>
                                                </StackPanel>

                                            </GroupBox>
                                        </StackPanel>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                            <TabItem x:Name="tabEffectiveR" Header="Effective Rights">
                                <Grid >
                                    <StackPanel Orientation="Horizontal">
                                        <StackPanel Orientation="Vertical" Margin="0,0">
                                            <CheckBox x:Name="chkBoxEffectiveRights" Content="Enable Effective Rights" HorizontalAlignment="Left" Margin="5,5,0,0" VerticalAlignment="Top"/>
                                            <Label x:Name="lblEffectiveDescText" Content="Effective Access allows you to view the effective &#10;permissions for a user, group, or device account." />
                                            <Label x:Name="lblEffectiveText" Content="Type the account name (samAccountName) for a &#10;user, group or computer" />
                                            <Label x:Name="lblSelectPrincipalDom" Content=":" />
                                            <TextBox x:Name="txtBoxSelectPrincipal" IsEnabled="False"  />
                                            <StackPanel  Orientation="Horizontal" Margin="0,0">
                                                <Button x:Name="btnGetSPAccount" Content="Get Account" Margin="5,0,0,0" IsEnabled="False"/>
                                                <Button x:Name="btnListLocations" Content="Locations..." Margin="50,0,0,0" IsEnabled="False"/>
                                            </StackPanel>

                                        </StackPanel>
                                        <StackPanel Orientation="Vertical" Margin="5,5,0,0" Width="320">
                                            <StackPanel  Orientation="Vertical" Margin="0,0"   >
                                                <GroupBox x:Name="gBoxEffectiveSelUser" Header="Selected Security Principal:" HorizontalAlignment="Left" Height="50" Margin="2,2,0,0" VerticalAlignment="Top" Width="290">
                                                    <StackPanel Orientation="Vertical" Margin="0,0">
                                                        <Label x:Name="lblEffectiveSelUser" Content="" />
                                                    </StackPanel>
                                                </GroupBox>
                                                <Button x:Name="btnGETSPNReport" HorizontalAlignment="Left" Content="View Account" Margin="5,2,0,0" IsEnabled="False" Width="110"/>
                                            </StackPanel>
                                        </StackPanel>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                            <TabItem x:Name="tabCompare" Header="Compare">
                                <Grid>
                                    <StackPanel Orientation="Horizontal">
                                        <StackPanel Orientation="Vertical" Margin="0,0" HorizontalAlignment="Left">
                                            <CheckBox x:Name="chkBoxCompare" Content="Enable Compare" HorizontalAlignment="Left" Margin="5,5,0,0" VerticalAlignment="Top"/>
                                            <Label x:Name="lblCompareDescText" Content="You can compare the current state with  &#10;a previously created CSV file." />
                                            <Label x:Name="lblCompareTemplate" Content="CSV Template File" />
                                            <TextBox x:Name="txtCompareTemplate" Margin="2,0,0,0" Width="275" IsEnabled="False"/>
                                            <Button x:Name="btnGetCompareInput" Content="Select Template" HorizontalAlignment="Right" Height="19" Margin="65,00,00,00" IsEnabled="False"/>
                                            <StackPanel Orientation="Horizontal" Margin="5,5,0,0">
                                                <Label x:Name="lblReturn" Content="Return:" />
                                                <ComboBox x:Name="combReturns" HorizontalAlignment="Left" Margin="05,02,00,00" VerticalAlignment="Top" Width="80" IsEnabled="False" SelectedValue="ALL"/>
                                            </StackPanel>
                                            <StackPanel Orientation="Vertical">
                                                <CheckBox x:Name="chkBoxTemplateNodes" Content="Use nodes from template." HorizontalAlignment="Left" Width="160" Margin="2,5,00,00" IsEnabled="False" />
                                                <CheckBox x:Name="chkBoxScanUsingUSN" Content="Faster compare using USNs of the&#10;NTSecurityDescriptor. This requires that your &#10;template to contain USNs.Requires SD Modified&#10;date selected when creating the template." HorizontalAlignment="Left"  Width="280" Margin="2,5,00,00" IsEnabled="False" />
                                            </StackPanel>

                                        </StackPanel>
                                        <StackPanel Orientation="Vertical" Width="300">

                                            <Label x:Name="lblReplaceDN" Content="Replace DN in file with current domain DN.&#10;E.g. DC=contoso,DC=com&#10;Type the old DN to be replaced:" />
                                            <TextBox x:Name="txtReplaceDN" Margin="2,0,0,0" Width="250" IsEnabled="False"/>
                                            <Label x:Name="lblReplaceNetbios" Content="Replace principals prefixed domain name with&#10;current domain. E.g. CONTOSO&#10;Type the old NETBIOS name to be replaced:" />
                                            <TextBox x:Name="txtReplaceNetbios" Margin="2,0,0,0" Width="250" IsEnabled="False"/>
                                            <Label x:Name="lblDownloadCSVDefACLs" Content="Download CSV templates for comparing with&#10;your environment:" Margin="05,20,00,00" />
                                            <Button x:Name="btnDownloadCSVDefACLs" Content="Download CSV Templates" HorizontalAlignment="Left" Width="140" Height="19" Margin="05,05,00,00" IsEnabled="True"/>
                                        </StackPanel>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                            <TabItem x:Name="tabOther" Header="Default SD">
                                <Grid>
                                    <StackPanel Orientation="Horizontal">
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
                                        <GroupBox x:Name="gBoxProgress" Header="Progress Bar" HorizontalAlignment="Left" Height="75" Margin="2,0,0,0" VerticalAlignment="Top" Width="290">
                                            <StackPanel Orientation="Vertical" Margin="0,0">
                                                <CheckBox x:Name="chkBoxSkipProgressBar" Content="Use Progress Bar" HorizontalAlignment="Left" Margin="5,10,0,0" VerticalAlignment="Top" IsEnabled="True" IsChecked="False"/>
                                                <Label x:Name="lblSkipProgressBar" Content="For increased speed, turn off the progress bar." />
                                            </StackPanel>
                                        </GroupBox>
                                    </StackPanel>
                                </Grid>
                            </TabItem>
                        </TabControl>
                        <StackPanel Orientation="Horizontal" Margin="5,5">
                            <Button x:Name="btnScan" Content="Run Scan" HorizontalAlignment="Left" Height="19" Margin="0,0,0,0" VerticalAlignment="Top" Width="66"/>
                            <Button x:Name="btnExit" Content="Exit" HorizontalAlignment="Left" Margin="100,0,0,0" VerticalAlignment="Top" Width="75"/>
                            <Button x:Name="btnSupport" Height="23" Tag="Support Statement"  Margin="270,0,0,0" Foreground="White" HorizontalAlignment="Right">
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
                <StackPanel >
                </StackPanel>
            </StackPanel>

        </Grid>
    </ScrollViewer>
</Window>
'@

[XML] $XAML = $xamlBase
$xaml.Window.RemoveAttribute('x:Class')

$reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Window = [Windows.Markup.XamlReader]::Load( $reader )

#Replace x:Name to XML variable Name
$xamlBase = $xamlBase.Replace('x:Name', 'Name')
[XML] $XAML = $xamlBase

#Search the XML data for object and create variables
$XAML.SelectNodes('//*[@Name]') | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Window.FindName($_.Name) }

$Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

$IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
$IconImage.BeginInit()
$IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
$IconImage.EndInit()

# Freeze() prevents memory leaks.
$IconImage.Freeze()

$Window.Icon = $IconImage


$twittericon = @'
iVBORw0KGgoAAAANSUhEUgAAAC0AAAAtCAYAAAA6GuKaAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAApSSURBVGhDtVkNjFRXFT7vzezszu6wC8uPLEv5sbAIi0hKadMmVtTWBi2iTdSYgDWmTVM1GtNYMLWFoEmtiWJNrbHVlFRq1Vg1bZVGWqXFgpVgkUJpF1p+Csuyu+wKuzOzOzszz+877947b4ZZZM3yzZx3zz3/97777n2z60kVzFz3qFc3d96K+KSpK/2a+FLxYzNFvCYY1wcSJL1A8I2AUawgGpEy01eTChsGCTx8PT8DLhsUg3NSLJ4s5nOv5ft7ns8cPbKj88E7y1IR0RSK+T/feVNN87SH/PrUwjK1ZSOFKCoKcYjaRW2q8YAzd/JACpnBA/m+7m8cvv2DL1BiYcMqFvxyz/3x5ukbvZjP8fOrKBkhmo0eyYLZD6cefScmw8YLja1e4QLDE7yaOFhHEORBoRiM9HVt6Fi7/DuhohRG2p7Yc1/N5JZNNoLLQUd0yJNMyBKsvpqyUlY1QCii/6hxIBjpPb2h4wvLN7FHE7nyZy/fWDdjzl8kFuO0OWiwkL0kjFJTiIsEK1ONFqRYCIY7j9185M4btseuuOcRL/ne9me8RN00GrsAZEDkbUCnM6jsEyozvmwIZ2MFhOVN6/IYv7K4lHlAPH51bPbCR/zEFfNXeMlUO55cIfEeBUVtDB/ggUbHkLVT24p+QCfK6Wd5xoroHc+P5inFYR62o8X1a1MLU7Pet8KPN01dyZHY2fEQiElDCmUkJojaVSXaaCFROS740s+S9l2eqG1UV4WAWNOUlb748aUcSVEDhKOqHK3y1KPV2TC8mwlLEf+QZ0jTBzFHmU0FuZhGzwBRvcpi8aW+iD9LChgCZ8gQRwV7HbHODGVWR4I99cqztWTilAhCytCoPf2MTvuG3B2I6thG41lbz5/lLdh66JRXVz8DIl381I03ZjbE5VOzG2TxpIQkY76czuTlb6ez8kJnVgpaoQHYhhpf0nlWWR3FoUyn1/bEGwOxuoYUBepuKrdPL8+BZVNq5V89w06vs2J4m1Pd9KJdBffc2xc0ylfbmySB86oSB/tzcvc/eqUTg7hmWp18dm5KXsRAnjmeVr3dsxnX5iwMpdPe/C0HhmLJVG2kDs1r2zok27l6pmw9PCAPHfgPJKUAWjQNMTFlhwNAky8vapKvLZ4YCkbB+ZFwVhsxw692D8mXXjqD2YeAsaiw8dhCFmTTwz7WmBfQisTFjtYDWVn7xIRMQMC7UMC9S5slRkfaocJKP9eC2ibUyFfaL14wwWJJe3uG5Ef/7pe18xplVn0cSRCL8QxJ3sX3fGXQV8KgSbRhnzM4uRbPqsHatgny2IemyZTamLNVMr768Bjfz8+bIDhfLxmLJtXKUze14M6KHD8/guIgNHGjOTgAzDR6LNxWSipCSxk+/UP0LuH66Ul57hOt8rkrUxJHUc4ffiQba9nUWuNxaahDsB/v75efvo4lyJiMZ2K5+tjiw+XBYz0UoGVi1qwO6O/HA5g2685iImZ/07VT5E+3tMqatkZpwu21/tzHSZNwN8aCLW+ck4f39btCLZUVrHVik/Yo4Nco9baweFN4NleQrW+eCyNXYE5jjdx/zWTZ9ZlZ8qubZ8jdVzXLqjkpuQqzPHSRbasautL5UnFaR6kGR5x9yL25D+8b9pOphPF1u4YFl0Aci/PJla3ygTHe8rFg/d+75XcdA3azcDVon5MKhnwhO5jzuXY4OkvhLQiJd+EjM+vlF3hA/nk6I5mKZTKe6BrIm7xFnVVXDynyrHAAfmk5GAUNTJ90GAfAtS1JuWPJJKnn2r0MQEY50jesefk8lRVchXSmXaFmAJAbJ5GjfTk5dBYBLyO6BvM609EZZW595yChLsrCPncPFKn7K0kHECrsQ8Cd4IFXesKBXCbsfDeteVwdJrcjHYyRoV5f+0ZZGmU5v/NEWtb9tUtyHOBlwLMd5zVPWDhy6kSW6nA8i8VXT0QuCQouMFIdoqJ9+uA5ueWpY7LtyIDkKR8nHMUzs+tEBjnQMbMc1oIWdXHJ6rJlTTjKueZLx7hTlpxVZgLUY+/73keny+ymGhkZxxn/yZ6zUkAxgdk1QmL+sLUTqDKmBa/LQ2caHTvbJCczNIjjfM/JjCyaWifJcdpF9ncNye8PmmPbFKgUrYcFkiL16INoH0AtmH22JMrdqAP5AQ6AXVjf44EhzO43n++Ugs3PPDa39iuIMmMbbnmqgJc62SIjQUAc4TAOl9t+e1we3t0rgzkY/J9ANLlv+2k51J01OZgTy8PUwlyUaz2RGqinzmvd8Oowfm4lPB6SjMag0bOUPFr3ck8ebX3Cl+vwE+q7H2uRVryDjAWbccc27+xxL/YK5VGQSWTzqDpiF+TS5hi3Tyc/dATPvuo4MrRuximD3dWtSVl3w7QxFUzX7+84Iz98udvNqM1T+eKm9dCBZGxI1Hkzvr172K9tSECkCMep/iGPi49LUzIm8/Fb8brZKVm1qFEW4IEcC/qzBVn33Cn5cwfeGBE8moewfXIoTVvLEfb3YnE4nfNm3Lt7yEs0RF7fQgdiIgq96/qpsnZZs0zA+7FdImNBATPzB7zYP/Bil5zBcW1yX4BK+Wh2KHrYa/nW7kGvtr7BWlxgDEFrY0JuWz5Zbl0yUVoucTn04P34WfwQ3oJ9+O1e8+5igrMhNI9NWCa8EFwdnLRgJDPotazffcpL8O8eJU/lSpfQA62P7Xkxfm4tn1UvbVge0zGABvMbcnC4KF34bXcYP1D3vpuR17uyODlNRLoTrhPmUdiu5iCsDn2t0hioGCdiLtvpveeeV970axoWROP8TyCO3WHY2LyEpjbTUh6S67NSdhGYoGFTukou/ZaPRXdCk5gntpxgZHThE236+PJp1z8UahvaWJ43KCrTbFZG3unIG3I1GD2+bMM4qF55iAuFE36QH9mnmzucwjYkOkdlDOL6Njj7ThYhE0NJZZE4+o5heFxUp20oUz7SujpItB3J7/MLg2e3qZajIcirkeFZoLboW171YZBwFqu01pYgbygUGZ3lra36UWRkam91obyYPrvNz/Uc21EcHjzkRkInfbuzM0JnyDQwvioLc2ks01d/leNi/FRn/SxZe6NTQl8LtIecsSnLAcJ2d7DQ/c6OWO6t7VLXvqrDr0utwaqza16hDS/qyQ550zoYARtD6mftqvmytfxogN6UoQiKhaBwvmtN36/veFv/opJ97TfvJN//6QC7yId1myFsUIzQbRUuKRnI2FBn+4TdJglrb22N2PFRP2vLVnlcXF4si8GejWcf++Tj7Lo/A2X2PvlScsnqwIsnVyAQrPGFscYOTcoBoQlZ0kcNLc+2Gk/YvsrCfBcAM1wc7N3Y++jH9d9xhM3r0PzFp2/0GyZv9hMNi1WtFtzGsHLIc+ajXuSjMxYFxTx7RtFXk7rzBJdgJH2okOn7et/jt24PtSGqZMI7x+oHPb9pzgo/2byS/5Ph/8Zh2ISI9XhAkxyDejI4EeWJSh1hKzQtV5GaeJiOwMsGfpCB4JxXLJwMgvy+YqZv28j5ozsG/rjeRjIQ+S9Qcb3TaPwbqQAAAABJRU5ErkJggg==
'@

# Create a streaming image by streaming the base64 string to a bitmap streamsource
$Twitterbitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$Twitterbitmap.BeginInit()
$Twitterbitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($twittericon)
$Twitterbitmap.EndInit()

# Freeze() prevents memory leaks.
$Twitterbitmap.Freeze()

$imgTwitter.Source = $Twitterbitmap

$githubicon = @'
iVBORw0KGgoAAAANSUhEUgAAAC0AAAAtCAYAAAA6GuKaAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAgjSURBVGhDxZl7VBNnFsAnk4fyhgCigIiKwIItSqWColZbF7tiPVW69nHag213t93uqqeeup7uq2u77XZ7uvbUHltdkUI9BUUUiQIF5CHlEUIgMCYQXgJ5kISQB3mRZJLZmfiVcyyZPDC4v3/47p2Z+12+uXO/e79QoIeAxymlBQQGZ4WExm1nLAl6AqbSE2GYGg1R4FCYQqHY7TYrhmFKzI5OoKhFMGtUsTWq8YaUDQeHgIlHx1B/dbpyavAbvV6htDn88hyLxYjNaKXIpJh3Aum+EgFMLh4jg/WZ+ErVWa0m4MLDYTKqDAqZ4PTdnvJIMIXv4PPKw5RyYaHVYrSD+XyKwaBUi8bYv+24U/RQ4TrHvaGmbL1OLgL2Fw2bDcWUisFbPE5JOJh6YYjG2fnmWZ0Z2H0kzGgkI3d5FcnABe8QjXUew2N3UcLBHXqdYorPY6UBVzwDj698q+X/4/BPzGhlio6W75KAS64ZGWzIftQhQcaUfHj4esm/mcC1Oajgr4NebikzdlVGvZ8/MwyoHgDD7FBDbZkuMNAf31TCYKBeEHY7CvV0NUFqtWI2clksDagfwD+AyaTRKKnhS+HSpvZuoP0ZCll/IfgnnSKXjWKHX9z7+4///nZyP3KnnmxjwXc/zGqddWQEZ2jUcuzzT06Icp/Jel7Ir8uz28kjEQ9TrLG26E3gooO5lRbyqzNXxKadoVLppLmS38eBOtpa/3D669Jh1KS+lJIaHxYYyNwslY5Adxqr7c23bwpqa8qaa6uu1TU13Kxra6lhCxDOkFRyz6BWycNDgoMYOp0K+vTD9zt7uMiOytpW7suHds1ErVj3LpXGALM8CEylQYwlS7KXBWEF9c0cE6Gbey2RUUkf0el+LpM7XktANCpVQYzPfVthx40dCw7yQxBk2IxabVVVDe3TjhudsPfpLEZ0TOQ2CkTZrFbrzlbUtGjuX6EQr+P+kIQVMYnMzdlbTkLQ2feACoIECCudeA3uEI8LsHfyDySCx3yCoI+1G18MMAM546N9+qNv5Dk+SsfHFBG57nc0+lJi6JKo6DVQQlJcLhB9AjNiTQ6F4v6bjolLDsjctimfGMNtjYU0P//QPMcVNzTfrsA62nvHgOgTpGJhoUGvVAGRFPxbg+LXpr7mEPh9lds8KS8HB7qw13695wPHQz5GgPywBy9Z3W5mE2N87Dev5K6Gmcz47TDsNE3OgdfyUFlJEc+gN30IVD4l5bGcGo1KVAZEUpaviIfWJcXvghlLg9KBjpSRYQRCeIKPy6uabUDlc+STwtM21AIk59AZ/lDsypVPwnisuN3fEV6XAd8OK4G4KEjEIrbRoJIDkZSQ0MgU2NHTuUGtUnSXVjaYgbgo7Nn3DobaLL1AJIWxxH8VnmsoIUAmxWo1S8BwUbHbUB0YkoKHRjix0m6TZDgz0n0S9wFUKm1eRecEPxjfjVAgkLI8Ju4XYLhotDYV0PANbiMQSUGtVhTG058ayKQkJKYmHn/7UAIQFwW8PM3xDwgPBSIpJpNRh680KgIyKcujEyj7854/AkSf01x/gYIXbH/GQxVoyNHrtJOwzWoWApkUCoUCPZ6+461b1790+/oWwuq1648Eh8ZmAdEFGCSbFI/AJpOWCzQuCQldTs/M3ne1s7U4Cqh8wuhQ096o6PWfebLKeBsIjY6O90I9nLJNqNXzllCrEQ8J+ipTgJ0F0/jDOWjiXvthb/rRAX4nduDZbb+EqirOwFq1VAL0HmEyaYyicc7JbvalBaXCu7zyOKVisIxoy7zh++IzhtxdmX4OI1Ix8h+g9xiir9PNTEomxby/9nEvr3EYckEP+3tYyL+1FXe2YNakmQVmPIY4Pzxx9NXLwBwEcdmXk82z+gWfc5jNeqyzjfUFMDePiTHO6/oZ2RReEIEnvIfb2YDte2ZLDmHPsRs+sfnQgFYjZRFjZxDtPh+5g5JVYQxGAKRUal8H4jzodP+NAUFRETBeyC8EojetqiznW63WOkKe28IlIuRvFrPBaelJ1NvBwWGyKtbFj3RahdPCST4pdXTKzlDIhko92HhJ4XGboR9b2Kdqmjl2Qp5zemPGwd4pxch5IM5j5ar1sYlJKcnXr57bwe28PWA03N9I8TcH9fW0QFW3qgocCifIZZMc/OO1AtErzGYD9N23F1ptqN15k9DSeCFYoxLfux9F80FRMybkN5zKSk+hvfFq7nP//Mcfvzp5PL9059aNb23dlOqy8FKrxDJgxgvsWFHB57M7s9JSgRnn9HJvZJmMGtLcSeT0SUnfeR6nxKvTe/W0WA5MeExnRy32q6czjwITrhm4e/uwxey60TQZ1RatRoJo1SKuVi3mdHfefAU87hRvnR4d7sNeeO6p4uyM9Z7/OiBAGt6zeHCA8xOs68Wkp0sE6mmRx05PjPdjL+ftrs7akOz8rMwVXWzWMZNxxv3xD05FWaHLrkPlodPC/i7spYO7WZkbkhfeeNRWFx5QKsZngE1SbpQXuXTaXXgQR2O1NVewnJ0ZXz6ZluT6TMMTvvjs3aTe7kY23iuCKeZTcdX1SrtyWjUtxT45dVyZkZb4ArjdNzyeupZafPFfRwYEnGlnJ1LunHYWHkajBiu59LVt/7PZF9etjlkGbvU927ekhXzz1Qd/aW2plup102B6DLt2pcC100qRI08TYSARD2Lnz346u3/v9uLHkuK9LnMX/GNjakIcPX1Typ6du57Ki4iMzmFVVIz+t+jaFnB5Hi1N1/4kFI68j/T2dLS3dd8wGExX+EPjSnDZCyDofzRoPO+k4gwnAAAAAElFTkSuQmCC
'@

# Create a streaming image by streaming the base64 string to a bitmap streamsource
$Githubbitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$Githubbitmap.BeginInit()
$Githubbitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($githubicon)
$Githubbitmap.EndInit()

# Freeze() prevents memory leaks.
$Githubbitmap.Freeze()

$imgGithub.Source = $Githubbitmap

# Base64 representation of Icon file from mmcndmgr.dll Index 0
$OUpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAUrSURBVFhH7Zd7TJVlHMdtq9ZWIEyBuUAEQYutOhS51tJs2Wazi80uVixzsHVzbi3LodwEBLkGiJqIpBkzScp0ioJFaXEXkIsgcgnkfrgjyOEIv76/533fc14OL8fm/KM/erbP3ud9nt/z/X5/D4dxmPP/uJuj8tRnb7Xl+tO17I9n0JLzCfHehQw/X5TeD+4Rh+7mYIOhq2lWqT0fQih1BBxi+ij65fPA5ryviGn67UtqxFNiKzX9vpWaLwRQy8Xt1JofRO2FodRZHEbdlyJIX7HLBJtYjm1ZRF8cbDQFyNzz3gbY2QDzLbD5QFUI/Zn56R1RfnIztf6xhXoKttBQb/M0YrMaKSC1ROwx1TkBfAsLwH3CnEd/VazomsbOE40yuSCH6MZZkE00wpzRpDZ7E+Uc/NAU4nbIATzBg8KchzA3lhF1JBJ1JYFkGZ6DTswV2lFz/WuiVsBPhOgo2UFHol+lo3FrKTNxHf2c8g6d+3Yj5WV8hBvaRAVZmwWqAF7AVpjz4BugiVKIw6yDDWdBmAM2VwK0g7FfpVvjWxk8TtT/gyb5x/ysBDAUSYJtLAoTgWzAa7x3PQHGQMzV6wryfku8DL/Le6gdrI0SPy5YagQY/0s6oD6k0AoxgWzARoqZMGSw/3ecRDPD7xzCjPUAY3nmYj6oPqwYTYNrJLMpTeIlUMNwndUAU6PnUIQgAqULwAJCUIMm0BhLk40xMjwHTWamFLBuPcDwCSIUMVMNEpMyUxAXCLE4mICGOLp1LQZEmzDK8HyyQQY1CtYDDGZKQvUssMuEsZ6fbASRegQCijHvTVxVE0UTdVFkAEboSPtYk/etB+j/Xhw04ICCEYdEIAt4nQVFPRiHsBoDmKibvn/zSpT1AJO9380Ugoi5O9yGjNLleG2kxBULxPlIYTpWE2nCaoBbPek4gEPVO2UkMQOEuCNmHILMzRoWVomjXlATIRitZnbSjSomwsRtAqTRKIoY5QCLqDsYq+F3CZNBZQSNWKA2Vq8PoqFZAxg796MonIYvh4snI0LIQSRDORybqIQtGRZP1gqjoQoJng/gVjUD6C/HkLF977TikcowmHAQtbgUjEMyQxUKZiOBbDysXitHAITXDNBdFk2Gtt3mYhnFyAy6A5Z1CoMVOwTKfKAclEn0gz6c1QzQUYJfmbYk+aBaVN0lKJcYnAHOqRgAbNh/KZT61EBTM0BrAT7p+AMkEqspgxgji3I4gWKk7Ku6NFEaSr1AXxpC+hKJPqxrBmi8GEGGFgRAgUSooF9GWlMbTkfqFlcMQwV9cbCgB3QXBVNXUZAIpBmgLi8MARJmXhnMGTYwh1N1CVO1cS93C3rQbTeM2bSr0ExvySwBqnNDaRw3oO5AYBnIYr0XRoy+BN0C0a0wBoWB1FkQSB35ZvTFIXR6v+/MALmH/SnnkD++x/nR2fSNdAYpTx/YQKdSP6CT3/jSiX3v00973qXjKevpx+S36Vjim3Q0YR1lxL9BR2LX0uHo1+hQ1CuUHrmG0iJeptTw1bQv9CXaG7yKUoJepN2BL1Dy9pWUtG0lJQY8PzPAUg9HGx+dy1JPdwedp9t8ndcSR28vT+AxD8zH3El+d/Re7rNo2eurHn129Yolzzz9uLPPI4sdnvRwnafzWGinW+xsI3B3ttWt8Fm4zM3Z3tvdxV7n5mwn8bCtztnpoSdguQiYvxVj3At4Ye6/wc72AbvlPq4O69c85vTcU64OLgvm2mvVWYG92POOB/9Xo4Xl0Fr7r4w5c/4B2rPd2qevIDUAAAAASUVORK5CYII=
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 60
$Computerpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAACqSURBVFhH7Y5BCsMwEAPzdD/NP3Mj1JCQlevQlaEUj5mbV9K26NAm+JhWa7WLXMaPkQFZkcv4MfejhMUxoCV0DWj34Kf+zYCvXQPWgDUgPaCkTQ1wilzGj5EBWZHL+M8cH2faRS53ix7WReSBW/SwLiIP3KKHdZHz0/tdD0fivqf4Jzk/lf3T7vXQJXpYF5EHbtHDuog8cIse1kXkgVv0sE5zfJjp4pfYthfqvQdyNdrtOAAAAABJRU5ErkJggg==
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 66
$Containerpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEISURBVFhH1Y4BboQwEAP5/6v42bUOu9U2nQQHaE8daaQ7sL1s/43XRR/htYo6R/U+MemjzlG9T0z6qHNU7xOTPuqEt4lJH3X2fW/qd3iJmPRRJ49X9Ty0iUkfdeh4VZlwSkz6qEMHq8oUh8Skjzp0sKpMJ0LBU+lglTqfIrPCD/tDJPVCxC03a5akThFZGqJsSvlOBMdSva9SRva5gQgO9io3yuY7QwRHRypfO/nfFPl2wFW9CyJ4wFHdRREcd1R3wSE47qiu6RQcd1TX8JQWpANnZnfiEq1Eh0ZmZ+Bl2gAd7M0s+AhtjA6nmel8nDZsfsCv0o5MPuDP+PqQ/K2H7+Ctxx9g2z4AyFihLQt96+cAAAAASUVORK5CYII=
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 95
$DomainDNSpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAADuSURBVFhH7ZZRDoQgDEQ9OkfzZq6P2tishcJKzJowyQsEpkztl8s/a/uRIdrWde2GuoNbch+PoC6ldLsBfaAbwoc04H1dBHWzgYBmuQE1qAGRv6pnJ5QbUgJ/SvVwXfHhzykVqakZaaAeztrcgPelJfDzsJ2C7rUxvQf8OaUiN6gEfg2ykrNrE/hzSkVuUAn8+rjo3Mt63gP+nFKRG1QCvwZZydlbJ9CLBlnJ2Vsn4AWVwK9BVnI2JzAn8MAEgBrFm4C93wnlhkRQZ/6GvumSGxBB3fwnfLyBPSXDnroR4egS1AJ1B0NkH+zhjVqWDwWbZLRmE0YzAAAAAElFTkSuQmCC
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 59
$Grouppng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFWSURBVFhH7ZFRkoMwDEM5OkfjZu0KolQxckiAz9XMG2diWwrt8lCfCV6VCxhlWs7kKUNyi2/SlVt4m1Ru+Dbbtn0gVCA9Kx14jIazll6qxmAUDZCQescqPau6OIMGsOKeZ61lJ1U1nQHSID4ghCqp3HAXSMMh3OsdxlCP876XigOXaAAU+1CcQQVlxqoxcdAoVrQ0wM2wFi8rNk/0DGMFVzvF96QaGOHiaHU7vC9Y6UCDGo1W7PHMWvxS1cAMGmVVQuodq/RS1eUeNMxqb6Z4dFWDHDTKKkN4jhSfrmqYAyYMy6rbE4bkFpuQHphd13Wn7N6WDYe0F+HMKw+AYrgGMMTNvPIAZ6z1F7La3pNH7KbOWOsvAH/LMd/26gPIkP4GYUho1PtKcJ5vfcD1I8JC5DCG2q9UdJbn+guArsrCFS5Qe00gGFZYjOaRe185o2jc4183tCxfI3xJToZZFYUAAAAASUVORK5CYII=
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 58
$Userpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAECSURBVFhH7ZFBDsMwCATz9DwtP0tDDNWCwDXY6SkjjahkvGs120uBM+FSvIJRp/FCs5bxwqqm8UJmTOOF/PQ4jpOgScJZCrw4LJbL5LM0KnhUKZX51wdIKU4+K6HCewalaAkvSEnYcpp0RLP9vndLfIusXmk0Sb6XRpWiEj46+V4aVYqOlNrJd1OoUk8JjyYUk2nwcqiURZP3yqgyq5RE8/EH9Mpl8u4UqlTEkp68vwS3nMAzx2XcZbZc5r7vt7TX1tcTluMjaK+tr0WCu4946gFXIH1nkUqa9hFPfIYrCMut7SGE+QfQKa4Ar9iKhe5ZGQlgbbgVd9TdZdjgni8DbNsHGNd/8V9LX0IAAAAASUVORK5CYII=
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 126
$Otherpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAErSURBVFhH1ZABjsMwCATzdD8tP2s1GCMUNQY3JFVXQtu7sDvI27/qpfMTvbrsiEcPMbh3/q9zqwR2hHtnR6dcBsk4+zolktII+snJ6nwtK7vi9OgsScJR+YrT2atjWajK6dQJZaEqp7O1ljrAQlVOJ/DWci8gSyN81eka8IUXsEvld9e6k/fw9Avs+y4FOH8zXXknc4QvvYA/YhSOb13nzt4n+FcvcHS+M11rcFzzU0nR7IgBGrtdMRzX3FQh3Dv7YyI4rrtTpeHeyUVwnD2hTJSGeicXwXH2hDJRGuqdXATH2RPKRGmod3IVcJSGeidXAUdpqHdyFXAkgQzUO5kKuJeEM3Cc3Uq4lxRFR7BzB9xLSs+O4NudcC8BnL2Afn9EAvMvoPO4LsK37Q0ZagAN4BkscgAAAABJRU5ErkJggg==
'@

# Base64 representation of Icon file from shell32.dll Index 234
$excludepng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAANTSURBVFhH7ZZLTxNRGIbnBwBFQcFLjD8B2erCGBUFGveujCuNG68ovwBR8IKgK9yCeElASltughZFRRAXGAKllrZUoPTCRmNsPt93phchpZ0ZcOeXvGkaynme882Zc47yvzLV6qRVVj9bJaamWmITWqLMeDJVEvn0V8a0hMcqJfwxnZUPaiYSQ+srwiX4yGQeiiwwLUizSMSpSiSG1lecOQeLe2oxQN86QLasgy88EAlD4P1JowLV6oDGBDLAAxRwSMiwAJ41B9UvsAE80AQB+78WyAIP3NcERg0KcLVz8NwCOeCBeyIrZgTwmhGQXUAH3E+BHlneegGdcP9dCNhk+d0JowJVKiizgAG4/445Ae5smQUMwrdWwATc1wiBbll6u2kBk3BfAwRemhDAobJGwCzcd3uzAjcSAibh/FsIAiMGBXiksu3xOQr06oLHnDUysHe/xBzXNDgTwP+FumTRdVQWRyrKOPYLpbAM8fBThWUqnuNse3zuOgScuuD9BaXiVbbLG3zGHFe1Lix1yM+5BllyHYFExcTAgX2HnUphZBq/68Tn840kNIGWtECOtnPmhEeVIllGhiERHaiX+GK7hEet8mvqvATarNKfVyw+/G4B+Yo8QycSyLWlCTRDoEY9z3M9c7adMyc8jCwiQ5Y94gf0x5ezEu0+J4MFJSk4Ze3oAAQyd4A3GLY97qaAIys8ueDYds6c8BASBGQwf4d46k8Zg7NUAbQ97saCwnGaC65m/pZEHZdlCBKELyEBxKVsMwZnaQJNaQEdcJmvR25K1H5JXkGC8O8IZZLwXqyBnHAW73Bse9yN1YzzXC9cjbdOvI2n1Zkn4ZQZxvfJ2nJ9+wGvUGy7JtBjCB61X8QzL021nXA/4kGc6MBTPR1QBdD2uPsKBGym4Ww7Z074POJGbFgDHYoluwSvUGx7SsAkvC+/WDx1ldKHt4Dwb8gMhLoVS+RJNglNwHzbCe+37BZva7n8nrogkc4z4izYqcLnkGmkCxLtG0nwDsdLRDI8zVLBwYJ9XYtLi21XCQZNw7naZx8fkuDr4xIcZo7JTOtBsecVqfBZZBxpUyyZd0KjxYOFezu312zvOdvOmROOdRCBQO4Fqbd4sADsyfWes+2cuQZXlD9Le+RDT9WknQAAAABJRU5ErkJggg==
'@

# Base64 representation of Icon file from mmcndmgr.dll Index 6
$Expandpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABCSURBVFhH7c6xDQAgFALRv//SusAVxKCN9xJaYCTp0II85YG/DtBYmgoqTlNBxWkqqDhNBRWnuebpGPGABySpZGYDyjh8hAYS3OQAAAAASUVORK5CYII=
'@

# Base64 representation of Icon file from shell32.dll Index 238
$refreshpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAPkSURBVFhH7Vc7UxNRFOYXKOIDeagQIA9C2M0mAbTiJ/ATQHkEMGHxgcyIEJ8zykjUUUEt0t0iKZzZJiVFipQpaCgyk4bCLj/h+J3lbtwkuyTY6pn5ZvZx7zln755zv+92/LN2YU50ysv2zXdfzIysiszwqij5Hhrk38iTD/A+ztPNuCj1L4lM35KYkcNd7eKcyCCBaXl7to0mRGcgIVKBtWxVeV6gaPqY7vz45YjoxzL5nxWofyVbvb4gUt0LzV/ZeVdkuu8b1FYCY0mhBhOiEn5VpKn9E7r9/VdbmMRYf6pIPcu5yrV5oUp3HZcQPPC6RMPbxdYJhNbE7PiGQbFPZZqC079B+EOZ+pMGXZ0Xs5fvnQbn50OtElAQXHli0AS+ZBIT7OBn4d0jCr0o0phE8HmRlHdHFPvaPJ6f9SEJDm49G3p2RgKqLlSVg2PixDcElGBHoVSBfMlcBUWYHloR0x5gYFlM34qL6Rtxkb65mqvw0kcb5jbC0yKBShTFFMNACxHccxGiC3Q5zNX6FoV+I/GzqqbrfdjhmkBYFykNBRc9QEVLaPiPo3q2ik6oFVMr61kUam88S9qXkzpfFgbdEtAeZqsRLF8Eg0zAQRDB0YptB2dDAmbB1fw0wDEBbV3MaC8KpGGABeUlCizZetnthl9gBrf7acTAlkMCkXWRCe8dU3gf7cP4jKJbz1Xk67aMd0IOXvPhArcEDnnDYaj4cmX7kLARpeXrloYuyAzoBnl3ijTCQK/zhsM9z23HhcdLz+heyzvXwH/7ty22laeJN0WKvcZGJBEBeGNiWMUZeGQQtuKMnNbSQERpz+ahWZxWgUIPHMrXf4yDO3G8HdrbErEgkVPasuvxXGXy4KTmQ3l/zAk0dxcn4MTtFjg4uOBcwaEFdB++2O7H87TACTSrphgSaORzCxzcf87gUENqTzxbjYG+LT983bWYrcoh9cb/3s7jFpj/QUacwHnJqMqCxO6LNyZIspQcVm+cgBN3M5ieRx/8bIuOe0HHfctZk47tPhTcQ5K5b+1c9U7cbYFFxjjUj9cmSAYhRmqCZOlUkHghSplR7XP5vidhUNe9M1bRbD0wFYP/uQI9GHXgc6Zoll8swxijUEABIPT2yHzXOJ41QS+CQxPOylDOxj3PXG0GXxOZUFLMhpAEC5JGPm8X43tlUw9egSiVYdwtwhsOgkOS1aodWkAN6rkKLz1/iRO3O4GpnNkQnVAny880bdMgSDLHVuODiR+aMLhTMIvJieMZY7vHNLJVIC5Ct4OJq7EgkZeu5rWOZiuixMexEWD4UZ486wZBD5wezRZbH83+2x/r6PgNVo1XtD2bLOEAAAAASUVORK5CYII=
'@


$txtTempFolder.Text = $CurrentFSPath
$global:bolTempValue_InhertiedChkBox = $false
[void]$combReturns.Items.Add('ALL')
[void]$combReturns.Items.Add('NEW')
[void]$combReturns.Items.Add('MATCH')
[void]$combReturns.Items.Add('MISSING')

[void]$combServerity.Items.Add('Critical')
[void]$combServerity.Items.Add('Warning')
[void]$combServerity.Items.Add('Medium')
[void]$combServerity.Items.Add('Low')
[void]$combServerity.Items.Add('Info')

[void]$combRecursiveFind.Items.Add('*')
[void]$combRecursiveFind.Items.Add('User')
[void]$combRecursiveFind.Items.Add('Group')
[void]$combRecursiveFind.Items.Add('Computer')
$combRecursiveFind.SelectedValue = '*'

[void]$combReturnObjectType.Items.Add('*')
[void]$combReturnObjectType.Items.Add('user')
[void]$combReturnObjectType.Items.Add('group')
[void]$combReturnObjectType.Items.Add('computer')
[void]$combReturnObjectType.Items.Add('msds-groupmanagedserviceaccount')
$combReturnObjectType.SelectedValue = '*'

[void]$combAccessCtrl.Items.Add('Allow')
[void]$combAccessCtrl.Items.Add('Deny')
[void]$combObjectDefSD.Items.Add('All Objects')
$combObjectDefSD.SelectedValue = 'All Objects'




    $Window.Add_Loaded({
            $Global:observableCollection = New-Object System.Collections.ObjectModel.ObservableCollection[System.Object]
            $TextBoxStatusMessage.ItemsSource = $Global:observableCollection
        })

    if ($PSVersionTable.PSVersion -gt '2.0') {

        try {
            Add-Type @'

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

'@
        } catch {
        }

    }


    try {
        Add-Type @'
  using System;
  using System.Runtime.InteropServices;
  public class SFW {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
'@
    } catch {
    }

    Add-Type -AssemblyName System.Windows.Forms | Out-Null


    $chkBoxShowDel.add_Checked({
            $global:bolShowDeleted = $true
        })

    $chkBoxShowDel.add_UnChecked({
            $global:bolShowDeleted = $false
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

    $rdbBase.add_Click({
            $txtDepth.IsEnabled = $false

        })

    $rdbDepth.add_Click({
            $txtDepth.IsEnabled = $true

        })

    $rdbOneLevel.add_Click({
            $txtDepth.IsEnabled = $false
        })

    $rdbSubtree.add_Click({
        $txtDepth.IsEnabled = $false
        })

    $rdbEXcel.add_Click({
            if (!$(Get-Module ImportExcel)) { 
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Checking for ImportExcel PowerShell Module...' -strType 'Info' -DateStamp ))
                if (!$(Get-Module -ListAvailable | Where-Object name -EQ 'ImportExcel')) {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'You need to install the PowerShell module ImportExcel found in the PSGallery' -strType 'Error' -DateStamp ))
                    $rdbOnlyHTA.IsChecked = $true
                } else {
                    Import-Module ImportExcel
                }

            }

        })
    $btnGetForestInfo.add_Click({

            if ($global:bolConnected -eq $true) {
                Get-SchemaData -CREDS $CREDS
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Information collected!' -strType 'Info' -DateStamp ))
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }
        })

    $btnClearExcludedBox.add_Click({
            $txtBoxExcluded.text = ''

        })
    $btnGetSchemaClass.add_Click(
        {

            if ($global:bolConnected -eq $true) {

                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])" 
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $SearchFilter = '(objectClass=classSchema)'
                $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", $SearchFilter, 'Subtree')
                [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
                $request.Controls.Add($pagedRqc) | Out-Null
                [void]$request.Attributes.Add('name')

                $arrSchemaObjects = New-Object System.Collections.ArrayList
                while ($true) {
                    $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

                    #for paged search, the response for paged search result control - we will need a cookie from result later
                    if ($global:PageSize -gt 0) {
                        [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
                        if ($response.Controls.Length -gt 0) {
                            foreach ($ctrl in $response.Controls) {
                                if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                                    $prrc = $ctrl;
                                    break;
                                }
                            }
                        }
                        if ($null -eq $prrc) {
                            #server was unable to process paged search
                            throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                        }
                    }
                    #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
                    $colResults = $response.Entries
                    foreach ($objResult in $colResults) {
                        [void]$arrSchemaObjects.Add($objResult.attributes.name[0])


                    }
                    if ($global:PageSize -gt 0) {
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
                foreach ($object in $arrSchemaObjects) {
                    [void]$combObjectDefSD.Items.Add($object)
                }
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'All classSchema collected!' -strType 'Info' -DateStamp ))
                $object = $null
                Remove-Variable object
                $arrSchemaObjects = $null
                Remove-Variable arrSchemaObjects
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }
        })



    $btnExportDefSD.add_Click(
        {
            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
            if ($global:bolConnected -eq $true) {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Scanning...' -strType 'Info' -DateStamp ))
                # Force UI update immediately
                $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [action]{})
    
                $strFileCSV = $txtTempFolder.Text + '\' + $global:strDomainShortName + '_DefaultSecDescriptor' + $date + '.csv'
                Write-DefaultSDCSV -fileout $strFileCSV -CREDS $CREDS
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Finished' -strType 'Info' -DateStamp ))
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }

        })

    $btnCompDefSD.add_Click(
        {
            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
            if ($global:bolConnected -eq $true) {

                if ($txtCompareDefSDTemplate.Text -eq '') {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'No Template CSV file selected!' -strType 'Error' -DateStamp ))
                } else {
                    $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked

                    $strDefaultSDCompareFile = $txtCompareDefSDTemplate.Text

                    if(Test-Path -Path $strDefaultSDCompareFile) {

                        if (Test-CSVColumnsDefaultSD $strDefaultSDCompareFile) {
                            $strSelectedItem = $combObjectDefSD.SelectedItem
                            if ($strSelectedItem -eq 'All Objects') {
                                $strSelectedItem = '*'
                            }
                            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Scanning...' -strType 'Info' -DateStamp ))
                            # Force UI update immediately
                            $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [action]{})

                            Get-DefaultSDCompare -strObjectClass $strSelectedItem -strTemplate $strDefaultSDCompareFile -CREDS $CREDS
                            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Finished' -strType 'Info' -DateStamp ))
                        } else {
                            $global:observableCollection.Insert(0, (LogMessage -strMessage "CSV file got wrong format! File:  $strDefaultSDCompareFile" -strType 'Error' -DateStamp ))
                        } #End if test column names exist

                    }
                }#end if txtCompareDefSDTemplate.Text is empty

            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }
        })

    $btnScanDefSD.add_Click(
        {
        
            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked

            $bolReplMeta = $true

            $strFileDefSDHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'
            #Set the path for the HTM file name
            if ($OutputFolder -gt '') {
                #Check if foler exist if not use current folder
                if (Test-Path $OutputFolder) {
                    $strFileDefSDHTM = $OutputFolder + '\' + "$global:strDomainShortName-$strSelectedItem-$global:SessionID" + '.htm'
                } else {
                    Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                    $strFileDefSDHTM = $CurrentFSPath + '\' + "$global:strDomainShortName-$strSelectedItem-$global:SessionID" + '.htm'
                }
            } else {
                $strFileDefSDHTM = $CurrentFSPath + '\' + "$global:strDomainShortName-$strSelectedItem-$global:SessionID" + '.htm'
            }

            if ($global:bolConnected -eq $true) {
                
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Scanning...' -strType 'Info' -DateStamp ))
                
                # Force UI update immediately
                $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [action]{})

                $strSelectedItem = $combObjectDefSD.SelectedItem
                if ($strSelectedItem -eq 'All Objects') {
                    $strSelectedItem = '*'
                }
                if ($chkBoxSeverity.isChecked -or $chkBoxEffectiveRightsColor.isChecked) {
                    $bolShowCriticalityColor = $true
                } else {
                    $bolShowCriticalityColor = $false
                }
                $bolSDDL = $rdbDefSD_SDDL.IsChecked
                if ($bolSDDL -eq $true) {
                    CreateDefaultSDReportHTA $global:strDomainFQDN $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath
                    CreateDefSDHTM $global:strDomainFQDN $strFileDefSDHTM
                    InitiateDefSDHTM $strFileDefSDHTM $strSelectedItem
                    InitiateDefSDHTM $strFileDefSDHTA $strSelectedItem
                } else {
                    CreateHTM $strSelectedItem $strFileDefSDHTM
                    CreateHTA $strSelectedItem $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                    Initialize-DefSDAccessHTM $strFileDefSDHTA $strSelectedItem $bolReplMeta $false '' $bolShowCriticalityColor
                    Initialize-DefSDAccessHTM $strFileDefSDHTM $strSelectedItem $bolReplMeta $false '' $bolShowCriticalityColor
                }

                Get-DefaultSD -strObjectClass $strSelectedItem -bolChangedDefSD $chkModifedDefSD.IsChecked -bolSDDL $rdbDefSD_SDDL.IsChecked -Show $true -File $strFileDefSDHTM -OutType 'HTML' -bolShowCriticalityColor $bolShowCriticalityColor -Assess $chkBoxSeverity.IsChecked -Criticality $combServerity.SelectedItem -bolReplMeta $bolReplMeta -CREDS $CREDS

                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Finished' -strType 'Info' -DateStamp ))

            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }



        })
    $btnGETSPNReport.add_Click(
        {
            If (($global:strEffectiveRightSP -ne '') -and ($global:tokens.count -gt 0)) {

                $strFileSPNHTA = $env:temp + '\' + $global:SPNHTMLFileName + '.hta'
                $strFileSPNHTM = $env:temp + '\' + "$global:strEffectiveRightAccount" + '.htm'
                CreateServicePrincipalReportHTA $global:strEffectiveRightSP $strFileSPNHTA $strFileSPNHTM $CurrentFSPath
                CreateSPNHTM $global:strEffectiveRightSP $strFileSPNHTM
                InitiateSPNHTM $strFileSPNHTA
                $strColorTemp = 1
                WriteSPNHTM $global:strEffectiveRightSP $global:tokens $global:strSPNobjectClass $($global:tokens.count - 1) $strColorTemp $strFileSPNHTA $strFileSPNHTM
                Invoke-Item $strFileSPNHTA
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'No service principal selected!' -strType 'Error' -DateStamp ))

            }
        })

    $btnViewLegend.add_Click(
        {

            DisplayLegend

        })


    $btnGetSPAccount.add_Click(
        {

            if ($global:bolConnected -eq $true) {

                If (!($txtBoxSelectPrincipal.Text -eq '')) {
                    GetEffectiveRightSP $txtBoxSelectPrincipal.Text $global:strDomainPrinDNName -CREDS $CREDS
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'Enter a principal name!' -strType 'Error' -DateStamp ))
                }
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }
        })



    $btnListDdomain.add_Click(
        {

            if($rdbCustomNC.IsChecked)
            {
                $SelectedServer = $txtBoxDSServer.Text
                $SelectedServerPort =$txtBoxDSServerPort.Text

                if ($SelectedServer -eq '') {
                    if ($SelectedServerPort -eq '') {
                        $CustomLDAPServer = ''
                    } else {
                        $CustomLDAPServer = 'localhost:' + $SelectedServerPort
                    }
                } else {
                    if ($SelectedServerPort -eq '') {
                        $CustomLDAPServer = $SelectedServer
                    } else {
                        $CustomLDAPServer = $SelectedServer + ':' + $SelectedServerPort
                    }
                }

            }

            if (($chkBoxCreds.IsChecked) -and ($null -eq $script:CREDS )) {
                $script:CREDS = Get-CredentialsUI
            }            

            GenerateDomainPicker -CREDS $script:CREDS -server $CustomLDAPServer
            $txtBoxDSServer.Text =  $global:PickedDDomainName 
            $txtBoxDomainConnect.Text = $global:strDomainSelect

        })

    $btnListLocations.add_Click(
        {

            if ($global:bolConnected -eq $true) {
                GenerateTrustedDomainPicker -CREDS $CREDS
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Connect to your naming context first!' -strType 'Error' -DateStamp ))
            }
        })


    $chkBoxScanUsingUSN.add_Click(
        {
            If ($chkBoxScanUsingUSN.IsChecked) {
                $global:bolTempValue_chkBoxReplMeta = $chkBoxReplMeta.IsChecked
                $chkBoxReplMeta.IsChecked = $true

            } else {
                if ($null -ne $global:bolTempValue_chkBoxReplMeta) {
                    $chkBoxReplMeta.IsChecked = $global:bolTempValue_chkBoxReplMeta
                }

            }
        })

    $chkBoxCompare.add_Click(
        {
            If ($chkBoxCompare.IsChecked) {
                if ($null -ne $global:bolTempValue_InhertiedChkBox) {
                    $chkInheritedPerm.IsChecked = $global:bolTempValue_InhertiedChkBox
                }

                if ($null -ne $global:bolTempValue_chkBoxGetOwner) {
                    $chkBoxGetOwner.IsChecked = $global:bolTempValue_chkBoxGetOwner
                }

                $chkInheritedPerm.IsEnabled = $true
                $chkBoxGetOwner.IsEnabled = $true
                #Activate Compare Objects
                $txtCompareTemplate.IsEnabled = $true
                $combReturns.IsEnabled = $true
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
                $chkBoxProperty.IsEnabled = $false
                $chkBoxTrustee.IsEnabled = $false
                $chkBoxPermission.IsEnabled = $false
                $chkBoxPermission.IsChecked = $false
                $txtPermission.IsEnabled = $false
                $chkBoxFilterBuiltin.IsEnabled = $false
                $chkBoxType.IsChecked = $false
                $chkBoxObject.IsChecked = $false
                $chkBoxProperty.IsChecked = $false
                $txtBoxObjectFilter.IsEnabled = $false
                $txtBoxPropertyFilter.IsEnabled = $false
                $txtFilterTrustee.IsEnabled = $false
                $combAccessCtrl.IsEnabled = $false

            } else {
                #Deactivate Compare Objects
                $txtCompareTemplate.IsEnabled = $false
                $combReturns.IsEnabled = $false
                $chkBoxTemplateNodes.IsEnabled = $false
                $chkBoxScanUsingUSN.IsEnabled = $false
                $btnGetCompareInput.IsEnabled = $false
                $txtReplaceDN.IsEnabled = $false
                $txtReplaceNetbios.IsEnabled = $false
            }

        })
    $chkBoxEffectiveRights.add_Click(
        {
            If ($chkBoxEffectiveRights.IsChecked) {

                $global:bolTempValue_InhertiedChkBox = $chkInheritedPerm.IsChecked
                $global:bolTempValue_chkBoxGetOwner = $chkBoxGetOwner.IsChecked
                $chkBoxFilter.IsChecked = $false

                #Deactivate Compare Objects
                $chkBoxCompare.IsChecked = $false
                $txtCompareTemplate.IsEnabled = $false
                $combReturns.IsEnabled = $false
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
                $chkBoxGetOwner.IsChecked = $true

                $chkBoxType.IsEnabled = $false
                $chkBoxObject.IsEnabled = $false
                $chkBoxProperty.IsEnabled = $false
                $chkBoxTrustee.IsEnabled = $false
                $chkBoxPermission.IsEnabled = $false
                $chkBoxPermission.IsChecked = $false
                $txtPermission.IsEnabled = $false
                $chkBoxType.IsChecked = $false
                $chkBoxObject.IsChecked = $false
                $chkBoxProperty.IsChecked = $false
                $chkBoxFilterBuiltin.IsChecked = $false
                $txtBoxObjectFilter.IsEnabled = $false
                $txtBoxPropertyFilter.IsEnabled = $false
                $txtFilterTrustee.IsEnabled = $false
                $combAccessCtrl.IsEnabled = $false

            } else {

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


    $chkBoxSeverity.add_Click(
        {
            If ($chkBoxSeverity.IsChecked -eq $true) {
                $combServerity.IsEnabled = $true
            } else {
                $combServerity.IsEnabled = $false
            }
        })


    $chkBoxRecursiveFind.add_Click(
        {
            If ($chkBoxRecursiveFind.IsChecked -eq $true) {
                $combRecursiveFind.IsEnabled = $true
            } else {
                $combRecursiveFind.IsEnabled = $false
            }
        })

    $chkBoxFilter.add_Click(
        {


            If ($chkBoxFilter.IsChecked -eq $true) {
                #Deactivate Compare Objects
                $chkBoxCompare.IsChecked = $false
                $txtCompareTemplate.IsEnabled = $false
                $combReturns.IsEnabled = $false
                $chkBoxTemplateNodes.IsEnabled = $false
                $chkBoxScanUsingUSN.IsEnabled = $false
                $btnGetCompareInput.IsEnabled = $false
                $txtReplaceDN.IsEnabled = $false
                $txtReplaceNetbios.IsEnabled = $false

                $chkBoxEffectiveRights.IsChecked = $false
                $chkBoxType.IsEnabled = $true
                $chkBoxObject.IsEnabled = $true
                $chkBoxProperty.IsEnabled = $true
                $chkBoxTrustee.IsEnabled = $true
                $chkBoxPermission.IsEnabled = $true
                $txtPermission.IsEnabled = $true
                $chkBoxFilterBuiltin.IsEnabled = $true
                $txtBoxObjectFilter.IsEnabled = $true
                $txtBoxPropertyFilter.IsEnabled = $true
                $txtFilterTrustee.IsEnabled = $true
                $combAccessCtrl.IsEnabled = $true
                $txtBoxSelectPrincipal.IsEnabled = $false
                $btnGetSPAccount.IsEnabled = $false
                $btnListLocations.IsEnabled = $false
                $btnGETSPNReport.IsEnabled = $false
                $chkBoxGetOwner.IsEnabled = $true
                if ($null -ne $global:bolTempValue_chkBoxGetOwner) {
                    $chkBoxGetOwner.IsChecked = $global:bolTempValue_chkBoxGetOwner
                }

            } else {
                $chkBoxType.IsEnabled = $false
                $chkBoxObject.IsEnabled = $false
                $chkBoxProperty.IsEnabled = $false
                $chkBoxTrustee.IsEnabled = $false
                $chkBoxPermission.IsEnabled = $false
                $chkBoxPermission.IsChecked = $false
                $txtPermission.IsEnabled = $false
                $chkBoxFilterBuiltin.IsEnabled = $false
                $chkBoxType.IsChecked = $false
                $chkBoxObject.IsChecked = $false
                $chkBoxProperty.IsChecked = $false
                $txtBoxObjectFilter.IsEnabled = $false
                $txtBoxPropertyFilter.IsEnabled = $false
                $txtFilterTrustee.IsEnabled = $false
                $combAccessCtrl.IsEnabled = $false
            }
        })

    $rdbDSSchm.add_Click(
        {
            If ($rdbCustomNC.IsChecked -eq $true) {
                $txtBoxDomainConnect.IsEnabled = $true
                $btnListDdomain.IsEnabled = $true
                if (($txtBoxDomainConnect.Text -eq 'rootDSE') -or ($txtBoxDomainConnect.Text -eq 'config') -or ($txtBoxDomainConnect.Text -eq 'schema')) {
                    $txtBoxDomainConnect.Text = ''
                }
            } else {
                $btnListDdomain.IsEnabled = $false
                If ($rdbDSdef.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = $global:strDomainSelect
                    $btnListDdomain.IsEnabled = $true
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false

                }
                If ($rdbDSConf.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'config'
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false


                }
                If ($rdbDSSchm.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'schema'
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false

                }
                $txtBoxDomainConnect.IsEnabled = $false
            }



        })

    $rdbDSConf.add_Click(
        {
            If ($rdbCustomNC.IsChecked -eq $true) {
                $txtBoxDomainConnect.IsEnabled = $true
                $btnListDdomain.IsEnabled = $false
                if (($txtBoxDomainConnect.Text -eq 'rootDSE') -or ($txtBoxDomainConnect.Text -eq 'config') -or ($txtBoxDomainConnect.Text -eq 'schema')) {
                    $txtBoxDomainConnect.Text = ''
                }
            } else {
                $btnListDdomain.IsEnabled = $false
                If ($rdbDSdef.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = $global:strDommainSelect
                    $btnListDdomain.IsEnabled = $true
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false

                }
                If ($rdbDSConf.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'config'
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false


                }
                If ($rdbDSSchm.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'schema'
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false


                }
                $txtBoxDomainConnect.IsEnabled = $false
            }



        })



    $rdbDSdef.add_Click(
        {
            If ($rdbCustomNC.IsChecked -eq $true) {
                $txtBoxDomainConnect.IsEnabled = $true
                $btnListDdomain.IsEnabled = $false
                if (($txtBoxDomainConnect.Text -eq 'rootDSE') -or ($txtBoxDomainConnect.Text -eq 'config') -or ($txtBoxDomainConnect.Text -eq 'schema')) {
                    $txtBoxDomainConnect.Text = ''
                }
            } else {
                $btnListDdomain.IsEnabled = $false
                If ($rdbDSdef.IsChecked -eq $true) {
                    $txtBoxDSServerPort.IsEnabled = $false
                    $txtBoxDSServer.IsEnabled = $false
                    $txtBoxDomainConnect.Text = $global:strDomainSelect
                    $btnListDdomain.IsEnabled = $true


                }
                If ($rdbDSConf.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'config'


                }
                If ($rdbDSSchm.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'schema'


                }
                $txtBoxDomainConnect.IsEnabled = $false
            }



        })


    $rdbCustomNC.add_Click(
        {
            If ($rdbCustomNC.IsChecked -eq $true) {
                $txtBoxDSServerPort.IsEnabled = $true
                $txtBoxDSServer.IsEnabled = $true
                $txtBoxDomainConnect.IsEnabled = $true
                $btnListDdomain.IsEnabled = $true
                if (($txtBoxDomainConnect.Text -eq 'rootDSE') -or ($txtBoxDomainConnect.Text -eq 'config') -or ($txtBoxDomainConnect.Text -eq 'schema')) {
                    $txtBoxDomainConnect.Text = ''
                }
            } else {
                $btnListDdomain.IsEnabled = $false
                If ($rdbDSdef.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = $global:strDommainSelect
                    $btnListDdomain.IsEnabled = $true

                }
                If ($rdbDSConf.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'config'


                }
                If ($rdbDSSchm.IsChecked -eq $true) {
                    $txtBoxDomainConnect.Text = 'schema'


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
            if ($chkBoxCreds.IsChecked) {
                if(($null -eq $script:CREDS) -or ($script:CREDS -eq '')) {
                    $script:CREDS = Get-CredentialsUI
                }
            }

            $global:bolRoot = $true

            $global:DSType = ''
            $global:strDC = ''
            $global:strDomainDNName = ''
            $global:ConfigDN = ''
            $global:SchemaDN = ''
            $global:ForestRootDomainDN = ''
            $global:IS_GC = ''
            $txtDC.text = ''
            $txtdefaultnamingcontext.text = ''
            $txtconfigurationnamingcontext.text = ''
            $txtschemanamingcontext.text = ''
            $txtrootdomainnamingcontext.text = ''
            
            If ($rdbDSConf.IsChecked) {
                $NamingContext = "Configuration"
            }

            If ($rdbDSSchm.IsChecked) {
                $NamingContext = "Schema"
            }

            If ($rdbCustomNC -and ($txtBoxDomainConnect.Text -eq '')) {
                $strNamingContextDN = 'rootDSE'
            } else {
                $strNamingContextDN = $txtBoxDomainConnect.Text
            }


            if (($null -eq $global:PickedDDomainName)  -or ($global:PickedDDomainName -eq '') ){
                $LdapServer = $txtBoxDSServer.Text
            } else {
                $LdapServer = $global:PickedDDomainName
                $global:PickedDDomainName = ''
            }
            
            $bolConnected = Connect-DirectoryServices -Base $strNamingContextDN -Server $LdapServer -Port $txtBoxDSServerPort.text -CREDS $CREDS -PreferSpecificDC:$PreferSpecificDC -NamingContext $NamingContext -UI ; Write-verbose "Calling Connect-DirectoryServices for server:$($LdapServer) at: $((Get-PSCallStack).ScriptLineNumber[0])"

            $lblSelectPrincipalDom.Content = $global:strDomainShortName + ':'

            If ($bolConnected-eq $true) {
                If (!($strLastCacheGuidsDom -eq $global:strDomainDNName)) {
                    $global:dicRightsGuids = @{'Seed' = 'xxx' }
                    CacheRightsGuids -CREDS $CREDS
                    $strLastCacheGuidsDom = $global:strDomainDNName


                }
                #Check Directory Service type
                $global:DSType = ''
                $global:bolADDSType = $false

                $global:observableCollection.Insert(0, (LogMessage -strMessage "Connected to directory service  $global:DSType" -strType 'Info' -DateStamp ))

                # If rootDSE , switch to default naming context
                
                if('rootDSE' -eq $strNamingContextDN ) {
                    $strNamingContextDN = $global:strDomainDNName
                } else {
                    $strNamingContextDN = $txtBoxDomainConnect.Text
                }

                If ($rdbDSConf.IsChecked) {
                    $strNamingContextDN = $global:ConfigDN
                }

                If ($rdbDSSchm.IsChecked) {
                    $strNamingContextDN = $global:SchemaDN
                }

                $global:TreeViewRootPath = $strNamingContextDN

                $xml = Get-XMLDomainOUTree $global:TreeViewRootPath -CREDS $CREDS
                # Change XML Document, XPath and Refresh
                $xmlprov.Document = $xml
                $xmlProv.XPath = '/DomainRoot'
                $xmlProv.Refresh()


                If (!(Test-Path ($env:temp + '\OU.png'))) {

                    $IconFilePath = $env:temp + '\OU.png'
                    $bytes = [Convert]::FromBase64String($OUpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)

                }
                If (!(Test-Path ($env:temp + '\Expand.png'))) {
                    $IconFilePath = $env:temp + '\Expand.png'
                    $bytes = [Convert]::FromBase64String($Expandpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\User.png'))) {
                    $IconFilePath = $env:temp + '\User.png'
                    $bytes = [Convert]::FromBase64String($Userpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\Group.png'))) {
                    $IconFilePath = $env:temp + '\Group.png'
                    $bytes = [Convert]::FromBase64String($Grouppng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\Computer.png'))) {
                    $IconFilePath = $env:temp + '\Computer.png'
                    $bytes = [Convert]::FromBase64String($Computerpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\Container.png'))) {
                    $IconFilePath = $env:temp + '\Container.png'
                    $bytes = [Convert]::FromBase64String($Containerpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\DomainDNS.png'))) {
                    $IconFilePath = $env:temp + '\DomainDNS.png'
                    $bytes = [Convert]::FromBase64String($DomainDNSpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\Other.png'))) {
                    $IconFilePath = $env:temp + '\Other.png'
                    $bytes = [Convert]::FromBase64String($Otherpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\refresh.png'))) {
                    $IconFilePath = $env:temp + '\refresh.png'
                    $bytes = [Convert]::FromBase64String($refreshpng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                If (!(Test-Path ($env:temp + '\exclude.png'))) {
                    $IconFilePath = $env:temp + '\exclude.png'
                    $bytes = [Convert]::FromBase64String($excludepng)
                    [IO.File]::WriteAllBytes($IconFilePath, $bytes)
                }
                #Test PS Version DeleteCommand requries PS 3.0 and above
                if ($PSVersionTable.PSVersion -gt '2.0') {

                    $TreeView1.ContextMenu.Items[0].Command = New-Object DelegateCommand( { Add-RefreshChild } )
                    $TreeView1.ContextMenu.Items[1].Command = New-Object DelegateCommand( { Add-ExcludeChild } )

                } else {
                    Write-Error 'Requries PS 3.0 and above'
                    break
                }
                #Update Connection Info
                $txtDC.text = $global:strDC
                $txtdefaultnamingcontext.text = $global:strDomainDNName
                $txtconfigurationnamingcontext.text = $global:ConfigDN
                $txtschemanamingcontext.text = $global:SchemaDN
                $txtrootdomainnamingcontext.text = $global:ForestRootDomainDN

            }#End If NCSelect


        })

    $chkBoxCreds.add_UnChecked({
            $script:CREDS = $null
        })

    $btnScan.add_Click(
        {

            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Scanning...Please wait!' -strType 'Info' -DateStamp )) 
             
            # Force UI update immediately
            $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [action]{})

            # Alternative shorter syntax:
            # [System.Windows.Forms.Application]::DoEvents()
            $UseCanonicalName = $chkBoxUseCanonicalName.IsChecked

            $Protected = $chkBoxGetOUProtected.IsChecked

            If ($chkBoxCompare.IsChecked) {
                RunCompare -CREDS $script:CREDS
            } else {
                RunScan -CREDS $script:CREDS
            }



        })

    $btnCreateHTML.add_Click(
        {
            if ($txtCSVImport.Text -eq '') {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'No Template CSV file selected!' -strType 'Error' -DateStamp ))
            } else {
 
                ConvertCSVtoHTM $txtCSVImport.Text $chkBoxTranslateGUIDinCSV.isChecked -CREDS $CREDS

            }

        })

    $btnSupport.add_Click(
        {
            GenerateSupportStatement
        })

    $btnExit.add_Click(
        {
            #TODO: Place custom script here

            $bolConnected = $null
            $bolTempValue_InhertiedChkBox = $null
            $dicDCSpecialSids = $null
            $dicNameToSchemaIDGUIDs = $null
            $dicRightsGuids = $null
            $dicSchemaIDGUIDs = $null
            $dicSidToName = $null
            $dicWellKnownSids = $null
            $myPID = $null
            $observableCollection = $null
            $strDomainPrinDNName = $null
            $strDomainSelect = $null
            $strEffectiveRightAccount = $null
            $strEffectiveRightSP = $null
            $strPinDomDC = $null
            $strPrincipalDN = $null
            $strPrinDomAttr = $null
            $strPrinDomDir = $null
            $strPrinDomFlat = $null
            $strSPNobjectClass = $null
            $tokens = $null
            $strDC = $null
            $strDomainDNName = $null
            $strDomainFQDN = $null
            $strDomainShortName = $null
            $strOwner = $null

            Remove-Variable -Name 'bolConnected' -Scope Global
            Remove-Variable -Name 'bolTempValue_InhertiedChkBox' -Scope Global
            Remove-Variable -Name 'dicDCSpecialSids' -Scope Global
            Remove-Variable -Name 'dicNameToSchemaIDGUIDs' -Scope Global
            Remove-Variable -Name 'dicRightsGuids' -Scope Global
            Remove-Variable -Name 'dicSchemaIDGUIDs' -Scope Global
            Remove-Variable -Name 'dicSidToName' -Scope Global
            Remove-Variable -Name 'dicWellKnownSids' -Scope Global
            Remove-Variable -Name 'myPID' -Scope Global
            Remove-Variable -Name 'observableCollection' -Scope Global
            Remove-Variable -Name 'strDomainPrinDNName' -Scope Global
            Remove-Variable -Name 'strDomainSelect' -Scope Global
            Remove-Variable -Name 'strEffectiveRightAccount' -Scope Global
            Remove-Variable -Name 'strEffectiveRightSP' -Scope Global
            Remove-Variable -Name 'strPinDomDC' -Scope Global
            Remove-Variable -Name 'strPrincipalDN' -Scope Global
            Remove-Variable -Name 'strPrinDomAttr' -Scope Global
            Remove-Variable -Name 'strPrinDomDir' -Scope Global
            Remove-Variable -Name 'strPrinDomFlat' -Scope Global
            Remove-Variable -Name 'strSPNobjectClass' -Scope Global
            Remove-Variable -Name 'tokens' -Scope Global



            $ErrorActionPreference = 'SilentlyContinue'
            & { #Try
                $xmlDoc = $null
                Remove-Variable -Name 'xmlDoc' -Scope Global
            }
            Trap [SystemException] {

                SilentlyContinue
            }

            $ErrorActionPreference = 'Continue'

            $Window.close()

        })



    $treeView1.add_SelectedItemChanged({

            $txtBoxSelected.Text = (Get-XMLPath -xmlElement ($this.SelectedItem))


            if ($this.SelectedItem.Tag -eq 'NotEnumerated') {

                $xmlNode = $global:xmlDoc

                $NodeDNPath = $($this.SelectedItem.ParentNode.Text.toString())
                [void]$this.SelectedItem.ParentNode.removeChild($this.SelectedItem);
                $Mynodes = $xmlNode.SelectNodes("//OU[@Text='$NodeDNPath']")

                $treeNodePath = $NodeDNPath

                # Initialize and Build Domain OU Tree
                ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath -CREDS $CREDS
                # Set tag to show this node is already enumerated
                $this.SelectedItem.Tag = 'Enumerated'

            }


        })


}#### End of if $base , check if UI should be loaded

<######################################################################

    Functions to Build Domains OU Tree XML Document

######################################################################>
#region
function RunCompare {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    if ($chkBoxSeverity.isChecked -or $chkBoxEffectiveRightsColor.isChecked) {
        $bolShowCriticalityColor = $true
    } else {
        $bolShowCriticalityColor = $false
    }
    If ($txtBoxSelected.Text -or $chkBoxTemplateNodes.IsChecked ) {
        #If the DC string is changed during the compre ti will be restored to it's orgi value
        $global:ResetDCvalue = ''
        $global:ResetDCvalue = $global:strDC

        $allSubOU = New-Object System.Collections.ArrayList
        $allSubOU.Clear()
        if ($txtCompareTemplate.Text -eq '') {
            $global:observableCollection.Insert(0, (LogMessage -strMessage 'No Template CSV file selected!' -strType 'Error' -DateStamp ))
        } else {
            if ($(Test-Path $txtCompareTemplate.Text) -eq $true) {

                if (($chkBoxEffectiveRights.isChecked -eq $true) -or ($chkBoxFilter.isChecked -eq $true)) {
                    if ($chkBoxEffectiveRights.isChecked) {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Can't compare while Effective Rights enabled!" -strType 'Error' -DateStamp ))
                    }
                    if ($chkBoxFilter.isChecked) {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Can't compare while Filter  enabled!" -strType 'Error' -DateStamp ))
                    }
                } else {
                    $global:bolCSVLoaded = $false
                    $strCompareFile = $txtCompareTemplate.Text

                    & { #Try
                        $global:bolCSVLoaded = $true
                        $global:csvHistACLs = Import-Csv $strCompareFile
                    }
                    Trap [SystemException] {
                        $strCSVErr = $_.Exception.Message
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to load CSV. $strCSVErr" -strType 'Error' -DateStamp ))
                        $global:bolCSVLoaded = $false
                        continue
                    }
                    #Verify that a successful CSV import is performed before continue
                    if ($global:bolCSVLoaded) {
                        #Test CSV file format
                        if (TestCSVColumns $global:csvHistACLs) {

                            $BolSkipDefPerm = $chkBoxDefaultPerm.IsChecked
                            $BolSkipProtectedPerm = $chkBoxSkipProtectedPerm.IsChecked
                            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
                            if (($rdbOnlyCSV.IsChecked) -or ($rdbOnlyCSVTEMPLATE.IsChecked)) {
                                $bolCSV = $true
                            } else {
                                $bolCSV = $false
                            }
                            if ($chkBoxTemplateNodes.IsChecked -eq $false) {
                                $sADobjectName = $txtBoxSelected.Text.ToString()

                                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                                $request = New-Object System.directoryServices.Protocols.SearchRequest
                                if ($global:bolShowDeleted) {
                                    [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                                    [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                                }
                                $request.DistinguishedName = $sADobjectName
                                $request.Filter = '(name=*)'
                                $request.Scope = 'Base'
                                [void]$request.Attributes.Add('name')
                                $response = $LDAPConnection.SendRequest($request)
                                $ADobject = $response.Entries[0]
                                if ($null -ne $ADobject.Attributes.name) {
                                    $strNode = fixfilename $ADobject.attributes.name[0]
                                } else {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not read object $($txtBoxSelected.Text.ToString()). Enough permissions?" -strType 'Error' -DateStamp ))
                                }

                            } else {
                                #Set the bolean to true so connection will be performed unless an error occur
                                $bolContinue = $true
                                if ($global:csvHistACLs[0].Object) {
                                    $strOUcol = $global:csvHistACLs[0].Object
                                } else {
                                    $strOUcol = $global:csvHistACLs[0].OU
                                }

                                if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                                }

                                if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                                    if ($global:strDomainDNName -ne $global:ForestRootDomainDN) {
                                        if ($global:IS_GC -eq 'TRUE') {
                                            $MsgBox = [System.Windows.Forms.MessageBox]::Show("You are not connected to the forest root domain: $global:ForestRootDomainDN.`n`nYour DC is a Global Catalog.`nDo you want to use Global Catalog and  continue?", 'Information', 3, 'Warning')
                                            if ($MsgBox -eq 'Yes') {
                                                if ($global:strDC.contains(':')) {
                                                    $global:strDC = $global:strDC.split(':')[0] + ':3268'
                                                } else {
                                                    $global:strDC = $global:strDC + ':3268'
                                                }

                                            } else {
                                                $bolContinue = $false
                                            }

                                        } else {
                                            $MsgBox = [System.Windows.Forms.MessageBox]::Show("You are not connected to the forest root domain: $global:ForestRootDomainDN.", 'Information', 0, 'Warning')
                                            $bolContinue = $false
                                        }
                                    }

                                }


                                if ($txtReplaceDN.text.Length -gt 0) {
                                    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                                }
                                $sADobjectName = $strOUcol
                                #Verify if the connection can be done
                                if ($bolContinue) {

                                    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                                    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                                    $request = New-Object System.directoryServices.Protocols.SearchRequest
                                    if ($global:bolShowDeleted) {
                                        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                                        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                                    }
                                    $request.DistinguishedName = $sADobjectName
                                    $request.Filter = '(name=*)'
                                    $request.Scope = 'Base'
                                    [void]$request.Attributes.Add('name')

                                    $response = $LDAPConnection.SendRequest($request)

                                    $ADobject = $response.Entries[0]
                                    $strNode = fixfilename $ADobject.attributes.name[0]
                                } else {
                                    #Set the node to empty , no connection will be done
                                    $strNode = ''
                                }
                            }
                            #if not is empty continue
                            if ($strNode -ne '') {
                                $bolTranslateGUIDStoObject = $false
                                $date = Get-Date -UFormat %Y%m%d_%H%M%S
                                $strNode = fixfilename $strNode
                                if($rdbOnlyCSVTEMPLATE.IsChecked) {
                                    $strFileCSV = $txtTempFolder.Text + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date +"_Template.csv" 
                                } else {
                                    $strFileCSV = $txtTempFolder.Text + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date +".csv" 
                                }
                                $strFileEXCEL = $txtTempFolder.Text + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.xlsx'
                                $strFileHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'
                                $strFileHTM = $env:temp + '\' + "$global:strDomainShortName-$strNode-$global:SessionID" + '.htm'
                                if (!($bolCSV)) {
                                    if (!($rdbEXcel.IsChecked)) {
                                        if ($chkBoxFilter.IsChecked) {
                                            CreateHTA "$global:strDomainShortName-$strNode Filtered" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                                            CreateHTM "$global:strDomainShortName-$strNode Filtered" $strFileHTM
                                        } else {
                                            CreateHTA "$global:strDomainShortName-$strNode" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                                            CreateHTM "$global:strDomainShortName-$strNode" $strFileHTM
                                        }

                                        InitiateHTM $strFileHTA $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $Protected $bolShowCriticalityColor $true $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked -bolCanonical:$UseCanonicalName $GPO
                                        InitiateHTM $strFileHTM $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $Protected $bolShowCriticalityColor $true $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked -bolCanonical:$UseCanonicalName $GPO

                                        $Format = 'HTML'
                                        $Show = $true
                                    } else {
                                        $Format = 'EXCEL'
                                        $Show = $false
                                    }
                                } else {
                                    if ($rdbOnlyCSV.IsChecked) {
                                        $Format = 'CSV'
                                    }
                                    if ($rdbOnlyCSVTEMPLATE.IsChecked) {
                                        $Format = 'CSVTEMPLATE'
                                    }
                                    $Show = $false
                                }
                                #Select type of scope
                                If ($rdbBase.IsChecked -eq $true)
                                {
                                    $Scope =  "base"
                                }
                                If ($rdbOneLevel.IsChecked -eq $true)
                                {
                                    $Scope =  "onelevel"
                                }
                                If ($rdbSubtree.IsChecked -eq $true)
                                {
                                    $Scope =  "subtree"
                                }

                                $IncludeInherited = $chkInheritedPerm.IsChecked

                                if($rdbDepth.IsChecked -eq $True) 
                                {
                                    if($txtDepth.text -match "^\d{1,3}$")
                                    {
                                        $Depth = $txtDepth.text
                                    }
                                    else
                                    {
                                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Depth does not meet the required range of 0-999!" -strType "Error" -DateStamp ))
                                        $bolDepthError = $true
                                    }
                                }

                                    If (($txtBoxSelected.Text.ToString().Length -gt 0) -or (($chkBoxTemplateNodes.IsChecked -eq $true)))
                                    {
                                        if(-not($bolDepthError))
                                        {

                                            if($rdbScanFilter.IsChecked -eq $true)
                                            {
                                                if($Depth)
                                                {
                                                    $allSubOU = GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CustomFilter $txtCustomFilter.Text -CREDS $CREDS -Depth $txtDepth.Text
                                                }
                                                else
                                                {
                                                    $allSubOU = GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CustomFilter $txtCustomFilter.Text -CREDS $CREDS
                                                }
                                            }
                                            else
                                            {

                                                $strFilterAll = '(objectClass=*)'
                                                $strFilterContainer = '(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=DomainDNS)(objectClass=dMD)))'
                                                $strFilterOU = '(|(objectClass=organizationalUnit)(objectClass=domainDNS))'
                                                $strFilterGPO = '(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gplink=*LDAP*))'

                                                If ($rdbScanAll.IsChecked -eq $true) {
                                                    $ReqFilter = $strFilterAll
                                                }
                                                If ($rdbScanOU.IsChecked -eq $true) {
                                                    $ReqFilter = $strFilterOU
                                                }
                                                If ($rdbScanContainer.IsChecked -eq $true) {
                                                    $ReqFilter = $strFilterContainer
                                                }
                                                if ($rdbGPO.IsChecked -eq $true) {
                                                    $ReqFilter = $strFilterGPO
                                                }

                                                if($Depth)
                                                {
                                                    $allSubOU = GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CREDS $CREDS -Depth $txtDepth.Text -CustomFilter $ReqFilter 
                                                }
                                                else
                                                {
                                                    $allSubOU = GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CREDS $CREDS -CustomFilter $ReqFilter
                                                }
                                            }
            

                                            #if any objects found compare ACLs
                                            if($allSubOU.count -gt 0)
                                            {			        
                                                $TemplateFilter = $combReturns.SelectedItem
                                                $bolToFile = $true
                                                #Used from comand line only
                                                $FilterBuiltin = $false
                                                Get-PermCompare $allSubOU $BolSkipDefPerm $BolSkipProtectedPerm $chkBoxReplMeta.IsChecked $chkBoxGetOwner.IsChecked $bolCSV $Protected $chkBoxACLsize.IsChecked $bolTranslateGUIDStoObject $Show $Format $TemplateFilter $bolToFile $bolShowCriticalityColor $chkBoxSeverity.IsChecked $combServerity.SelectedItem $chkBoxTranslateGUID.isChecked -DACL $rdbDACL.IsChecked -CREDS $CREDS
                                            }	
                                            else
                                            {
                                                $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects returned!" -strType "Error" -DateStamp ))
                                            }
                                            $global:observableCollection.Insert(0,(LogMessage -strMessage "Finished" -strType "Info" -DateStamp ))
                                        }
                                        else
                                        {
                                            $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not perform an LDAP search!" -strType "Error" -DateStamp ))
                                        }
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
            else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'CSV file not found!' -strType 'Error' -DateStamp ))
            }#End If Test-Path Else
        }# End If

        #Restore the DC string to its original
        $global:strDC = $global:ResetDCvalue
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'No object selected!' -strType 'Error' -DateStamp ))
    }
    $allSubOU = ''
    $strFileCSV = ''
    $strFileHTA = ''
    $strFileHTM = ''
    $sADobjectName = ''
    $date = ''
}

function RunScan {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    if ($rdbGPO.isChecked) {
        $GPO = $true
    }
    
    if ($chkBoxSeverity.isChecked -or $chkBoxEffectiveRightsColor.isChecked) {
        $bolShowCriticalityColor = $true
    } else {
        $bolShowCriticalityColor = $false
    }
    $bolPreChecks = $true
    If ($txtBoxSelected.Text) {
        If (($chkBoxFilter.IsChecked -eq $true) -and (($chkBoxType.IsChecked -eq $false) -and ($chkBoxObject.IsChecked -eq $false) -and ($chkBoxProperty.IsChecked -eq $false) -and ($chkBoxTrustee.IsChecked -eq $false) -and ($chkBoxFilterBuiltin.IsChecked -eq $false) -and ($chkBoxPermission.IsChecked -eq $false))) {

            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Filter Enabled , but no filter is specified!' -strType 'Error' -DateStamp ))
            $bolPreChecks = $false
        } else {
            If (($chkBoxFilter.IsChecked -eq $true) -and (($combAccessCtrl.SelectedIndex -eq -1) -and ($txtBoxObjectFilter.Text -eq '') -and ($txtBoxPropertyFilter.Text -eq '') -and ($txtFilterTrustee.Text -eq '') -and ($txtPermission.Text -eq '') -and ($chkBoxFilterBuiltin.IsChecked -eq $false))) {

                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Filter Enabled , but no filter is specified!' -strType 'Error' -DateStamp ))
                $bolPreChecks = $false
            }
            # Set the filter if filter is enabled
            If ($chkBoxFilter.IsChecked -eq $true) {

                $strObjectFilter = ''
                $strPropertyFilter = '' 
                $strFilterTrustee = '' 
                $strAccessCtrl = ''
                $strPermission = ''

                 If ($chkBoxObject.IsChecked -eq $true) {
                    $strObjectFilter = $txtBoxObjectFilter.Text
                }
                 If ($chkBoxProperty.IsChecked -eq $true) {
                    $strPropertyFilter = $txtBoxPropertyFilter.Text
                }
                 If ($chkBoxTrustee.IsChecked -eq $true) {
                    $strFilterTrustee = $txtFilterTrustee.Text
                }
                 If ($chkBoxType.IsChecked -eq $true) {
                    $strAccessCtrl = $combAccessCtrl.SelectedItem
                }
                 If ($chkBoxPermission.IsChecked -eq $true) {
                    $strPermission = $txtPermission.Text
                }                                                                
            }            
        }

        If (($chkBoxEffectiveRights.IsChecked -eq $true) -and ($global:tokens.count -eq 0)) {

            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Effective rights enabled , but no service principal selected!' -strType 'Error' -DateStamp ))
            $bolPreChecks = $false
        }
        $global:intShowCriticalityLevel = 0
        if ($bolPreChecks -eq $true) {
            $strCompareFile = ''
            $allSubOU = New-Object System.Collections.ArrayList
            $allSubOU.Clear()

            $BolSkipDefPerm = $chkBoxDefaultPerm.IsChecked
            $BolSkipProtectedPerm = $chkBoxSkipProtectedPerm.IsChecked
            $global:bolProgressBar = $chkBoxSkipProgressBar.IsChecked
            $bolSDDL = $chkBoxSDDLView.IsChecked
            if (($rdbOnlyCSV.IsChecked) -or ($rdbOnlyCSVTEMPLATE.IsChecked)) {
                $bolCSV = $true
            }

            $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
            if($LDAPConnection) {
                
            
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $request = New-Object System.directoryServices.Protocols.SearchRequest
                if ($global:bolShowDeleted) {
                    [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                    [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                }
                $request.DistinguishedName = $txtBoxSelected.Text.ToString()
                $request.Filter = '(name=*)'
                $request.Scope = 'Base'
                [void]$request.Attributes.Add('name')

                $response = $LDAPConnection.SendRequest($request)
                $ADobject = $response.Entries[0]
                #Verify that attributes can be read
                if ($null -ne $ADobject.distinguishedName) {

                    if ($null -ne $ADobject.Attributes.name) {
                        $strNode = $ADobject.Attributes.name[0]
                    } else {
                        $strNode = $ADobject.distinguishedName
                    }

                    if ($GPO) {
                        $strNode = $strNode + '_GPOs'
                    }


                    $bolTranslateGUIDStoObject = $false
                    $date = Get-Date -UFormat %Y%m%d_%H%M%S
                    $strNode = fixfilename $strNode
                    $strFileCSV = $txtTempFolder.Text + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.csv'
                    $strFileEXCEL = $txtTempFolder.Text + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.xlsx'
                    $strFileHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'
                    $strFileHTM = $env:temp + '\' + "$global:strDomainShortName-$strNode-$global:SessionID" + '.htm'
                    if (!($bolCSV)) {
                        if (!($rdbEXcel.IsChecked)) {
                            if ($chkBoxFilter.IsChecked) {
                                CreateHTA "$global:strDomainShortName-$strNode Filtered" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                                CreateHTM "$global:strDomainShortName-$strNode Filtered" $strFileHTM
                            } else {
                                CreateHTA "$global:strDomainShortName-$strNode" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                                CreateHTM "$global:strDomainShortName-$strNode" $strFileHTM
                            }

                            InitiateHTM $strFileHTA $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $Protected $bolShowCriticalityColor $false $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked -bolCanonical:$UseCanonicalName $GPO $chkBoxSDDLView.isChecked
                            InitiateHTM $strFileHTM $strNode $txtBoxSelected.Text.ToString() $chkBoxReplMeta.IsChecked $chkBoxACLsize.IsChecked $Protected $bolShowCriticalityColor $false $BolSkipDefPerm $BolSkipProtectedPerm $strCompareFile $chkBoxFilter.isChecked $chkBoxEffectiveRights.isChecked $chkBoxObjType.isChecked -bolCanonical:$UseCanonicalName $GPO $chkBoxSDDLView.isChecked
                            $Format = 'HTML'
                            $Show = $true
                        } else {
                            $Format = 'EXCEL'
                            $Show = $false
                        }
                    } else {
                        if ($rdbOnlyCSV.IsChecked) {
                            $Format = 'CSV'
                        }
                        if ($rdbOnlyCSVTEMPLATE.IsChecked) {
                            $Format = 'CSVTEMPLATE'
                        }
                        $Show = $false
                    }
                    If ($txtBoxSelected.Text.ToString().Length -gt 0) {
                            #Select type of scope
                            If ($rdbBase.IsChecked -eq $true) {
                                $Scope =  "base"
                            }
                            If ($rdbOneLevel.IsChecked -eq $true) {
                                $Scope =  "onelevel"
                            }
                            If ($rdbSubtree.IsChecked -eq $true) {
                                $Scope =  "subtree"
                            }

                            $IncludeInherited = $chkInheritedPerm.IsChecked

                            if($rdbDepth.IsChecked -eq $True) 
                            {
                                if($txtDepth.text -match "^\d{1,3}$")
                                {
                                    $Depth = $txtDepth.text
                                }
                                else
                                {
                                    $global:observableCollection.Insert(0,(LogMessage -strMessage "Depth does not meet the required range of 0-999!" -strType "Error" -DateStamp ))
                                    $bolDepthError = $true
                                }
                            }

                            if(-not($bolDepthError))
                            {
                                if($rdbScanFilter.IsChecked -eq $true)
                                {
                                    if($Depth)
                                    {
                                        $allSubOU = @(GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CustomFilter $txtCustomFilter.Text -CREDS $CREDS -Depth $txtDepth.Text)
                                    }
                                    else
                                    {
                                        $allSubOU = @(GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CustomFilter $txtCustomFilter.Text -CREDS $CREDS)
                                    }
                                }
                                else
                                {
                                    $strFilterAll = '(objectClass=*)'
                                    $strFilterContainer = '(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=DomainDNS)(objectClass=dMD)))'
                                    $strFilterOU = '(|(objectClass=organizationalUnit)(objectClass=domainDNS))'
                                    $strFilterGPO = '(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gplink=*LDAP*))'

                                    If ($rdbScanAll.IsChecked -eq $true) {
                                        $ReqFilter = $strFilterAll
                                    }
                                    If ($rdbScanOU.IsChecked -eq $true) {
                                        $ReqFilter = $strFilterOU
                                    }
                                    If ($rdbScanContainer.IsChecked -eq $true) {
                                        $ReqFilter = $strFilterContainer
                                    }
                                    if ($rdbGPO.IsChecked -eq $true) {
                                        $ReqFilter = $strFilterGPO
                                    }

                                    if($Depth)
                                    {
                                        $allSubOU = @(GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CREDS $CREDS -Depth $txtDepth.Text -CustomFilter $ReqFilter)
                                    }
                                    else
                                    {
                                    $allSubOU = @(GetAllChildNodes -firstnode $txtBoxSelected.Text -scope $Scope -ExcludedDNs $txtBoxExcluded.text -CREDS $CREDS -CustomFilter $ReqFilter)
                                    }

                                }

                                #if any objects found read ACLs
                                if($allSubOU.count -gt 0)
                                {			        
                                    $bolToFile = $true
                                    #Used from comand line only
                                    $FilterBuiltin = $chkBoxFilterBuiltin.IsChecked

                                    Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $BolSkipDefPerm -SkipProtectedPerm $BolSkipProtectedPerm -bolGetOwnerEna $chkBoxGetOwner.IsChecked -bolReplMeta $chkBoxReplMeta.IsChecked -bolACLsize $chkBoxACLsize.IsChecked -bolEffectiveR $chkBoxEffectiveRights.IsChecked -bolGetOUProtected $Protected -bolGUIDtoText $bolTranslateGUIDStoObject -Show $Show -OutType $Format -bolToFile $bolToFile -bolAssess $chkBoxSeverity.IsChecked -AssessLevel $combServerity.SelectedItem -bolShowCriticalityColor $bolShowCriticalityColor -GPO $GPO -FilterBuiltin $FilterBuiltin -TranslateGUID $chkBoxTranslateGUID.isChecked -RecursiveFind $chkBoxRecursiveFind.isChecked -RecursiveObjectType $combRecursiveFind.SelectedValue -ApplyTo $strObjectFilter -PropertyFilter $strPropertyFilter -FilterTrustee $strFilterTrustee -AccessType $strAccessCtrl -ACLPermissionFilter $strPermission -CREDS $CREDS -ReturnObjectType $combReturnObjectType.SelectedItem -SDDL $bolSDDL -DACL $rdbDACL.IsChecked
                                }
                                else
                                {
                                    $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects returned! Does your filter relfect the objects you are searching for?" -strType "Error" -DateStamp ))
                                }   
                            }
                            else
                            {
                                $global:observableCollection.Insert(0,(LogMessage -strMessage "Could not perform an LDAP search!" -strType "Error" -DateStamp ))
                            } 
                        }
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not read object $($txtBoxSelected.Text.ToString()). Enough permissions?" -strType 'Error' -DateStamp ))
                }
                
            }
        }
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'No object selected!' -strType 'Error' -DateStamp ))
    }
    $global:observableCollection.Insert(0, (LogMessage -strMessage 'Finished' -strType 'Info' -DateStamp ))

    $allSubOU = ''
    $strFileCSV = ''
    $strFileHTA = ''
    $strFileHTM = ''
    $sADobjectName = ''
    $date = ''

}
function Get-XMLPath {
    Param($xmlElement)
    $Path = ''

    $FQDN = $xmlElement.Text

    return $FQDN
}

function AddXMLAttribute {
    Param([ref]$node, $szName, $value)
    $attribute = $global:xmlDoc.createAttribute($szName);
    [void]$node.value.setAttributeNode($attribute);
    $node.value.setAttribute($szName, $value);

    #return $node;
}

function Add-ExcludeChild {

    # Test if any node is selected
    if ($txtBoxSelected.Text.Length -gt 0) {
        if ($txtBoxExcluded.Text.Length -gt 0) {
            $txtBoxExcluded.Text = $txtBoxExcluded.Text + ';' + $txtBoxSelected.Text
        } else {
            $txtBoxExcluded.Text = $txtBoxSelected.Text
        }

    }

}

function Add-RefreshChild {

    # Test if any node is selected
    if ($txtBoxSelected.Text.Length -gt 0) {
        $xmlNode = $global:xmlDoc
        $NodeDNPath = $txtBoxSelected.Text

        if ($global:TreeViewRootPath -eq $NodeDNPath) {
            $Mynodes = $xmlNode.SelectSingleNode("//DomainRoot[@Text='$NodeDNPath']")
            # Make sure a node was found
            if ($Mynodes.Name.Length -gt 0) {
                $Mynodes.IsEmpty = $true
                $treeNodePath = $NodeDNPath

                # Initialize and Build Domain OU Tree

                ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath -CREDS $CREDS
                # Set tag to show this node is already enumerated

            }
        } else {
            $Mynodes = $xmlNode.SelectSingleNode("//OU[@Text='$NodeDNPath']")
            # Make sure a node was found
            if ($Mynodes.Name.Length -gt 0) {
                $Mynodes.IsEmpty = $true
                $treeNodePath = $NodeDNPath

                # Initialize and Build Domain OU Tree
                ProcessOUTree -node $($Mynodes) -ADSObject $treeNodePath -CREDS $CREDS
                # Set tag to show this node is already enumerated

            }
        }
    }

}

#  Processes an OU tree

function ProcessOUTree {

    Param(
        $node,
        $ADSObject,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    # Increment the node count to indicate we are done with the domain level


    $strFilterOUCont = '(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)))'
    $strFilterAll = '(objectClass=*)'
    
    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null

    if ($global:bolShowDeleted) {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
    }
    $request.DistinguishedName = $ADSObject


    # Single line Directory searcher
    # set a filter



    If ($rdbBrowseAll.IsChecked -eq $true) {
        $request.Filter = $strFilterAll

    } else {
        $request.Filter = $strFilterOUCont
    }
    # set search scope
    $request.Scope = 'OneLevel'

    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('objectclass')

    # Now walk the list and recursively process each child
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
        foreach ($objResult in $colResults) {
            $NewOUNode = $global:xmlDoc.createElement('OU');
            if ($objResult.attributes.Count -ne 0) {

                # Add an Attribute for the Name

                if (($null -ne $($objResult.attributes.name[0]))) {

                    # Add an Attribute for the Name
                    $OUName = "$($objResult.attributes.name[0])"

                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Name' -value $OUName
                    $DNName = $objResult.distinguishedname
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Text' -value $DNName
                    Switch ($objResult.attributes.objectclass[$objResult.attributes.objectclass.count - 1]) {
                        'domainDNS' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\DomainDNS.png"
                        }
                        'OrganizationalUnit' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\OU.png"
                        }
                        'user' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\User.png"
                        }
                        'group' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Group.png"
                        }
                        'computer' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Computer.png"
                        }
                        'container' {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Container.png"
                        }
                        default {
                            AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Other.png"
                        }
                    }
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Tag' -value 'Enumerated'
                    $child = $node.appendChild($NewOUNode);
                    ProcessOUTreeStep2OnlyShow -node $NewOUNode -DNName $DNName -CREDS $CREDS
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not read object $($objResult.distinguishedname)" -strType 'Error' -DateStamp ))
                }
            } else {
                if ($null -ne $objResult.distinguishedname) {
                    # Add an Attribute for the Name
                    $DNName = $objResult.distinguishedname
                    $OUName = $DNName.toString().Split(',')[0]
                    if ($OUName -match '=') {
                        $OUName = $OUName.Split('=')[1]
                    }

                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Name' -value $OUName
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Text' -value $DNName
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Container.png"
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Tag' -value 'Enumerated'
                    $child = $node.appendChild($NewOUNode);
                    ProcessOUTreeStep2OnlyShow -node $NewOUNode -DNName $DNName -CREDS $CREDS
                }

                $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not read object $($objResult.distinguishedname). Enough permissions?" -strType 'Warning' -DateStamp ))
            }

        }
        if ($global:PageSize -gt 0) {
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
function ProcessOUTreeStep2OnlyShow {
    Param(
        $node,

        [string]
        $DNName,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    # Increment the node count to indicate we are done with the domain level

    $strFilterOUCont = '(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)))'
    $strFilterAll = '(&(name=*))'

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.distinguishedName = $DNName
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    if ($global:bolShowDeleted) {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
    }
    # Single line Directory searcher
    # set a filter

    If ($rdbBrowseAll.IsChecked -eq $true) {
        $request.Filter = $strFilterAll

    } else {
        $request.Filter = $strFilterOUCont
    }

    # set search scope
    $request.Scope = 'oneLevel'

    [void]$request.Attributes.Add('name')

    $arrSchemaObjects = New-Object System.Collections.ArrayList
    $intStop = 0
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
        foreach ($objResult in $colResults) {
            if ($intStop -eq 0) {
                $global:DirSrchResults = $objResult
                if ($null -ne $global:DirSrchResults.attributes) {


                    # Add an Attribute for the Name
                    $NewOUNode = $global:xmlDoc.createElement('OU');
                    # Add an Attribute for the Name

                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Name' -value 'Click ...'
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Text' -value 'Click ...'
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Expand.png"
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Tag' -value 'NotEnumerated'

                    [void]$node.appendChild($NewOUNode);

                } else {

                    $global:observableCollection.Insert(0, (LogMessage -strMessage "At least one child object could not be accessed: $DNName" -strType 'Warning' -DateStamp ))
                    # Add an Attribute for the Name
                    $NewOUNode = $global:xmlDoc.createElement('OU');
                    # Add an Attribute for the Name

                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Name' -value 'Click ...'
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Text' -value 'Click ...'
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Img' -value "$env:temp\Expand.png"
                    AddXMLAttribute -node ([ref]$NewOUNode) -szName 'Tag' -value 'NotEnumerated'

                    [void]$node.appendChild($NewOUNode);
                }
            }
            $intStop++
        }

        if ($global:PageSize -gt 0) {
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
function Get-XMLDomainOUTree {

    param
    (
        $szDomainRoot,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )



    $treeNodePath = $szDomainRoot


    # Initialize and Build Domain OU Tree

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    if ($global:bolShowDeleted) {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
    }

    $request.distinguishedName = $treeNodePath
    $request.filter = '(name=*)'
    $request.Scope = 'base'
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('objectclass')

    $response = $LDAPConnection.SendRequest($request)
    $DomainRoot = $response.Entries[0]
    if ($DomainRoot.attributes.count -ne 0) {
        $DNName = $DomainRoot.distinguishedname
        if ($null -ne $DomainRoot.Attributes.objectclass) {
            $strObClass = $DomainRoot.Attributes.objectclass[$DomainRoot.Attributes.objectclass.count - 1]
        } else {
            $strObClass = 'unknown'
        }
    } else {
        $DNName = $DomainRoot.distinguishedname
        $strObClass = 'container'

        $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not read object $DNName . Enough permissions?" -strType 'Error' -DateStamp ))
    }
    $global:xmlDoc = New-Object -TypeName System.Xml.XmlDocument
    $global:xmlDoc.PreserveWhitespace = $false

    $RootNode = $global:xmlDoc.createElement('DomainRoot')
    AddXMLAttribute -Node ([ref]$RootNode) -szName 'Name' -value $szDomainRoot
    AddXMLAttribute -node ([ref]$RootNode) -szName 'Text' -value $DNName
    AddXMLAttribute -node ([ref]$RootNode) -szName 'Icon' -value "$env:temp\refresh.png"
    AddXMLAttribute -node ([ref]$RootNode) -szName 'Icon2' -value "$env:temp\exclude.png"

    Switch ($strObClass) {
        'domainDNS' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\DomainDNS.png"
        }
        'OrganizationalUnit' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\OU.png"
        }
        'user' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\User.png"
        }
        'group' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\Group.png"
        }
        'computer' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\Computer.png"
        }
        'container' {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\Container.png"
        }
        default {
            AddXMLAttribute -node ([ref]$RootNode) -szName 'Img' -value "$env:temp\Other.png"
        }
    }
    [void]$global:xmlDoc.appendChild($RootNode)

    $node = $global:xmlDoc.documentElement;

    #Process the OU tree
    ProcessOUTree -node $node -ADSObject $treeNodePath -CREDS $CREDS

    return $global:xmlDoc
}







$global:dicRightsGuids = @{'Seed' = 'xxx' }
$global:dicSidToName = @{'Seed' = 'xxx' }
$global:dicSidToObject = @{'Seed' = 'xxx' }
$global:dicDCSpecialSids = @{'BUILTIN\Incoming Forest Trust Builders' = 'S-1-5-32-557'; `
        'BUILTIN\Account Operators'                                   = 'S-1-5-32-548'; `
        'BUILTIN\Server Operators'                                    = 'S-1-5-32-549'; `
        'BUILTIN\Pre-Windows 2000 Compatible Access'                  = 'S-1-5-32-554'; `
        'BUILTIN\Terminal Server License Servers'                     = 'S-1-5-32-561'; `
        'BUILTIN\Windows Authorization Access Group'                  = 'S-1-5-32-560'
}
$global:dicWellKnownSids = @{'S-1-0' = 'Null Authority'; `
        'S-1-0-0'                    = 'Nobody'; `
        'S-1-1'                      = 'World Authority'; `
        'S-1-1-0'                    = 'Everyone'; `
        'S-1-2'                      = 'Local Authority'; `
        'S-1-2-0'                    = 'Local '; `
        'S-1-2-1'                    = 'Console Logon '; `
        'S-1-3'                      = 'Creator Authority'; `
        'S-1-3-0'                    = 'Creator Owner'; `
        'S-1-3-1'                    = 'Creator Group'; `
        'S-1-3-2'                    = 'Creator Owner Server'; `
        'S-1-3-3'                    = 'Creator Group Server'; `
        'S-1-3-4'                    = 'Owner Rights'; `
        'S-1-4'                      = 'Non-unique Authority'; `
        'S-1-5'                      = 'NT Authority'; `
        'S-1-5-1'                    = 'Dialup'; `
        'S-1-5-2'                    = 'Network'; `
        'S-1-5-3'                    = 'Batch'; `
        'S-1-5-4'                    = 'Interactive'; `
        'S-1-5-6'                    = 'Service'; `
        'S-1-5-7'                    = 'Anonymous'; `
        'S-1-5-8'                    = 'Proxy'; `
        'S-1-5-9'                    = 'Enterprise Domain Controllers'; `
        'S-1-5-10'                   = 'Principal Self'; `
        'S-1-5-11'                   = 'Authenticated Users'; `
        'S-1-5-12'                   = 'Restricted Code'; `
        'S-1-5-13'                   = 'Terminal Server Users'; `
        'S-1-5-14'                   = 'Remote Interactive Logon'; `
        'S-1-5-15'                   = 'This Organization'; `
        'S-1-5-17'                   = 'IUSR'; `
        'S-1-5-18'                   = 'Local System'; `
        'S-1-5-19'                   = 'NT Authority'; `
        'S-1-5-20'                   = 'NT Authority'; `
        'S-1-5-22'                   = 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS BETA'; `
        'S-1-5-32-544'               = 'Administrators'; `
        'S-1-5-32-545'               = 'Users'; `
        'S-1-5-32-546'               = 'Guests'; `
        'S-1-5-32-547'               = 'Power Users'; `
        'S-1-5-32-548'               = 'BUILTIN\Account Operators'; `
        'S-1-5-32-549'               = 'Server Operators'; `
        'S-1-5-32-550'               = 'Print Operators'; `
        'S-1-5-32-551'               = 'Backup Operators'; `
        'S-1-5-32-552'               = 'Replicator'; `
        'S-1-5-32-554'               = 'BUILTIN\Pre-Windows 2000 Compatible Access'; `
        'S-1-5-32-555'               = 'BUILTIN\Remote Desktop Users'; `
        'S-1-5-32-556'               = 'BUILTIN\Network Configuration Operators'; `
        'S-1-5-32-557'               = 'BUILTIN\Incoming Forest Trust Builders'; `
        'S-1-5-32-558'               = 'BUILTIN\Performance Monitor Users'; `
        'S-1-5-32-559'               = 'BUILTIN\Performance Log Users'; `
        'S-1-5-32-560'               = 'BUILTIN\Windows Authorization Access Group'; `
        'S-1-5-32-561'               = 'BUILTIN\Terminal Server License Servers'; `
        'S-1-5-32-562'               = 'BUILTIN\Distributed COM Users'; `
        'S-1-5-32-568'               = 'BUILTIN\IIS_IUSRS'; `
        'S-1-5-32-569'               = 'BUILTIN\Cryptographic Operators'; `
        'S-1-5-32-573'               = 'BUILTIN\Event Log Readers '; `
        'S-1-5-32-574'               = 'BUILTIN\Certificate Service DCOM Access'; `
        'S-1-5-32-575'               = 'BUILTIN\RDS Remote Access Servers'; `
        'S-1-5-32-576'               = 'BUILTIN\RDS Endpoint Servers'; `
        'S-1-5-32-577'               = 'BUILTIN\RDS Management Servers'; `
        'S-1-5-32-578'               = 'BUILTIN\Hyper-V Administrators'; `
        'S-1-5-32-579'               = 'BUILTIN\Access Control Assistance Operators'; `
        'S-1-5-32-580'               = 'BUILTIN\Remote Management Users'; `
        'S-1-5-33'                   = 'Write Restricted Code'; `
        'S-1-5-64-10'                = 'NTLM Authentication'; `
        'S-1-5-64-14'                = 'SChannel Authentication'; `
        'S-1-5-64-21'                = 'Digest Authentication'; `
        'S-1-5-65-1'                 = 'This Organization Certificate'; `
        'S-1-5-80'                   = 'NT Service'; `
        'S-1-5-84-0-0-0-0-0'         = 'User Mode Drivers'; `
        'S-1-5-113'                  = 'Local Account'; `
        'S-1-5-114'                  = 'Local Account And Member Of Administrators Group'; `
        'S-1-5-1000'                 = 'Other Organization'; `
        'S-1-15-2-1'                 = 'All App Packages'; `
        'S-1-16-0'                   = 'Untrusted Mandatory Level'; `
        'S-1-16-4096'                = 'Low Mandatory Level'; `
        'S-1-16-8192'                = 'Medium Mandatory Level'; `
        'S-1-16-8448'                = 'Medium Plus Mandatory Level'; `
        'S-1-16-12288'               = 'High Mandatory Level'; `
        'S-1-16-16384'               = 'System Mandatory Level'; `
        'S-1-16-20480'               = 'Protected Process Mandatory Level'; `
        'S-1-16-28672'               = 'Secure Process Mandatory Level'; `
        'S-1-18-1'                   = 'Authentication Authority Asserted Identityl'; `
        'S-1-18-2'                   = 'Service Asserted Identity'
}


# Global connection pool
$Global:LdapConnectionPool = @{}
$Global:ForestObject = @{
    Name = ''
    Domain = ''
    DistinguishedName = ''
    NetBIOSName = ''
    RWDC = ''
    ForestModeLevel = ''
    ForestMode = ''
    Schema = ''
    Configuration = ''
    SchemaRoleOwner = ''
    NamingRoleOwner = ''
    Domains = ''
    Sites = ''
    GlobalCatalogs = ''
    ApplicationPartitions = ''
}

$Global:Domainlist = @{}

# Load required assemblies
Add-Type -AssemblyName System.DirectoryServices.Protocols

#region Helper Functions

function Get-PoolKey {
    <#
    .SYNOPSIS
    Generates a unique key for connection pooling
    #>
    param(
        [string]$Server,
        [PSCredential]$Credential
    )
    
    $username = if ($Credential) { $Credential.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    return "$Server|$username"
}
Function Connect-DirectoryServices
{
    Param
(
    # DistinguishedName to start your search at or type RootDSE for the domain root. Will be included in the result if your filter matches the object.
    [Parameter(Mandatory = $false)]
    [String]
    $Base = '',
    # LDAP server
    [Parameter(Mandatory = $false)]
    [String]
    $Server = '',    

    # Port number
    [Parameter(Mandatory = $false)]
    [String]
    $Port,

    # Credential
    [Parameter(Mandatory = $false)]
    [PSCredential]    
    $CREDS,

    # Maintain a specific LDAP Server
    [Parameter(Mandatory = $false)]
    [switch]    
    $PreferSpecificDC,

    # Scope. Set your scope. Default is base.
    [Parameter(Mandatory = $false)]
    [ValidateSet($null,'Schema', 'Configuration')]
    [String]
    $NamingContext = '',    

    [switch]
    $UI
)
    $bolConnected = $false




    if ($Server -eq '') {
        if ($Port -eq '') {
            $global:strDC = ''
        } else {
            $global:strDC = 'localhost:' + $Port
        }
    } else {
        if ($Port -eq '') {
            $global:strDC = $Server
        } else {
            $global:strDC = $Server + ':' + $Port
        }
    }
    $global:bolLDAPConnection = $false

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS -PreferSpecificDC:$PreferSpecificDC ; Write-verbose "Calling Connect-SecureLDAP for server:$($global:strDC) at: $((Get-PSCallStack).ScriptLineNumber[0])"
    if($LDAPConnection) {
        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
        $request = New-Object System.directoryServices.Protocols.SearchRequest('', '(objectClass=*)', 'base')
        if ($global:bolShowDeleted) {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
            [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
        }
        [void]$request.Attributes.Add('dnshostname')
        [void]$request.Attributes.Add('supportedcapabilities')
        [void]$request.Attributes.Add('namingcontexts')
        [void]$request.Attributes.Add('defaultnamingcontext')
        [void]$request.Attributes.Add('schemanamingcontext')
        [void]$request.Attributes.Add('configurationnamingcontext')
        [void]$request.Attributes.Add('rootdomainnamingcontext')
        [void]$request.Attributes.Add('isGlobalCatalogReady')
        [void]$request.Attributes.Add('forestfunctionality')
        [void]$request.Attributes.Add('domainfunctionality')
        
        

        try {
            $response = $LDAPConnection.SendRequest($request)
            $bolConnected = $true

        } catch {
            
            if($UI) {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed! Domain does not exist or can not be connected' -strType 'Error' -DateStamp ))
            } else {
                Write-Host "Failed! Domain does not exist or can not be connected: $($_.Exception.InnerException.Message.ToString())" -ForegroundColor red
            }
            retun $false

        }
        if ($bolConnected -eq $true) {
            # Set the DC to the current host name
            if(($null -eq $global:strDC) -or ($global:strDC -eq '')) {
                $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
            }
            
            $strPrimaryCapability = $response.Entries[0].attributes.supportedcapabilities[0]
            Switch ($strPrimaryCapability) {
                '1.2.840.113556.1.4.1851' {
                    $global:DSType = 'AD LDS'
                    $global:bolADDSType = $false
                    $global:strDomainDNName = $response.Entries[0].Attributes.namingcontexts[-1]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]

                    $Global:ForestObject.DistinguishedName = $global:strDomainDNName
                    $Global:ForestObject.Schema = $global:SchemaDN 
                    $Global:ForestObject.Configuration = $global:ConfigDN 
                    $Global:ForestObject.SchemaRoleOwner = $global:strDC
                    $Global:ForestObject.NamingRoleOwner = $global:strDC
                

                }
                '1.2.840.113556.1.4.800' {
                    $global:DSType = 'AD DS'
                    $global:bolADDSType = $true
                    $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                    $global:forestfunctionality = $response.Entries[0].Attributes.forestfunctionality[0]
                    $global:domainfunctionality = $response.Entries[0].Attributes.domainfunctionality[0]

                    $global:strDomainFQDN = $global:strDomainDNName.Replace('DC=', '')
                    $global:strDomainFQDN = $global:strDomainFQDN.Replace(',', '.')

                    $global:strDomainPrinDNName = $global:strDomainDNName

                    $Global:Domainlist = Get-Domains -strDomainDN $global:strDomainDNName -strConfigDN $global:ConfigDN -CREDS $CREDS -DC $global:strDC
                    if($Global:Domainlist) {
                        $global:strDomainShortName = ($Global:Domainlist | Where-Object{$_.IsCurrentDomain -eq "True"}).NetBIOSName 
                        $global:strRootDomainShortName = ($Global:Domainlist | Where-Object{$_.IsRootDomain -eq "True"}).NetBIOSName 
                        $global:strRootDomainFQDN = ($Global:Domainlist | Where-Object{$_.IsRootDomain -eq "True"}).DomainFQDN
                        $Global:ForestObject.Name = ($Global:Domainlist | Where-Object{$_.IsRootDomain -eq "True"}).DomainName 
                        $Global:ForestObject.Domain = ($Global:Domainlist | Where-Object{$_.IsRootDomain -eq "True"}).DomainFQDN 
                        $Global:ForestObject.NetBIOSName = ($Global:Domainlist | Where-Object{$_.IsRootDomain -eq "True"}).NetBIOSName 


                        $global:DomainSID = ($Global:Domainlist | Where-Object {$_.IsCurrentDomain -eq $true}).DomainSID
                        # Only set the forest root Domain SID if it is the current domain
                        $global:ForestRootDomainSID = ($Global:Domainlist | Where-Object {($_.IsCurrentDomain -eq $true) -and  ($_.IsRootDomain -eq $true)}).DomainSID
                    }

                    $Global:ForestObject.DistinguishedName = $global:ForestRootDomainDN
                    $Global:ForestObject.ForestModeLevel = $global:forestfunctionality
                    $Global:ForestObject.ForestMode = $global:ForestFLHashAD[[int]$($global:forestfunctionality)]
                    
                    $Global:ForestObject.Schema = $global:SchemaDN 
                    $Global:ForestObject.Configuration = $global:ConfigDN 


                    


                }
                default {
                    $global:ForestRootDomainDN = $response.Entries[0].Attributes.rootdomainnamingcontext[0]
                    $global:strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
                    $global:SchemaDN = $response.Entries[0].Attributes.schemanamingcontext[0]
                    $global:ConfigDN = $response.Entries[0].Attributes.configurationnamingcontext[0]
                    $global:IS_GC = $response.Entries[0].Attributes.isglobalcatalogready[0]
                }
            }

            if(('rootDSE' -eq $base) -or ('' -eq $base)) {
                $base = $global:strDomainDNName
            } 

            if($NamingContext -eq "Schema") {
                $base = $global:SchemaDN 
            }
            if($NamingContext -eq "Configuration") {
                $base = $global:ConfigDN 
            }    

            if(($null -eq $global:strDC) -or ($global:strDC -eq '')) {
                if($Port -ne '') {
                    $global:strDC = $response.Entries[0].Attributes.dnshostname[0] + ':' + $Port  
                } else {
                    $global:strDC = $response.Entries[0].Attributes.dnshostname[0]
                }
            }

            $strNode = CheckDNExist -sADobjectName $base -strDC $global:strDC -CREDS $CREDS
            If ($strNode) {
                return $true
            } else {

                if($UI) {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed! Domain does not exist or can not be connected' -strType 'Error' -DateStamp ))
                } else {
                    Write-host "Failed to connect to $base"
                }                    
                
                return $false
            }

        }#bolLDAPConnection
    } # End If D lenght
    else {
        return $false
    }

}
function Connect-SecureLDAP {
    <#
    .SYNOPSIS
    Establishes a secure LDAP connection with automatic pooling and smart domain detection
    
    .PARAMETER Server
    Server name, domain name, or IP address
    
    .PARAMETER Credential
    Credentials for authentication
    
    .PARAMETER ForceNew
    Force creation of new connection instead of reusing pooled connection
    
    .PARAMETER TimeoutSeconds
    Connection timeout in seconds
    
    .PARAMETER PreferSpecificDC
    Keep the specific DC name instead of using domain SRV records. Falls back to IP if Kerberos fails.
    #>
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$ForceNew,
        [int]$TimeoutSeconds = 30,
        [switch]$PreferSpecificDC
    )
    
    # Generate pool key using original server input
    $poolKey = Get-PoolKey -Server $Server -Credential $Credential
    
    # Check if we have a valid connection in the pool
    if (-not $ForceNew -and $Global:LdapConnectionPool.ContainsKey($poolKey)) {
        $existingConnection = $Global:LdapConnectionPool[$poolKey]
        
        if (Test-LdapConnection -Connection $existingConnection) {
            Write-Verbose "Reusing existing LDAP connection for $Server"
            return $existingConnection
        } else {
            Write-Verbose "Existing connection invalid, removing from pool"
            Remove-LdapConnection -Server $Server -Credential $Credential
        }
    }

    # Smart server/domain detection using rootDSE (only for new connections)
    $targetInfo = Get-LdapTarget -Server $Server -TimeoutMs 5000 -PreferSpecificDC:$PreferSpecificDC
    $actualServer = $targetInfo.Target
    
    Write-Verbose "Input: $Server, Detected: $($targetInfo.Type), Target: $actualServer"
    
    if ($targetInfo.Type -eq 'SpecificDC') {
        Write-Verbose "Specific DC mode - will try $actualServer first, fallback to $($targetInfo.FallbackTarget) if needed"
        
        try {
            Write-Verbose "Attempting connection to specific DC: $actualServer"
            $connection = New-LdapConnection -Server $actualServer -Credential $Credential -TimeoutSeconds $TimeoutSeconds
            if($connection) {
                # Add to pool using original server as key
                $Global:LdapConnectionPool[$poolKey] = $connection

                $targetInfo.Domain = Get-LdapDomain -Server $Server -TimeoutMs $TimeoutMs

                $global:bolConnected = $true
            }
            return $connection
        }
        catch {
            # Check if this looks like a Kerberos/SRV failure (not credential error)
            $isCredentialError = $false
            if ($_.Exception.Message -match "invalid credentials|49|authentication|logon failure") {
                $isCredentialError = $true
            }
            if ($_.Exception -is [System.DirectoryServices.Protocols.DirectoryException]) {
                if ($_.Exception.Response.ResultCode -eq 49) {
                    $isCredentialError = $true
                }
            }
            
            if ($isCredentialError) {
                # Dont fallback for credential errors
                throw
            }
            if($global:bolCMD) {
                Write-Warning "Specific DC connection failed, falling back to IP: $($targetInfo.FallbackTarget)"
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage "Specific DC connection failed, falling back to IP: $($targetInfo.FallbackTarget)" -strType 'Warning' -DateStamp ))
            }
            
            Write-Verbose "Original error: $($_.Exception.Message)"
            
            try {
                $connection = New-LdapConnection -Server $targetInfo.FallbackTarget -Credential $Credential -TimeoutSeconds $TimeoutSeconds
                
                # Add to pool using original server as key
                $Global:LdapConnectionPool[$poolKey] = $connection
                return $connection
            }
            catch {
                Write-Error "Both specific DC and IP fallback failed: $($_.Exception.Message)"
                throw
            }
        }
    } else {
        # Normal mode - use detected target
        Write-Verbose "Creating new LDAP connection for $actualServer"
        
        # Create new connection
        $connection = New-LdapConnection -Server $actualServer -Credential $Credential -TimeoutSeconds $TimeoutSeconds
        
        # Add to pool using original server as key
        $Global:LdapConnectionPool[$poolKey] = $connection
        return $connection
    }
}
function Get-LdapDomain {
    <#
    .SYNOPSIS
    Gets the domain name from rootDSE query (no authentication required)
    #>
    param(
        [string]$Server,
        [int]$TimeoutMs = 5000
    )
    
    $connection = $null

        Write-Verbose "Querying rootDSE on $Server to get domain name"
        
        $connection = Connect-SecureLDAP -Server $Server -Credential $Credential ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
        
        # Query rootDSE (no authentication needed)
        try {
            # Bind to the server
   
            # Create a search request for RootDSE (empty DN, base scope)
            $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest `
                "", "(objectClass=*)", `
                ([System.DirectoryServices.Protocols.SearchScope]::Base), `
                $null  # Null retrieves all attributes
        
            # Send the request
            $searchResponse = $connection.SendRequest($searchRequest)
        
            # Display results
            $entry = $searchResponse.Entries[0]

            # Check if defaultNamingContext attribute exists
            if ($entry.Attributes.Contains("ldapservicename") -and $entry.Attributes["ldapservicename"].Count -gt 0) {
                $ldapservicename = $entry.Attributes.ldapservicename[0].split(":")[0]
            
                return $ldapservicename 
            }


            # Check if defaultNamingContext attribute exists
            if ($entry.Attributes.Contains("defaultNamingContext") -and $entry.Attributes["defaultNamingContext"].Count -gt 0) {
                $defaultNC = $entry.Attributes["defaultNamingContext"][0].ToString()
                
                # Extract domain from defaultNamingContext (e.g., "DC=adsa,DC=net" -> "adsa.net")
                if ($defaultNC -match '^DC=(.+)$') {
                    $domainParts = ($matches[1] -split ',DC=')
                    $domainName = $domainParts -join '.'
                    
                    Write-Verbose "Extracted domain from rootDSE: $domainName"
                    return $domainName
                }
            }


        }
        catch {
            Write-Host "Error: $($_.Exception.Message)"
            return $null
        }

}

function Get-LdapTarget {
    <#
    .SYNOPSIS
    Determines optimal LDAP target using rootDSE query
    #>
    param(
        [string]$Server,
        [int]$TimeoutMs = 5000,
        [switch]$PreferSpecificDC
    )
    
    # If it's already an IP address, return as-is
    if ($Server -match '^(\d{1,3}\.){3}\d{1,3}') {
        Write-Verbose "$Server is an IP address"
        return @{ Type = 'IP'; Target = $Server; FallbackTarget = $Server }
    }

    # If PreferSpecificDC is set, try to keep the original server
    if ($PreferSpecificDC) {
        Write-Verbose "PreferSpecificDC enabled - keeping original server: $Server"

        # Try to resolve server to IP for fallback
        try {
            $ipAddresses = [System.Net.Dns]::GetHostAddresses($Server.split(":")[0])
            if ($ipAddresses -and $ipAddresses.Count -gt 0) {
                $ipFallback = $ipAddresses[0].IPAddressToString
                Write-Verbose "Specific DC fallback IP: $ipFallback"
                return @{ 
                    Type = 'SpecificDC'; 
                    Target = $Server; 
                    FallbackTarget = $ipFallback;
                    Domain = $domainFromRootDSE 
                }
            }
        }
        catch {
            Write-Verbose "Could not resolve $Server to IP for fallback"
        }
        
        # If IP resolution fails, still use the server name
        return @{ 
            Type = 'SpecificDC'; 
            Target = $Server; 
            FallbackTarget = $Server;
            Domain = $domainFromRootDSE 
        }
        
    } else {

        Write-Verbose "PreferSpecificDC disabled - Selecting dns host name from server: $Server"

        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($Server)

        # Set authentication type to Anonymous
        $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous

        # Optional: Set session options (like SSL/TLS if needed)
        $ldapConnection.SessionOptions.ProtocolVersion = 3

        # Create a search request for RootDSE (empty base DN, base scope)
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $null,  # Empty/null base DN for RootDSE
            "(objectClass=*)",  # Filter
            [System.DirectoryServices.Protocols.SearchScope]::Base,  # Base scope
            $null  # Return all attributes (or specify specific ones)
        )

        # Send the request
        try {
            $searchResponse = [System.DirectoryServices.Protocols.SearchResponse]$ldapConnection.SendRequest($searchRequest)

            $dnshostname = $searchResponse.Entries[0].Attributes.dnshostname[0]
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            $dnshostname = $server
        }
        finally {
            # Clean up
            $ldapConnection.Dispose()
        }            



        # Try to resolve server to IP for fallback
        try {
            $ipAddresses = [System.Net.Dns]::GetHostAddresses($Server.split(":")[0])
            if ($ipAddresses -and $ipAddresses.Count -gt 0) {
                $ipFallback = $ipAddresses[0].IPAddressToString
                Write-Verbose "Specific DC fallback IP: $ipFallback"
                return @{ 
                    Type = 'SpecificDC'; 
                    Target = $dnshostname; 
                    FallbackTarget = $ipFallback;
                    Domain = $domainFromRootDSE 
                }
            }
        }
        catch {
            Write-Verbose "Could not resolve $Server to IP for fallback"
        }
        
        # If IP resolution fails, still use the server name
        return @{ 
            Type = 'SpecificDC'; 
            Target = $dnshostname; 
            FallbackTarget = $dnshostname;
            Domain = $domainFromRootDSE 
        }
    }
    
    # Final fallback
    Write-Warning "Could not classify $Server, returning as-is"
    return @{ Type = 'Unknown'; Target = $Server; FallbackTarget = $Server }
}

function Test-LdapConnection {
    <#
    .SYNOPSIS
    Tests if an LDAP connection is still valid
    #>
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Connection
    )
    
    try {
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
        $searchRequest.DistinguishedName = ""
        $searchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
        $searchRequest.Filter = "(objectClass=*)"
        $searchRequest.Attributes.Add("defaultNamingContext") | Out-Null
        
        $response = $Connection.SendRequest($searchRequest)
        return $true
    }
    catch {
        return $false
    }
}

function New-LdapConnection {
    <#
    .SYNOPSIS
    Creates a new LDAP connection with proper security settings
    #>
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [int]$TimeoutSeconds = 30,
        [switch]$NoRetry
    )
    
    $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($Server)
    $connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    
    try {
        # Try LDAP with signing first
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        Write-Verbose "Setting Session Options for $Server"
        if ($Credential) {
            $connection.Credential = $Credential.GetNetworkCredential()
            Write-Verbose "Adding credential to Session Options for $Server"
        }
        Write-Verbose "Connecting using .Bind to $Server"

        $connection.Bind()
 

        Write-Verbose "Connected with LDAP signing to $Server"
        return $connection
    }
    catch {
        # Check for credential errors first
        $isCredentialError = $false

        if($_.Exception.InnerException.ErrorCode -eq 49) {
            $isCredentialError = $true
        }
        elseif ($_.Exception.Message -match "credential is invalid|invalid credentials|49|authentication|logon failure") {
            $isCredentialError = $true
        }
        
        if ($_.Exception -is [System.DirectoryServices.Protocols.DirectoryException]) {
            if ($_.Exception.Response.ResultCode -eq 49) {
                $isCredentialError = $true
            }
        }
        
        if ($isCredentialError) {
            if($global:bolCMD) {
                Write-Host "Authentication failed - invalid credentials provided!"
                Write-Host "The supplied credential is invalid."
                if(-not($NoRetry)) {
                    $Credential = Get-Credential
                    
                    Write-Verbose "Second connection attempt with LDAP signing to $Server, using account $($Credential.UserName)"
                    
                    $secondtry = New-LdapConnection -Server $Server -Credential $Credential -NoRetry

                    return $secondtry  
                }
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage "Authentication failed - invalid credentials provided!" -strType 'Error' -DateStamp ))
                $global:observableCollection.Insert(0, (LogMessage -strMessage "The supplied credential is invalid." -strType 'Error' -DateStamp ))
                if(-not($NoRetry)) {
                    $Credential = Get-CredentialsUI

                    Write-Verbose "Second connection attempt with LDAP signing to $Server, using account $($Credential.UserName)"

                    $secondtry = New-LdapConnection -Server $Server -Credential $Credential -NoRetry
                    return $secondtry       
                }
            }
            

            return $null
        }
        
        Write-Verbose "LDAP signing failed for $Server, trying LDAPS..."
        
        try {
            # Try LDAPS
            $connection = New-Object System.DirectoryServices.Protocols.LdapConnection("${Server}:636")
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            
            if ($Credential) {
                $connection.Credential = $Credential.GetNetworkCredential()
            }
            
            $connection.Bind()
            Write-Verbose "Connected with LDAPS to $Server"
            return $connection
        }
        catch {
            if ($global:bolCMD) {
                Write-Host "Both LDAP signing and LDAPS failed"
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage "Both LDAP signing and LDAPS failed" -strType 'Error' -DateStamp ))
            }            
            # Write-Error "Both LDAP signing and LDAPS failed: $($_.Exception.Message)"
            # throw
        }
    }
}

#endregion

#region Main Functions
function Test-DomainJoined {
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
        return ($computer.DomainRole -in @(1,3,4,5)) -and ($computer.Domain -ne $computer.Name)
    } catch {
        return $false
    }
}

function Remove-LdapConnection {
    <#
    .SYNOPSIS
    Removes a specific LDAP connection from the pool
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Server,
        [PSCredential]$Credential
    )
    
    $poolKey = Get-PoolKey -Server $Server -Credential $Credential
    
    if ($Global:LdapConnectionPool.ContainsKey($poolKey)) {
        try {
            $connection = $Global:LdapConnectionPool[$poolKey]
            $connection.Dispose()
        }
        catch {
            Write-Warning "Error disposing connection: $($_.Exception.Message)"
        }
        
        $Global:LdapConnectionPool.Remove($poolKey)
        Write-Verbose "Removed LDAP connection for $Server from pool"
    }
}

function Clear-LdapConnectionPool {
    <#
    .SYNOPSIS
    Clears all connections from the pool
    #>
    param(
        [switch]$Force
    )
    
    if ($Force -or (Read-Host "Clear all LDAP connections? (y/N)") -eq 'y') {
        foreach ($connection in $Global:LdapConnectionPool.Values) {
            try {
                $connection.Dispose()
            }
            catch {
                Write-Warning "Error disposing connection: $($_.Exception.Message)"
            }
        }
        
        $Global:LdapConnectionPool.Clear()
        Write-Host "All LDAP connections cleared from pool"
    }
}

function Get-LdapConnectionPool {
    <#
    .SYNOPSIS
    Returns information about current connections in the pool
    #>
    $poolInfo = @()
    
    foreach ($key in $Global:LdapConnectionPool.Keys) {
        $parts = $key -split '\|', 2
        $connection = $Global:LdapConnectionPool[$key]
        $isValid = Test-LdapConnection -Connection $connection
        
        $poolInfo += [PSCustomObject]@{
            Server = $parts[0]
            Username = $parts[1]
            IsValid = $isValid
            ConnectionType = if ($connection.SessionOptions.SecureSocketLayer) { "LDAPS" } else { "LDAP+Signing" }
        }
    }
    
    return $poolInfo
}

#==========================================================================
# Function		: Get-DomainShortName
# Arguments     : domain name 
# Returns   	: N/A
# Description   : Search for short domain name
#==========================================================================
function Get-Domains
{ 

    param(
    [Parameter(Mandatory=$false)]
    [pscredential] 
    $CREDS,
    [string]
    $strDomainDN,
    [string]
    $strConfigDN,
    [string]
    $DC
    )

   $DomainObjectArray = New-Object System.Collections.ArrayList

    
    $null = Add-Type -AssemblyName System.DirectoryServices.Protocols

    $LDAPConnection = Connect-SecureLDAP -Server $strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,$strConfigDN", "(&(objectClass=crossRef)(systemFlags=3))", "Subtree")
    [void]$request.Attributes.Add("name")
    [void]$request.Attributes.Add("ncname")
    [void]$request.Attributes.Add("netbiosname")
    [void]$request.Attributes.Add("msds-behavior-version")
    [void]$request.Attributes.Add("dnsroot")
    [void]$request.Attributes.Add("objectguid")
    [void]$request.Attributes.Add("trustparent")
    [void]$request.Attributes.Add("roottrust")
    
    
    
    


    $response = $LDAPConnection.SendRequest($request)
    $DomainObjects = $response.Entries

    if($DomainObjects) {
        foreach($Domain in $DomainObjects) {
            try{
            # If the this is the current domain get the sid
            if($Domain.Attributes.ncname[0] -eq $strDomainDN){
                $domaindata = New-LDAPSearch -Server $strDC -creds $CREDS  -LDAPFilter "(objectClass=*)" -Scope base -BaseDN $strDomainDN -Attributes "objectsid"

                if($domaindata) {
                    $objectSid = [byte[]]$domaindata.Attributes.objectsid[0]
                    $domainsid = (New-Object System.Security.Principal.SecurityIdentifier($objectSid, 0)).value
                } else  {
                    $domainsid = ''
                }
            }else{
                $domainsid = ''
            }

            $objDomain = [PSCustomObject]@{
                DomainFQDN = $Domain.Attributes.dnsroot[0]
                DomainDN = $Domain.Attributes.ncname[0]
                DomainName = $Domain.Attributes.name[0]
                NetBIOSName = $Domain.Attributes.netbiosname[0]
                ObjectGUID = $Domain.Attributes.objectguid[0]
                DomainSID = $domainsid
                DomainMode = $global:DomainFLHashAD[[int]$($Domain.Attributes.'msds-behavior-version'[0])]
                DomainModeLevel =$Domain.Attributes.'msds-behavior-version'[0]
                IsRootDomain = if(($null -eq $Domain.Attributes.roottrust) -and  ($null -eq $Domain.Attributes.trustparent)){"True"}else{"False"}
                IsCurrentDomain = if($Domain.Attributes.ncname[0] -eq $strDomainDN){"True"}else{"False"}
                PdcRoleOwner = ''
                NearestRWDC = ''                
            }

            [VOID]$DomainObjectArray.Add($objDomain)
        }
        catch{
            if($global:bolCMD) {
                Write-Warning "Failed to create domain info list"
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to create domain info list" -strType 'Warning' -DateStamp ))
            }
        }
        }
    } 

    return $DomainObjectArray 
}
#==========================================================================
# Function		: Get-DomainShortName
# Arguments     : domain name 
# Returns   	: N/A
# Description   : Search for short domain name
#==========================================================================
function Get-DomainShortName
{ 

    param(
    [Parameter(Mandatory=$false)]
    [pscredential] 
    $CREDS,
    [string]
    $strDomainDN,
    [string]
    $strConfigDN,
    [string]
    $DC
    )
    
    
    $null = Add-Type -AssemblyName System.DirectoryServices.Protocols
    
    $LDAPConnection = Connect-SecureLDAP -Server $strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,$strConfigDN", "(&(objectClass=crossRef)(nCName=$strDomainDN))", "Subtree")
    [void]$request.Attributes.Add("netbiosname")
    $response = $LDAPConnection.SendRequest($request)
    $Object = $response.Entries[0]

    if($null -ne $Object) {

        $ReturnShortName = $Object.Attributes.netbiosname[0]
    } else {
        $ReturnShortName = ""
    }

    return $ReturnShortName
}
#==========================================================================
# Function		: New-LDAPSearch
# Arguments     : basedn,ldapfilter,scope,server,attributes,creds
# Returns   	: ldap search result
# Description   : This function makes a ldap search and returns the results
# 
#==========================================================================
Function New-LDAPSearch
{
param(
    # DistinguishedName to start your search at or type RootDSE for the domain root. Will be included in the result if your filter matches the object.
    [Alias("b")]
    [Parameter(Mandatory=$true, 
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true, 
                ValueFromRemainingArguments=$false, 
                Position=0,
                ParameterSetName='Default')]
    [String] 
    $BaseDN="",

    # Filter. Specify your custom filter. Default is OrganizationalUnit.
    [Alias("filter")]
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [validatescript({$_ -like "(*=*)"})]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $LDAPFilter = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)))",

    # Scope. Set your scope. Default is base.
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateSet("base", "onelevel", "subtree")]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Scope = "base",

    # Server. Specify your specific server to target your search at.
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Server='',

     # Attributes to return
    [Parameter(Mandatory=$false, 
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [String] 
    $Attributes = "objectClass;name;description;canonicalName",

    # Add Credentials to the command by first creating a pscredential object like for example $CREDS = get-credential
    [Parameter(Mandatory=$false)]
    [PSCredential] 
    $creds
)



$null = Add-Type -AssemblyName System.DirectoryServices.Protocols

$LDAPConnection = $null
$request = $null
$response = $null



if(($BaseDN -eq "") -or ($BaseDN -eq "RootDSE")) {
    $LDAPConnection = Connect-SecureLDAP -Server $Server -Credential $creds ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = "None"
    $request = New-Object System.directoryServices.Protocols.SearchRequest($null, "(objectClass=*)", "base")
    [void]$request.Attributes.Add("defaultnamingcontext")
    try
    {
        $response = $LDAPConnection.SendRequest($request)
        $strDomainDNName = $response.Entries[0].Attributes.defaultnamingcontext[0]
        $bolLDAPConnection = $true
    }
    catch
    {
        $bolLDAPConnection = $false
        $observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
    }

    $BaseDN = $strDomainDNName
}

#Set global value for time out in paged searches
$global:TimeoutSeconds = 120
#Set global value for page size in paged searches
$global:PageSize = 1000


$LDAPConnection = Connect-SecureLDAP -Server $Server -Credential $creds ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"

$request = New-Object System.directoryServices.Protocols.SearchRequest($BaseDN, $LDAPFilter, $Scope)
$SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group'-bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
$control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
[void]$request.Controls.Add($control)
[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
$request.Controls.Add($pagedRqc) | Out-Null

if(@($Attributes.split(";")).Count -gt 0)
{
    foreach($Attribute in $Attributes.split(";"))
    {
        [void]$request.Attributes.Add($($Attribute.ToString().ToLower()))
    }
}

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

return $colResults

}



#==========================================================================
# Function		: Convert-DSRights
# Arguments     : [string] ActiveDirectoryRights
# Returns   	: [string] String
# Description   : This function will generate a text string of the ActiveDirectoryRights
# 
#==========================================================================
Function Convert-ActiveDirectoryRights
{
param(
[string]$strADRights,

[string]$objInheritanceType,

[string]$objFlags
)

    Switch ($strADRights)
    {
        "Self"
        {
            #Self right are never express in gui it's a validated write ( 0x00000008 ACTRL_DS_SELF)

                $ADRightsString = ""
        }
        "GenericRead"
        {
                $ADRightsString = "Read Permissions,List Contents,Read All Properties,List"
        }
        "CreateChild"
        {
                $ADRightsString = "Create"	
        }
        "DeleteChild"
        {
            $ADRightsString = "Delete Child"		
        }
        "GenericAll"
        {
            $ADRightsString = "Full Control"		
        }
        "CreateChild, DeleteChild"
        {
            $ADRightsString = "Create/Delete"		
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
                            $ADRightsString = "Read"	
                        }
    		      	    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $ADRightsString = "Read"	
                        }
                        default
    	 	            {$ADRightsString = "Read All Properties"	}
                    }#End switch
                }
                    "Children"
    	 	    {
                     
                    Switch ($objFlags)
    	    	    { 
    		      	    "ObjectAceTypePresent"
                        {
                            $ADRightsString = "Read"	
                        }
    		      	    "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $ADRightsString = "Read"	
                        }
                        default
    	 	            {$ADRightsString = "Read All Properties"	}
                    }#End switch
                }
                "Descendents"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                        $ADRightsString = "Read"	
                        }
                       	                
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                        $ADRightsString = "Read"	
                        }
                        default
                        {$ADRightsString = "Read All Properties"	}
                    }#End switch
                }
                default
                {$ADRightsString = "Read All Properties"	}
            }#End switch
        }
        "ReadProperty, WriteProperty" 
        {
            $ADRightsString = "Read All Properties;Write All Properties"			
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
                            $ADRightsString = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $ADRightsString = "Write"	
                        }
                        default
                        {
                            $ADRightsString = "Write All Properties"	
                        }
                    }#End switch
                }
                "Children"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            $ADRightsString = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $ADRightsString = "Write"	
                        }
                        default
                        {
                            $ADRightsString = "Write All Properties"	
                        }
                    }#End switch
                }
                "Descendents"
                {
                    Switch ($objFlags)
                    { 
                        "ObjectAceTypePresent"
                        {
                            $ADRightsString = "Write"	
                        }
                        "ObjectAceTypePresent, InheritedObjectAceTypePresent"
                        {
                            $ADRightsString = "Write"	
                        }
                        default
                        {
                            $ADRightsString = "Write All Properties"	
                        }
                    }#End switch
                }
                default
                {
                    $ADRightsString = "Write All Properties"
                }
            }#End switch		
        }
        default
        {
  
        }
    }# End Switch 

    return $ADRightsString
}

#==========================================================================
# Function		: Create-CanonicalName
# Arguments     : [string] distinguishedName
# Returns   	: [string] CanonicalName
# Description   : This function will create a canonical name of a distinguishedName string
#
#==========================================================================
Function Create-CanonicalName {
    param (
        [Parameter(Mandatory = $True)]
        [System.Array]$distinguishedname
    )

    $stringlistReversed = @()


    $stringSplitted = $distinguishedname.Split(',')
    $Counter = $stringSplitted.Count

    $domainstring = ''
    $intC = 0
    for ($i = 0; $i -le $stringSplitted.count; $i++) {
        if ($stringSplitted[$i] -match 'dc=') {
            if ($intC -gt 0) {
                $domainstring += '.' + $stringSplitted[$i].tostring().remove(0, 3)
            } else {
                $domainstring += $stringSplitted[$i].tostring().remove(0, 3)

            }
            $intC++
        }

    }

    $stringReversed = ''
    while ($Counter -gt 0) {
        if ($stringSplitted[$Counter - 1] -match 'dc=') {
            $Counter = $Counter - 1
        } else {
            $stringReversed += $stringSplitted[$Counter - 1].tostring().remove(0, 3)
            $Counter = $Counter - 1
            if ($Counter -gt 0) {
                $stringReversed += '/'
            }
        }
    }
    $stringlistReversed = $domainstring + '/' + $stringReversed

    return $stringlistReversed
}
#==========================================================================
# Function		: Get-LargeNestedADGroup
# Arguments     : DC name, DN of Group, Object type, Array of Members
# Returns   	: Array of Members
# Description   : This function will enumerate large groups and returns direct and recusive members
#
#==========================================================================
Function Get-LargeNestedADGroup {
    Param (
        # Domain Controller
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$strDC,

        # DistinguishedName of the group
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$GroupDN,

        # Returns members of type
        [Parameter(Mandatory = $false)]
        [ValidateSet('*', 'User', 'Group', 'Computer')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Output = '*',
        
        [System.Collections.ArrayList]
        $MembersExpanded,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )

    begin {
        $null = Add-Type -AssemblyName System.DirectoryServices.Protocols
        if (-not($MembersExpanded)) {
            $MembersExpanded = New-Object System.Collections.ArrayList
        }
    }
    
    Process {
        # Create LDAP connection
        $LDAPConnection = Connect-SecureLDAP -Server $strDC -Credential $CREDS
        $LDAPConnection.SessionOptions.ReferralChasing = 'None'

        # Setup range limits
        $RangeStep = 1499
        $LowRange = 0
        $HighRange = $LowRange + $RangeStep
        $ExitFlag = $False

        Do {
            # Create search request for the group
            $request = New-Object System.DirectoryServices.Protocols.SearchRequest
            $request.DistinguishedName = $GroupDN
            $request.Filter = '(objectCategory=group)'
            $request.Scope = 'Base'
            
            # Set up ranged member attribute
            if ($HighRange -ge 0) {
                $memberAttribute = "member;range=$LowRange-$HighRange"
            } else {
                $memberAttribute = "member;range=$LowRange-*"
            }
            [void]$request.Attributes.Add($memberAttribute)

            Try {
                $response = $LDAPConnection.SendRequest($request)
                $groupEntry = $response.Entries[0]
            } catch {
                Write-Verbose "Error querying group $GroupDN : $($_.Exception.Message)"
                break
            }

            # Check if we have members
            $Members = $null
            $Count = 0
            
            # Find the actual attribute name returned (may have different range)
            $actualAttributeName = $null
            foreach ($attrName in $groupEntry.Attributes.AttributeNames) {
                if ($attrName -like "member;range=*" -or $attrName -eq "member") {
                    $actualAttributeName = $attrName
                    break
                }
            }
            
            if ($actualAttributeName -and $groupEntry.Attributes[$actualAttributeName]) {
                $Members = $groupEntry.Attributes[$actualAttributeName].GetValues([string])
                $Count = $Members.Count
                
                # Check if this is the last range (indicated by * in the attribute name)
                if ($actualAttributeName -like "*-*") {
                    $ExitFlag = $true
                }
            } else {
                # No more members
                $ExitFlag = $true
            }

            # Process each member
            if ($Members -and $Count -gt 0) {
                ForEach ($Member in $Members) {
                    # Get member details
                    $memberRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
                    $memberRequest.DistinguishedName = $Member
                    $memberRequest.Filter = '(name=*)'
                    $memberRequest.Scope = 'Base'
                    [void]$memberRequest.Attributes.Add('objectclass')
                    [void]$memberRequest.Attributes.Add('member')

                    Try {
                        $memberResponse = $LDAPConnection.SendRequest($memberRequest)
                        $memberEntry = $memberResponse.Entries[0]
                    } catch {
                        Write-Verbose "Error - Could not read object $Member : $($_.Exception.Message)"
                        continue
                    }

                    # Get object class
                    Try {
                        $objectClassValues = $memberEntry.Attributes['objectclass'].GetValues([string])
                        $ObjectClass = $objectClassValues[$objectClassValues.Count - 1]
                    } catch {
                        Write-Verbose "Error - Could not read objectClass for $Member"
                        continue
                    }

                    # If this is a group, recursively process it
                    if ($ObjectClass -eq 'group') {
                        # Check if group has members (to avoid infinite recursion on empty groups)
                        $hasMemberAttribute = $memberEntry.Attributes.AttributeNames -contains 'member' -or 
                                            ($memberEntry.Attributes.AttributeNames | Where-Object { $_ -like 'member;range=*' })
                        
                        if ($hasMemberAttribute -and 
                            ($global:colOfGroupMembersExpanded -notcontains $Member) -and 
                            ($GroupDN -ne $Member)) {
                            
                            $MembersExpanded = @(Get-LargeNestedADGroup -strDC $strDC -GroupDN $Member -Output $Output -MembersExpanded $MembersExpanded -CREDS $CREDS)
                            [void]$global:GroupMembersExpanded.insert(0, $Member)
                        }
                    }

                    # Add member to results if it matches the output filter
                    if (($Output -eq '*') -or ($ObjectClass -eq $Output)) {
                        if ($MembersExpanded -notcontains $Member) {
                            [void]$MembersExpanded.add($Member)
                        }
                    }
                }
            }

            # Prepare for next range if not done
            if (-not $ExitFlag) {
                if ($Count -eq 0) {
                    # No members returned, we're done
                    $ExitFlag = $true
                } else {
                    # Setup next range
                    $LowRange = $HighRange + 1
                    $HighRange = $LowRange + $RangeStep
                }
            }
            
        } Until ($ExitFlag -eq $true)
        
        # Close the connection
        $LDAPConnection.Dispose()
    }
    
    End {
        return $MembersExpanded
    }
}

#==========================================================================
# Function		: Test-ResolveDNS
# Arguments     : DNS Name, DNS Server
# Returns   	: boolean
# Description   : This function try to resolve a dns record and retruns true or false
#
#==========================================================================
Function Test-ResolveDNS {
    param
    (
        $strDNS,
        $strDNSServer = ''
    )
    $bolResolved = $false
    $global:bolDNSSuccess = $true
    $global:DNSrslt = $null
    try {
        if ($strDNSServer -eq '') {
            $global:DNSrslt = Resolve-DnsName -Type ALL -Name $strDNS -ErrorAction Stop
        } else {
            $global:DNSrslt = Resolve-DnsName -Type ALL -Name $strDNS -ErrorAction Stop -Server $strDNSServer
        }
    } catch {
        $global:bolDNSSuccess = $false
    }
    if ($global:bolDNSSuccess) {
        if (($global:DNSrslt)[0].IPAddress -ne $null) {
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
function LogMessage {
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

        if ($DateStamp) {

            $newMessageObject = New-Object PSObject -Property @{Type = "$strType"; Message = "[$(Get-Date)] $strMessage" }
        } else {

            $newMessageObject = New-Object PSObject -Property @{Type = "$strType"; Message = "$strMessage" }
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
function ConvertTo-ObjectArrayListFromPsCustomObject {
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
            $Newobject = New-Object psobject -Property $hashTable
            [void]$myCustomArray.add($Newobject)
        }
        return $myCustomArray
    }
}
#==========================================================================
# Function		: DisplayLegend
# Arguments     : -
# Returns   	: -
# Description   : Show color legend
#==========================================================================
Function DisplayLegend {
    $xamlLegend = @'
<Window x:Class="WpfApplication1.Legend"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Color Legend" WindowStartupLocation = "CenterScreen"
        Width = "450" Height = "390" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="#2A3238" >
    <Window.Resources>

        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Pink"/>
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
                <Label x:Name="lblText" Content="Use colors in report to identify criticality level of permissions.&#10;This might help you in implementing Least-Privilege Administrative Models." Margin="10,05,00,00" Foreground="White" />
                    <StackPanel Orientation="Vertical" Margin="10,0">
                    <DataGrid x:Name="dgLegend" HorizontalAlignment="Left" Margin="0,0,0,0" Height="235" Width="290" GridLinesVisibility="All"  IsReadOnly="True" FontSize="12" VerticalScrollBarVisibility="Disabled" >
                        <DataGrid.Columns>
                            <DataGridTextColumn Header='Permissions' Binding='{Binding Permissions}' Width='100'  />
                            <DataGridTextColumn Header='Criticality' Width='182' SortMemberPath='Criticality' SortDirection='Ascending'>
                                    <DataGridTextColumn.CellStyle>
                                        <Style TargetType="DataGridCell">
                                            <Style.Triggers>
                                                <DataTrigger Binding="{Binding Path=Criticality}" Value="Critical">
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="DataGridCell">
                                                                <TextBox Text="Critical" BorderBrush='{x:Null}' Background="Red"/>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                </DataTrigger>
                                                <DataTrigger Binding="{Binding Path=Criticality}" Value="Warning">
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="DataGridCell">
                                                                <TextBox Text="Warning" BorderBrush='{x:Null}' Background="#FFD700"/>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                </DataTrigger>
                                                <DataTrigger Binding="{Binding Path=Criticality}" Value="Medium">
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="DataGridCell">
                                                                <TextBox Text="Medium" BorderBrush='{x:Null}' Background="Yellow"/>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                </DataTrigger>
                                                <DataTrigger Binding="{Binding Path=Criticality}" Value="Low">
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="DataGridCell">
                                                                <TextBox Text="Low" BorderBrush='{x:Null}' Background="#0099FF"/>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                </DataTrigger>
                                                <DataTrigger Binding="{Binding Path=Criticality}" Value="Info">
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="DataGridCell">
                                                                <TextBox Text="Info" BorderBrush='{x:Null}' Background="Gray"/>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                </DataTrigger>
                                            </Style.Triggers>
                                        </Style>
                                    </DataGridTextColumn.CellStyle>
                                </DataGridTextColumn>
                        </DataGrid.Columns>
                    </DataGrid>
                    </StackPanel>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                    <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
                </StackPanel>
            </StackPanel>
        </Grid>
    </ScrollViewer>
</Window>


'@


    [XML] $XAML = $xamlLegend
    $xaml.Window.RemoveAttribute('x:Class')

    $reader = (New-Object System.Xml.XmlNodeReader $XAML)

    $WindowLegend = [Windows.Markup.XamlReader]::Load( $reader )

    #Replace x:Name to XML variable Name
    $xamlLegend = $xamlLegend.Replace('x:Name', 'Name')
    [XML] $XAML = $xamlLegend

    #Search the XML data for object and create variables
    $XAML.SelectNodes('//*[@Name]') | ForEach-Object { Set-Variable -Name ($_.Name) -Value $WindowLegend.FindName($_.Name) }

    $Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

    $IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $IconImage.BeginInit()
    $IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
    $IconImage.EndInit()

    # Freeze() prevents memory leaks.
    $IconImage.Freeze()


    $WindowLegend.Icon = $IconImage

    $btnOK.add_Click(
        {
            #TODO: Place custom script here


            $WindowLegend.close()

        })

    $Legend = @{
        'Deny Permissions'  = 'Info';
        'List'              = 'Info';
        'Read Properties'   = 'Low';
        'Read Object'       = 'Low';
        'Read Permissions'  = 'Low';
        'Write Propeties'   = 'Medium';
        'Create Object'     = 'Warning';
        'Delete Object'     = 'Warning';
        'ExtendedRight'     = 'Warning';
        'Modify Permisions' = 'Critical';
        'Full Control'      = 'Critical'
    }

    foreach ($LegendRow in $Legend.keys) {

        # Legend Object to put in DataGrid
        $objCriticality = New-Object PSObject
        Add-Member -InputObject $objCriticality -MemberType NoteProperty -Name 'Permissions' -Value $LegendRow
        Add-Member -InputObject $objCriticality -MemberType NoteProperty -Name 'Criticality' -Value $Legend."$LegendRow"

        $dgLegend.AddChild($objCriticality)

    }


    [void]$WindowLegend.ShowDialog()

}
#==========================================================================
# Function		: GenerateTemplateDownloaderSchemaDefSD
# Arguments     : -
# Returns   	: -
# Description   : Generates a form for download links
#==========================================================================
Function GenerateTemplateDownloaderSchemaDefSD {
    [xml]$xamlTemplateDownloaderSchemaDefSD = @'
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="CSV Templates" WindowStartupLocation = "CenterScreen"
        Width = "380" Height = "250" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="#2A3238">
    <Window.Resources>

        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Pink"/>
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
            <Label x:Name="lblDownloadLinks" Content="Download links for defaultSecuritydescriptor CSV templates:" Margin="10,05,00,00"  Foreground="White"/>
                <GroupBox x:Name="gBoxTemplate" Header="Templates" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Foreground="White">
                    <StackPanel Orientation="Vertical" Margin="0,0">
                        <Button x:Name="btnDownloadCSVFileSchema2025" Content="Windows Server 2025" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        <Button x:Name="btnDownloadCSVFileSchema2019_1809" Content="Windows Server 2019 1809" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
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

'@

    $xamlTemplateDownloaderSchemaDefSD.Window.RemoveAttribute('x:Class')

    $reader = (New-Object System.Xml.XmlNodeReader $xamlTemplateDownloaderSchemaDefSD)
    $TemplateDownloaderSchemaDefSDGui = [Windows.Markup.XamlReader]::Load( $reader )

    $Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

    $IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $IconImage.BeginInit()
    $IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
    $IconImage.EndInit()

    # Freeze() prevents memory leaks.
    $IconImage.Freeze()


    $TemplateDownloaderSchemaDefSDGui.Icon = $IconImage

    $btnOK = $TemplateDownloaderSchemaDefSDGui.FindName('btnOK')
    $btnDownloadCSVFileSchema2025 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2025')
    $btnDownloadCSVFileSchema2019_1809 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2019_1809')
    $btnDownloadCSVFileSchema2016 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2016')
    $btnDownloadCSVFileSchema2012R2 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2012R2')
    $btnDownloadCSVFileSchema2012 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2012')
    $btnDownloadCSVFileSchema2008R2 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2008R2')
    $btnDownloadCSVFileSchema2003SP1 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2003SP1')
    $btnDownloadCSVFileSchema2003 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2003')
    $btnDownloadCSVFileSchema2000SP4 = $TemplateDownloaderSchemaDefSDGui.FindName('btnDownloadCSVFileSchema2000SP4')


    $btnOK.add_Click({
            $TemplateDownloaderSchemaDefSDGui.Close()
        })
    $btnDownloadCSVFileSchema2025.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2025_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2019_1809.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2019_1809_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2016.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2016_RTM_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2012R2.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2012_RTM_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2012.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2012_R2_RTM_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2008R2.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2008_R2_SP1_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2003SP1.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2003_SP1_defaultsSecurityDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2003.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2003_RTM_defaultsSecurityDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFileSchema2000SP4.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DefaultSecurityDescriptors/Win_2000_SP4_DefaultSecDescriptor.csv'
            Invoke-FileDownload -Url $URL
        })



    $TemplateDownloaderSchemaDefSDGui.ShowDialog()

}
#==========================================================================
# Function		: Invoke-FileDownload
# Arguments     : -
# Returns   	: -
# Description   : download file
#==========================================================================
function Invoke-FileDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [Parameter(Mandatory = $false)]
        [string]$DestinationPath = $PSScriptRoot,
        
        [Parameter(Mandatory = $false)]
        [string]$FileName
    )
    
    try {

        # Extract filename if not provided
        if (-not $FileName) {
            $FileName = Split-Path -Leaf ([System.Uri]$Url).LocalPath
            if (-not $FileName) {
                $FileName = "Downloaded_file_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            }
        }
        
        $DestinationFile = Join-Path -Path $DestinationPath -ChildPath $FileName
       

        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
        # Download the file
        Invoke-WebRequest -Uri $Url -OutFile $DestinationFile -ErrorAction Stop -UserAgent $UserAgent 
        
        if (Test-Path -Path $DestinationFile) {
            $MsgBox = [System.Windows.Forms.MessageBox]::Show("File downloaded: `n$DestinationFile", 'Downloads' , 0, 'Information')
        }
        else {
            $MsgBox = [System.Windows.Forms.MessageBox]::Show('Download failed', 'Error' , 0, 'Error')
        }
    }
    catch {
        $MsgBox = [System.Windows.Forms.MessageBox]::Show("Download failed!`n $($_.Exception.Message)", 'Error' , 0, 'Error')

    }
}

#==========================================================================
# Function		: GenerateTemplateDownloader
# Arguments     : -
# Returns   	: -
# Description   : Generates a form for download links
#==========================================================================
Function GenerateTemplateDownloader {
    [xml]$xamlTemplateDownloader = @'
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="CSV Templates" WindowStartupLocation = "CenterScreen"
        Width = "390" Height = "290" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="#2A3238" >
    <Window.Resources>

        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Pink"/>
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
            <StackPanel Orientation="Vertical" Margin="0,0,0,0">
                <Label x:Name="lblDownloadLinks" Content="Download links for operating system default DACL templates:" Margin="5,05,00,00" Foreground="White" />
                <StackPanel Orientation="Horizontal">
                <Label x:Name="lblDownloadSelect" Content="Select OS:" Margin="5,00,00,00" Foreground="White" />
                <ComboBox x:Name="SelectOS"  Width="190" Margin="0,0,0,0" HorizontalAlignment="Left" />
                </StackPanel>
                <StackPanel Orientation="Vertical" Margin="0,10">
                    <GroupBox x:Name="gBox2025" Header="Windows Server 2025" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Visibility="Visible" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2025" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}" />
                            <Button x:Name="btnDownloadCSVFile2025Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2025Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2025Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2025DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2025ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2025AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2019_1809" Header="Windows Server 2019 1809" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2019_1809" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}" />
                            <Button x:Name="btnDownloadCSVFile2019_1809Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2019_1809Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2019_1809Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2019_1809DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2019_1809ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2019_1809AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2016" Header="Windows Server 2016" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2016" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2016AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2012R2" Header="Windows Server 2012 R2" HorizontalAlignment="Left"  Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0" >
                            <Button x:Name="btnDownloadCSVFile2012R2" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012R2AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2012" Header="Windows Server 2012" HorizontalAlignment="Left" Margin="2,1,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2012" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2012AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2008R2" Header="Windows Server 2008 R2" HorizontalAlignment="Left"  Margin="2,0,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2008R2" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2008R2AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2003" Header="Windows Server 2003" HorizontalAlignment="Left" Margin="2,0,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2003" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003Schema" Content="Schema NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003DomainDNS" Content="Domain DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003ForestDNS" Content="Forest DNS Zone NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2003AllFiles" Content="All Files Compressed" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                        </StackPanel>
                    </GroupBox>
                    <GroupBox x:Name="gBox2000SP4" Header="Windows 2000 Server SP4" HorizontalAlignment="Left" Margin="2,0,0,0" VerticalAlignment="Top" Width="210" Visibility="Collapsed" Foreground="White" >
                        <StackPanel Orientation="Vertical" Margin="0,0">
                            <Button x:Name="btnDownloadCSVFile2000SP4" Content="Each NC root combined" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2000SP4Domain" Content="Domain NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
                            <Button x:Name="btnDownloadCSVFile2000SP4Config" Content="Configuration NC" HorizontalAlignment="Left"  VerticalAlignment="Top" Width="200" Style="{StaticResource AButtonStyle}"/>
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

'@

    $xamlTemplateDownloader.Window.RemoveAttribute('x:Class')

    $reader = (New-Object System.Xml.XmlNodeReader $xamlTemplateDownloader)
    $TemplateDownloaderGui = [Windows.Markup.XamlReader]::Load( $reader )

    $Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

    $IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $IconImage.BeginInit()
    $IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
    $IconImage.EndInit()

    # Freeze() prevents memory leaks.
    $IconImage.Freeze()


    $TemplateDownloaderGui.Icon = $IconImage


    $btnOK = $TemplateDownloaderGui.FindName('btnOK')

    $btnDownloadCSVFile2025 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025')
    $btnDownloadCSVFile2025Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025Domain')
    $btnDownloadCSVFile2025Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025Config')
    $btnDownloadCSVFile2025Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025Schema')
    $btnDownloadCSVFile2025DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025DomainDNS')
    $btnDownloadCSVFile2025ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025ForestDNS')
    $btnDownloadCSVFile2025AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2025AllFiles')

    $btnDownloadCSVFile2019_1809 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809')
    $btnDownloadCSVFile2019_1809Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809Domain')
    $btnDownloadCSVFile2019_1809Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809Config')
    $btnDownloadCSVFile2019_1809Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809Schema')
    $btnDownloadCSVFile2019_1809DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809DomainDNS')
    $btnDownloadCSVFile2019_1809ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809ForestDNS')
    $btnDownloadCSVFile2019_1809AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2019_1809AllFiles')

    $btnDownloadCSVFile2016 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016')
    $btnDownloadCSVFile2016Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016Domain')
    $btnDownloadCSVFile2016Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016Config')
    $btnDownloadCSVFile2016Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016Schema')
    $btnDownloadCSVFile2016DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016DomainDNS')
    $btnDownloadCSVFile2016ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016ForestDNS')
    $btnDownloadCSVFile2016AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2016AllFiles')

    $btnDownloadCSVFile2012R2 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2')
    $btnDownloadCSVFile2012R2Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2Domain')
    $btnDownloadCSVFile2012R2Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2Config')
    $btnDownloadCSVFile2012R2Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2Schema')
    $btnDownloadCSVFile2012R2DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2DomainDNS')
    $btnDownloadCSVFile2012R2ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2ForestDNS')
    $btnDownloadCSVFile2012R2AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012R2AllFiles')
    $btnDownloadCSVFile2012 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012')
    $btnDownloadCSVFile2012Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012Domain')
    $btnDownloadCSVFile2012Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012Config')
    $btnDownloadCSVFile2012Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012Schema')
    $btnDownloadCSVFile2012DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012DomainDNS')
    $btnDownloadCSVFile2012ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012ForestDNS')
    $btnDownloadCSVFile2012AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2012AllFiles')
    $btnDownloadCSVFile2008R2 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2')
    $btnDownloadCSVFile2008R2Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2Domain')
    $btnDownloadCSVFile2008R2Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2Config')
    $btnDownloadCSVFile2008R2Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2Schema')
    $btnDownloadCSVFile2008R2DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2DomainDNS')
    $btnDownloadCSVFile2008R2ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2ForestDNS')
    $btnDownloadCSVFile2008R2AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2008R2AllFiles')
    $btnDownloadCSVFile2003 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003')
    $btnDownloadCSVFile2003Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003Domain')
    $btnDownloadCSVFile2003Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003Config')
    $btnDownloadCSVFile2003Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003Schema')
    $btnDownloadCSVFile2003DomainDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003DomainDNS')
    $btnDownloadCSVFile2003ForestDNS = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003ForestDNS')
    $btnDownloadCSVFile2003AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2003AllFiles')
    $btnDownloadCSVFile2000SP4 = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2000SP4')
    $btnDownloadCSVFile2000SP4Domain = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2000SP4Domain')
    $btnDownloadCSVFile2000SP4Config = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2000SP4Config')
    $btnDownloadCSVFile2000SP4Schema = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2000SP4Schema')
    $btnDownloadCSVFile2000SP4AllFiles = $TemplateDownloaderGui.FindName('btnDownloadCSVFile2000SP4AllFiles')
    $SelectOS = $TemplateDownloaderGui.FindName('SelectOS')
    $gBox2025 = $TemplateDownloaderGui.FindName('gBox2025')    
    $gBox2019_1809 = $TemplateDownloaderGui.FindName('gBox2019_1809')
    $gBox2016 = $TemplateDownloaderGui.FindName('gBox2016')
    $gBox2012R2 = $TemplateDownloaderGui.FindName('gBox2012R2')
    $gBox2012 = $TemplateDownloaderGui.FindName('gBox2012')
    $gBox2008R2 = $TemplateDownloaderGui.FindName('gBox2008R2')
    $gBox2003 = $TemplateDownloaderGui.FindName('gBox2003')
    $gBox2000SP4 = $TemplateDownloaderGui.FindName('gBox2000SP4')

    [void]$SelectOS.Items.Add('Windows Server 2025')    
    [void]$SelectOS.Items.Add('Windows Server 2019 1809')
    [void]$SelectOS.Items.Add('Windows Server 2016')
    [void]$SelectOS.Items.Add('Windows Server 2012 R2')
    [void]$SelectOS.Items.Add('Windows Server 2012')    
    [void]$SelectOS.Items.Add('Windows Server 2008 R2')
    [void]$SelectOS.Items.Add('Windows Server 2003')
    [void]$SelectOS.Items.Add('Windows 2000 Server SP4')

    $SelectOS.SelectedValue = 'Windows Server 2025'

    $SelectOS.add_SelectionChanged({

            Switch ($SelectOS.SelectedValue) {
                'Windows Server 2025' {
                    $gBox2025.Visibility = 'Visible'                    
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2019 1809' {
                    $gBox2025.Visibility = 'Collapsed'                    
                    $gBox2019_1809.Visibility = 'Visible'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2016' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Visible'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2012 R2' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Visible'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2012' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Visible'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2008 R2' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Visible'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows Server 2003' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Visible'
                    $gBox2000SP4.Visibility = 'Collapsed'
                }
                'Windows 2000 Server SP4' {
                    $gBox2025.Visibility = 'Collapsed'
                    $gBox2019_1809.Visibility = 'Collapsed'
                    $gBox2016.Visibility = 'Collapsed'
                    $gBox2012R2.Visibility = 'Collapsed'
                    $gBox2012.Visibility = 'Collapsed'
                    $gBox2008R2.Visibility = 'Collapsed'
                    $gBox2003.Visibility = 'Collapsed'
                    $gBox2000SP4.Visibility = 'Visible'
                }
                default {
                }
            }

        })

    $btnOK.add_Click({
            $TemplateDownloaderGui.Close()
        })
    ## START 2025
    $btnDownloadCSVFile2025.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL

        })
    $btnDownloadCSVFile2025Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2025Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2025Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2025DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2025ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Win_2025_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2025AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2025_RTM/Windows_Server_2025_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2025
    ## START 2019 1809
    $btnDownloadCSVFile2019_1809.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL

        })
    $btnDownloadCSVFile2019_1809Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2019_1809Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2019_1809Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2019_1809DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2019_1809ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Win_2019_1809_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2019_1809AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2019_1809/Windows_Server_2019_1809_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2019 1809

    ## START 2016
    $btnDownloadCSVFile2016.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Win_2016_RTM_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2016AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2016_RTM/Windows_Server_2016_RTM_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2016

    ## START 2012 R2
    $btnDownloadCSVFile2012R2.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Win_2012_R2_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012R2AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_R2_RTM/Windows_Server_2012_R2_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2012 R2
    ## START 2012
    $btnDownloadCSVFile2012.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Win_2012_RTM_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2012AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2012_RTM/Windows_Server_2012_RTM_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2012
    ## START 2008 R2
    $btnDownloadCSVFile2008R2.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Win_2008_R2_SP1_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2008R2AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2008_R2_SP1/Windows_Server_2008_R2_SP1_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2008 R2
    ## START 2003

    $btnDownloadCSVFile2003.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003DomainDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_DomainDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003ForestDNS.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Win_2003_SP1_Default_DACL_ForestDnsZones.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2003AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2003_SP1/Windows_Server_2003_SP1_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2003

    ## START 2000 SP4

    $btnDownloadCSVFile2000SP4.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2000_SP4/Win_2000_SP4_Default_DACL_NC.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2000SP4Domain.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2000_SP4/Win_2000_SP4_Default_DACL_Domain.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2000SP4Config.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2000_SP4/Win_2000_SP4_Default_DACL_Config.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2000SP4Schema.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2000_SP4/Win_2000_SP4_Default_DACL_Schema.csv'
            Invoke-FileDownload -Url $URL
        })
    $btnDownloadCSVFile2000SP4AllFiles.add_Click({
            $URL = 'https://raw.githubusercontent.com/canix1/ADACLRepository/refs/heads/main/DACL_Library/Windows_Server_2000_SP4/Windows_2000_Server_SP4_DACL.zip'
            Invoke-FileDownload -Url $URL
        })
    ## END 2000


    $TemplateDownloaderGui.ShowDialog()

}

function Get-CredentialsUI
{
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Base64 representation of Icon file from mmcndmgr.dll Index 58
$Userpng = @'
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAECSURBVFhH7ZFBDsMwCATz9DwtP0tDDNWCwDXY6SkjjahkvGs120uBM+FSvIJRp/FCs5bxwqqm8UJmTOOF/PQ4jpOgScJZCrw4LJbL5LM0KnhUKZX51wdIKU4+K6HCewalaAkvSEnYcpp0RLP9vndLfIusXmk0Sb6XRpWiEj46+V4aVYqOlNrJd1OoUk8JjyYUk2nwcqiURZP3yqgyq5RE8/EH9Mpl8u4UqlTEkp68vwS3nMAzx2XcZbZc5r7vt7TX1tcTluMjaK+tr0WCu4946gFXIH1nkUqa9hFPfIYrCMut7SGE+QfQKa4Ar9iKhe5ZGQlgbbgVd9TdZdjgni8DbNsHGNd/8V9LX0IAAAAASUVORK5CYII=
'@

# #$UserCombo = $Window.FindName("UserCombo")
 If (!(Test-Path ($env:temp + '\User.png'))) {
     $IconFilePath = $env:temp + '\User.png'
     $bytes = [Convert]::FromBase64String($Userpng)
     [IO.File]::WriteAllBytes($IconFilePath, $bytes)
 }


$DefaultIcon = New-Object System.Windows.Media.Imaging.BitmapImage
$DefaultIcon.BeginInit()
# Use absolute Uri so WPF loads from file
#$DefaultIcon.UriSource = (New-Object System.Uri($iconPath, [System.UriKind]::Absolute))
$DefaultIcon.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Userpng)
$DefaultIcon.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
$DefaultIcon.EndInit()
$DefaultIcon.Freeze()

# Define the XAML without event handler attributes (we'll add them programmatically)
$xamlBase = @"
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows PowerShell credential request" 
        Height="280" 
        Width="320"
        WindowStyle="None"
        ResizeMode="NoResize"
        WindowStartupLocation="CenterScreen"
        AllowsTransparency="True"
        Background="Transparent">

    <Border BorderBrush="#FF707070" BorderThickness="1">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="30"/>
                <RowDefinition Height="60"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <!-- Custom Title Bar -->
            <Border Name="TitleBar" Grid.Row="0" Background="White">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>

                    <!-- Title Text -->
                    <TextBlock Grid.Column="0" 
                               Text="Windows PowerShell credential request" 
                               VerticalAlignment="Center"
                               Margin="10,0,0,0"
                               FontFamily="Segoe UI"
                               FontSize="12"/>

                    <!-- Window Control Buttons -->
                    <StackPanel Grid.Column="1" Orientation="Horizontal">
                        <Button Name="HelpButton" 
                                Content="?" 
                                Width="30" 
                                Height="30"
                                Background="White"
                                BorderThickness="0"
                                FontWeight="Bold"
                                FontSize="12">
                            <Button.Style>
                                <Style TargetType="Button">
                                    <Setter Property="Template">
                                        <Setter.Value>
                                            <ControlTemplate TargetType="Button">
                                                <Border Background="{TemplateBinding Background}">
                                                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                </Border>
                                            </ControlTemplate>
                                        </Setter.Value>
                                    </Setter>
                                    <Style.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#FFE5E5E5"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </Button.Style>
                        </Button>
                        <Button Name="CloseButton" 
                                Content="✕" 
                                Width="30" 
                                Height="30"
                                Background="White"
                                BorderThickness="0"
                                FontSize="12">
                            <Button.Style>
                                <Style TargetType="Button">
                                    <Setter Property="Template">
                                        <Setter.Value>
                                            <ControlTemplate TargetType="Button">
                                                <Border Background="{TemplateBinding Background}">
                                                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                </Border>
                                            </ControlTemplate>
                                        </Setter.Value>
                                    </Setter>
                                    <Style.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#FFE81123"/>
                                            <Setter Property="Foreground" Value="White"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </Button.Style>
                        </Button>
                    </StackPanel>
                </Grid>
            </Border>

            <!-- Blue Header Section with Keys Icon -->
            <Border Grid.Row="1">
                <Image x:Name="imgKeyImage" HorizontalAlignment="Left"  VerticalAlignment="Center"  />
            </Border>

            <!-- Main Content Area -->
            <Grid Grid.Row="2" Background="#FFF0F0F0">
                <StackPanel Margin="10,15,20,0">
                    <!-- Enter your credentials text -->
                    <TextBlock Text="Enter your credentials." 
                               FontFamily="Segoe UI"
                               FontSize="11"
                               Margin="0,0,0,20"/>

                <!-- User name Field -->
                    <Grid Margin="0,0,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="90"/>
                            <ColumnDefinition Width="180"/>
                            <ColumnDefinition Width="20"/>
                        </Grid.ColumnDefinitions>
                        
                        <Label Grid.Column="0" 
                               Content="User name:" 

                               Padding="0,5,5,5"
                               FontFamily="Segoe UI"
                               FontSize="11"/>
                               
                        <ComboBox Grid.Column="1" 
                            Name="UserCombo"
                            Height="23"
                            Width="180"
                            IsEditable="True"
                            TextSearch.TextPath="Name">
                            <!-- Custom Template: puts an Image inside the edit area -->
                            <ComboBox.Template>
                                <ControlTemplate TargetType="ComboBox">
                                    <Grid>
                                        <Border BorderBrush="DarkBlue" BorderThickness="0.5" CornerRadius="0" Background="White">
                                            <Grid>
                                                <!-- Image inside the edit area (we will set Source from code) -->
                                                <Image x:Name="PART_DisplayImage"
                                                    Width="16" Height="16"
                                                    Margin="6,0,0,0"
                                                    VerticalAlignment="Center"
                                                    HorizontalAlignment="Left"/>

                                                <!-- Editable text area. Bind to the ComboBox.Text property -->
                                                <TextBox x:Name="PART_EditableTextBox"
                                                        Text="{Binding Path=Text, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
                                                        Background="Transparent"
                                                        FontFamily="Segoe UI"
                                                        FontSize="11"
                                                        BorderThickness="0"
                                                        Padding="22,0,24,0"
                                                        VerticalContentAlignment="Center"/>

                                                <!-- Drop-down toggle -->
                                                <ToggleButton x:Name="PART_DropDownToggle"
                                                            Focusable="False"
                                                            IsChecked="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay}"
                                                            ClickMode="Press"
                                                            HorizontalAlignment="Right"
                                                            Width="20"
                                                            BorderThickness="0"
                                                            Background="Transparent">
                                                    <Path HorizontalAlignment="Center" VerticalAlignment="Center" Data="M 0 0 L 4 4 L 8 0 Z" Fill="Black"/>
                                                </ToggleButton>
                                            </Grid>
                                        </Border>

                                        <!-- The popup for the dropdown -->
                                        <Popup Name="PART_Popup"
                                            Placement="Bottom"
                                            PlacementTarget="{Binding RelativeSource={RelativeSource TemplatedParent}}"
                                            IsOpen="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}}"
                                            AllowsTransparency="True"
                                            Focusable="False"
                                            PopupAnimation="Slide">
                                            <Border BorderBrush="Gray" BorderThickness="1" Background="White">
                                                <ScrollViewer MaxHeight="200" MinHeight="200">
                                                    <ItemsPresenter/>
                                                </ScrollViewer>
                                            </Border>
                                        </Popup>
                                    </Grid>
                                </ControlTemplate>
                            </ComboBox.Template>

                            <!-- Item template for dropdown items (icon + name) -->
                            <ComboBox.ItemTemplate>
                                <DataTemplate>
                                    <StackPanel Orientation="Horizontal" Margin="2" Width="165">
                                        <Image Source="{Binding Icon}" Width="16" Height="16" Margin="2,0,4,0"/>
                                        <TextBlock Text="{Binding Name}" VerticalAlignment="Center"/>
                                    </StackPanel>
                                </DataTemplate>
                            </ComboBox.ItemTemplate>
                        </ComboBox>

                        <Button Grid.Column="2" 
                                Name="DotButton"
                                Content="..."
                                Width="15" Height="20"
                                Margin="0,0,0,0"
                                Background="#F9F9F9"
                                BorderBrush="#F9F9F9"
                                IsEnabled="False">
    
                        </Button>
                    </Grid>

                    <!-- Password Field -->
                    <Grid Margin="0,0,0,20">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="90"/>
                            <ColumnDefinition Width="180"/>
                        </Grid.ColumnDefinitions>

                        <Label Grid.Column="0" 
                               Content="Password:" 
                               VerticalAlignment="Center"
                               Padding="0,5,5,5"
                               FontFamily="Segoe UI"
                               FontSize="12"/>

                        <PasswordBox Grid.Column="1" 
                                    Name="PasswordBox"
                                    Width="180"
                                    Height="23"
                                    VerticalContentAlignment="Center"/>
                    </Grid>

                    <!-- Buttons -->
                    <StackPanel Orientation="Horizontal" 
                                HorizontalAlignment="Center"
                                Margin="100,25,0,0">
                        <Button Name="OkButton"
                                Content="OK"
                                Width="80"
                                Height="23"
                                Margin="0,0,10,0"
                                IsDefault="True"/>
                        <Button Name="CancelButton"
                                Content="Cancel"
                                Width="80"
                                Height="23"
                                IsCancel="True"/>
                    </StackPanel>

                </StackPanel>
            </Grid>
            
        </Grid>
    </Border>
</Window>
"@

#Replace x:Name to XML variable Name
$xamlBase = $xamlBase.Replace("x:Name","Name")
[XML] $XAML = $xamlBase
$xaml.Window.RemoveAttribute("x:Class")  
  
$reader=(New-Object System.Xml.XmlNodeReader $XAML)
$Window=[Windows.Markup.XamlReader]::Load( $reader )

#Search the XML data for object and create variables
$XAML.SelectNodes("//*[@Name]")| %{set-variable -Name ($_.Name) -Value $Window.FindName($_.Name)}



# Build some sample items (use the same icon for demo; you can load different images per item)
 $items = @(
     [PSCustomObject]@{ Name = ""; Icon = ""}
 )

$UserCombo.ItemsSource = $items


function Update-Image {
    param($ComboBox , $displayImage, $DefaultIcon)
    $displayImage = $ComboBox.Template.FindName("PART_DisplayImage", $ComboBox)
    if ($ComboBox.SelectedItem -ne $null) {
        $si = $ComboBox.SelectedItem
        # Some objects may not expose Icon - guard
        if ($si.PSObject.Properties.Match("Icon")) {
            $displayImage.Source = $si.Icon
            return
        }
    }
    # fallback: default icon
    $displayImage.Source = $DefaultIcon
}


$KeyImageicon = @'
iVBORw0KGgoAAAANSUhEUgAAAUAAAAA8CAIAAACYZfTzAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3YXJlAFBhaW50Lk5FVCA1LjEuOWxu2j4AAAC2ZVhJZklJKgAIAAAABQAaAQUAAQAAAEoAAAAbAQUAAQAAAFIAAAAoAQMAAQAAAAMAAAAxAQIAEAAAAFoAAABphwQAAQAAAGoAAAAAAAAAo5MAAOgDAACjkwAA6AMAAFBhaW50Lk5FVCA1LjEuOQADAACQBwAEAAAAMDIzMAGgAwABAAAAAQAAAAWgBAABAAAAlAAAAAAAAAACAAEAAgAEAAAAUjk4AAIABwAEAAAAMDEwMAAAAABdUNkYj53BAQAAKYpJREFUeF7tfXmsXcd53zcz55x77vr2heQj+UiRokRRJrXYkqhYkh1ncRzHSJOmTh0laZoEBYK2KVIEQYMCLtC0KBoUSN02QNEiTRq0KLy0dqwsim3ZskVZEinJkiWK6+P23iMf+ba7nXVm+sd37ty5c85d3uMjJdn8gXicO/v2m++b9ZCvfkcCACGgIKh0qEAz0R00GPbdvPWAlLLHTwVlHwqatleuevBIsrSlEEmJTPvQ1uyzPLQCBq0MKFc9zm7pcs7bPgBE0E4OAITIzD/VnRB6WqFIEkrXQ8sDxpBR5M6yW5qH9t9Uch0F12NQdaK7Gt6wWvRQNKSpIhMA0KtTuYaio2vp1ZJZJ0ajKBgN0YZvWhBuWulh0/FQERo2cRwbNpmW3bLKoKM1e4OkCWxZvAcndfu0n5SFic6ehjZtK6MjGpa3jcPdQvXmsEpU97BpAg/SWbsV/xYRGIPrMWQSOO0tkkz/2Y3AAMC5FELYNiuVhB9D7FMvAioirEbJcnmb5Ji089yyLJdJ1QMxw0YDpf9icYIGaYYCAEpW7BRE3gIpZdhqPtYiZOixKIqwWW2StCOlVAhx40bsx1CpiJJrYd4CTvw6hGEIAE5BOI6jNz2TEfJFSlmvWwDg+/6WEJgarKMUMpmJUPaEEM3c/tcXac+dUbXNCspS6QXK3siS7trDsi82F2oQ0FxkWgFsNEWHmkIgExTbshMDJpQZdmth5MQm0iYJIaOIr67Kxjr3vEBGvqB2LpcbLrlTY3LbOEyPybECHXJEjmUMFjowNt1D5LFajTZDYRM+lJNDlYS9eihOnQis0GPNUOiDsg6e7xiIDfi+mxbUahCx3BgAbLtXDIOD6tXYg70GzVqGDtLahA/yT/nvQWPlRyGTw7qTDj0VBb1T6kGo0yZVKqYNdOXMRBnL7gEISlPpdcHg2chEuooM9HNvo29UmwN2AOSkEEIIYVlWecSenHR2TYjtE2TbOIwVqGslVREKqqsGRq5Q1nHO/RhCQSPJQkHrdavmRXHMCw4tDVuVMseokq5FOP7lnIfVEEV0JoQQJCCMMaNRIskEdVCp5pxnNj0hxG3pPTfZpoh2FBhbZo/SqYXmTOq2f/eEwWSDxoZBR5rDhn89lBZ/23LwKsvMQK7f0oBCXw89YJOuXSeNzIQyh7k0qGPOyrIiGzQ2A5kZ6wtCSL5MRkfpzBSbnZIzQ3SiREsuzdtJ3pDbZjANUkovks1QhE0a+y2u+BA0SCPgnNjlPCuXObJIqc0qw42m06yKWpTBPYUGt1HA4nCDEEIYUjdTCCMsN2aMWVZ7CrNpkGdekAZ7SU9NVW9mRZKV6sLKwvmF+bd833ddt+KIQqGg/DebzWqYMKdQGZ0anx3dvreYG0Mb1FIIDyTLKV0mc86m2xgTs/RUZ9Mz4XQe9FA3Pw02ZsLvr2lwupKNaXBmW2TOgTs9EJtI7GYjw1Aqxd0yZrA3FBQT9TnxIkkCoqbTSiH3Y/AiifrOUA6cQhKDlFJNd7Egfj3xCQAWdIxu2NVxAnytQaJaZJftUSdEMcs5X18nvhbCtYBp0yWcAyseeZGMfYtzHgRBO0wLG5oDtwmsZK9OYIO9mdQ9f+qFlaUF13Xvvf+BmW3jIxPbhoq5gkPzNgGAKIzCMGh63lrNX7h0/sxi7cqFswAwOrl974HHRyvbLf+VicVnMbZ1nvdKe6LxTwqay+xw+s+b53BnVx5oKas3gbul2GMpS6eo1qH7EFjncGZF3SICY3A9hi0hsIIisJ63zIwhdX1O4jiOfcuPQcqEsZQm7JVS+jEgr/I2KZViy7IwOCatCOzF0Gw6UdSmXJrAyfKVb0W1CADKZV5wkoI0Q1GrMb2VXQvA8pUWrQiMZey9lLVhAhvKsyKwzt40dQFgcfHkm68+67ruoSc+eXDnCACsXl+sX7+ysNIM1q8pb/mC67r54aHhobEDxWLUaNgXr108+eZr1ZWlu/fu+rntc8MfdAEAGj6cenvl0sL37/53UemJbn1O/ey2KK17zqRTZrdOE7hbKIPDt43AKVKZCekpqsrJHK20UnclsB52cALrHrTidBBYcdiwxM42VBGVijAITEiyySSECDjxOeGcB5wokSsEIIGRvSjVvQiEkCh43VKShNFeloyqNdYIuJEZncDY5yPJ1gMimiIMQ7tsT+TbbbreCBqNpE0ZYwlHuhNYCeE4jnHhWseGCMye/o3PdrCXALSUmb7sPfGdL+y/5+i9n/g5u1w5dexr3/jbZ0+fOl0NKVDLym1zy9vs/ISdnwh44dra2vLixbfOnDp56sxasz4zPrN3/+GYyO+/8lxky3uOPEor94G4DOcv5daXY5avjjzZKflbOdB+MiJ5S19KuyIYkSJZaW9bpvsNABAmJO8181GhjERxQFU/MbneKRKrnRYhJJ0dAUlYw0mPh7dIngmVyczCKkjejqSzjqFHkXVkOhntpVpBgfDuoSzIM4YZU3mXEvwYwljUIxJE3I9BBgwjwbqSEpC9aBML4scghMzbZLgSlwtgtXpLR2MJUa+RRmDOcQCAQpvnjMhaxKq+4A0upbRK1kSeU0oxqmYomk0HzVSEAqjl+EBjfc1Fjw2LaVEIQ4orbcoJ0atdUyB/9aLsYC8AENGXvSvVhePf/vzM7L69T/10c2H++LOfd113/8EnKqOTdr7sgqt8IqSUdf/G4tzJd958zl9fBIDZwx85fOjRG1frJ45/4fBs5e8+dc2eOysuzUPkX3IPnb/nX4M7i1VtDOd6nGnhgH91z5kicUAhnBlkE1p0upEGFMK3WgJDSgjr1bxpCZz2lqlF6zaqv9l5PllWRUv+NkPhxUmcKjM0pFJK/RAIpYkoxuMfKHhzVOiZFEKgMuzH4NWkrjbr0CUwCl5sRFqgyF6sHH32q050OI4DVnIaBIVwWgKjEA4aJIoio/9sTAL/0q9/VlEUDYSiuc1em3BGOiJ9642/9hq1/R/5TBTIE8/8yejk9oee+PRoZXvOLlpg4WI1IcQHf23t6pXzr3//e381d/rV1dXFoiOecr/5+AcPvH3ZOzt39q49h/PlkROvfHOqfmn7KCFNXwKVcnUlN8tLB5P8aKNJGn0lwM0I4cwgaixPOyEMaYMjseFHTygrL4lgMeSzHomSwJk1k5bAmd6gUwgbUGENZUePKrP+0+grgSNJKEhCCLVEKWdmqR611Zy2jtOSwKr/S5nk2aJtwWtkkhAihAgapNHgQghDgVJAmenHUK3nIIywEa2SNVlIxBuGWg7s0BeKvXEcCyHsPHccR99GSktgAIgFgLAIIcb4bha+J9gv/8Zn0dRiC6D6pu3LgsFeQsjZk9+ujE7O3H9/4/Q7S4vnHvnoL7ngKtJ63urixTdPnf7OydeeW7l8gsTr+/bte+DQ/o/NBh8vvLr7R+/b8djPPn6k/Nbx06euXLxn/2PctZ9/8/rjO9dygS+FcAFkY2l58ilC8j04jD/1vpXpLd170E9ms/XQovUgmKJKqC+B034GJLDhmklgBWPYSmuMmTAIrFdeZ3JmrSK62RvoS2ABhBEghMQUhlzMOai/uEbV8kmVDMeA6EIpEJL4dy3I5RmXJE1gznmtxrygLRLTVYTidz0gUUMSmYjifJmM5NqaMyGk5kVhs/VTcjwsWR6xx8fYSAmYLfN5EkZMSplJYKVFG9qKBNL3n6pN9vSvZxC4xQRIn09Ap1Nvf2fb9N2V3bv9a9erq/Mzdz3geavXr81dvPDdq+9888LcSdGY3zk98uAHDh49evThhx8eHS7vvPx/xqpvyAc+Ys3+NJA8tcn4cO3l19cIGZkan72+cnmaXt9uN6UQ1LZFvLxcOSxyu7WMYZbMhk/LB4TRm9OkSjebzqusdNpBjOS6TYN19CDw4NNgPRJGZJrDOjZHYB23msB6GykCSybLjtnOftzW55PRkxOlP0uZrDwzkrhySQQVEZd+DAEnRCZ92ItkvWoeS05XUcSlEryJ2lzmpdYJDPRfi1ijltQwFWEcx5ZlDY+728bBZgQFbK1uYVqZBCaECCp4RCil6UlWb5gEbrMXgFCsXDDYq05xAMD8pdc54aXi8KXTJ+bf+W4QB2sXX2msXJgeKx04cODoIw88/PDD+/ftq0zuYjKOz/zN9pP/JV8ZoT/2i2T0KJENXjtNm98dHs/dmLcXq6tjI7uX165sE2f2FkMpBHFHvMhr8IoYezSTDAoqPwMKYd1eNZtuuSVa9CDrWEYqqS6UTWBjpBiEwJm6RkfGto7ARuV38jODwDp0ApdsaZxRk0JEIsmPIrCqJZy6xwKaMQkiLgllRIKg1JIoq0VMeUR4RHwfAk4oCE5sRSqjfhoBD+sCBa9kbqHEJ0uUsfYukZTyhm/xWpB0Kh7EcVwoFCYm7JFKMjTU/VixtxuBUQjHsZUWwn2hahO7Nai/iEz2GuarF945/uznm9fPfeCBRx46sP2TP/PTv/Irv/ypT33qsccenZycjKLoWpM2V+bdV//T1JWvyv0/BR/954I9QsQSXP5zduYr0PCh1LHWdXqVidaKwujExFjte5F3GfPQymFH/0Dgz8zTQrrP9EGxwU9l3U6oPG/oPNbthFH/6nTaFsLYINTR7XCyF8mVpqz7wo9JHPNQEM4TPginnUPGSN/jq5w4aJDMnRpqjg8lfRLntHEc41ZwJBnnXEYeqs0T03GpGGFO1qu03khOa/VAjibT6ZuBWVN9I8Qkp4fdRx4+/FM/evQzn/nMr/6DX33iySdmZ2eLpdLa2trJkye/97035ufn+Tt/sfOl36vwZXn0d+iRX5JyKLz4kvjLP4LXvycaHIpu/Ub9xo0bhcooAITNaqVx/IbfSJLJ2xV+zlk/rrjXN2MKN18piEGiyUwrPVi8X2CU5jaPceoQlZJFA8okSkEI4VpyokxHC8SyGACEgsS+mX+bSIf2ibTIQslcAGC50LZtwXLUDnDyvB6Q6x7DgxyccypCQZ2JCXvHZHJsyYtkrW6p41y9EQia9slADvJP+U8uM6T/ZopfZRgZHXnyyScfe+zR2dlZxmh1vXrhwoWXX375W9/61rEXXlxcXKTn/vc9C38udj8VPPUH1s4PErIu3/qi+63fhcvHAICOlKHh//UXLs3XnR3jh5aXlwFgYmSn53kqUWt83LryfMDXlY3KQCZtDHTzk2mfaZnGzXRo42h7t2tJafSVGINjwGLeBuhSEYGnL1Dj9VMKdm9gWEpppQIjI2RiRFQcKYTkXKq1LgXGCCe2vq9jwLIslgsBQDRFMxSUB0GTrjTFYk16NSmaQrGXDRVnpq2hSlKWesOu1ZOTXn0hpazVWNAgcRynd5IGh1m8NNKtTghpcqdWq+I555MnT77++uuvvvra22+9PX9lPi/WHlz74uF8I37is/aj/yhfHvFWF+Ebf0i+/Qdy9QotlCFvX5m/9sf/9fUT80OHH/5JAFi4duLuvbtYcTyfz6tUSiMTE9abTuP7fYUw5rCvFp3GgITsHUlv3EzYm0RmhbzHgbI3PRtU1YhOagdYdXvcmOWc56jIW+AUhGtBKIh+pwjD2qT9XkU3uBagEF5pivkV59p6watJEiT7Pag2V0adXRO8kA8AwA/y9YaNF5gyOxUnybY/FgSPUnLOpZRhGG6avR0ExirC4T5TCdSlXyPgnudxLjzPv750/cbyMvopFAqTeT5LL8r7H2Mz+4QQ8eVXct/8fXjjfwGALE0BwPFz4t8/M7RQ+MhDP/Lzw6XpN99+trp4qhy8uePhp0d+/A9lZRaiKgDQIpsYLhWXXgppx1mzQYRwpmtmodLQbxcOjsxmu9VQF4Mzy/v+RYvGAAB4/QgLmDkBVqIbEQgaCMoYy9tEF8L6oOBQoRiVhpQyxyQKYRIQ0RTqjQ6c9FpuafskHRulTEac2H6QD4Kgx/VDHXhZCtkbRVH6HOVG0V7EyoTqGTptuM2LOba2to4Dku04AOD7Xr7gNpvNvz3Z+Pr1Mls/LsUXQP53eu6PyYXnZG4IbBcAnr0Q/M+3Jg8+9omf+MlPl6zSiy9/qbp46hMTr334Iw/vPvKUdeV5Ur2gUi+NTMjrx0ijfay6GzJ7cKblVuFWLN7cAQKvDHZrPRS/ibk1bOJEI+BEtQsKYT8GZJbeGSSzBxHCCFqgtEBlTiLZ2FBxehzyJUC5GjQp3ijSrxb2gB8D3kPqdgJso9i83IjCMI47MuE1/Wptfe/BB3c8/DTMzdGVJQDg2ydQ8CJmhyQAlAuTb71z/G++/G+ri6c++Sj70d/+l5PbK7nv/b48/3UAALsCAKLB5+bmyMRRO1/uq0Uj+rYKYnBiD+zxZrGFE90fGKT06K4ghDhUhoKtr5NrK3RtDbyaDBpJlXJu7tDYRGbetteRY1Ky5GENHjhRLWKMDY3lZoYt240BIPKtoJkcqBwQ9bq1textExh7ajf92RC/AFByrXqjEUfJNpfve17TzxdcAJgayo0+9PNrzmHx1jkAYFMzdNcOFdXdI+49Qwsvff1P3n7xmQ9ZX/nHP1f42KefBgDy+v+lazdo652RajOcm5tbnP4tb//vAAyr4IhBtGiFrfV2BwPCqE+b8EFqWC1Ep4lh7JSiT7w2KJxEx26GcrkhlhtioSoXqnKlKXE5OkitilEKkiXbRd1QLIYA4K/5kVd1HGfbBBkfinBFOvKtvk8L6OCc4/1BXLIynW8CvSRwtxq3CRdOJeQ0imMUxcppemrbiy+++Ln/+Lk/e52vLpynK0tQcmF6BmwXomQi8eP76x+yvvIzs5c/+S9+d9+Hf0E0j7OLXwMAyNsAQG17pblyetG6dNcfw7a/o2LOHFl6oFvmtxyZCW0oq+9HZJZ6q4Av4Bgp9E6R0oynwiillBIhZMA75sD4fkCP/aQYLE7sHEsEtTvsTo9DriCQusheM8y7BLOa0tArDsUvANi0IqImjiW243hNHwBcNz8yOoKbusXJfTV/Rrx1Duo+bJ+kE5MqkrtGyk/+xJMf+c2PV0YfFfT7NKxGeZcWE5UGz3LE9k5n6IAKoqNbhns38FbhXVmsuqUY8GGd2wklbHWepNtXvbmBZryeRSl1LVly6USZTo2JcllQSuKYB1w73A8QyY6f3VCo0KGx3LYysd1YRLlIvdEzAHQtnTGGb9kNkuiG0O6OqD93m4sZCReLxSZ3fN8z9IHhoeFP/MRHf/Xpv/fJX3h65Oivry6cp6tLwqnAjqm2EM7bMwf3A4BoHtfDghcdmzt7efXGaGF0tP4iX/s2WmeWOdNyq7C5hej3Am5ptdxOpE8WqqIZDqg/E0IKDowWyLYyjI7SsaG4VBKuBa6Fih0YQhiFNnIsc1DGjeIck6MFCgAiyuF8eHDZG4ahfhgLU9mqp7AUMrKO6NYVUDkUTgUA9HMXAOC6br6Q37V71+7duycrNtn2oGAH4NTbAAAT07QwpgQsXL9KV5f0sNBSob8z3wCA8ZLlnP6CulS5VUhrtpmNd3vQ9yzHe/Y05a0GDWmQUqEN6LtHUkrLjceG4kpFOAWRY8l7Oti+hUJsWQyFcEcUg616RlGEy04bmvSGYdisirDZ7l0OFbdCCG+g+yr9GQCKOQYAzabn+wmH8wXXzbmO4wCAZdmcC5/klyefWl5e5teuQNEVO9pr0QZszxcNDgD7xscBYGnl0uiu7aP1F8Vyp4geAJlvR9/B+wjqLEfmKrR+sgqXr1Qr41iMwRhjjLG8BTkqLMvKMUAhrBbJFPouR0eSpZnfF2GTxnEcx7ESwoSQWyEt6ObmPJLlSq6lb0O7bj5fyBcK+XK5glc3WFST00dq/ow9dxb3k2ihDADgtSQPXmZYWAIAnANPlof3DMPZGzcAYGyqGF56qbcQvsPPH1RIKVHcqfefCSEGe5VZKVaEJM8156jA7zbgWxxOQVBK45irGw7QesRjECG8CTiOg6qyEsJSJifAtlaL3vyQIJyKWn/OF1zXdR3Hyefz5XKZMep73oULF5pNb7l8eOXSAiws2Y4D29pLWVB0oe7Xv/KV0984BgAwMY3WO4rFuTVYXl4e2b53uHYsWrnUDnIHPzTIlr+d0MUvToPRnD5jg5NhPEexCSG8Cag3ZQ0hvOVa9CYJTCm1aaXeaHie5ziO6+ZLxWKhkHfd/MrKyokTr371ma+eOvXO+tr6teKh89E0XL0CADA9gzNhcApw4cLcl750Jn5ipfTYlflrYmRS5IYAYOfI+J5hOHXqFC2ykfwav/gXg7TlHfzAIJJEOEJ/+6oHCCE9bt0obRyflW2dlza7kwXxliu3jDHqJE+j60JYHfDaKiE8UL6NAQOHuuHx6ZDTubkLYRi6rhvHfHHh6rFjx778tZeOvXBsbm7OdfMAEHJ6Xs6uXFqA61cBQOyYgrxdPX/+3PfPLk7/VvyB3w7v/vng2jUAoLPJeQ+cCVevXN2zZw+5+lxcO6Onfgc/DEi/RItASzX7RfQWv6iNy5x0LQgF059fR1BKt1AkKriujyxNC+EtlPkDEdgAVqJTqEze9SS3d527sry2tnpmsbaw0oTi9AcOP3noyMcq5aHxsTHLYiJq1nL3v7Y2cvo7r1fPn6drN1YuLZxetOb3/it776cAwB49fD2+n1+7InbuguERnAkDwNULV+lIeXbc4xf/wszBHfxAQz/t3AO6+NUZqMisP0aJirRDeaYQ3rQE7nFrn7HkU0m6EFanrAkhWyKEB8p3t9pkjE3uunv7jvvKE4cP3vf4gSM/uXPvhyy3JC0XAIqlku04uEz97OqH/tr7sZfrT3z9THwaPkiO/uf89scxEuoU4pknLr3wsqxNw549AAB2Zd/4+I21K2K1dtehfeTqc5F32Uj6lkJ/X/YO3i3ovU43Z4pfNOMbF7iHpK1mtww5aVksFCx9mNGCeMuFMGPMdZMl2DiO1YxAzYS3BBRg0FPjrMsXn8oTO6dn73FL7RPLjuMUCoVCIY83HFBc15yZ4r4PfzP42MKuXxTFji2l/Laj1+P7z/zln5579Y3LqzeqBTr56KMAMDc3BxPTs+OeOPd53b9CemQZZOJ0B+8LZLy/3fkMgH6+ujf91D3EvA0O5ZFkaSG8IXlIKY2iaCV0euww4QcKVbSGEGaMbcnG0obDp+9kpne3JcsBQD6fx23hfMF1iQfBKgBMVhy/QYxQcX4ifuD3lnb8k8Xp3zpL7l4a2sf3/8yBAweuXXgHrl+t3Hf3poWwwfB05t9FGB/7vgMEvsyOZn04xsmtsferS2DlAe3TL87TkNrkZoUwUm49ICuhA3VfCKEmtJk3CtW31DjnaSG8oVEjEyaB1ZcA0sJNh+FqcBizdeniJbVRXCkPKclcay6lOW+Vxp2pR+XszxaH95HRvQAwNja2o1hcPnNmYnJyqJirLbyk+++dvcGRzsl7B+oLST+cUKqvstEJ1rpemiDtIUcFfrgk8ljsU7WHjHcYGjz5GIqOvvIQ17HXA9IMBQkIAHgyh5K227qUEsJSyvRMeJBEe6MduPMjHm2k67EvLLe05+BHT15eO/7K8Waz6bp59bVRvPRv+MfII8lI41pj7ezs8DCsrYncUHlkon7lShSGux+eLM39qfE+1ruC9zLhN9pMCP3TKu8p6GVBs014eu9X+TF++pwEDVKrsfWgfSUY7zAUWYhnJJVnRF8u4dcJkb34KQbmRephOsZYXyGsPOOZk5tfyuqTYwM4DUZFtLcQLk/sPPLBj49s21Otrd977z3btm/DA6LDwyO6N529ABA1qwBw5tiXzxz7MgCMHjkEAN5bb0/s2TVUzDUu/C1A1xn7JvruluDdSvfWYZAC3YZSCyHUF0MNpGe/eO4KbeoBX12DpRWyHoASuXqe8SZwgzvGiokF2Rs8KO0jyW74VnLFn3O1HYVC2AiiQxfC7W+OQ/IV1UEGjh6gekMYQrhd4C6tleawfuCbc94I+AMPPLhje/tCf6lYbFZX1E8jBqs8YX/o967wRy6dvnReDMGRXyvNzKyeOQkNH4Uw4UE6VCb6Zt7AgN4GxHtqsv2uwKjPbvu6mcDDUqGgjbDj/oDR0XWRK6VsRnJ1DRZvwNIKvVonzRAAgLEOsYxwqCyyEB/BM5zSe8I24ZFktYittL5vxrwIDdjKzIvUUlYm/1EIY7T4kB1aohA2vW4QSY3oddut82HCuhDuBqTx1cuvWf6NBx98cGV1xfd9AIjCsFgqqahUSZKKiBhjY2z4w3DvP2TF8ULuIQAY278fAODU22MHDgFA9eL/U6mkO8SAS9DpgN0wsMebhfEVwh9yCAE4a408tuqD17nngkxApkkp4zj263BthS6tkFVPNgIuhHAodyhH2Utpe26sVsg4sSmltcjS+0wMVnqYwMsM6s060RSq8yv+69p4phatJsn4zXEFtZ+0aSHcJ1imHDMU6Uw+SCmvX7+eL7irqyuLi1dd162Uh+KY496S/j1lxd72GNFcAoDi2AwAREOjpZmZlUsLAPCBJ3cG175rpgTQjZOZllsF45DAHWwthEjeoyMBCRqkEYpAUBS5eCUAv825vk6W1631ALxICqHuPyQECwVpPRkNSrCjgKGU4AsemW8yG98WxQ8I4wuVHf6Sw9WMB8mbssjVTDaqmXDQaH/sJm9vxRwYY8O/KAkyBazOVcXhzPkwDpO79z0q7KEvfelLq6urU1NTAOAHPr78HHk19KazV8Grz/HGjaaY5/Nnbc8f278/9uv09Bu53feMVoJ0Wmlk+sksVBqbO8WR7gS3AelPBP+AgXMZSSKljDzWDAXOiiOPNZtW2KReJPHT3Ki/CCFCwVSdKNhEGk/PxsDUzLbBnbofe1H76LV6dNaPYb31FrR6FDoTkWR6B8gUwg4VlmWhLqCEcI4Ky40ty7IsK5P2fdE/jNE5DA73EMUjIyPbd9wHAHv2zO7YsQMAfN933XzFEUEQKPKreDC4lDJf2rM28fi3nzv+9f/xubPLFI782vjMB+Gtdyq0uef+e3XPujlTf+7ds28D63pn4JYis0Led+Bc4hUiEpCwSWOf+nGyqhwKIkQieDOb0qEShTbSRt9h1gf0BneqIas2w7W67/s+LhQHnAS8zd52pKnjk/gzbFLOOXPCTCGM73sohTn2LSklblzfpBBOFrHSf3V5pYqtOIYGg8PKCV0552fOv3HvvQfvumuf73tqJwkAgkayIZRmLwDYlbvHfuTfjD/wT+ldD9duWII9wu+bEM1atFpVMfRFN+Zk2mdaKijXzF4yIHqM372xhdPj3sW8nUh/8aQ3OJcBJ/gpBqSuH0MP6iJCQQBAOMI4woVVihIY26Xi8GKO4TvSjYDX/TgRknHeYG83RJJ5keRh15cuCSF4AEstYuMb9Dc5E95wAIPMLGKGOq1cl+fPhSuXjh49GseR53n5guv7nm3bhUIh9uvd2ItwhIOv9kztOEzIuj1SoY8/yaZmdP/d0Nt1cGw6mkF09ffmMSyjyD24seVIX9PV2zEUJOBIY/xW8KBtk/4IU8LqzhgYY8UcK7lWybU4cXiQ/FPfZOgNQwgzJyw41FhhxuIgV3E/SRfC6aXyAWHOgfW/mUJYNyuDLorb/0S1UCjMz89fvHgRn+wAANuyRkZHgiBQq1Zp9qLZW13EpSwiloRTEYcO1f24evqSwU/8maku6j7TpNqS3rlVg4WCivA9ewxry4s8OJB73aDPfnWz0/qKp55zSjM4wxhLrgpxH/8ZHnoDPyYOADx0mBNmilN1CloJYZwJ54pJ3jJD9UBX35kcTlNXV6eVNEZM7ji85+BHnz9x+tgLL46MjA4PDbden3VDvp45EBhmce74mW/80Wtf/G8LL7ywfOL46S8+f3Jtm3LNRHo40JFp35FiagUrM8i7tQS9iUFnE0E2hPSR48wae1eAYhZvHSJdcdqsnBRb9DwzueHvFVGRPEDp12FlVa43gvUqxdfwEhBbbVzrM2EVQ94mduurBhuCKoD+t6MBDNmVpq5Z/haTqSg4lUn8Fun09FS+kAeApueNjIw0m03V2JkRAkBpeJ/90T9bmv3Nk/EDz1/50HOvFOYnPz3xwG8rDyrdTPGrIy1++2JDnbAbSQbsyoMrhDrSy62DY8CM3SRuTyp9kRa/6Vc41PfTNn2yAk9W+jE0GnajYVer1KvJsEnxn1eTpRwrOrToUH0mnCyYCaoL4Q2Bpk5f4V9kV4eTgl4XinVoMEi4ujhXoc2jR48qGwXDp1G/kWSS5WTpntzUx6cO/P3JB//Z6CP/oTj7C7ofhM5elZN0hAa6UW5D6J3E7ceW5Gcr4hgU6QxvRbNkI60wg/Z5Rx3qmoGOQdYgqQj1f7qTUxDgArhg5EQXwq4FKIQ3pEXrvV8ZdBpApgQzqj7NRillM1xZuvjSwfsOTk9PNZvN4eGhIw8cqVTKc3Pnd8wcMoLrPxXQWrmmE9V/doO+Qm66daK3/rwlnN8oNiecM7WSvsXvASO2m4lqE+g99e0Bvcn01SxKiaBmW28h8EFZ9ZIOXldSrjkqSqX2oWt1vcFtfcllQ6DQcYWww21DHFa8VQCA3NDU4uLiyZMnq9XaXXfte+ihB5eWlpZvrIztuEsP1RFLK61B2Hvz4jfTZ5ZdG70nwOmKGnD87paZvthcKMR79ipSN2xiRFP7wGoCjLAgtklCLdVA1Ak3waK+wH1ghN5/OOcohNGyVIqptTEhnPgzOGzQBn8ZG0Xo2qP3uNbwjtmP2eW7nz9x5tixY+fOnX3xxe9+/WvfmNr3VE7mdJ4raEe7IJ0NhR6JGhhc/G4a3SRzjxT77iG9K0vQ3fO7YaSbtUdtbDn0FsGtnUz9uRv0c5RbBVc7m4VXrPSn7bwo2U9ymXSsjTU9eeYFiWxXX0UirXf9VLE1A+jvaGeiR2X1bkWNbPi3D3sHEb+ZBM6UwLr+3BkPMYLgYNkO2EngzBQNCawTWJcJKogisO5qJJQ+R6mniJWTWdKOqtAkMForxw4adFa1HkPmKrTREAaB1SkOZUkIRJJI2TEHVq66Cm1I4M5MJhWClq4l0dK1ZDFHHApeJP0YKCUWJM0hhKiGjHNeZGGl4BBCqBPWamx9nRp7SHoLpvUpY8Ybx8kQoO4bTY9JnADH9dhvfWYNj3MDQK4o83byafIwtlbXuYijdItngjzzgoTWaW/ksCJwDw4DwBbqGapR0sq80auUn86WbtvrTuloAUBola/bq0bJDtWKk7cMMmVjmFXwVHN32KggvZMzzVml0OsEPes27fzolql4smPrrJzMrKIZnfRWkxJkyltiSKWVLoJZ8KxcIbRKS+JllOBPRoltA+fAGDAKDAcQEQOA53E/Zq7FiwVqMWkxWfPo6joXLRIiJG//FMIU0borACD9AAD1YQv45BgawWvykFNGJAD4gQwjwrlgjBaLxGFJAVarxPcDGIzAaqQHo2EQ6WG7PULLDP8bhR6JMmyIvQZ6OPVAmmM6NhdnN/ROS4feWftiazM5IDJpuSXYUNm7gQuJZOZC+oGMYhlFEEZ9Ird7iqa+7DVAeGTnLMsGyszlBjdHAIAxyrmIWpeZAKBYJIPPhNs+enA4pRqZNE6H6g0jlG5uD9uDsVcXvx39SYu8bZkSON3Q2zVT/OroHXwLkZlQt1wZ0GsjscmMLeVtEKSb770ALmQUS0Yh54DFgLZuKcUxF5JYTAKARaKcNVgNDow4gtCP4wi4ICh+EY6dmMOIhDwho8ME6zoNNZGo0AqUAqVdJ/1on7i2wnX7pHBfGN3FELxbwl7TnEXgbHVUD5WiayaBb0Z/7ki6X+R6JOlQumdlqRen7ZoqeHapO71l+lFmdDXG302o0Jn6s1knesY6iq9lUVnGqZYAAADeqSoDgKE8I5SYHUQCKxW6t+UgGnJfdDypoypCX3LQoYvitBDOqjcTac/Y2AZp00LeaCSDvd3Q0dtS/bUbuvXRm0eaz4je+THQLZJBMKhwHszbzWBDRb6Dbmg/DjA4OBcd32m8Ccg4QAPliYHE7Y+Gy6ChzABAo+QSooiTRT8Stj2QsAYAEGnfHA+SZwMAgATtq4hE1GTYHg5JVAcAiJNVRz1RIpNQxGstM4qWa2CedNeTaEPPz5bDzps2m8Ntz6TMVUyrnJsYaBH/l/nkap4kbc8kl7iC5QKAtEuJvWMDgKRl5bMjiVzLvpUZ6Wg+nSROajkAIOwh5YRQiUqrXRbBcomrlRhuEhZjLFle2wA2HOAO7uAO3jv4/1SH6H/Y6aCNAAAAAElFTkSuQmCC
'@

# Create a streaming image by streaming the base64 string to a bitmap streamsource
$KeyImagebitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$KeyImagebitmap.BeginInit()
$KeyImagebitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($KeyImageicon)
$KeyImagebitmap.EndInit()

# Freeze() prevents memory leaks.
$KeyImagebitmap.Freeze()

$imgKeyImage.Source = $KeyImagebitmap


# Add event handler for title bar drag
$titleBar.Add_MouseLeftButtonDown({
    $window.DragMove()
})

# Add event handler for Help button
$helpButton.Add_Click({
    [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::Help
})

# Add event handler for Close button
$closeButton.Add_Click({
    $window.DialogResult = $false
    $window.Close()
})

# Add event handler for OK button
$okButton.Add_Click({
    # Get the credentials
    $script:username = $UserCombo.Text
    $script:password = $passwordBox.Password
    
    if ([string]::IsNullOrWhiteSpace($username)) {
        [System.Windows.MessageBox]::Show("Please enter a username.", "Validation", "OK", "Warning")
        return
    }
    
    $window.DialogResult = $true
    $window.Close()
})

# Add event handler for Cancel button
$cancelButton.Add_Click({
    $window.DialogResult = $false
    $window.Close()
})


$Window.Add_MouseDown({
    # Action to perform when any click occurs in the window
    [System.Windows.Input.Mouse]::OverrideCursor = $null
})


$Window.Add_Loaded( {
    param($s,$e)
    try {
        # Find template parts (template must be applied)
        $displayImage = $UserCombo.Template.FindName("PART_DisplayImage", $UserCombo)

        # Helper to update image depending on selected item or typed text


        # Initial image
        Update-Image -ComboBox $UserCombo -displayImage $displayImage -DefaultIcon $DefaultIcon

        $UserCombo.Focus()


    } catch {
        [System.Windows.MessageBox]::Show("Error wiring template parts:`n$($_.Exception.Message)","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
    }
})

# Show the window and capture the result
$result = $window.ShowDialog()

# Return credentials if OK was clicked
if ($result -eq $true) {
    # Create a PSCredential object
    if ($script:password) {
        $securePassword = ConvertTo-SecureString $script:password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($script:username, $securePassword)
        
        # Return the credential object
        return $credential
    }
} else {
    Write-Verbose "Credential dialog was cancelled." 
    return $null
}    
}
#==========================================================================
# Function		: GenerateTrustedDomainPicker
# Arguments     : -
# Returns   	: Domain DistinguishedName
# Description   : Windows Form List AD Domains in Forest
#==========================================================================
Function GenerateTrustedDomainPicker {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)
    [xml]$TrustedDomainPickerXAML = @'
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

'@

    $TrustedDomainPickerXAML.Window.RemoveAttribute('x:Class')

    $reader = (New-Object System.Xml.XmlNodeReader $TrustedDomainPickerXAML)
    $TrustedDomainPickerGui = [Windows.Markup.XamlReader]::Load( $reader )
    $btnOK = $TrustedDomainPickerGui.FindName('btnOK')
    $btnCancel = $TrustedDomainPickerGui.FindName('btnCancel')
    $objListBoxDomainList = $TrustedDomainPickerGui.FindName('objListBoxDomainList')



    $btnCancel.add_Click(
        {
            $TrustedDomainPickerGui.Close()
        })

    $btnOK.add_Click({
            $global:strDomainPrinDNName = $objListBoxDomainList.SelectedItem

            if ( $global:strDomainPrinDNName -eq $global:strDomainFQDN ) {
                $lblSelectPrincipalDom.Content = $global:strDomainShortName + ':'
            } else {

                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", "(&(trustPartner=$global:strDomainPrinDNName))", 'Onelevel')
                [void]$request.Attributes.Add('trustdirection')
                [void]$request.Attributes.Add('trustattributes')
                [void]$request.Attributes.Add('flatname')
                $response = $LDAPConnection.SendRequest($request)
                $colResults = $response.Entries[0]

                if ($null -ne $colResults) {
                    $global:strPrinDomDir = $colResults.attributes.trustdirection[0]
                    $global:strPrinDomAttr = '{0:X2}' -f [int]  $colResults.attributes.trustattributes[0]
                    $global:strPrinDomFlat = $colResults.attributes.flatname[0].ToString()
                    $lblSelectPrincipalDom.Content = $global:strPrinDomFlat + ':'

                }

            }
            $TrustedDomainPickerGui.Close()
        })


    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", '(&(cn=*)(objectClass=trustedDomain))', 'Onelevel')
    [void]$request.Attributes.Add('trustpartner')
    $response = $LDAPConnection.SendRequest($request)
    $colResults = $response.Entries

    foreach ($objResult in $colResults) {
        [void] $objListBoxDomainList.Items.Add($objResult.attributes.trustpartner[0])
    }



    [void] $objListBoxDomainList.Items.Add($global:strDomainFQDN)

    $TrustedDomainPickerGui.ShowDialog()

}
#==========================================================================
# Function		: GenerateSupportStatement
# Arguments     : -
# Returns   	: Support
# Description   : Generate Support Statement
#==========================================================================
Function GenerateSupportStatement {
    [xml]$SupportStatementXAML = @'
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Support Statement" WindowStartupLocation = "CenterScreen"
        Width = "400" Height = "500" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="#2A3238">
    <Window.Resources>

        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Pink"/>
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
    <Grid HorizontalAlignment="Center">
        <StackPanel Orientation="Vertical"  Margin="0,0,00,0" HorizontalAlignment="Center">
            <Label x:Name="lblSupportHeader" Content="Carefully read and understand the support statement." Height="25" Width="350" FontSize="12" Foreground="White"/>
            <Label x:Name="lblSupportStatement" Content="" Height="380"  Width="370" FontSize="12" Background="White" BorderBrush="#FFC9C9CA" BorderThickness="1,1,1,1" FontWeight="Bold"/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                <Button x:Name="btnOK" Content="OK" Margin="00,10,00,00" Width="50" Height="20"/>
            </StackPanel>
        </StackPanel>
    </Grid>
</Window>

'@

    $SupportStatementXAML.Window.RemoveAttribute('x:Class')
    $reader = (New-Object System.Xml.XmlNodeReader $SupportStatementXAML)
    $SuportGui = [Windows.Markup.XamlReader]::Load( $reader )


    $Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

    $IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $IconImage.BeginInit()
    $IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
    $IconImage.EndInit()

    # Freeze() prevents memory leaks.
    $IconImage.Freeze()


    $SuportGui.Icon = $IconImage

    $btnOK = $SuportGui.FindName('btnOK')
    $lblSupportStatement = $SuportGui.FindName('lblSupportStatement')
    $txtSupoprt = @'
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR
A PARTICULAR PURPOSE.


'@
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
Function GenerateDomainPicker {
    param($CREDS, $server='')
    [xml]$DomainPickerXAML = @'
<Window x:Class="WpfApplication1.StatusBar"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Select a domain" WindowStartupLocation = "CenterScreen"
        Width = "380" Height = "250" ShowInTaskbar = "True" ResizeMode="CanResizeWithGrip" WindowState="Normal" Background="#2A3238">
    <Window.Resources>

        <Style TargetType="{x:Type Button}" x:Key="AButtonStyle">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="HorizontalAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Foreground" Value="Pink"/>
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
        <Grid>
        <StackPanel Orientation="Vertical">
        <Label x:Name="lblDomainPciker" Content="Please select a domain:" Margin="10,05,00,00" Foreground="White"/>
        <ListBox x:Name="objListBoxDomainList" HorizontalAlignment="Left" Height="78" Margin="10,05,0,0" VerticalAlignment="Top" Width="320"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
            <Button x:Name="btnOK" Content="OK" Margin="00,05,00,00" Width="50" Height="20"/>
            <Button x:Name="btnCancel" Content="Cancel" Margin="10,05,00,00" Width="50" Height="20"/>
        </StackPanel>
        </StackPanel>
    </Grid>
</Window>
'@

    $DomainPickerXAML.Window.RemoveAttribute('x:Class')

    $reader = (New-Object System.Xml.XmlNodeReader $DomainPickerXAML)
    $DomainPickerGui = [Windows.Markup.XamlReader]::Load( $reader )


    $Icon = @'
iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAMAAABHPGVmAAAABGdBTUEAALGPC/xhBQAAAwBQTFRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAszD0iAAAAQB0Uk5T////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////AFP3ByUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjEuNWRHWFIAAAI3SURBVGhD7ZLRluQgCETn/3+6t4WrYoIKmfTM7p7c
hwhFQb3k6/UDPCEpnpAUT0iKJyRFLuSrgRAj4eZ8AzlA1MrhAwx3xHzcdMCwJuLi3gRMKwIejilTacXWwqUCCiAWUKasDRwpoAwwKqD4LKasK2gHGCpoDqcRGyPMHDCMMGtEQphMwGRh0tiHoC/A2EFvbEIQt2AHxMYqBCUISwWUxiSEJo2/7YdQX8Bd/8WQyyn+9n
8coj7qPO7yzSH+8r8YItuUnV8MobxANqQUgnRH7EBcfUkKi6NYvyCdBb1g+lrKO+BJdrMgbQdVMQqlPCOOtglBBCNRyjPiaKeQwYNUMZqW8j3giGaxPQ3pDUaU0sUZmcX2VKR9QwueZpmO2JOnm7Q9LrmiYTaqe/VVtDvt+GpnF6KFap8JaUV1aXNXSF/rVWs+G6L1
x0LURn1TiN0617eGWAZdm46vdqIh6rO1wVc77kiXRoaBNB1XNORCTilajNqZcIg9Z/BU0SxeyME7tDQNTxTNkg1xD1JXRLPMQ2jeaO+nOFIo5GQ9CvTCSXgjmuVKSGEQZNxB7Tgh9/OEpPgLQiZ/y0DA8+0Le0cwZGHaGgqb8e7IZgy7+frMctjZGlaHFqOBvWN+aj
o4ErDMjk1kh4jHP+eKPiFTPWjMCMF13g2cbG7a6DbvDo7qWcpoRjjEXO4w2RIPOaUgB0hYDymIETJeG4MQI+euMTRRsv4SQxEnv3GBJyTFE5LiCUnxhCR4vf4AzHXw0b9akGYAAAAASUVORK5CYII=
'@

    $IconImage = New-Object System.Windows.Media.Imaging.BitmapImage
    $IconImage.BeginInit()
    $IconImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Icon)
    $IconImage.EndInit()

    # Freeze() prevents memory leaks.
    $IconImage.Freeze()


    $DomainPickerGui.Icon = $IconImage

    $btnOK = $DomainPickerGui.FindName('btnOK')
    $btnCancel = $DomainPickerGui.FindName('btnCancel')
    $objListBoxDomainList = $DomainPickerGui.FindName('objListBoxDomainList')

    $btnCancel.add_Click(
        {
            $DomainPickerGui.Close()
        })

    $btnOK.add_Click(
        {
            $strSelectedDomain = $objListBoxDomainList.SelectedItem
            if ($strSelectedDomain) {
                $SelectedDomain = ($domainsArray | Where-Object { $_.ncname -eq $strSelectedDomain }).dnsroot
                 
                $global:PickedDDomainName = $null
                if ($strSelectedDomain.Contains('.')) {
                    # Set the domain FQDN as the LDAP server
                    $global:PickedDDomainName = $SelectedDomain
                    # If the domain name is a FQDN convert it to a DistinguishedName
                    $strSelectedDomain = 'DC=' + $strSelectedDomain.Replace('.', ',DC=')
                } else {
                    $global:PickedDDomainName = $SelectedDomain
                }
                $global:strDomainSelect = $strSelectedDomain
            }
            $DomainPickerGui.Close()
        })

    $domainsArray = @()

    $LDAPConnection = Connect-SecureLDAP -Server $server -Credential $CREDS; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    if($LDAPConnection) {
        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
        $request = New-Object System.directoryServices.Protocols.SearchRequest($null, '(objectClass=*)', 'base')
        [void]$request.Attributes.Add('dnshostname')
        [void]$request.Attributes.Add('supportedcapabilities')
        [void]$request.Attributes.Add('namingcontexts')
        [void]$request.Attributes.Add('defaultnamingcontext')
        [void]$request.Attributes.Add('schemanamingcontext')
        [void]$request.Attributes.Add('configurationnamingcontext')
        [void]$request.Attributes.Add('rootdomainnamingcontext')
        [void]$request.Attributes.Add('isGlobalCatalogReady')
        try {
            $response = $LDAPConnection.SendRequest($request)
            $global:bolLDAPConnection = $true
        } catch {
            $global:bolLDAPConnection = $false
            $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed! Domain does not exist or can not be connected" -strType "Error" -DateStamp ))
        }
        if ($global:bolLDAPConnection -eq $true) {
            $global:ConfigDN = $response.Entries[0].attributes.configurationnamingcontext[0]
            $global:strDomainDNName = $response.Entries[0].attributes.defaultnamingcontext[0]

        }
        
        #Get all NC and Domain partititons
        $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,$global:ConfigDN ", '(&(cn=*)(systemFlags:1.2.840.113556.1.4.803:=3))', 'Onelevel')
        [void]$request.Attributes.Add('ncname')
        [void]$request.Attributes.Add('dnsroot')

        try {
            $response = $LDAPConnection.SendRequest($request)

        } catch {
            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed! Domain does not exist or can not be connected' -strType 'Error' -DateStamp ))
        }
        #If connection established list partitions
        if ($response) {
            $colResults = $response.Entries
            foreach ($objResult in $colResults) {
    #            [void] $arrPartitions.add($objResult.attributes.dnsroot[0])
                $domainsArray += [PSCustomObject]@{
                    dnsroot = $objResult.attributes.dnsroot[0]
                    ncname = $objResult.attributes.ncname[0]
                }
                [void] $objListBoxDomainList.Items.Add($objResult.attributes.ncname[0])
            }
        }

        #Get all incoming and bidirectional trusts
        $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=System,$global:strDomainDNName", '(&(cn=*)(objectClass=trustedDomain)(|(trustDirection:1.2.840.113556.1.4.803:=1)(trustDirection:1.2.840.113556.1.4.803:=3)))', 'Onelevel')
        [void]$request.Attributes.Add('trustpartner')
        try {
            $response = $LDAPConnection.SendRequest($request)

        } catch {
            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed! Domain does not exist or can not be connected' -strType 'Error' -DateStamp ))
        }
        #If connection established list partitions
        if ($response) {

            $colResults = $response.Entries
            foreach ($objResult in $colResults) {

                $bolPartitionMatch = $false
                # Check if the trusted domain is a partion within the forests
                foreach ($DomainRoot in $domainsArray.dnsroot) {
                    if ($DomainRoot -eq $objResult.attributes.trustpartner[0]) {
                        $bolPartitionMatch = $true
                    }
                }
                # if the trusted domain is external add to list
                if (!($bolPartitionMatch)) {
                    $domainsArray += [PSCustomObject]@{
                        dnsroot = $objResult.attributes.trustpartner[0]
                        ncname = $objResult.attributes.trustpartner[0]
                    }                
                    [void] $objListBoxDomainList.Items.Add($objResult.attributes.trustpartner[0])
                }


            }
        }



        if ($objListBoxDomainList.Items.count -gt 0) {
            $DomainPickerGui.ShowDialog()
        }
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed! Domain does not exist or can not be connected' -strType 'Error' -DateStamp ))
    }

}
#==========================================================================
# Function		: Get-SchemaData
# Arguments     :
# Returns   	: string
# Description   : Returns Schema Version
#==========================================================================
function Get-SchemaData {
    Param([System.Management.Automation.PSCredential] $CREDS)

    # Retrieve schema

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", '(CN=ms-Exch-Schema-Version-Pt)', 'onelevel')
    [void]$request.Attributes.Add('rangeupper')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                [int] $ExchangeVersion = $entry.Attributes.rangeupper[0]

                if ( $global:SchemaHashExchange.ContainsKey($ExchangeVersion) ) {
                    $txtBoxExSchema.Text = $global:SchemaHashExchange[$ExchangeVersion]
                } else {
                    $txtBoxExSchema.Text = 'Unknown'
                }
            } catch {
                $txtBoxExSchema.Text = 'Not Found'
            }

        }
    } else {
        $txtBoxExSchema.Text = 'Not Found'
    }
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", '(CN=ms-RTC-SIP-SchemaVersion)', 'onelevel')
    [void]$request.Attributes.Add('rangeupper')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                [int] $LyncVersion = $entry.Attributes.rangeupper[0]

                if ( $global:SchemaHashLync.ContainsKey($LyncVersion) ) {
                    $txtBoxLyncSchema.Text = $global:SchemaHashLync[$LyncVersion]
                } else {
                    $txtBoxLyncSchema.Text = 'Unknown'
                }
            } catch {
                $txtBoxLyncSchema.Text = 'Not Found'
            }

        }
    } else {
        $txtBoxLyncSchema.Text = 'Not Found'
    }
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", '(CN=*)', 'Base')
    [void]$request.Attributes.Add('objectversion')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                $ADSchemaVersion = $entry.Attributes.objectversion[0]

                if ( $global:SchemaHashAD.ContainsKey([int]$ADSchemaVersion) ) {
                    $txtBoxADSchema.Text = $global:SchemaHashAD[[int]$ADSchemaVersion]
                } else {
                    $txtBoxADSchema.Text = $ADSchemaVersion
                }
            } catch {
                $txtBoxADSchema.Text = 'Not Found'
            }

        }
    } else {
        $txtBoxADSchema.Text = 'Not Found'
    }

    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:strDomainDNName", '(name=*)', 'Base')
    [void]$request.Attributes.Add('msds-behavior-version')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                $ADDFL = $entry.Attributes.'msds-behavior-version'[0]

                if ( $global:DomainFLHashAD.ContainsKey([int]$ADDFL) ) {
                    $txtBoxDFL.Text = $global:DomainFLHashAD[[int]$ADDFL]
                } else {
                    $txtBoxDFL.Text = 'Unknown'
                }
            } catch {
                $txtBoxDFL.Text = 'Not Found'
            }

        }
    } else {
        $txtBoxDFL.Text = 'Not Found'
    }
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Partitions,CN=Configuration,$global:ForestRootDomainDN", '(name=*)', 'Base')
    [void]$request.Attributes.Add('msds-behavior-version')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                $ADFFL = $entry.Attributes.'msds-behavior-version'[0]

                if ( $global:ForestFLHashAD.ContainsKey([int]$ADFFL) ) {
                    $txtBoxFFL.Text = $global:ForestFLHashAD[[int]$ADFFL]
                } else {
                    $txtBoxFFL.Text = 'Unknown'
                }
            } catch {
                $txtBoxFFL.Text = 'Not Found'
            }

        }
    } else {
        $txtBoxFFL.Text = 'Not Found'
    }
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$global:ForestRootDomainDN", '(dSHeuristics=*)', 'Base')
    [void]$request.Attributes.Add('dsheuristics')
    $response = $LDAPConnection.SendRequest($request)
    $adObject = $response.Entries

    if (($null -ne $adObject) -and ($adobject.Count -ne 0 )) {
        foreach ($entry  in $response.Entries) {


            try {
                $DSHeuristics = $entry.Attributes.dsheuristics[0]

                if ($DSHeuristics.Substring(2, 1) -eq '1') {
                    $txtListObjectMode.Text = 'Enabled'
                } else {
                    $txtListObjectMode.Text = 'Disabled'
                }
            } catch {
                $txtListObjectMode.Text = 'Not Found'
            }

        }
    } else {
        $txtListObjectMode.Text = 'Disabled'
    }
}
#==========================================================================
# Function		: Get-HighestNetFrameWorkVer
# Arguments     :
# Returns   	: string
# Description   : Returns Highest .Net Framework Version
#==========================================================================
Function Get-HighestNetFrameWorkVer {
    $arrDotNetFrameWorkVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
        Get-ItemProperty -Name Version, Release -EA 0 |
        Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } |
        Select-Object Version
    $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 4.6 } | Select-Object -Last 1
    if ($DotNetVer) {
        $HighestDotNetFrmVer = $DotNetVer.Version
    } else {
        $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 4.5 } | Select-Object -Last 1
        if ($DotNetVer) {
            $HighestDotNetFrmVer = $DotNetVer.Version
        } else {
            $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 4.0 } | Select-Object -Last 1
            if ($DotNetVer) {
                $HighestDotNetFrmVer = $DotNetVer.Version
            } else {
                $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 3.5 } | Select-Object -Last 1
                if ($DotNetVer) {
                    $HighestDotNetFrmVer = $DotNetVer.Version
                } else {
                    $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 3.0 } | Select-Object -Last 1
                    if ($DotNetVer) {
                        $HighestDotNetFrmVer = $DotNetVer.Version
                    } else {
                        $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 2.0 } | Select-Object -Last 1
                        if ($DotNetVer) {
                            $HighestDotNetFrmVer = $DotNetVer.Version
                        } else {
                            $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 1.1 } | Select-Object -Last 1
                            if ($DotNetVer) {
                                $HighestDotNetFrmVer = $DotNetVer.Version
                            } else {
                                $DotNetVer = $arrDotNetFrameWorkVersions | Where-Object { $_.version -ge 1.0 } | Select-Object -Last 1
                                if ($DotNetVer) {
                                    $HighestDotNetFrmVer = $DotNetVer.Version
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Remove-Variable DotNetVer, arrDotNetFrameWorkVersions

    return $HighestDotNetFrmVer

}
#==========================================================================
# Function		: GetDomainController
# Arguments     : Domain FQDN,bol using creds, PSCredential
# Returns   	: Domain Controller
# Description   : Locate a domain controller in a specified domain
#==========================================================================
Function GetDomainController {
    Param([string] $strDomainFQDN,
        [bool] $bolCreds,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $DCCREDS)

    $strDomainController = ''

    if ($bolCreds -eq $true) {

        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $strDomainFQDN, $DCCREDS.UserName, $DCCREDS.GetNetworkCredential().Password)
        $ojbDomain = [DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
        $strDomainController = $($ojbDomain.FindDomainController()).name
    } else {

        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $strDomainFQDN )
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
function Get-DirContext {
    Param($DomainController,
        [System.Management.Automation.PSCredential] $CREDS)

    if ($CREDS) {
        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $DomainController, $CREDS.UserName, $CREDS.GetNetworkCredential().Password)
    } else {
        $Context = New-Object DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $DomainController)
    }


    return $Context
}
#==========================================================================
# Function		: TestCreds
# Arguments     : System.Management.Automation.PSCredential
# Returns   	: Boolean
# Description   : Check If username and password is valid
#==========================================================================
Function TestCreds {
    Param([System.Management.Automation.PSCredential] $psCred)

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    if ($psCred.UserName -match '\\') {
        If ($psCred.UserName.split('\')[0] -eq '') {
            [directoryservices.directoryEntry]$root = (New-Object system.directoryservices.directoryEntry)

            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $root.name)
        } else {

            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $psCred.UserName.split('\')[0])
        }
        $bolValid = $ctx.ValidateCredentials($psCred.UserName.split('\')[1], $psCred.GetNetworkCredential().Password)
    } else {
        [directoryservices.directoryEntry]$root = (New-Object system.directoryservices.directoryEntry)

        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $root.name)

        $bolValid = $ctx.ValidateCredentials($psCred.UserName, $psCred.GetNetworkCredential().Password)
    }

    return $bolValid
}
#==========================================================================
# Function		: GetTokenGroups
# Arguments     : Principal DistinguishedName string
# Returns   	: ArrayList of groups names
# Description   : Group names of all sids in tokenGroups
#==========================================================================
Function GetTokenGroups {
    Param(
        $PrincipalDomDC,

        $PrincipalDN,

        [bool]
        $bolCreds,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $GetTokenCreds,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )


    $script:bolErr = $false
    $tokenGroups = New-Object System.Collections.ArrayList

    $tokenGroups.Clear()
    $LDAPConnection = Connect-SecureLDAP -Server $PrincipalDomDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.DistinguishedName = $PrincipalDN
    $request.Filter = '(name=*)'
    $request.Scope = 'Base'
    [void]$request.Attributes.Add('tokengroups')
    [void]$request.Attributes.Add('tokengroupsglobalanduniversal')
    [void]$request.Attributes.Add('objectsid')
    $response = $LDAPConnection.SendRequest($request)
    $ADobject = $response.Entries[0]

    if ( $global:strDomainPrinDNName -eq $global:strDomainDNName ) {
        $SIDs = $ADobject.Attributes.tokengroups
    } else {
        $SIDs = $ADobject.Attributes.tokengroupsglobalanduniversal
    }
    #Get selected principal SID
    $ownerSIDs = (New-Object System.Security.Principal.SecurityIdentifier $ADobject.Attributes.objectsid[0], 0).Value
    # Add selected principal SID to tokenGroups
    [void]$tokenGroups.Add($ownerSIDs)

    $arrForeignSecGroups = FindForeignSecPrinMemberships $(GenerateSearchAbleSID $ownerSIDs) $CREDS

    foreach ($ForeignMemb in $arrForeignSecGroups) {
        if ($null -ne $ForeignMemb) {
            if ($ForeignMemb.tostring().length -gt 0 ) {
                [void]$tokenGroups.add($ForeignMemb)
            }
        }
    }

    # Populate hash table with security group memberships.
    $LDAPConnection = Connect-SecureLDAP -Server $PrincipalDomDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.DistinguishedName = "CN=ForeignSecurityPrincipals,$global:strDomainDNName"
    $request.Filter = '(CN=S-1-5-11)'
    $request.Scope = 'onelevel'
    [void]$request.Attributes.Add('objectsid')
    $response = $LDAPConnection.SendRequest($request)
    $colResults = $response.Entries
    foreach ($objResult in $colResults) {

        [byte[]] $byte = $objResult.Attributes.objectsid.GetValues([byte[]])[0]
        $ForeignDefaultWellKnownSIDs = (New-Object System.Security.Principal.SecurityIdentifier($byte, 0)).value

        $arrForeignSecGroups = FindForeignSecPrinMemberships $(GenerateSearchAbleSID $ForeignDefaultWellKnownSIDs) $CREDS

        foreach ($ForeignMemb in $arrForeignSecGroups) {
            if ($null -ne $ForeignMemb) {
                if ($ForeignMemb.tostring().length -gt 0 ) {
                    [void]$tokenGroups.add($ForeignMemb)
                }
            }
        }
    }
    #Add SID string to tokenGroups
    ForEach ($Value In $SIDs) {
        $SID = New-Object System.Security.Principal.SecurityIdentifier $Value, 0

        [void]$tokenGroups.Add($SID.Value)
    }
    #Add Everyone
    [void]$tokenGroups.Add('S-1-1-0')
    #Add Authenticated Users
    [void]$tokenGroups.Add('S-1-5-11')
    if (($global:strPrinDomAttr -eq 14) -or ($global:strPrinDomAttr -eq 18) -or ($global:strPrinDomAttr -eq '5C') -or ($global:strPrinDomAttr -eq '1C') -or ($global:strPrinDomAttr -eq '44') -or ($global:strPrinDomAttr -eq '54') -or ($global:strPrinDomAttr -eq '50')) {
        #Add Other Organization
        [void]$tokenGroups.Add('S-1-5-1000')
    } else {
        #Add This Organization
        [void]$tokenGroups.Add('S-1-5-15')
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
Function GenerateSearchAbleSID {
    Param([String] $SidValue)

    # Create SID .NET object using SID string provided
    $sid = New-Object system.Security.Principal.SecurityIdentifier $SidValue

    # Create a byte array of the proper length
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $SidDec = $sid.GetBinaryForm( $sidBytes, 0 )

    Foreach ($intSID in $sidBytes) {
        [string] $SIDHex = '{0:X2}' -f [int] $intSID
        $strSIDHextString = $strSIDHextString + '\' + $SIDHex

    }


    return $strSIDHextString
}
#==========================================================================
# Function		: FindForeignSecPrinMemberships
# Arguments     : SID Decimal form Value as string
# Returns   	: Group names
# Description   : Searching for ForeignSecurityPrinicpals and return memberhsip
#==========================================================================
Function FindForeignSecPrinMemberships {
    Param([string] $strSearchAbleSID,
        [System.Management.Automation.PSCredential] $ForeignCREDS)

    $arrForeignMembership = New-Object System.Collections.ArrayList
    [void]$arrForeignMembership.clear()

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $ForeignCREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.DistinguishedName = "CN=ForeignSecurityPrincipals,$global:strDomainDNName"
    $request.Filter = "(&(objectSID=$strSearchAbleSID))"
    $request.Scope = 'Subtree'
    [void]$request.Attributes.Add('memberof')
    $response = $LDAPConnection.SendRequest($request)

    Foreach ( $obj in $response.Entries) {

        $index = 0
        while ($index -le $obj.Attributes.memberof.count - 1) {
            $member = $obj.Attributes.memberof[$index]
            $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $ForeignCREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
            $LDAPConnection.SessionOptions.ReferralChasing = 'None'
            $request = New-Object System.directoryServices.Protocols.SearchRequest

            $request.DistinguishedName = $member
            $request.Filter = '(name=*)'
            $request.Scope = 'Base'
            [void]$request.Attributes.Add('objectsid')
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
Function GetSidStringFromSidByte {
    Param([byte[]] $SidByte)

    $objectSid = [byte[]]$SidByte
    $sid = New-Object System.Security.Principal.SecurityIdentifier($objectSid, 0)
    $sidString = ($sid.value).ToString()
    return $sidString
}
#==========================================================================
# Function		: GetSecPrinDN
# Arguments     : samAccountName
# Returns   	: DistinguishedName
# Description   : Search Security Principal and Return DistinguishedName
#==========================================================================
Function GetSecPrinDN {
    Param([string] $samAccountName,
        [string] $strDomainDC,
        [bool] $bolCreds,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $CREDS)


    $LDAPConnection = Connect-SecureLDAP -Server $strDomainDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.Filter = '(name=*)'
    $request.Scope = 'Base'
    $response = $LDAPConnection.SendRequest($request)
    $strPrinDomDefNC = $response.Entries[0].Attributes.defaultnamingcontext[0]


    $request = New-Object System.directoryServices.Protocols.SearchRequest
    $request.DistinguishedName = $strPrinDomDefNC
    $request.Filter = "(&(samAccountName=$samAccountName))"
    $request.Scope = 'Subtree'
    [void]$request.Attributes.Add('name')

    $response = $LDAPConnection.SendRequest($request)
    $ADobject = $response.Entries[0]


    if ($ADobject.Attributes.Count -gt 0) {

        $global:strPrincipalDN = $ADobject.distinguishedname
    } else {
        $global:strPrincipalDN = ''
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
Function GetSchemaObjectGUID {
    Param(
        [string]
        $Domain,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    [string] $strOut = ''
    [string] $strLDAPname = ''


    BuildSchemaDic



    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", '(&(schemaIDGUID=*))', 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('ldapdisplayname')
    [void]$request.Attributes.Add('schemaidguid')
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
        foreach ($objResult in $colResults) {
            $strLDAPname = $objResult.attributes.ldapdisplayname[0]
            $guidGUID = [System.GUID] $objResult.attributes.schemaidguid[0]
            $strGUID = $guidGUID.toString().toUpper()
            If (!($global:dicSchemaIDGUIDs.ContainsKey($strGUID))) {
                $global:dicSchemaIDGUIDs.Add($strGUID, $strLDAPname)
                $global:dicNameToSchemaIDGUIDs.Add($strLDAPname, $strGUID)
            }

        }
        if ($global:PageSize -gt 0) {
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


#==========================================================================
# Function		: CheckDNExist
# Arguments     : string distinguishedName, string directory server
# Returns   	: string Name
# Description   : Check If distinguishedName exist
#==========================================================================
function CheckDNExist {
    Param (
        $sADobjectName,

        [string]
        $strDC,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )

    $LDAPConnection = Connect-SecureLDAP -Server $strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"

    $request = New-Object System.directoryServices.Protocols.SearchRequest
    if ($global:bolShowDeleted) {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
    }

    $request.DistinguishedName = $sADobjectName
    $request.Filter = '(name=*)'
    $request.Scope = 'Base'
    [void]$request.Attributes.Add('name')
    try {
        $response = $LDAPConnection.SendRequest($request)
    } catch {
        return $false
    }
    if ($response.Entries.count -gt 0) {
        $ADobject = $response.Entries[0]
        If ($null -eq $ADobject.distinguishedname) {
            return $false
        } else {
            If ($null -eq $ADobject.Attributes.name) {
                return $false
            } else {
                return $ADobject.Attributes.name[0]
            }
        }
    }
}


#==========================================================================
# Function		: Test-CSVColumnsDefaultSD
# Arguments     : CSV import for Default Security descriptor
# Returns   	: Boolean
# Description   : Search for all requried column names in CSV and return true or false
#==========================================================================
function Test-CSVColumnsDefaultSD {
    param($CSVDefaultSD)
    
    $bolDefaultSDCSVLoaded = $false
    $bolColumExist = $false

    if(Test-Path -Path $CSVDefaultSD) {

        Try { #Try
            $bolDefaultSDCSVLoaded = $true
            $CSVImport = Import-Csv $CSVDefaultSD
        }
        Catch [SystemException] {
            $strCSVErr = $_.Exception.Message
            $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to load CSV. $strCSVErr" -strType 'Error' -DateStamp ))
            $global:bolDefaultSDCSVLoaded = $false
            continue
        }
    }

    if($bolDefaultSDCSVLoaded) {

        $colHeaders = ( $CSVImport | Get-Member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
        $bolName = $false
        $boldistinguishedName = $false
        $bolVersion = $false
        $bolModifiedDate = $false
        $bolSDDL = $false

        Foreach ($ColumnName in $colHeaders ) {

            if ($ColumnName.Trim() -eq 'Name') {
                $bolName = $true
            }
            if ($ColumnName.Trim() -eq 'distinguishedName') {
                $boldistinguishedName = $true
            }
            if ($ColumnName.Trim() -eq 'Version') {
                $bolVersion = $true
            }
            if ($ColumnName.Trim() -eq 'ModifiedDate') {
                $bolModifiedDate = $true
            }
            if ($ColumnName.Trim() -eq 'SDDL') {
                $bolSDDL = $true
            }


        }

        #if test column names exist
        if ($bolName -and $boldistinguishedName -and $bolVersion -and $bolModifiedDate -and $bolSDDL) {
            $bolColumExist = $true
        }

    }
    return $bolColumExist
    
}
#==========================================================================
# Function		: TestCSVColumns
# Arguments     : CSV import
# Returns   	: Boolean
# Description   : Search for all requried column names in CSV and return true or false
#==========================================================================
function TestCSVColumns {
    param($CSVImport)
    $bolColumExist = $false
    $colHeaders = ( $CSVImport | Get-Member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
    $bolAccessControlType = $false
    $bolActiveDirectoryRights = $false
    $bolIdentityReference = $false
    $bolInheritanceFlags = $false
    $bolInheritanceType = $false
    $bolInheritedObjectType = $false
    $bolInvocationID = $false
    $bolIsInherited = $false
    $bolObjectFlags = $false
    $bolObjectType = $false
    $bolOrgUSN = $false
    $bolOU = $false
    $bolPropagationFlags = $false
    $bolSDDate = $false
    Foreach ($ColumnName in $colHeaders ) {

        if ($ColumnName.Trim() -eq 'AccessControlType') {
            $bolAccessControlType = $true
        }
        if ($ColumnName.Trim() -eq 'ActiveDirectoryRights') {
            $bolActiveDirectoryRights = $true
        }
        if ($ColumnName.Trim() -eq 'IdentityReference') {
            $bolIdentityReference = $true
        }
        if ($ColumnName.Trim() -eq 'InheritanceFlags') {
            $bolInheritanceFlags = $true
        }
        if ($ColumnName.Trim() -eq 'InheritanceType') {
            $bolInheritanceType = $true
        }
        if ($ColumnName.Trim() -eq 'InheritedObjectType') {
            $bolInheritedObjectType = $true
        }
        if ($ColumnName.Trim() -eq 'InvocationID') {
            $bolInvocationID = $true
        }
        if ($ColumnName.Trim() -eq 'IsInherited') {
            $bolIsInherited = $true
        }

        if ($ColumnName.Trim() -eq 'ObjectFlags') {
            $bolObjectFlags = $true
        }
        if ($ColumnName.Trim() -eq 'ObjectType') {
            $bolObjectType = $true
        }
        if ($ColumnName.Trim() -eq 'OrgUSN') {
            $bolOrgUSN = $true
        }
        if (($ColumnName.Trim() -eq 'Object') -or ($ColumnName.Trim() -eq 'OU')) {
            $bolOU = $true
        }
        if ($ColumnName.Trim() -eq 'PropagationFlags') {
            $bolPropagationFlags = $true
        }
        if ($ColumnName.Trim() -eq 'SDDate') {
            $bolSDDate = $true
        }

    }
    #if test column names exist
    if ($bolAccessControlType -and $bolActiveDirectoryRights -and $bolIdentityReference -and $bolInheritanceFlags -and $bolInheritanceType -and $bolInheritedObjectType `
            -and $bolInvocationID -and $bolIsInherited -and $bolObjectFlags -and $bolObjectType -and $bolOrgUSN -and $bolOU -and $bolPropagationFlags`
            -and $bolSDDate) {
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
        [Parameter(Mandatory = $True)]
        [System.Array]$stringlist
    )

    $stringlistReversed = @()

    foreach ($string in $stringlist) {
        $stringSplitted = $string.Split(',')
        $Counter = $stringSplitted.Count
        $stringReversed = ''
        while ($Counter -gt 0) {
            $stringReversed += $stringSplitted[$Counter - 1]
            $Counter = $Counter - 1
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
function GetAllChildNodes {
    param (
        # Search base
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0,
            ParameterSetName = 'Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String]
        $firstnode,
        # Scope
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1,
            ParameterSetName = 'Default')]
        [ValidateSet('base', 'onelevel', 'subtree')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,
        # Search filter (Optional)
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 2,
            ParameterSetName = 'Default')]
        [string]
        $CustomFilter = '',
        # Distinguishednames to exlude in result
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 3,
            ParameterSetName = 'Default')]
        [string]
        $ExcludedDNs = '',

        # Depth of LDAP searches
        [int]
        $Depth,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )

    $nodelist = New-Object System.Collections.ArrayList
    $nodelist.Clear()

    [boolean]$global:SearchFailed = $false

    # Add all Children found as Sub Nodes to the selected TreeNode

    $ReqFilter = ''

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null

    if ($global:bolShowDeleted) {
        [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
        [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
    }


    $request.DistinguishedName = $firstnode
  

    if ($CustomFilter -ne '') {
        $ReqFilter = $CustomFilter
    } else {
        $ReqFilter = '(objectClass=*)'
    }




    if($Depth) {
           if($Depth -eq 0) {
                $Scope = "base"
            } elseif($Depth -ge  1) {
                $Scope = "onelevel"
            }
    }

    # Set search scope
    $request.Scope = $Scope

    #if the seaching using a scope of onelevel we add the base node to the results
    if ($Scope -eq 'onelevel') {
        # Test the filter against the first node
        $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
        $request2 = New-Object System.directoryServices.Protocols.Searchrequest($firstnode, $ReqFilter, 'base')
        if ($GPO) {
            [void]$request2.Attributes.Add('gplink')
        } else {
            [void]$request2.Attributes.Add('name')
        }

        try {
            $response2 = $LDAPConnection.Sendrequest($request2)
        } catch {
            if ($_.Exception.Message.tostring() -match 'The search filter is invalid') {
                $global:SearchFailed = $true
                if ($global:bolCMD) {
                    Write-Host 'The search filter is invalid'
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'The search filter is invalid' -strType 'Error' -DateStamp ))
                }
                break
            }
        }
        #if the filter catch the first node add it to list
        If ($response2.Entries.Count -gt 0) 
        {
            if($ExcludedDNs)
            {
                $arrExcludedDN = $ExcludedDNs.split(";")
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
                        if($GPO)
                        {
                            $colResults = $response2.Entries
                            foreach ($objResult in $colResults)
                            {             
                                $gplink = $objResult.attributes.gplink[0]
                                $arrLinks = @($gplink.split("["))
                            

                                foreach ($link in $arrLinks)
                                {
                                    $nodelist +=$link.split(";")[0].replace("LDAP://","")+";"+$objResult.DistinguishedName
                                }

                            }

                        }
                        else
                        {
                            $nodelist += $firstnode
                        }
                    }
                    catch
                    {}
                    $intNomatch++
                    
                }
            }
            else
            {   
                if($GPO)
                {
                    $colResults = $response2.Entries
                    foreach ($objResult in $colResults)
                    {             
                        $gplink = $objResult.attributes.gplink[0]
                        $arrLinks = @($gplink.split("["))
                            

                        foreach ($link in $arrLinks)
                        {
                            $nodelist +=$link.split(";")[0].replace("LDAP://","")+";"+$objResult.DistinguishedName
                        }

                    }

                }
                else
                {
                    $nodelist += $firstnode
                }
            }
        }
    }#End if Scope = onelevel
    $request.filter = $ReqFilter
    if ($ExcludedDNs) {
        $arrExcludedDN = $ExcludedDNs.split(';')
        while ($true) {
            try {
                $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        if($Depth -gt 1) {

            #Adapting to the onelevel search where first level comes for free
            $Depth  = $Depth -1 

            # Add first levels to $colLevels
            $colLevels = $response.Entries

            # For each level in the result create an array with the expected depth and fetch next level

	        foreach ($Level in $colLevels) {

                # Define the size of the array as the size of depth
                $array = New-Object Object[] $Depth

                # Populate $colResults and $array until $Depth is reached
                for ($IntLevel = 0; $IntLevel -lt $Depth; $IntLevel++) {
                    # First search will search will create an result from the $Level
                    if($IntLevel -eq 0) {
                        $SearchResult = New-LDAPSearch -Server $global:strDC -creds $CREDS  -LDAPFilter $ReqFilter -Scope onelevel -BaseDN $Level.DistinguishedName -Attributes "name;gplink"
                        if($SearchResult) {

                            # Add results to the first level of the array
                            $array[$IntLevel] = $SearchResult
                            # Add results to $colResults
                            $colResults += $array[$IntLevel]
                        }
                    } else {
                        # Second and later search will search will populate increatemented levels of the array

                        # Check if the previous search have any results
                        if($array[$IntLevel-1]) {
                            # for each previous search make a new search
	                        foreach ($ParentLevel in @($array[$IntLevel-1])) {
                                $SearchResult = New-LDAPSearch -Server $global:strDC -creds $CREDS -LDAPFilter $ReqFilter -Scope onelevel -BaseDN $ParentLevel.DistinguishedName -Attributes "name;gplink"
                                if($SearchResult) {
                                    # Add results to the current level of the array
                                    $array[$IntLevel] = $SearchResult
                                    # Add results to $colResults
                                    $colResults += $array[$IntLevel]
                                }
                            }
                        }
                    }
                }
            }

        }                
            } catch {
                if ($_.Exception.Message.tostring() -match 'The search filter is invalid') {
                    $global:SearchFailed = $true
                    if ($global:bolCMD) {
                        Write-Host 'The search filter is invalid'
                    } else {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage 'The search filter is invalid' -strType 'Error' -DateStamp ))
                    }
                    break
                }
            }
            #for paged search, the response for paged search result control - we will need a cookie from result later
            if ($global:PageSize -gt 0) {
                [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
                if ($response.Controls.Length -gt 0) {
                    foreach ($ctrl in $response.Controls) {
                        if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                            $prrc = $ctrl;
                            break;
                        }
                    }
                }
                if ($null -eq $prrc) {
                    #server was unable to process paged search
                    throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                }
            }
            #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
            $colResults = $response.Entries
            $intTotalSearch = $colResults.Count
            $intNomatch = 0
            foreach ($objResult in $colResults) {
                $bolInclude = $true
                Foreach ( $strExcludeDN in $arrExcludedDN) {
                    if (!($objResult.distinguishedName -notmatch $strExcludeDN )) {
                        $bolInclude = $false
                        break
                    }
                }
                #Add objects with distinguihsedname not matching string
                if ($bolInclude) {
                    #Reverse string to be able to sort output
                    $nodelist += $objResult.distinguishedName
                    $intNomatch++
                }

            }
            if ($global:PageSize -gt 0) {
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
        if ($global:bolCMD) {
            Write-Host "Number of objects excluded: $global:intObjExluced"
        } else {
            $global:observableCollection.Insert(0, (LogMessage -strMessage "Number of objects excluded: $global:intObjExluced" -strType 'Info' -DateStamp ))
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
    
            if($Depth -gt 1)
            {
                #Adapting to the onelevel search where first level comes for free
                $Depth  = $Depth -1 

                # Add first levels to $colLevels
                $colLevels = $response.Entries

                # For each level in the result create an array with the expected depth and fetch next level

                foreach ($Level in $colLevels)
                {
                    # Define the size of the array as the size of depth
                    $array = New-Object Object[] $Depth

                    # Populate $colResults and $array until $Depth is reached
                    for ($IntLevel = 0; $IntLevel -lt $Depth; $IntLevel++) {
                        # First search will search will create an result from the $Level
                        if($IntLevel -eq 0)
                        {
                            $SearchResult = New-LDAPSearch -Server $global:strDC -LDAPFilter $ReqFilter -Scope onelevel -BaseDN $Level.DistinguishedName -Attributes "name;gplink" -creds $CREDS
                            if($SearchResult)
                            {
                                # Add results to the first level of the array
                                $array[$IntLevel] = $SearchResult
                                # Add results to $colResults
                                $colResults += $array[$IntLevel]
                            }
                        }
                        else
                        {
                            # Second and later search will search will populate increatemented levels of the array

                            # Check if the previous search have any results
                            if($array[$IntLevel-1])
                            {
                                # for each previous search make a new search
                                foreach ($ParentLevel in @($array[$IntLevel-1]))
                                {
                                    $SearchResult = New-LDAPSearch -Server $global:strDC -LDAPFilter $ReqFilter -Scope onelevel -BaseDN $ParentLevel.DistinguishedName -Attributes "name;gplink" -creds $CREDS
                                    if($SearchResult)
                                    {
                                        # Add results to the current level of the array
                                        $array[$IntLevel] = $SearchResult
                                        # Add results to $colResults
                                        $colResults += $array[$IntLevel]
                                    }
                                }
                            }
                        }
                    }
                }

            }

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
            if($GPO)
            {
                $colResults = $response.Entries
                foreach ($objResult in $colResults)
                {             
                    $gplink = $objResult.attributes.gplink[0]
                    $arrLinks = @($gplink.split("["))
                            

                    foreach ($link in $arrLinks)
                    {
                        $nodelist +=$link.split(";")[0].replace("LDAP://","")+";"+$objResult.DistinguishedName
                    }

                }


            }
            else
            {
                $colResults += $response.Entries
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
        if(-not($GPO))
        {
            if($colResults.count -gt 0)
            {
                $nodelist += $colResults.DistinguishedName
            }
        }

    }
    if (-not($GPO)) {
        if ($nodelist.count -gt 0) {
            $nodelist = ReverseDNList $nodelist
            $nodelist = $nodelist | Sort-Object
            $nodelist = ReverseDNList $nodelist
        }
    }
    return $nodelist

}

#==========================================================================
# Function		: Get-ProtectedPerm
# Arguments     :
# Returns   	: ArrayList
# Description   : Creates the Security Descriptor with the Protect object from accidental deleations ACE
#==========================================================================
Function Get-ProtectedPerm {

    $sdProtectedDeletion = New-Object System.Collections.ArrayList
    $sdProtectedDeletion.clear()

    $protectedDeletionsACE1 = New-Object PSObject -Property @{ActiveDirectoryRights = 'DeleteChild'; InheritanceType = 'None'; ObjectType = '00000000-0000-0000-0000-000000000000'; `
            InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'None'; AccessControlType = 'Deny'; IdentityReference = 'S-1-1-0'; IsInherited = 'False'; `
            InheritanceFlags = 'None'; PropagationFlags = 'None'
    }

    [void]$sdProtectedDeletion.insert(0, $protectedDeletionsACE)


    $protectedDeletionsACE2 = New-Object PSObject -Property @{ActiveDirectoryRights = 'DeleteChild, DeleteTree, Delete'; InheritanceType = 'None'; ObjectType = '00000000-0000-0000-0000-000000000000'; `
            InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Deny'; IdentityReference = 'S-1-1-0'; IsInherited = 'False'; `
            InheritanceFlags = 'None'; PropagationFlags = 'None'
    }

    $protectedDeletionsACE3 = New-Object PSObject -Property @{ActiveDirectoryRights = 'DeleteTree, Delete'; InheritanceType = 'None'; ObjectType = '00000000-0000-0000-0000-000000000000'; `
            InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'None'; AccessControlType = 'Deny'; IdentityReference = 'S-1-1-0'; IsInherited = 'False'; `
            InheritanceFlags = 'None'; PropagationFlags = 'None'
    }

    [void]$sdProtectedDeletion.insert(0, @($protectedDeletionsACE1, $protectedDeletionsACE2, $protectedDeletionsACE3))




    return $sdProtectedDeletion

}
#==========================================================================
# Function		: Get-DefaultPermissions
# Arguments     : Object Class, Trustee Name
# Returns   	: ArrayList
# Description   : Fetch the Default Security Descriptor with the Default
#==========================================================================
Function Get-DefaultPermissions {
    Param(
        $strObjectClass,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)


    $sdOUDef = New-Object System.Collections.ArrayList
    $sdOUDef.clear()


    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest("$global:SchemaDN", "(ldapdisplayname=$strObjectClass)", 'Subtree')
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    $response = $LDAPConnection.SendRequest($request)
    $colResults = $response.Entries

    foreach ($entry  in $response.Entries) {
        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $defSD = ''
        if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
            Try {
                $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
            } catch {
                if ($bolCMD) {
                    Write-Host 'The SDDL string contains an invalid sid or a sid that cannot be translated.' -ForegroundColor Red
                    Write-Host 'Only domain-joined computers can translate some sids.' -ForegroundColor Red
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'The SDDL string contains an invalid sid or a sid that cannot be translated.' -strType 'Error' -DateStamp ))
                    $global:observableCollection.Insert(0, (LogMessage -strMessage 'Only domain-joined computers can translate some sids.' -strType 'Error' -DateStamp ))
                }
            }
        }
        $defSD = $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        $sec = $null
    }


    if ($null -ne $defSD) {

        $(ConvertTo-ObjectArrayListFromPsCustomObject $defSD) | ForEach-Object { [void]$sdOUDef.add($_) }
        $defSD = $null
        if ($strObjectClass -eq 'computer') {
            if ($global:intObjeComputer -eq 0) {

                $global:additionalComputerACE1 = New-Object PSObject -Property @{ActiveDirectoryRights = 'DeleteTree, ExtendedRight, Delete, GenericRead'; InheritanceType = 'None'; ObjectType = '00000000-0000-0000-0000-000000000000'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'None'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


                $global:additionalComputerACE2 = New-Object PSObject -Property @{ActiveDirectoryRights = 'WriteProperty'; InheritanceType = 'None'; ObjectType = '4c164200-20c0-11d0-a768-00aa006e0529'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


                $global:additionalComputerACE3 = New-Object PSObject -Property @{ActiveDirectoryRights = 'WriteProperty'; InheritanceType = 'None'; ObjectType = '3e0abfd0-126a-11d0-a060-00aa006c33ed'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


                $global:additionalComputerACE4 = New-Object PSObject -Property @{ActiveDirectoryRights = 'WriteProperty'; InheritanceType = 'None'; ObjectType = 'bf967953-0de6-11d0-a285-00aa003049e2'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)

                $global:additionalComputerACE5 = New-Object PSObject -Property @{ActiveDirectoryRights = 'WriteProperty'; InheritanceType = 'None'; ObjectType = 'bf967950-0de6-11d0-a285-00aa003049e2'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)

                $global:additionalComputerACE6 = New-Object PSObject -Property @{ActiveDirectoryRights = 'WriteProperty'; InheritanceType = 'None'; ObjectType = '5f202010-79a5-11d0-9020-00c04fc2d4cf'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)


                $global:additionalComputerACE7 = New-Object PSObject -Property @{ActiveDirectoryRights = 'Self'; InheritanceType = 'None'; ObjectType = 'f3a64788-5306-11d1-a9c5-0000f80367c1'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                #[void]$sdOUDef.insert(0,$global:additionalComputerACE)

                $global:additionalComputerACE8 = New-Object PSObject -Property @{ActiveDirectoryRights = 'Self'; InheritanceType = 'None'; ObjectType = '72e39547-7b18-11d1-adef-00c04fd8d5cd'; `
                        InheritedObjectType = '00000000-0000-0000-0000-000000000000'; ObjectFlags = 'ObjectAceTypePresent'; AccessControlType = 'Allow'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                [void]$sdOUDef.insert(0, @($global:additionalComputerACE1, $global:additionalComputerACE2, $global:additionalComputerACE3, $global:additionalComputerACE4, $global:additionalComputerACE5, $global:additionalComputerACE6, $global:additionalComputerACE7, $global:additionalComputerACE8))
            } else {
                [void]$sdOUDef.insert(0, @($global:additionalComputerACE1, $global:additionalComputerACE2, $global:additionalComputerACE3, $global:additionalComputerACE4, $global:additionalComputerACE5, $global:additionalComputerACE6, $global:additionalComputerACE7, $global:additionalComputerACE8))
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
Function CacheRightsGuids {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $searcher = New-Object System.directoryServices.Protocols.SearchRequest
    $searcher.DistinguishedName = $global:ConfigDN

    [void]$searcher.Attributes.Add('cn')
    [void]$searcher.Attributes.Add('name')
    [void]$searcher.Attributes.Add('rightsguid')
    [void]$searcher.Attributes.Add('validaccesses')
    [void]$searcher.Attributes.Add('displayname')
    $searcher.filter = '(&(objectClass=controlAccessRight))'

    try {
        $searcherSent = $LDAPConnection.SendRequest($searcher)
        $colResults = $searcherSent.Entries
    } catch {
    }
    $intCounter = 0

    foreach ($objResult in $colResults) {

        $strRightDisplayName = $objResult.Attributes.displayname[0]
        $strRightGuid = $objResult.Attributes.rightsguid[0]
        $strRightGuid = $($strRightGuid).toString()

        #Expecting to fail at lest once since two objects have the same rightsguid
        & { #Try

            $global:dicRightsGuids.Add($strRightGuid, $strRightDisplayName)
        }
        Trap [SystemException] {
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
Function MapGUIDToMatchingName {
    Param(
        [string]
        $strGUIDAsString,

        [string]
        $Domain,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    [string] $strOut = $strGUIDAsString
    [string] $strLDAPname = ''

    If ($strGUIDAsString -eq '') {

        return $null
    }
    $strGUIDAsString = $strGUIDAsString.toUpper()

    if ($global:dicRightsGuids.ContainsKey($strGUIDAsString)) {
        $strOut = $global:dicRightsGuids.Item($strGUIDAsString)

        return $strOut
    }

    If ($strOut -eq $strGUIDAsString) {
        #Didn't find a match in extended rights
        If ($global:dicSchemaIDGUIDs.ContainsKey($strGUIDAsString)) {
            $strOut = $global:dicSchemaIDGUIDs.Item($strGUIDAsString)
        } else {

            if ($strGUIDAsString -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$')) {

                $ConvertGUID = ConvertGUID($strGUIDAsString)

                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $searcher = New-Object System.directoryServices.Protocols.SearchRequest
                $searcher.DistinguishedName = $global:SchemaDN

                [void]$searcher.Attributes.Add('cn')

                [void]$searcher.Attributes.Add('name')
                [void]$searcher.Attributes.Add('ldapdisplayname')
                $searcher.filter = "(&(schemaIDGUID=$ConvertGUID))"

                $searcherSent = $LDAPConnection.SendRequest($searcher)
                $objSchemaObject = $searcherSent.Entries[0]

                if ($objSchemaObject) {
                    $strLDAPname = $objSchemaObject.attributes.ldapdisplayname[0]
                    $global:dicSchemaIDGUIDs.Add($strGUIDAsString.toUpper(), $strLDAPname)
                    $strOut = $strLDAPname

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
Function ConvertGUID {
    Param($guid)

    $test = '(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})'
    $pattern = '"\$4\$3\$2\$1\$6\$5\$8\$7\$9\$10\$11\$12\$13\$14\$15\$16"'
    $ConvertGUID = [regex]::Replace($guid.replace('-', ''), $test, $pattern).Replace("`"", '')
    return $ConvertGUID
}
#==========================================================================
# Function		: fixfilename
# Arguments     : Text for naming text file
# Returns   	: Text with replace special characters
# Description   : Replace characters that be contained in a file name.

#==========================================================================
function fixfilename {
    Param([string] $strFileName)
    $strFileName = $strFileName.Replace('*', '#')
    $strFileName = $strFileName.Replace('/', '#')
    $strFileName = $strFileName.Replace('\', '#')
    $strFileName = $strFileName.Replace(':', '#')
    $strFileName = $strFileName.Replace('<', '#')
    $strFileName = $strFileName.Replace('>', '#')
    $strFileName = $strFileName.Replace('|', '#')
    $strFileName = $strFileName.Replace('"', '#')
    $strFileName = $strFileName.Replace('?', '#')

    return $strFileName
}
#==========================================================================
# Function		: Write-PermCSV
# Arguments     : Security Descriptor, OU distinguishedName, Ou put text file
# Returns   	: n/a
# Description   : Writes the SD to a text file.
#==========================================================================
function Write-PermCSV {
    Param($sd, [string]$object, [string]$canonical, [string]$objType, [string] $fileout, [bool] $ACLMeta, [string]  $strACLDate, [string] $strInvocationID, [string] $strOrgUSN, [bool] $GetOUProtected, [bool] $OUProtected, [bool] $compare, [bool]$Outfile, [bool]$GPO, [string]$GPOdisplayname, [bool]$TranslateGUID,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)


    $sd | ForEach-Object {
        #Convert SID to Names for lookups
        $strPrincipalName = $_.IdentityReference.toString()
        If ($strPrincipalName -match 'S-1-') {
            $strPrincipalName = Convert-SidToName -server $global:strDomainFQDN -Sid $strPrincipalName -CREDS $CREDS

        }
        # Add Translated object GUID information to output
        if ($TranslateGUID -eq $True) {
            if ($($_.InheritedObjectType.toString()) -ne '00000000-0000-0000-0000-000000000000' ) {

                $strTranslatedInheritObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.InheritedObjectType.toString() -Domain $global:strDomainDNName -CREDS $CREDS)
            } else {
                $strTranslatedInheritObjType = 'None' #$($_.InheritedObjectType.toString())
            }
            if ($($_.ObjectType.toString()) -ne '00000000-0000-0000-0000-000000000000' ) {

                $strTranslatedObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.ObjectType.toString() -Domain $global:strDomainDNName -CREDS $CREDS)
            } else {
                $strTranslatedObjType = 'None' #$($_.ObjectType.toString())
            }
        } else {
            $strTranslatedInheritObjType = $($_.InheritedObjectType.toString())
            $strTranslatedObjType = $($_.ObjectType.toString())
        }


        if ($bolShowCriticalityColor -eq $true) {
            $intCriticalityValue = Get-Criticality -Returns 'Color' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() 0
            Switch ($intCriticalityValue) {
                0 {
                    $strLegendText = 'Info'
                }
                1 {
                    $strLegendText = 'Low'
                }
                2 {
                    $strLegendText = 'Medium'
                }
                3 {
                    $strLegendText = 'Warning'
                }
                4 {
                    $strLegendText = 'Critical'
                }
            }
        } else {
            $strLegendText = ''
        }

        $objCSVLine = New-Object PSObject
        if ($GPO) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'GPO' -Value $GPOdisplayname
        }
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Object' -Value $object
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectClass' -Value $objType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'IdentityReference' -Value $_.IdentityReference.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'PrincipalName' -Value $strPrincipalName
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ActiveDirectoryRights' -Value $_.ActiveDirectoryRights.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritanceType' -Value $_.InheritanceType.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectType' -Value $strTranslatedObjType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritedObjectType' -Value $strTranslatedInheritObjType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectFlags' -Value $_.ObjectFlags.toString()
        if ($null -ne $_.AccessControlType) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'AccessControlType' -Value $_.AccessControlType.toString()
        } else {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'AccessControlType' -Value $_.AuditFlags.toString()
        }
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'IsInherited' -Value $_.IsInherited.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritanceFlags' -Value $_.InheritanceFlags.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'PropagationFlags' -Value $_.PropagationFlags.toString()

        # Add Meta data info to output
        If ($ACLMeta -eq $true) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'SDDate' -Value $strACLDate.toString()
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InvocationID' -Value $strInvocationID.toString()
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'OrgUSN' -Value $strOrgUSN.toString()

        } else {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'SDDate' -Value ''
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InvocationID' -Value ''
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'OrgUSN' -Value ''
        }

        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Criticality' -Value $strLegendText

        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'CanonicalName' -Value $canonical

        if ($GetOUProtected) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Inheritance Disabled' -Value $OUProtected.toString()
        } else {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Inheritance Disabled' -Value ''
        }

        if ($compare) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'State' -Value $_.State.toString()
        }

        if ($Outfile) {
            Export-Csv -InputObject $objCSVLine -Path $fileout -Encoding UTF8 -NoClobber -NoTypeInformation -Append
        } else {
            return $objCSVLine
        }
    }
}
#==========================================================================
# Function		: Write-DefSDPermCSV
# Arguments     : Security Descriptor, OU distinguishedName, Ou put text file
# Returns   	: n/a
# Description   : Writes the SD to a text file.
#==========================================================================
function Write-DefSDPermCSV {
    Param($sd, [string]$object, [string]$objType, [string] $fileout, [bool] $ACLMeta, [string] $strVersion, [string]  $strACLDate, [bool]$Outfile, [bool]$bolShowCriticalityColor, [bool]$TranslateGUID, [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $sd | ForEach-Object {
        #Convert SID to Names for lookups
        $strPrincipalName = $_.IdentityReference.toString()
        If ($strPrincipalName -match 'S-1-') {
            $strPrincipalName = Convert-SidToName -server $global:strDomainFQDN -Sid $strPrincipalName -CREDS $CREDS

        }
        # Add Translated object GUID information to output
        if ($TranslateGUID -eq $True) {
            if ($($_.InheritedObjectType.toString()) -ne '00000000-0000-0000-0000-000000000000' ) {

                $strTranslatedInheritObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.InheritedObjectType.toString() -Domain $global:strDomainDNName -CREDS $CREDS)
            } else {
                $strTranslatedInheritObjType = 'None' #$($_.InheritedObjectType.toString())
            }
            if ($($_.ObjectType.toString()) -ne '00000000-0000-0000-0000-000000000000' ) {

                $strTranslatedObjType = $(MapGUIDToMatchingName -strGUIDAsString $_.ObjectType.toString() -Domain $global:strDomainDNName -CREDS $CREDS)
            } else {
                $strTranslatedObjType = 'None' #$($_.ObjectType.toString())
            }
        } else {
            $strTranslatedInheritObjType = $($_.InheritedObjectType.toString())
            $strTranslatedObjType = $($_.ObjectType.toString())
        }


        if ($bolShowCriticalityColor -eq $true) {
            $intCriticalityValue = Get-Criticality -Returns 'Color' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() 0
            Switch ($intCriticalityValue) {
                0 {
                    $strLegendText = 'Info'
                }
                1 {
                    $strLegendText = 'Low'
                }
                2 {
                    $strLegendText = 'Medium'
                }
                3 {
                    $strLegendText = 'Warning'
                }
                4 {
                    $strLegendText = 'Critical'
                }
            }
        } else {
            $strLegendText = ''
        }

        $objCSVLine = New-Object PSObject
        if ($GPO) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'GPO' -Value $GPOdisplayname
        }
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Object' -Value $object
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectClass' -Value $objType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'IdentityReference' -Value $_.IdentityReference.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'PrincipalName' -Value $strPrincipalName
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ActiveDirectoryRights' -Value $_.ActiveDirectoryRights.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritanceType' -Value $_.InheritanceType.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectType' -Value $strTranslatedObjType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritedObjectType' -Value $strTranslatedInheritObjType
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'ObjectFlags' -Value $_.ObjectFlags.toString()
        if ($null -ne $_.AccessControlType) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'AccessControlType' -Value $_.AccessControlType.toString()
        } else {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'AccessControlType' -Value $_.AuditFlags.toString()
        }
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'IsInherited' -Value $_.IsInherited.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'InheritanceFlags' -Value $_.InheritanceFlags.toString()
        Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'PropagationFlags' -Value $_.PropagationFlags.toString()

        # Add Meta data info to output
        If ($ACLMeta -eq $true) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'SDDate' -Value $strACLDate.toString()
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Version' -Value $strVersion.toString()
            #Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name "OrgUSN"  -value $strOrgUSN.toString()

        } else {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'SDDate' -Value ''
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Version' -Value ''
            #Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name "OrgUSN"  -value ""
        }

        if($bolShowCriticalityColor -eq $true)
        {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'Criticality'  -value $strLegendText
        }

        if ($compare) {
            Add-Member -InputObject $objCSVLine -MemberType NoteProperty -Name 'State' -Value $_.State.toString()
        }

        if ($Outfile) {
            Export-Csv -InputObject $objCSVLine -Path $fileout -Encoding UTF8 -NoClobber -NoTypeInformation -Append
        } else {
            return $objCSVLine
        }
    }
}
#==========================================================================
# Function		: Get-ObjectTypeFromSid
# Arguments     : SID string
# Returns   	: Object type of Security Object
# Description   : Try to get the object of a SID
#==========================================================================
function Get-ObjectTypeFromSid {
    Param($server, $sid,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $strObjectType = $null
    $ID = New-Object System.Security.Principal.SecurityIdentifier($sid)


    If ($global:dicSidToObject.ContainsKey($sid)) {
        $strObjectType = $global:dicSidToObject.Item($sid)
    } else {

        $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"

        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
        $request = New-Object System.directoryServices.Protocols.SearchRequest
        if ($global:bolShowDeleted) {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
            [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
        }
        $request.DistinguishedName = "<SID=$sid>"
        $request.Filter = '(name=*)'
        $request.Scope = 'Base'
        [void]$request.Attributes.Add('objectclass')
        try {
            $response = $LDAPConnection.SendRequest($request)
            $result = $response.Entries[0]
            $strObjectType = $result.attributes.objectclass[-1]

        } catch {

        }
        if ($null -ne $strObjectType ) {
            $global:dicSidToObject.Add($sid, $strObjectType)
        }
    }



    return $strObjectType
}
#==========================================================================
# Function		: Convert-SidToName
# Arguments     : SID string
# Returns   	: Friendly Name of Security Object
# Description   : Try to translate the SID if it fails it try to match a Well-Known.
#==========================================================================
function Convert-SidToName {
    Param($server, $sid,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $global:strAccNameTranslation = ''
    $ID = New-Object System.Security.Principal.SecurityIdentifier($sid)

    & { #Try
        $User = $ID.Translate( [System.Security.Principal.NTAccount])
        $global:strAccNameTranslation = $User.Value
    }
    Trap [SystemException] {
        If ($global:dicWellKnownSids.ContainsKey($sid)) {
            $global:strAccNameTranslation = $global:dicWellKnownSids.Item($sid)
            return $global:strAccNameTranslation
        }
        ; Continue
    }

    if ($global:strAccNameTranslation -eq '') {

        If ($global:dicSidToName.ContainsKey($sid)) {
            $global:strAccNameTranslation = $global:dicSidToName.Item($sid)
        } else {


            $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"

            $LDAPConnection.SessionOptions.ReferralChasing = 'None'
            $request = New-Object System.directoryServices.Protocols.SearchRequest
            if ($global:bolShowDeleted) {
                [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
            }
            $request.DistinguishedName = "<SID=$sid>"
            $request.Filter = '(name=*)'
            $request.Scope = 'Base'
            [void]$request.Attributes.Add('samaccountname')

            $response = $LDAPConnection.SendRequest($request)
            $result = $response.Entries[0]

            try {
                $global:strAccNameTranslation = $global:strDomainShortName + '\' + $result.attributes.samaccountname[0]

            } catch {

            }

            if (!($global:strAccNameTranslation)) {
                $global:strAccNameTranslation = $result.distinguishedname
            }
            $global:dicSidToName.Add($sid, $global:strAccNameTranslation)
        }

    }

    If (($global:strAccNameTranslation -eq $nul) -or ($global:strAccNameTranslation -eq '')) {
        $global:strAccNameTranslation = $sid
    }

    return $global:strAccNameTranslation
}
#==========================================================================
# Function		: Get-Criticality
# Arguments     : $objRights,$objAccess,$objFlags,$objInheritanceType
# Returns   	: Integer
# Description   : Check criticality and returns number for rating
#==========================================================================
Function Get-Criticality {
    Param($Returns = 'Filter', $objIdentity, $objRights, $objAccess, $objFlags, $objInheritanceType, $objObjectType, $objInheritedObjectType, [int]$CriticalityFilter = 0)

    $intCriticalityLevel = 0


    Switch ($objRights) {
        'ListChildren' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 0
            }
        }
        'Read permissions, Modify permissions' {
            $intCriticalityLevel = 4
        }
        'Modify permissions' {
            $intCriticalityLevel = 4
        }
        { ($_ -match 'WriteDacl') -or ($_ -match 'WriteOwner') } {
            $intCriticalityLevel = 4
        }
        'DeleteChild, DeleteTree, Delete' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 3
            }
        }
        'Delete' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 3
            }
        }
        'GenericRead' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 1
            }
        }
        'CreateChild' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 3
            }
        }
        'DeleteChild' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 3
            }
        }
        'ExtendedRight' {
            If ($objAccess -eq 'Allow') {
                Switch ($objObjectType) {

                    # Domain Administer Server =
                    'ab721a52-1e2f-11d0-9819-00aa0040529b' {
                        $intCriticalityLevel = 4
                    }
                    # Change Password =
                    'ab721a53-1e2f-11d0-9819-00aa0040529b' {
                        $intCriticalityLevel = 1
                    }
                    # Reset Password =
                    '00299570-246d-11d0-a768-00aa006e0529' {
                        $intCriticalityLevel = 4
                    }
                    # Send As =
                    'ab721a54-1e2f-11d0-9819-00aa0040529b' {
                        $intCriticalityLevel = 4
                    }
                    # Receive As =
                    'ab721a56-1e2f-11d0-9819-00aa0040529b' {
                        $intCriticalityLevel = 4
                    }
                    # Send To =
                    'ab721a55-1e2f-11d0-9819-00aa0040529b' {
                        $intCriticalityLevel = 4
                    }
                    # Open Address List =
                    'a1990816-4298-11d1-ade2-00c04fd8d5cd' {
                        $intCriticalityLevel = 1
                    }
                    # Replicating Directory Changes =
                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' {
                        $intCriticalityLevel = 4
                    }
                    # Replication Synchronization =
                    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' {
                        $intCriticalityLevel = 4
                    }
                    # Manage Replication Topology =
                    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' {
                        $intCriticalityLevel = 4
                    }
                    # Change Schema Master =
                    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Change Rid Master =
                    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Do Garbage Collection =
                    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Recalculate Hierarchy =
                    '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Allocate Rids =
                    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Change PDC =
                    'bae50096-4752-11d1-9052-00c04fc2d4cf' {
                        $intCriticalityLevel = 4
                    }
                    # Add GUID =
                    '440820ad-65b4-11d1-a3da-0000f875ae0d' {
                        $intCriticalityLevel = 4
                    }
                    # Change Domain Master =
                    '014bf69c-7b3b-11d1-85f6-08002be74fab' {
                        $intCriticalityLevel = 4
                    }
                    # Receive Dead Letter =
                    '4b6e08c0-df3c-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Peek Dead Letter =
                    '4b6e08c1-df3c-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Receive Computer Journal =
                    '4b6e08c2-df3c-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Peek Computer Journal =
                    '4b6e08c3-df3c-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Receive Message =
                    '06bd3200-df3e-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Peek Message =
                    '06bd3201-df3e-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Send Message =
                    '06bd3202-df3e-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Receive Journal =
                    '06bd3203-df3e-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Open Connector Queue =
                    'b4e60130-df3f-11d1-9c86-006008764d0e' {
                        $intCriticalityLevel = 1
                    }
                    # Apply Group Policy =
                    'edacfd8f-ffb3-11d1-b41d-00a0c968f939' {
                        $intCriticalityLevel = 1
                    }
                    # Add/Remove Replica In Domain =
                    '9923a32a-3607-11d2-b9be-0000f87a36b2' {
                        $intCriticalityLevel = 4
                    }
                    # Change Infrastructure Master =
                    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' {
                        $intCriticalityLevel = 4
                    }
                    # Update Schema Cache =
                    'be2bb760-7f46-11d2-b9ad-00c04f79f805' {
                        $intCriticalityLevel = 4
                    }
                    # Recalculate Security Inheritance =
                    '62dd28a8-7f46-11d2-b9ad-00c04f79f805' {
                        $intCriticalityLevel = 4
                    }
                    # Check Stale Phantoms =
                    '69ae6200-7f46-11d2-b9ad-00c04f79f805' {
                        $intCriticalityLevel = 4
                    }
                    # Enroll =
                    '0e10c968-78fb-11d2-90d4-00c04f79dc55' {
                        $intCriticalityLevel = 1
                    }
                    # Generate Resultant Set of Policy (Planning) =
                    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' {
                        $intCriticalityLevel = 1
                    }
                    # Refresh Group Cache for Logons =
                    '9432c620-033c-4db7-8b58-14ef6d0bf477' {
                        $intCriticalityLevel = 4
                    }
                    # Enumerate Entire SAM Domain =
                    '91d67418-0135-4acc-8d79-c08e857cfbec' {
                        $intCriticalityLevel = 4
                    }
                    # Generate Resultant Set of Policy (Logging) =
                    'b7b1b3de-ab09-4242-9e30-9980e5d322f7' {
                        $intCriticalityLevel = 1
                    }
                    # Create Inbound Forest Trust =
                    'e2a36dc9-ae17-47c3-b58b-be34c55ba633' {
                        $intCriticalityLevel = 4
                    }
                    # Replicating Directory Changes All =
                    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' {
                        $intCriticalityLevel = 4
                    }
                    # Migrate SID History =
                    'BA33815A-4F93-4c76-87F3-57574BFF8109' {
                        $intCriticalityLevel = 4
                    }
                    # Reanimate Tombstones =
                    '45EC5156-DB7E-47bb-B53F-DBEB2D03C40F' {
                        $intCriticalityLevel = 4
                    }
                    # Allowed to Authenticate =
                    '68B1D179-0D15-4d4f-AB71-46152E79A7BC' {
                        $intCriticalityLevel = 1
                    }
                    # Execute Forest Update Script =
                    '2f16c4a5-b98e-432c-952a-cb388ba33f2e' {
                        $intCriticalityLevel = 4
                    }
                    # Monitor Active Directory Replication =
                    'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' {
                        $intCriticalityLevel = 3
                    }
                    # Update Password Not Required Bit =
                    '280f369c-67c7-438e-ae98-1d46f3c6f541' {
                        $intCriticalityLevel = 1
                    }
                    # Unexpire Password =
                    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' {
                        $intCriticalityLevel = 1
                    }
                    # Enable Per User Reversibly Encrypted Password =
                    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' {
                        $intCriticalityLevel = 1
                    }
                    # Query Self Quota =
                    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' {
                        $intCriticalityLevel = 1
                    }
                    # Read Only Replication Secret Synchronization =
                    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' {
                        $intCriticalityLevel = 4
                    }
                    # Reload SSL/TLS Certificate =
                    '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' {
                        $intCriticalityLevel = 4
                    }
                    # Replicating Directory Changes In Filtered Set =
                    '89e95b76-444d-4c62-991a-0facbeda640c' {
                        $intCriticalityLevel = 4
                    }
                    # Run Protect Admin Groups Task =
                    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' {
                        $intCriticalityLevel = 4
                    }
                    # Manage Optional Features for Active Directory =
                    '7c0e2a7c-a419-48e4-a995-10180aad54dd' {
                        $intCriticalityLevel = 4
                    }
                    # Allow a DC to create a clone of itself =
                    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' {
                        $intCriticalityLevel = 4
                    }
                    # AutoEnrollment =
                    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' {
                        $intCriticalityLevel = 1
                    }
                    # Set Owner of an object during creation. =
                    '4125c71f-7fac-4ff0-bcb7-f09a41325286' {
                        $intCriticalityLevel = 1
                    }
                    # Bypass the quota restrictions during creation. =
                    '88a9933e-e5c8-4f2a-9dd7-2527416b8092' {
                        $intCriticalityLevel = 4
                    }
                    # Read secret attributes of objects in a Partition. =
                    '084c93a2-620d-4879-a836-f0ae47de0e89' {
                        $intCriticalityLevel = 4
                    }
                    # Write secret attributes of objects in a Partition. =
                    '94825A8D-B171-4116-8146-1E34D8F54401' {
                        $intCriticalityLevel = 4
                    }
                    default {
                        $intCriticalityLevel = 1
                    }
                }

            }
        }
        'GenericAll' {
            If ($objAccess -eq 'Allow') {
                Switch ($objInheritanceType) {
                    'All' {
                        Switch ($objObjectType) {
                            # Any =  4
                            '00000000-0000-0000-0000-000000000000' {
                                $intCriticalityLevel = 4
                            }
                            # Privat-Information = 3
                            '91e647de-d96f-4b70-9557-d63ff4f3ccd8' {
                                $intCriticalityLevel = 3
                            }
                            # Password Reset = 4
                            '00299570-246d-11d0-a768-00aa006e0529' {
                                $intCriticalityLevel = 4
                            }
                            # Membership = 4
                            'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                $intCriticalityLevel = 4
                            }
                            default {
                                $intCriticalityLevel = 3
                            }
                        }
                    }
                    'None' {
                        $intCriticalityLevel = 4
                    }
                    'Children' {

                    }
                    'Descendents' {
                        Switch ($objInheritedObjectType) {
                            # Any =  4
                            '00000000-0000-0000-0000-000000000000' {
                                $intCriticalityLevel = 4
                            }
                            # User = 4
                            'bf967aba-0de6-11d0-a285-00aa003049e2' {
                                $intCriticalityLevel = 4

                            }
                            # Group = 4
                            'bf967a9c-0de6-11d0-a285-00aa003049e2' {
                                $intCriticalityLevel = 4

                            }
                            # Computer = 4
                            'bf967a86-0de6-11d0-a285-00aa003049e2' {
                                $intCriticalityLevel = 4

                            }
                            # ms-DS-Managed-Service-Account = 4
                            'ce206244-5827-4a86-ba1c-1c0c386c1b64' {
                                $intCriticalityLevel = 4

                            }
                            # msDS-Group-Managed-Service-Account = 4
                            '7b8b558a-93a5-4af7-adca-c017e67f1057' {
                                $intCriticalityLevel = 4

                            }
                            default {
                                $intCriticalityLevel = 3
                            }
                        }

                    }
                    default {
                        $intCriticalityLevel = 3
                    }
                }#End switch


            }
        }
        'CreateChild, DeleteChild' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 3
            }
        }
        'ReadProperty' {
            If ($objAccess -eq 'Allow') {
                $intCriticalityLevel = 1

                Switch ($objInheritanceType) {
                    'None' {

                    }
                    'Children' {

                    }
                    'Descendents' {

                    }
                    default {

                    }
                }#End switch
            }
        }
        { $_ -match 'WriteProperty' } {
            If ($objAccess -eq 'Allow') {
                Switch ($objInheritanceType) {
                    { ($_ -match 'All') -or ($_ -match 'None') } {
                        Switch ($objFlags) {
                            'ObjectAceTypePresent' {
                                Switch ($objObjectType) {

                                    # msDS-KeyCredentialLink = 4
                                    '5b47d60f-6090-40b2-9f37-2a4de88f3063' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Domain Password & Lockout Policies = 4
                                    'c7407360-20bf-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Account Restrictions = 4
                                    '4c164200-20c0-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Group Membership = 4
                                    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Public Information = 4
                                    'e48d0154-bcf8-11d1-8702-00c04fb96050' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Email-Information = 0
                                    'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                        $intCriticalityLevel = 0
                                    }
                                    # Web-Information = 2
                                    'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 1
                                        }
                                    }
                                    # Personal-Information = 2
                                    '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # User-Account-Control = 4
                                    'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Service-Principal-Name = 4
                                    'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                        $intCriticalityLevel = 4
                                    }
                                    #  Is-Member-Of-DL = 4
                                    'bf967991-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    default {
                                        $intCriticalityLevel = 2
                                    }
                                }
                            }
                            'ObjectAceTypePresent, InheritedObjectAceTypePresent' {

                            }
                            default {
                                $intCriticalityLevel = 3
                            }
                        }#End switch
                    }
                    'Children' {
                        Switch ($objFlags) {
                            'ObjectAceTypePresent' {
                                Switch ($objObjectType) {
                                    # Domain Password & Lockout Policies = 4
                                    'c7407360-20bf-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Account Restrictions = 4
                                    '4c164200-20c0-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Group Membership = 4
                                    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Email-Information = 0
                                    'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                        $intCriticalityLevel = 0
                                    }
                                    # Web-Information = 2
                                    'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # Personal-Information = 2
                                    '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # User-Account-Control = 4
                                    'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Service-Principal-Name = 4
                                    'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                        $intCriticalityLevel = 4
                                    }
                                    #  Is-Member-Of-DL = 4
                                    'bf967991-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    default {
                                        $intCriticalityLevel = 2
                                    }
                                }
                            }
                            'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                                Switch ($objInheritedObjectType) {
                                    # User = 4 ,Group = 4,Computer = 4
                                    { ($_ -eq 'bf967aba-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a9c-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a86-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'ce206244-5827-4a86-ba1c-1c0c386c1b64') -or ($_ -eq '7b8b558a-93a5-4af7-adca-c017e67f1057') } {

                                        Switch ($objObjectType) {
                                            # Account Restrictions = 4
                                            '4c164200-20c0-11d0-a768-00aa006e0529' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Group Membership = 4
                                            'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Email-Information = 0
                                            'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                                $intCriticalityLevel = 0
                                            }
                                            # Web-Information = 2
                                            'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # Personal-Information = 2
                                            '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # User-Account-Control = 4
                                            'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Service-Principal-Name = 4
                                            'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                                $intCriticalityLevel = 4
                                            }
                                            #  Is-Member-Of-DL = 4
                                            'bf967991-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            default {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                    }
                                    default {
                                        $intCriticalityLevel = 3
                                    }
                                }

                            }
                            'InheritedObjectAceTypePresent' {
                                Switch ($objInheritedObjectType) {
                                    # User = 4 ,Group = 4,Computer = 4
                                    { ($_ -eq 'bf967aba-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a9c-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a86-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'ce206244-5827-4a86-ba1c-1c0c386c1b64') -or ($_ -eq '7b8b558a-93a5-4af7-adca-c017e67f1057') } {

                                        Switch ($objObjectType) {
                                            # All
                                            '00000000-0000-0000-0000-000000000000' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Account Restrictions = 4
                                            '4c164200-20c0-11d0-a768-00aa006e0529' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Group Membership = 4
                                            'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Email-Information = 0
                                            'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                                $intCriticalityLevel = 0
                                            }
                                            # Web-Information = 2
                                            'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # Personal-Information = 2
                                            '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # User-Account-Control = 4
                                            'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Service-Principal-Name = 4
                                            'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                                $intCriticalityLevel = 4
                                            }
                                            #  Is-Member-Of-DL = 4
                                            'bf967991-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            default {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                    }
                                    default {
                                        $intCriticalityLevel = 3
                                    }
                                }

                            }
                            'None' {

                                Switch ($objObjectType) {
                                    # All
                                    '00000000-0000-0000-0000-000000000000' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Account Restrictions = 4
                                    '4c164200-20c0-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Group Membership = 4
                                    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Email-Information = 0
                                    'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                        $intCriticalityLevel = 0
                                    }
                                    # Web-Information = 2
                                    'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # Personal-Information = 2
                                    '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # User-Account-Control = 4
                                    'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Service-Principal-Name = 4
                                    'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                        $intCriticalityLevel = 4
                                    }
                                    #  Is-Member-Of-DL = 4
                                    'bf967991-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    default {
                                        $intCriticalityLevel = 2
                                    }
                                }
                            }
                            default {

                            }
                        }#End switch

                    }
                    'Descendents' {
                        Switch ($objFlags) {
                            'ObjectAceTypePresent' {
                                Switch ($objObjectType) {
                                    # Domain Password & Lockout Policies = 4
                                    'c7407360-20bf-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Account Restrictions = 4
                                    '4c164200-20c0-11d0-a768-00aa006e0529' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Group Membership = 4
                                    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Email-Information = 0
                                    'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                        $intCriticalityLevel = 0
                                    }
                                    # Web-Information = 2
                                    'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # Personal-Information = 2
                                    '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                        #If it SELF then = 1
                                        if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                            $intCriticalityLevel = 1
                                        } else {
                                            $intCriticalityLevel = 2
                                        }
                                    }
                                    # User-Account-Control = 4
                                    'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    # Service-Principal-Name = 4
                                    'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                        $intCriticalityLevel = 4
                                    }
                                    #  Is-Member-Of-DL = 4
                                    'bf967991-0de6-11d0-a285-00aa003049e2' {
                                        $intCriticalityLevel = 4
                                    }
                                    default {
                                        $intCriticalityLevel = 2
                                    }
                                }
                            }
                            'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                                Switch ($objInheritedObjectType) {
                                    # User = 4 ,Group = 4,Computer = 4
                                    { ($_ -eq 'bf967aba-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a9c-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a86-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'ce206244-5827-4a86-ba1c-1c0c386c1b64') -or ($_ -eq '7b8b558a-93a5-4af7-adca-c017e67f1057') } {

                                        Switch ($objObjectType) {
                                            # Account Restrictions = 4
                                            '4c164200-20c0-11d0-a768-00aa006e0529' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Group Membership = 4
                                            'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Email-Information = 0
                                            'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                                $intCriticalityLevel = 0
                                            }
                                            # Web-Information = 2
                                            'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # Personal-Information = 2
                                            '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # User-Account-Control = 4
                                            'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Service-Principal-Name = 4
                                            'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                                $intCriticalityLevel = 4
                                            }
                                            #  Is-Member-Of-DL = 4
                                            'bf967991-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            default {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                    }
                                    default {
                                        $intCriticalityLevel = 3
                                    }
                                }

                            }
                            'InheritedObjectAceTypePresent' {
                                Switch ($objInheritedObjectType) {
                                    # User = 4 ,Group = 4,Computer = 4
                                    { ($_ -eq 'bf967aba-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a9c-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'bf967a86-0de6-11d0-a285-00aa003049e2') -or ($_ -eq 'ce206244-5827-4a86-ba1c-1c0c386c1b64') -or ($_ -eq '7b8b558a-93a5-4af7-adca-c017e67f1057') } {

                                        Switch ($objObjectType) {
                                            # All
                                            '00000000-0000-0000-0000-000000000000' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Account Restrictions = 4
                                            '4c164200-20c0-11d0-a768-00aa006e0529' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Group Membership = 4
                                            'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Email-Information = 0
                                            'E45795B2-9455-11d1-AEBD-0000F80367C1' {
                                                $intCriticalityLevel = 0
                                            }
                                            # Web-Information = 2
                                            'E45795B3-9455-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # Personal-Information = 2
                                            '77B5B886-944A-11d1-AEBD-0000F80367C1' {
                                                #If it SELF then = 1
                                                if ($objIdentity -eq 'NT AUTHORITY\SELF') {
                                                    $intCriticalityLevel = 1
                                                } else {
                                                    $intCriticalityLevel = 2
                                                }
                                            }
                                            # User-Account-Control = 4
                                            'bf967a68-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            # Service-Principal-Name = 4
                                            'f3a64788-5306-11d1-a9c5-0000f80367c1' {
                                                $intCriticalityLevel = 4
                                            }
                                            #  Is-Member-Of-DL = 4
                                            'bf967991-0de6-11d0-a285-00aa003049e2' {
                                                $intCriticalityLevel = 4
                                            }
                                            default {
                                                $intCriticalityLevel = 2
                                            }
                                        }
                                    }
                                    default {
                                        $intCriticalityLevel = 3
                                    }
                                }

                            }
                            default {

                            }
                        }#End switch

                    }
                    default {
                        $intCriticalityLevel = 3
                    }
                }#End switch
            }#End if Allow
        }
        { ($_ -match 'WriteDacl') -or ($_ -match 'WriteOwner') } {
            $intCriticalityLevel = 4
        }
        default {
            If ($objAccess -eq 'Allow') {
                if ($objRights -match 'Write') {
                    $intCriticalityLevel = 2
                }
                if ($objRights -match 'Create') {
                    $intCriticalityLevel = 3
                }
                if ($objRights -match 'Delete') {
                    $intCriticalityLevel = 3
                }
                if ($objRights -match 'ExtendedRight') {
                    $intCriticalityLevel = 3
                }
                if ($objRights -match 'WriteDacl') {
                    $intCriticalityLevel = 4
                }
                if ($objRights -match 'WriteOwner') {
                    $intCriticalityLevel = 4
                }
            }
        }
    }# End Switch

    if ($Returns -eq 'Filter') {
        if ($intCriticalityLevel -ge $CriticalityFilter) {
            Return $True
        } else {
            Return $false
        }

    } else {
        Return $intCriticalityLevel
    }


}

#==========================================================================
# Function		: Write-ToFile
# Arguments     : Security Descriptor, OU dn string, Output htm file or other format
# Returns   	: n/a
# Description   : Wites the SD info to a HTM table or other format, it appends info if the file exist
#==========================================================================
function Write-ToFile
{
    Param([bool] $bolACLExist,
    $sd,
    [string]$DSObject,
    [string]$Canonical,
    [bool] $OUHeader,
    [string] $strColorTemp,
    [string] $htmfileout,
    [bool] $CompareMode,
    [bool] $FilterMode,
    [bool]$boolReplMetaDate,
    [string]$strReplMetaDate,
    [bool]$boolACLSize,
    [string]$strACLSize,
    [string]$Version,
    [bool]$bolShowOUProtected,
    [bool]$bolOUPRotected,
    [bool]$bolCriticalityLevel,
    [bool]$bolTranslateGUID,
    [string]$strObjClass,
    [string]$Type,
    [bool]$GPO,
    [string]$GPODisplayname,
    [bool]$bolShowCriticalityColor,
    [string]$strSDDL,
    [Parameter(Mandatory=$false)]
    [pscredential] 
    $CREDS)

    if(-not(($null -eq $strObjClass) -and ($strObjClass -ne ""))) {
        $bolObjClass = $true
    } else {
        $bolObjClass = $false
    }

    if ($Type -eq 'HTML') {
        $htm = $true
        $fileout = $htmfileout
    }
    if ($HTM) {
        $strTHOUColor = 'E5CF00'
        $strTHColor = 'EFAC00'
        if ($bolCriticalityLevel -eq $true) {
            $strLegendColor = @'
bgcolor="#A4A4A4"
'@
        } else {
            $strLegendColor = ''
        }
        $strLegendColorInfo = @'
bgcolor="#A4A4A4"
'@
        $strLegendColorLow = @'
bgcolor="#0099FF"
'@
        $strLegendColorMedium = @'
bgcolor="#FFFF00"
'@
        $strLegendColorWarning = @'
bgcolor="#FFD700"
'@
        $strLegendColorCritical = @'
bgcolor="#DF0101"
'@
        $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontRights = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@
        If ($OUHeader -eq $true) {

            if ($GPO) {
                $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $GPOdisplayname</b>
"@
            } else {
                $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHOUColor">
"@
            }

            $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $DSObject</b>
"@

            if ($Canonical) {
                $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $Canonical</b>
"@
            }

            if ($bolObjClass -eq $true) {
                $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $strObjClass</b>
"@
            }
            if ($boolReplMetaDate -eq $true) {
                $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $strReplMetaDate</b>
"@
            }
            if ($Version) {
            $strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $Version</b>
"@
            }            
            if ($boolACLSize -eq $true) {
                $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $strACLSize bytes</b>
"@
            }
            if ($bolShowOUProtected -eq $true) {
                if ($bolOUProtected -eq $true) {
                    $strHTMLText =@"
$strHTMLText
<TD bgcolor="FF0000"><b>$strFontOU $bolOUProtected</b>
"@
                } else {
                    $strHTMLText =@"
$strHTMLText
<TD><b>$strFontOU $bolOUProtected</b>
"@
                }
            }

            $strHTMLText = @"
$strHTMLText
</TR>
"@
        }


        Switch ($strColorTemp) {

            '1' {
                $strColor = 'DDDDDD'
                $strColorTemp = '2'
            }
            '2' {
                $strColor = 'AAAAAA'
                $strColorTemp = '1'
            }
            '3' {
                $strColor = 'FF1111'
            }
            '4' {
                $strColor = '00FFAA'
            }
            '5' {
                $strColor = 'FFFF00'
            }
        }# End Switch
    }#End if HTM
    if ($bolACLExist) {
        $sd | ForEach-Object {


            if ($null -ne $_.AccessControlType) {
                $objAccess = $($_.AccessControlType.toString())
            } else {
                $objAccess = $($_.AuditFlags.toString())
            }
            $objFlags = $($_.ObjectFlags.toString())
            $objType = $($_.ObjectType.toString())
            $objIsInheried = $($_.IsInherited.toString())
            $objInheritedType = $($_.InheritedObjectType.toString())
            $objRights = $($_.ActiveDirectoryRights.toString())
            $objInheritanceType = $($_.InheritanceType.toString())

            $strConvRights = Convert-ActiveDirectoryRights -strADRights $objRights -objInheritanceType $objInheritanceType -objFlags $objFlags

            if($strConvRights) {
                $objRights = $strConvRights
            }

            if ($bolShowCriticalityColor) {
                $intCriticalityValue = Get-Criticality -Returns 'Color' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() 0

                Switch ($intCriticalityValue) {
                    0 {
                        $strLegendText = 'Info'; $strLegendColor = $strLegendColorInfo
                    }
                    1 {
                        $strLegendText = 'Low'; $strLegendColor = $strLegendColorLow
                    }
                    2 {
                        $strLegendText = 'Medium'; $strLegendColor = $strLegendColorMedium
                    }
                    3 {
                        $strLegendText = 'Warning'; $strLegendColor = $strLegendColorWarning
                    }
                    4 {
                        $strLegendText = 'Critical'; $strLegendColor = $strLegendColorCritical
                    }
                }
                $strLegendTextVal = $strLegendText
                if ($intCriticalityValue -gt $global:intShowCriticalityLevel) {
                    $global:intShowCriticalityLevel = $intCriticalityValue
                }
            }



            $IdentityReference = $($_.IdentityReference.toString())

            If ($IdentityReference.contains('S-1-')) {
                $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $IdentityReference -CREDS $CREDS

            } else {
                $strNTAccount = $IdentityReference
            }

            Switch ($strColorTemp) {

                '1' {
                    $strColor = 'DDDDDD'
                    $strColorTemp = '2'
                }
                '2' {
                    $strColor = 'AAAAAA'
                    $strColorTemp = '1'
                }
                '3' {
                    $strColor = 'FF1111'
                }
                '4' {
                    $strColor = '00FFAA'
                }
                '5' {
                    $strColor = 'FFFF00'
                }
            }# End Switch

            Switch ($objInheritanceType) {
                'All' {
                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 1K'
                        }

                    }# End Switch

                }
                'Descendents' {

                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = "Descendant $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS}) objects"
                            $strPerm = "$objRights"
                        }
                        'None' {
                            $strApplyTo = 'Child Objects Only'
                            $strPerm = "$objRights"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'Child Objects Only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo =	"$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm =	"$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 2K'
                        }

                    }
                }
                'None' {
                    Switch ($objFlags) {
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This Object Only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This Object Only'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 4K'
                        }

                    }
                }
                'SelfAndChildren' {
                    Switch ($objFlags) {
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }

                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 5K'
                        }

                    }
                }
                'Children' {
                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = "Descendant $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS}) objects within this container only"
                            $strPerm = "$objRights"
                        }
                        'None' {
                            $strApplyTo = 'Children  within this container only'
                            $strPerm = "$objRights"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS}) $objRights"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'Children within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 6K'
                        }

                    }
                }
                default {
                    $strApplyTo = 'Error'
                    $strPerm = 'Error: Failed to display permissions 7K'
                }
            }# End Switch

            ##

            if ($Type -eq 'Object') {
                $objhashtableACE = [pscustomobject][ordered]@{
                    Object          = $DSObject ; `
                        ObjectClass = $strObjClass
                }

                if ($strSDDL) {
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'SDDL' -Value $strSDDL
                } else {
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'IdentityReference' -Value $IdentityReference
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'Trustee' -Value $strNTAccount
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'Access' -Value $objAccess
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'Inherited' -Value $objIsInheried
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'Apply To' -Value $strApplyTo
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'Permission' -Value $strPerm
                }

                if ($Canonical) {
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'CanonicalName' -Value $Canonical
                    $objhashtableACE = $objhashtableACE | Select-Object -Property Object, CanonicalName, * -ErrorAction SilentlyContinue
                }

                if ($GPO) {
                    Add-Member -InputObject $objhashtableACE -MemberType NoteProperty -Name 'GPO' -Value $GPOdisplayname
                    $objhashtableACE = $objhashtableACE | Select-Object -Property GPO, * -ErrorAction SilentlyContinue

                }


                if ($bolShowOUProtected) {
                    $objhashtableACE | Add-Member NoteProperty 'Inheritance Disabled' $bolOUProtected.toString()
                }

                if ($boolReplMetaDate) {
                    $objhashtableACE | Add-Member NoteProperty 'Security Descriptor Modified' $strReplMetaDate
                }

                if($Version) {
                    $objhashtableACE | Add-Member NoteProperty 'Version' $Version
                }                

                if ($CompareMode) {
                    $objhashtableACE | Add-Member NoteProperty State $($_.State.toString())
                }

                if ($bolCriticalityLevel -or $bolShowCriticalityColor) {

                    $objhashtableACE | Add-Member NoteProperty 'Criticality Level' $strLegendTextVal
                }

                [VOID]$global:ArrayAllACE.Add($objhashtableACE)
            }

            If ($HTM) {
                if ($GPO) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TR bgcolor="$strColor"><TD>$strFont $GPOdisplayname</TD>
"@
                } else {
                    $strACLHTMLText = @"
$strACLHTMLText
<TR bgcolor="$strColor">
"@
                }
                $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $DSObject</TD>
"@

                if ($Canonical) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $Canonical</TD>
"@
                }

                if ($bolObjClass -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strObjClass</TD>
"@
                }

                if ($boolReplMetaDate -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
                }

                if ($Version) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $Version</TD>
"@
                }

                if ($boolACLSize -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
                }

                if ($bolShowOUProtected -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
                }
                if ($strSDDL) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strSDDL</TD>
"@
                } else {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont <a href="#web" onclick="GetGroupDN('$strNTAccount')">$strNTAccount</a></TD>
<TD>$strFont $objAccess</TD>
<TD>$strFont $objIsInheried </TD>
<TD>$strFont $strApplyTo</TD>
<TD $strLegendColor>$strFontRights $strPerm</TD>
"@
                }

                if ($CompareMode) {

                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $($_.State.toString())</TD>
"@
                }
                if ($bolShowCriticalityColor -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@

                }
            }#End If HTM
        }# End Foreach


    } else {
        if ($HTM) {
            if ($OUHeader -eq $false) {
                if ($FilterMode) {



                    if ($boolReplMetaDate -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
                    }

                    if ($Version) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $Version</TD>
"@
                    }

                    if ($strSDDL) {
                        $strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strSDDL</TD>
"@
                    }

                    if ($boolACLSize -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
                    }

                    if ($bolShowOUProtected -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
                    }
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Matching Permissions Set</TD>
"@



                    if ($bolShowCriticalityColor -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
                    }
                } else {


                    if ($boolReplMetaDate -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
                    }

                    if ($Version) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $Version</TD>
"@
                    }
                    if ($strSDDL) {
                        $strACLHTMLText =@"
$strACLHTMLText
<TD>$strFont $strSDDL</TD>
"@
                    }                    
                    if ($boolACLSize -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
                    }

                    if ($bolShowOUProtected -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
                    }

                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Permissions Set</TD>
"@


                    if ($bolCriticalityLevel -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
                    }

                }# End If
            }#end If OUHeader false
        }#End if HTM
    } #End if bolACLExist
    if ($HTM) {
        $strACLHTMLText = @"
$strACLHTMLText
</TR>
"@

        #end ifelse OUHEader
        $strHTMLText = $strHTMLText + $strACLHTMLText

        Out-File -InputObject $strHTMLText -Append -FilePath $fileout
        Out-File -InputObject $strHTMLText -Append -FilePath $strFileHTM

        $strHTMLText = $null
        $strACLHTMLText = $null
        Remove-Variable -Name 'strHTMLText'
        Remove-Variable -Name 'strACLHTMLText'
    }#End if HTM

}
#==========================================================================
# Function		: Write-DefSDAccessHTM
# Arguments     : Security Descriptor, OU dn string, Output htm file
# Returns   	: n/a
# Description   : Wites the SD info to a HTM table, it appends info if the file exist
#==========================================================================
function Write-DefSDAccessHTM {
    Param([bool]$bolACLExist, $sd, [bool]$bolObjClass, [string]$strObjectClass, [string]$strColorTemp, [string]$htmfileout, [string]$strFileHTM, [bool]$OUHeader, [bool]$boolReplMetaDate, [string]$strReplMetaVer, [string]$strReplMetaDate, [bool]$bolCriticalityLevel, [boolean]$CompareMode, [string]$xlsxout, [string]$Type)

    if ($Type -eq 'HTML') {
        $htm = $true
        $fileout = $htmfileout
    }
    if ($Type -eq 'EXCEL') {
        $EXCEL = $true
        $fileout = $xlsxout
    }
    if ($HTM) {
        $strTHOUColor = 'E5CF00'
        $strTHColor = 'EFAC00'
        if ($bolCriticalityLevel -eq $true) {
            $strLegendColor = @'
bgcolor="#A4A4A4"
'@
        } else {
            $strLegendColor = ''
        }
        $strLegendColorInfo = @'
bgcolor="#A4A4A4"
'@
        $strLegendColorLow = @'
bgcolor="#0099FF"
'@
        $strLegendColorMedium = @'
bgcolor="#FFFF00"
'@
        $strLegendColorWarning = @'
bgcolor="#FFD700"
'@
        $strLegendColorCritical = @'
bgcolor="#DF0101"
'@
        $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontRights = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
        $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@
        If ($OUHeader -eq $true) {


            $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHOUColor">
"@

            $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $strObjectClass</b>
"@

            if ($boolReplMetaDate -eq $true) {
                $strHTMLText = @"
$strHTMLText
<TD><b>$strFontOU $strReplMetaDate</b>
<TD><b>$strFontOU $strReplMetaVer</b>
"@
            }




            $strHTMLText = @"
$strHTMLText
</TR>
"@
        }


        Switch ($strColorTemp) {

            '1' {
                $strColor = 'DDDDDD'
                $strColorTemp = '2'
            }
            '2' {
                $strColor = 'AAAAAA'
                $strColorTemp = '1'
            }
            '3' {
                $strColor = 'FF1111'
            }
            '4' {
                $strColor = '00FFAA'
            }
            '5' {
                $strColor = 'FFFF00'
            }
        }# End Switch
    }#End if HTM
    if ($bolACLExist) {
        $sd | ForEach-Object {


            if ($null -ne $_.AccessControlType) {
                $objAccess = $($_.AccessControlType.toString())
            } else {
                $objAccess = $($_.AuditFlags.toString())
            }
            $objFlags = $($_.ObjectFlags.toString())
            $objType = $($_.ObjectType.toString())
            $objIsInheried = $($_.IsInherited.toString())
            $objInheritedType = $($_.InheritedObjectType.toString())
            $objRights = $($_.ActiveDirectoryRights.toString())
            $objInheritanceType = $($_.InheritanceType.toString())

            $strConvRights = Convert-ActiveDirectoryRights -strADRights $objRights -objInheritanceType $objInheritanceType -objFlags $objFlags

            if($strConvRights) {
                $objRights = $strConvRights
            }

            if ($bolShowCriticalityColor) {
                $intCriticalityValue = Get-Criticality -Returns 'Color' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() 0

                Switch ($intCriticalityValue) {
                    0 {
                        $strLegendText = 'Info'; $strLegendColor = $strLegendColorInfo
                    }
                    1 {
                        $strLegendText = 'Low'; $strLegendColor = $strLegendColorLow
                    }
                    2 {
                        $strLegendText = 'Medium'; $strLegendColor = $strLegendColorMedium
                    }
                    3 {
                        $strLegendText = 'Warning'; $strLegendColor = $strLegendColorWarning
                    }
                    4 {
                        $strLegendText = 'Critical'; $strLegendColor = $strLegendColorCritical
                    }
                }
                $strLegendTextVal = $strLegendText
                if ($intCriticalityValue -gt $global:intShowCriticalityLevel) {
                    $global:intShowCriticalityLevel = $intCriticalityValue
                }
            }



            $IdentityReference = $($_.IdentityReference.toString())

            If ($IdentityReference.contains('S-1-')) {
                $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $IdentityReference -CREDS $CREDS

            } else {
                $strNTAccount = $IdentityReference
            }

            Switch ($strColorTemp) {

                '1' {
                    $strColor = 'DDDDDD'
                    $strColorTemp = '2'
                }
                '2' {
                    $strColor = 'AAAAAA'
                    $strColorTemp = '1'
                }
                '3' {
                    $strColor = 'FF1111'
                }
                '4' {
                    $strColor = '00FFAA'
                }
                '5' {
                    $strColor = 'FFFF00'
                }
            }# End Switch

            Switch ($objInheritanceType) {
                'All' {
                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 1K'
                        }

                    }# End Switch

                }
                'Descendents' {

                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$objRights"
                        }
                        'None' {
                            $strApplyTo = 'Child Objects Only'
                            $strPerm = "$objRights"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'Child Objects Only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo =	"$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm =	"$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 2K'
                        }

                    }
                }
                'None' {
                    Switch ($objFlags) {
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This Object Only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This Object Only'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 4K'
                        }

                    }
                }
                'SelfAndChildren' {
                    Switch ($objFlags) {
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'This object and all child objects within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = 'Children within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }

                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'This object and all child objects'
                            $strPerm = "$objRights"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 5K'
                        }

                    }
                }
                'Children' {
                    Switch ($objFlags) {
                        'InheritedObjectAceTypePresent' {
                            $strApplyTo = 'Children within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        'None' {
                            $strApplyTo = 'Children  within this container only'
                            $strPerm = "$objRights"
                        }
                        'ObjectAceTypePresent, InheritedObjectAceTypePresent' {
                            $strApplyTo = "$(if($bolTranslateGUID){$objInheritedType}else{MapGUIDToMatchingName -strGUIDAsString $objInheritedType -Domain $global:strDomainDNName -CREDS $CREDS})"
                            $strPerm = "$(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS}) $objRights"
                        }
                        'ObjectAceTypePresent' {
                            $strApplyTo = 'Children within this container only'
                            $strPerm = "$objRights $(if($bolTranslateGUID){$objType}else{MapGUIDToMatchingName -strGUIDAsString $objType -Domain $global:strDomainDNName -CREDS $CREDS})"
                        }
                        default {
                            $strApplyTo = 'Error'
                            $strPerm = 'Error: Failed to display permissions 6K'
                        }

                    }
                }
                default {
                    $strApplyTo = 'Error'
                    $strPerm = 'Error: Failed to display permissions 7K'
                }
            }# End Switch



            If ($Excel) {


                $objhashtableACE = [pscustomobject][ordered]@{
                    ObjectClass = $strObjectClass
                }

                if ($boolReplMetaDate) {
                    $objhashtableACE | Add-Member NoteProperty 'Security Descriptor Modified' $strReplMetaDate
                    $objhashtableACE | Add-Member NoteProperty 'Version' $strReplMetaVer
                }
                $objhashtableACE | Add-Member NoteProperty 'IdentityReference' $IdentityReference.toString()
                $objhashtableACE | Add-Member NoteProperty 'Trustee' $strNTAccount.toString()
                $objhashtableACE | Add-Member NoteProperty 'Access' $objAccess.toString()
                $objhashtableACE | Add-Member NoteProperty 'Inherited' $objIsInheried.toString()
                $objhashtableACE | Add-Member NoteProperty 'Apply To' $strApplyTo.toString()
                $objhashtableACE | Add-Member NoteProperty 'Permission' $strPerm.toString()

                if ($bolShowOUProtected) {
                    $objhashtableACE | Add-Member NoteProperty 'Inheritance Disabled' $bolOUProtected.toString()
                }

                if ($bolCriticalityLevel -eq $true) {
                    $objhashtableACE | Add-Member NoteProperty 'Criticality Level' $strLegendTextVal.toString()
                }

                if ($CompareMode) {
                    $objhashtableACE | Add-Member NoteProperty State $($_.State.toString())
                }

                [VOID]$global:ArrayAllACE.Add($objhashtableACE)
            }

            If ($HTM) {

                $strACLHTMLText = @"
$strACLHTMLText
<TR bgcolor="$strColor">
"@

                $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strObjectClass</TD>
"@

                if ($boolReplMetaDate -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
<TD>$strFont $strReplMetaVer</TD>
"@
                }

                $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont <a href="#web" onclick="GetGroupDN('$strNTAccount')">$strNTAccount</a></TD>
<TD>$strFont $objAccess</TD>
<TD>$strFont $objIsInheried </TD>
<TD>$strFont $strApplyTo</TD>
<TD $strLegendColor>$strFontRights $strPerm</TD>
"@


                if ($CompareMode) {

                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $($_.State.toString())</TD>
"@
                }
                if ($bolCriticalityLevel -eq $true) {
                    $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@

                }
            }#End If HTM
        }# End Foreach


    } else {
        if ($HTM) {
            if ($OUHeader -eq $false) {
                if ($FilterMode) {



                    if ($boolReplMetaDate -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
                    }

                    if ($boolACLSize -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
                    }

                    if ($bolShowOUProtected -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
                    }
                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Matching Permissions Set</TD>
"@



                    if ($bolCriticalityLevel -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
                    }
                } else {


                    if ($boolReplMetaDate -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strReplMetaDate</TD>
"@
                    }

                    if ($boolACLSize -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $strACLSize bytes</TD>
"@
                    }

                    if ($bolShowOUProtected -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont $bolOUPRotected </TD>
"@
                    }

                    $strACLHTMLText = @"
$strACLHTMLText
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont N/A</TD>
<TD>$strFont No Permissions Set</TD>
"@


                    if ($bolCriticalityLevel -eq $true) {
                        $strACLHTMLText = @"
$strACLHTMLText
<TD $strLegendColor>$strFont $strLegendTextVal</TD>
"@
                    }

                }# End If
            }#end If OUHeader false
        }#End if HTM
    } #End if bolACLExist
    if ($HTM) {
        $strACLHTMLText = @"
$strACLHTMLText
</TR>
"@

        #end ifelse OUHEader
        $strHTMLText = $strHTMLText + $strACLHTMLText

        Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout 
        Out-File -InputObject $strHTMLText -Append -FilePath $strFileHTM

        $strHTMLText = $null
        $strACLHTMLText = $null
        Remove-Variable -Name 'strHTMLText'
        Remove-Variable -Name 'strACLHTMLText'
    }#End if HTM

}

#==========================================================================
# Function		: Initialize-DefSDAccessHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function Initialize-DefSDAccessHTM {
    Param([string] $htmfileout,
        [string]$strStartingPoint,
        $RepMetaDate,
        [bool]$bolCompare,
        [string] $strComparefile,
        [bool]$bolCriticaltiy)

    $strACLTypeHeader = 'Access'
    If ($bolCompare) {
        $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor COMPARE REPORT - $($strStartingPoint.ToUpper())</h1>
<h3 style="color: #191010;text-align: center;">
Template: $strComparefile
</h3>
"@
    } else {
        $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor REPORT - $($strStartingPoint.ToUpper())</h1>
"@
    }

    $strHTMLText = @"
$strHTMLText
<TABLE BORDER=1>
"@
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@
    $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH ObjectClass</font></th>
"@
    if ($RepMetaDate -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Security Descriptor Modified</font>
<th bgcolor="$strTHColor">$strFontTH Version</font>
"@
    }
    $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Trustee</font></th><th bgcolor="$strTHColor">$strFontTH $strACLTypeHeader</font></th><th bgcolor="$strTHColor">$strFontTH Inherited</font></th><th bgcolor="$strTHColor">$strFontTH Apply To</font></th><th bgcolor="$strTHColor">$strFontTH Permission</font></th>
"@


    if ($bolCompare -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH State</font></th>
"@
    }

    if ($bolCriticaltiy -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Criticality Level</font></th>
"@
    }

    Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout
    $strHTMLText = $null
    $strTHOUColor = $null
    $strTHColor = $null
    Remove-Variable -Name 'strHTMLText'
    Remove-Variable -Name 'strTHOUColor'
    Remove-Variable -Name 'strTHColor'


}

#==========================================================================
# Function		: InitiateHTM
# Arguments     : Output htm file
# Returns   	: n/a
# Description   : Wites base HTM table syntax, it appends info if the file exist
#==========================================================================
Function InitiateHTM {
    Param([string] $htmfileout, [string]$strStartingPoint, [string]$strDN, [bool]$RepMetaDate , [bool]$ACLSize, [bool]$bolACEOUProtected, [bool]$bolCriticaltiy, [bool]$bolCompare, [bool]$SkipDefACE, [bool]$SkipProtectDelACE, [string]$strComparefile, [bool]$bolFilter, [bool]$bolEffectiveRights, [bool]$bolObjType, [bool]$bolCanonical, [bool]$GPO, [bool]$SDDL)
    
    $bolObjType = $true
    
    If ($rdbSACL.IsChecked) {
        $strACLTypeHeader = 'Audit'
    } else {
        $strACLTypeHeader = 'Access'
    }
    If ($bolCompare) {
        $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">COMPARE REPORT - $($strStartingPoint.ToUpper())</h1>
<h3 style="color: #191010;text-align: center;">
Template: $strComparefile
</h3>
"@
    } else {
        If ($bolFilter) {
            $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">FILTERED REPORT - $($strStartingPoint.ToUpper())</h1>
"@
        } else {
            If ($bolEffectiveRights) {

                $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">EFFECTIVE RIGHTS REPORT <br>
Service Principal: $($global:strEffectiveRightAccount.ToUpper())</h1>
"@
            } else {
                $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">ACL REPORT - $($strStartingPoint.ToUpper())</h1>
"@
            }
        }
    }
    If ($bolCriticaltiy) {
        $strHTMLText = @"
$strHTMLText
<div style="text-align: center;font-weight: bold}">
<FONT size="6"  color= "#79A0E0">Highest Criticality Level:</FONT> 20141220T021111056594002014122000</FONT>
</div>
"@
    }
    $strHTMLText = @"
$strHTMLText
<h3 style="color: #191010;text-align: center;">$strDN<br>
Report Created: $(Get-Date -UFormat '%Y-%m-%d %H:%M:%S')</h3>
"@
    If ($SkipDefACE) {
        $strHTMLText = @"
$strHTMLText
<h3 style="color: #191010;text-align: center;">Default permissions excluded</h3>
"@
    }
    If ($SkipProtectDelACE) {
        $strHTMLText = @"
$strHTMLText
<h3 style="color: #191010;text-align: center;">Protected against accidental deletions permissions excluded</h3>
"@
    }
    $strHTMLText = @"
$strHTMLText
<TABLE BORDER=1>
"@
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@

    if ($GPO) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH GPO</font>
"@
    }

    $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Object</font></th>
"@

    if ($bolCanonical -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH CanonicalName</font>
"@
    }

    if ($bolObjType -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH ObjectClass</font>
"@
    }
    if ($RepMetaDate -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Security Descriptor Modified</font>
"@
    }
    if ($ACLSize -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH DACL Size</font>
"@
    }
    if ($bolACEOUProtected -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Inheritance Disabled</font>
"@
    }
    if ($SDDL) {
        $strHTMLText = @"
$strHTMLText
</th><th bgcolor="$strTHColor">$strFontTH SDDL</font></th>
"@
    } else {
        $strHTMLText = @"
$strHTMLText
</th><th bgcolor="$strTHColor">$strFontTH Trustee</font></th><th bgcolor="$strTHColor">$strFontTH $strACLTypeHeader</font></th><th bgcolor="$strTHColor">$strFontTH Inherited</font></th><th bgcolor="$strTHColor">$strFontTH Apply To</font></th><th bgcolor="$strTHColor">$strFontTH Permission</font></th>
"@
    }
    if ($bolCompare -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH State</font></th>
"@
    }


    if ($bolCriticaltiy -eq $true) {
        $strHTMLText = @"
$strHTMLText
<th bgcolor="$strTHColor">$strFontTH Criticality Level</font></th>
"@
    }



    Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout
    $strHTMLText = $null
    $strTHOUColor = $null
    $strTHColor = $null
    Remove-Variable -Name 'strHTMLText'
    Remove-Variable -Name 'strTHOUColor'
    Remove-Variable -Name 'strTHColor'


}

#==========================================================================
# Function		: CreateHTA
# Arguments     : OU Name, Ou put HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateHTA {
    Param([string]$NodeName, [string]$htafileout, [string]$htmfileout, [string] $folder, [string] $strDomainDN, [string] $strDC)
    $strHTAText = @"
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
		    strGroupMemberList = "<TR "&strBGColor&"><TD>" & objMember.Get("samAccountName") & "</TD><TD>" & objMember.Get("distinguishedname") & "</TD></TR>"
	    Else
		    If strBGColor = strBG1 Then
			    strBGColor = strBG2
		    Else
			    strBGColor = strBG1
		    End If
	    strGroupMemberList = strGroupMemberList & vbCrlf & "<TR "&strBGColor&"><TD>" & objMember.Get("samAccountName") & "</TD><TD>" & objMember.Get("distinguishedname") & "</TD></	TR>"
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
function WriteSPNHTM {
    Param([string] $strSPN, $tokens, [string]$objType, [int]$intMemberOf, [string] $strColorTemp, [string] $htafileout, [string] $htmfileout)
    #$strHTMLText ="<TABLE BORDER=1>"
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@

    $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $strSPN</b><TD><b>$strFontOU $objType</b><TD><b>$strFontOU $intMemberOf</b></TR>
"@
    $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHColor"><TD><b>$strFontTH Groups</b></TD><TD></TD><TD></TD></TR>
"@


    $tokens | ForEach-Object {
        If ($_.contains('S-1-')) {
            $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $_ -CREDS $CREDS

        }
        if ($($strNTAccount.toString()) -ne $strSPN) {
            Switch ($strColorTemp) {

                '1' {
                    $strColor = 'DDDDDD'
                    $strColorTemp = '2'
                }
                '2' {
                    $strColor = 'AAAAAA'
                    $strColorTemp = '1'
                }
                '3' {
                    $strColor = 'FF1111'
                }
                '4' {
                    $strColor = '00FFAA'
                }
                '5' {
                    $strColor = 'FFFF00'
                }
            }# End Switch
            $strGroupText = $strGroupText + @"
<TR bgcolor="$strColor"><TD>
$strFont $($strNTAccount.toString())</TD></TR>
"@
        }
    }
    $strHTMLText = $strHTMLText + $strGroupText


    Out-File -InputObject $strHTMLText -Append -FilePath $htafileout
    Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout

    $strHTMLText = ''

}

#==========================================================================
# Function		: WriteDefSDSDDLHTM
# Arguments     : Security Principal Name,  Output htm file
# Returns   	: n/a
# Description   : Wites the account membership info to a HTM table, it appends info if the file exist
#==========================================================================
function WriteDefSDSDDLHTM {
    Param([string] $strColorTemp, [string] $htafileout, [string] $htmfileout, [string]$strObjectClass, [string]$strDefSDVer, [string]$strDefSDDate, [string]$strSDDL)
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@

    $strHTMLText = @"
$strHTMLText
<TR bgcolor="$strTHOUColor"><TD><b>$strFontOU $strObjectClass</b>
<TD><b>$strFontOU $strDefSDVer</b>
<TD><b>$strFontOU $strDefSDDate</b>
"@




    $strHTMLText = @"
$strHTMLText
</TR>
"@

    Switch ($strColorTemp) {

        '1' {
            $strColor = 'DDDDDD'
            $strColorTemp = '2'
        }
        '2' {
            $strColor = 'AAAAAA'
            $strColorTemp = '1'
        }
        '3' {
            $strColor = 'FF1111'
        }
        '4' {
            $strColor = '00FFAA'
        }
        '5' {
            $strColor = 'FFFF00'
        }
    }# End Switch

    $strGroupText = $strGroupText + @"
<TR bgcolor="$strColor"><TD> $strFont $strObjectClass</TD><TD> $strFont $strDefSDVer</TD><TD> $strFont $strDefSDDate</TD><TD> $strFont $strSDDL</TD></TR>
"@


    $strHTMLText = $strHTMLText + $strGroupText


    Out-File -InputObject $strHTMLText -Append -FilePath $htafileout
    Out-File -InputObject $strHTMLText -Append -FilePath $htmfileout

    $strHTMLText = ''

}

#==========================================================================
# Function		: CreateDefaultSDReportHTA
# Arguments     : Forest Name, Output HTA file
# Returns   	: n/a
# Description   : Initiates a base HTA file with Export(Save As),Print and Exit buttons.
#==========================================================================
function CreateDefaultSDReportHTA {
    Param([string]$Forest, [string]$htafileout, [string]$htmfileout, [string] $folder)
    $strHTAText = @"
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
strFile=SaveAs("$($Forest.Split('\')[-1]).htm",strOutputFolder)
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
function CreateDefSDHTM {
    Param([string]$SPN, [string]$htmfileout)
    $strHTAText = @"
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
Function InitiateDefSDHTM {
    Param([string] $htmfileout, [string] $strStartingPoint)
    $strHTMLText = @"
<h1 style="color: #79A0E0;text-align: center;">Default Security Descriptor REPORT - $($strStartingPoint.ToUpper())</h1>
"@
    $strHTMLText = $strHTMLText + '<TABLE BORDER=1>'
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@


    $strHTMLText = @"
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
function CreateServicePrincipalReportHTA {
    Param([string]$SPN, [string]$htafileout, [string]$htmfileout, [string] $folder)
    $strHTAText = @"
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
strFile=SaveAs("$($SPN.Split('\')[-1]).htm",strOutputFolder)
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
function CreateSPNHTM {
    Param([string]$SPN, [string]$htmfileout)
    $strHTAText = @"
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
Function InitiateSPNHTM {
    Param([string] $htmfileout)
    $strHTMLText = '<TABLE BORDER=1>'
    $strTHOUColor = 'E5CF00'
    $strTHColor = 'EFAC00'
    $strFont = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontOU = @'
<FONT size="1" face="verdana, hevetica, arial">
'@
    $strFontTH = @'
<FONT size="2" face="verdana, hevetica, arial">
'@


    $strHTMLText = @"
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
function CreateHTM {
    Param([string]$NodeName, [string]$htmfileout)
    $strHTAText = @"
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
function Select-File {
    param (
        [System.String]$Title = 'Select Template File',
        [System.String]$InitialDirectory = $CurrentFSPath,
        [System.String]$Filter = 'All Files(*.csv)|*.csv'
    )

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = $filter
    $dialog.InitialDirectory = $initialDirectory
    $dialog.ShowHelp = $true
    $dialog.Title = $title
    $result = $dialog.ShowDialog()

    if ($result -eq 'OK') {
        return $dialog.FileName
    } else {
        return ''

    }
}
#==========================================================================
# Function		: Select-Folder
# Arguments     : n/a
# Returns   	: folder path
# Description   : Dialogbox for selecting a folder
#==========================================================================
function Select-Folder {
    Param($message = 'Select a folder', $path = 0)
    $object = New-Object -ComObject Shell.Application

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
Function Get-Perm {
    Param(
        #Array of distinguishedNames
        [System.Collections.ArrayList]
        $AllObjectDn,
        #Domain NetBiosName
        [string]
        $DomainNetbiosName,
        #If inherited permissions should be included
        $IncludeInherited,
        [boolean]
        #If default permissions should be ignored
        $SkipDefaultPerm,
        [boolean]
        #If protected object permissions should be ignored
        $SkipProtectedPerm,
        [boolean]
        #Retrieve the Owner
        $bolGetOwnerEna,
        [boolean]
        #Get replication meta data
        [boolean]
        $bolReplMeta,
        #Get the size of the DACL
        [boolean]
        $bolACLsize,
        #Perform a effictive permissions check
        [boolean]
        $bolEffectiveR,
        #Show if the OU is protected from inheritance
        [boolean]
        $bolGetOUProtected,
        #Convert GUIDs to names
        [boolean]
        $bolGUIDtoText,
        #Show the result
        [boolean]
        $Show,
        #The ouput type of the result
        [string]
        $OutType,
        #If the result should be written to a file
        [boolean]
        $bolToFile,
        #if criticality level have been selected
        [boolean]
        $bolAssess,
        #the criticality level selected
        [string]
        $AssessLevel,
        #Display the colors of the criticality level
        [boolean]
        $bolShowCriticalityColor,
        #Scan GPO
        [boolean]
        $GPO,
        #Skipt built-in groups
        [boolean]
        $FilterBuiltin,
        #Translate the GUID
        [boolean]
        $TranslateGUID,
        #Search every nested group
        [boolean]
        $RecursiveFind,
        #Return this type of objects when searching nested groups
        [string]
        $RecursiveObjectType,
        #Permissiosn that apply to this type of object
        [string]
        $ApplyTo,
        #Permissiosn that apply to this type of property
        [string]
        $PropertyFilter,
        #Filter a trustee string
        [string]
        $FilterTrustee,
        #Filter for Allow of Deny
        [string]
        $AccessType,
        #Permissions to filter
        [string]
        $ACLPermissionFilter,
        #Added credentials
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS,
        #Retrun only objects of a this type
        [string]
        $ReturnObjectType,
        #If a object type have been selected
        [boolean]
        $SDDL,
        #Get Discretionary ACL (DACL)
        [boolean]
        $DACL = $true

    )


    $bolCompare = $false
    $bolACLExist = $true
    $global:strOwner = ''
    $strACLSize = ''
    $bolOUProtected = $false
    $aclcount = 0
    $sdOUProtect = ''
    $global:ArrayAllACE = New-Object System.Collections.ArrayList

    if (($OutType -eq 'EXCEL') -or ($OutType -eq 'CSV')) {
        $OutputFormat = 'Object'
    } else {
        $OutputFormat = 'HTML'
    }
    if (($OutType -eq 'CSVTEMPLATE') -or ($OutType -eq 'CSV')) {
        $bolCSV = $true
        If ((Test-Path $strFileCSV) -eq $true) {
            Remove-Item $strFileCSV
        }
    } else {
        $bolCSV = $false
    }


    $count = 0
    $i = 0
    $intCSV = 0
    if ($global:bolCMD) {
        $intTot = 0
        #calculate percentage
        $intTot = $AllObjectDn.count
    } else {
        if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
            $intTot = 0
            #calculate percentage
            $intTot = $AllObjectDn.count
            if ($intTot -gt 0) {
                LoadProgressBar

            }
        }
    }

    # If objecttype or InheritedObjectType is used get all guids
    if(($ApplyTo.Length -gt 0) -or ($PropertyFilter.Length -gt 0))
    {
        GetSchemaObjectGUID -Domain $global:strDomainDNName -CREDS $CREDS
    }

    while ($count -le $AllObjectDn.count - 1) {
        if ($GPO) {
            $ADObjDN = $AllObjectDn[$count].Split(';')[0]
            $GPOTarget = $AllObjectDn[$count].Split(';')[1]
            if ($GPO) {

                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $request = New-Object System.directoryServices.Protocols.SearchRequest
                $request.DistinguishedName = $ADObjDN
                $request.Filter = '(objectClass=*)'
                $request.Scope = 'Base'
                [void]$request.Attributes.Add('displayname')
                $response = $LDAPConnection.SendRequest($request)
                $result = $response.Entries[0]
                try {
                    $GPOdisplayname = $result.attributes.displayname[0]
                } catch {
                }
            }
        } else {
            $ADObjDN = $($AllObjectDn[$count])
        }
        $global:secd = ''
        $bolACLExist = $true
        $global:GetSecErr = $false
        if (($global:bolCMD) -and ($global:bolProgressBar)) {

            $i++
            [int]$pct = ($i / $intTot) * 100
            Write-Progress -Activity 'Collecting objects' -Status "Currently scanning $i of $intTot objects" -Id 0 -CurrentOperation "Reading ACL on: $ADObjDN" -PercentComplete $pct
        } else {
            if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                $i++
                [int]$pct = ($i / $intTot) * 100
                #Update the progress bar

                while (($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20)) {
                    Start-Sleep -Milliseconds 1
                    $cc++
                }
                if ($global:ProgressBarWindow.Window.IsInitialized -eq $true) {
                    Update-ProgressBar "Currently scanning $i of $intTot objects" $pct
                }

            }
        }

        $sd = New-Object System.Collections.ArrayList
        $GetOwnerEna = $bolGetOwnerEna

        $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
        $request = New-Object System.directoryServices.Protocols.SearchRequest("$ADObjDN", '(name=*)', 'base')
        if ($global:bolShowDeleted) {
            [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
            [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
        }
        [void]$request.Attributes.Add('objectclass')
        if ($UseCanonicalName) {
            [void]$request.Attributes.Add('canonicalname')
        }
        [void]$request.Attributes.Add('ntsecuritydescriptor')



        if ($DACL -eq $True) {
            $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
            $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
            [void]$request.Controls.Add($control)
            $response = $LDAPConnection.SendRequest($request)
            $DSobject = $response.Entries[0]
            #Check if any NTsecuritydescr
            if ($null -ne $DSobject.Attributes.ntsecuritydescriptor) {
                if ($null -ne $DSobject.Attributes.objectclass) {
                    $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count - 1]
                } else {
                    $strObjectClass = 'unknown'
                }
                if ($SDDL) {
                    [string]$strSDDL = ''
                    $objSd = $DSobject.Attributes.ntsecuritydescriptor[0]
                    if ($objSD -is [Byte[]]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd, 0)
                    } elseif ($objSD -is [string]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd)
                    }

                    if (!($IncludeInherited)) {
                        $arrSDDL = @(($SDDLSec.GetSddlForm('Access,Owner')).split(')') | Where-Object { $_ -notmatch 'ID;' })
                        if ($arrSDDL.count -gt 0) {
                            for ($IntCount = 0; $IntCount -lt $($arrSDDL.count - 1); $IntCount++) {
                                $strSDDL += "$($arrSDDL[$IntCount]))"
                            }
                        }
                    } else {
                        $strSDDL = $SDDLSec.GetSddlForm('Access,Owner')
                    }

                }
                $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                if ($chkBoxRAWSDDL.IsChecked) {
                    $secSDDL = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $objSd = $DSobject.Attributes.ntsecuritydescriptor[0]
                    if ($objSD -is [Byte[]]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd, 0)
                    } elseif ($objSD -is [string]) {
                        $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd)
                    }
                    $strSDDLForm = $SDDLSec.GetSddlForm('Access,Owner')

                    $arrSplitedSDDL = $strSDDLForm.Split('(')
                    $intI = 0
                    Foreach ($strSDDLPart in $arrSplitedSDDL) {
                        if ($intI -gt 0) {
                            if ($sec.Owner -eq $null) {
                                $sec.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                            } else {
                                if (!($IncludeInherited)) {
                                    if (($strSDDLPart.split(';')[1] -ne 'CIID') -and ($strSDDLPart.split(';')[1] -ne 'CIIOID')) {
                                        $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                        $sd = $secSDDL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                                        $sec.AddAccessRule($sd[0])
                                    }
                                } else {
                                    $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                    $sd = $secSDDL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                                    $sec.AddAccessRule($sd[0])
                                }
                            }
                        }
                        $intI++
                    }
                } else {
                    $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
                }

                & { #Try
                    $global:secd = $sec.GetAccessRules($true, $IncludeInherited, [System.Security.Principal.SecurityIdentifier])

                }
                Trap [SystemException] {
                    if ($bolCMD) {
                        Write-Host "Failed to translate identity:$ADObjDN" -ForegroundColor red
                    } else {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                    }
                    $global:GetSecErr = $true
                    Continue
                }

            } else {
                #Fail futher scan when NTsecurityDescriptor is null
                $global:GetSecErr = $true
            }
        } else {
            $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
            $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
            [void]$request.Controls.Add($control)
            $response = $LDAPConnection.SendRequest($request)
            $DSobject = $response.Entries[0]
            if ($null -ne $DSobject.Attributes.objectclass) {
                $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count - 1]
            } else {
                $strObjectClass = 'unknown'
            }
            $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
            & { #Try
                $global:secd = $sec.GetAuditRules($true, $IncludeInherited, [System.Security.Principal.SecurityIdentifier])
            }
            Trap [SystemException] {
                if ($bolCMD) {
                    Write-Host "Failed to translate identity:$ADObjDN" -ForegroundColor red
                } else {
                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                }
                $global:GetSecErr = $true
                Continue
            }
        }

        if (($global:GetSecErr -ne $true) -or ($global:secd -ne '')) {
            $sd.clear()
            if ($null -ne $global:secd) {
                $(ConvertTo-ObjectArrayListFromPsCustomObject $global:secd) | ForEach-Object { [void]$sd.add($_) }
            }
            If ($GetOwnerEna -eq $true) {

                & { #Try
                    $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                }

                Trap [SystemException] {
                    if ($global:bolADDSType) {
                        if ($bolCMD) {
                            Write-Host "Failed to translate owner identity:$ADObjDN" -ForegroundColor red
                        } else {
                            $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                        }
                    }
                    Continue
                }

                $newSdOwnerObject = New-Object PSObject -Property @{ActiveDirectoryRights = 'Read permissions, Modify permissions'; InheritanceType = 'None'; ObjectType = 'None'; `
                        InheritedObjectType = 'None'; ObjectFlags = 'None'; AccessControlType = 'Owner'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                        InheritanceFlags = 'None'; PropagationFlags = 'None'
                }

                [void]$sd.insert(0, $newSdOwnerObject)

            }
            If ($SkipDefaultPerm) {
                If ($GetOwnerEna -eq $false) {

                    & { #Try
                        $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                    }

                    Trap [SystemException] {
                        if ($bolCMD) {
                            Write-Host "Failed to translate owner identity:$ADObjDN" -ForegroundColor red
                        } else {
                            $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType 'Error' -DateStamp ))
                        }
                        Continue
                    }
                }

            }

            if ($bolACLsize -eq $true) {
                $strACLSize = $sec.GetSecurityDescriptorBinaryForm().length
            }
            if ($bolGetOUProtected -eq $true) {
                $bolOUProtected = $sec.AreAccessRulesProtected
            }

            if ($bolReplMeta -eq $true) {

                $objACLMeta = $(Get-ACLMeta  $global:strDC $ADObjDN -CREDS $CREDS)
                $objLastChange = $objACLMeta.LastChangeDate
                $strOrigInvocationID = $objACLMeta.InvocationID
                $strOrigUSN = $objACLMeta.OriginatingChange
                $strVersion = $objACLMeta.Version
            }


            If ((($AccessType.Length -gt 0) -or ($ApplyTo.Length -gt 0) -or ($PropertyFilter.Length -gt 0) -or ($ACLPermissionFilter.Length -gt 0)) -and ($bolEffectiveR -eq $false)) {

                # Check Allow or Deny
                If ($AccessType) {
                    if ($AccessType.Length -gt 0) {
                        $sd = @($sd | Where-Object { $_.AccessControlType -eq $AccessType })
                    }
                }

                
                # Check for apply to
                If ($ApplyTo) {
                    if ($ApplyTo.Length -gt 0) {
                        if ($ApplyTo.Split('|').Count -gt 1 ) {
                            [System.Collections.ArrayList]$arryApplyTo = $ApplyTo.Split('|')
                            if ($arryApplyTo -contains '*') {
                                $arryApplyTo.Remove('*')
                            }
                            $ApplyToString = ''
                            For ($i = 0 ; $i -lt $arryApplyTo.count ; $i++) {
                                if ($i -eq $arryApplyTo.count - 1) {
                                    $ApplyToString += $global:dicNameToSchemaIDGUIDs.Item($arryApplyTo[$i])
                                } else {
                                    $ApplyToString += $global:dicNameToSchemaIDGUIDs.Item($arryApplyTo[$i]) + '|'
                                }

                            }
                            if ($ApplyTo.Split('|') -contains '*') {
                                $sd = @($sd | Where-Object { (($_.ObjectType -match $ApplyToString) -or ($_.InheritedObjectType -match $ApplyToString)) -or (($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') -and ($_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000')) })
                            } else {
                                $sd = @($sd | Where-Object { ($_.ObjectType -match $ApplyToString) -or ($_.InheritedObjectType -match $ApplyToString) })
                            }

                        } else {
                            if ($ApplyTo -contains '*') {
                                $sd = @($sd | Where-Object { (($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') -and ($_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000')) })
                            } else {
                                $sd = @($sd | Where-Object { ($_.ObjectType -eq $global:dicNameToSchemaIDGUIDs.Item($ApplyTo)) -or ($_.InheritedObjectType -eq $global:dicNameToSchemaIDGUIDs.Item($ApplyTo)) })
                            }
                        }
                    }
                }


                # Check for properties
                If ($PropertyFilter) {
       
                    if ($PropertyFilter.Length -gt 0) {
                        if ($PropertyFilter.Split('|').Count -gt 1 ) {
                            [System.Collections.ArrayList]$arrProperty = $PropertyFilter.Split('|')
                            if ($arrProperty -contains '*') {
                                $arrProperty.Remove('*')
                            }
                            $PropertyString = ''
                            For ($i = 0 ; $i -lt $arrProperty.count ; $i++) {
                                $value = $null

                                # First try the schema GUID dictionary
                                if ($global:dicNameToSchemaIDGUIDs.ContainsKey($arrProperty[$i])) {
                                    $value = $global:dicNameToSchemaIDGUIDs[$arrProperty[$i]]
                                }
                                else {
                                    # Fallback to reverse lookup in rights GUIDs
                                    $value = ($global:dicRightsGuids.GetEnumerator() | Where-Object { $_.Value -eq $arrProperty[$i] }).Key
                                }

                                if ($value) {
                                     
                                    if ($i -eq $arrProperty.count - 1) {
                                        $PropertyString += $value
                                    } else {
                                        $PropertyString += $value + '|'
                                    }
                                }      

                            }
                            if ($PropertyFilter.Split('|') -contains '*') {
                                $sd = @($sd | Where-Object { (($_.ObjectType -match $PropertyString) -or ($_.InheritedObjectType -match $PropertyString)) -or (($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') -and ($_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000')) })
                            } else {
                                $sd = @($sd | Where-Object { ($_.ObjectType -match $PropertyString) -or ($_.InheritedObjectType -match $PropertyString) })
                            }

                        } else {
                            if ($PropertyFilter -contains '*') {
                                $sd = @($sd | Where-Object { (($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') -and ($_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000')) })
                            } else {
                                # First try the schema GUID dictionary
                                if ($global:dicNameToSchemaIDGUIDs.ContainsKey($PropertyFilter)) {
                                    $value = $global:dicNameToSchemaIDGUIDs[$PropertyFilter]
                                }
                                else {
                                    # Fallback to reverse lookup in rights GUIDs
                                    $value = ($global:dicRightsGuids.GetEnumerator() | Where-Object { $_.Value -eq $PropertyFilter }).Key
                                }

                                if ($value) {
                                    $PropertyFilter = $value
                                }
                                $sd = @(
                                    $sd | Where-Object { ($_.ObjectType -eq $PropertyFilter) -or ($_.InheritedObjectType -eq $PropertyFilter) })
                            }
                        }
                    }
                }

                # Check for permissions
                If ($ACLPermissionFilter) {
                    if ($ACLPermissionFilter.Length -gt 0) {
                        $sd = @($sd | Where-Object { $_.ActiveDirectoryRights -match $ACLPermissionFilter })
                    }
                }
                

            }

            if ($FilterBuiltin) {
                # Filter out default and built-in security principals
                $sd = @($sd | Where-Object {`
                        ($_.IdentityReference -match 'S-1-5-21-') -and `
                        ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^5\d{2}$')) -and
            ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^4\d{2}$'))
                    })
            }

            if ($RecursiveFind) {
                $RecursiveData = New-Object System.Collections.ArrayList
                foreach ($ace in $sd) {
                    [Void]$RecursiveData.add($ace)
                    $SID_DN = ''

                    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                    $request = New-Object System.directoryServices.Protocols.SearchRequest
                    $request.DistinguishedName = "<SID=$($ace.IdentityReference)>"
                    $request.Filter = '(name=*)'
                    $request.Scope = 'Base'
                    [void]$request.Attributes.Add('objectClass')
                    [void]$request.Attributes.Add('member')

                    try {
                        $response = $LDAPConnection.SendRequest($request)
                        $result = $response.Entries[0]
                        $SID_DN = $result.distinguishedName
                        $ObjectClass = $result.attributes.objectclass[$result.attributes.objectclass.count - 1]
                    } catch {
                        Write-Verbose "Could not resolve $sid"
                    }

                    if ($SID_DN) {
                        if ($ObjectClass -eq 'Group') {
                            if (($result.Attributes.AttributeNames -contains 'member;range=0-1499') -or ($result.Attributes.AttributeNames -contains 'member')) {
                                $global:GroupMembersExpanded = New-Object System.Collections.ArrayList
                                $NetstedResult = Get-LargeNestedADGroup $global:strDC $SID_DN $RecursiveObjectType -CREDS $CREDS
                                if ($NetstedResult) {
                                    foreach ($NestedObject in $NetstedResult) {

                                        $LDAPConnection = Connect-SecureLDAP -Server $strDC -Credential $CREDS
                                        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                                        $request = New-Object System.directoryServices.Protocols.SearchRequest
                                        $request.DistinguishedName = $NestedObject
                                        $request.Filter = '(name=*)'
                                        $request.Scope = 'Base'
                                        [void]$request.Attributes.Add('objectsid')
                                        [void]$request.Attributes.Add('msds-principalname')

                                        $response = $LDAPConnection.SendRequest($request)
                                        $ADObject = $response.Entries[0]

                                        $recursiveobject = New-Object psobject
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'IdentityReference' -Value $(try {
                                                GetSidStringFromSidByte $ADObject.attributes.objectsid.GetValues([byte[]])[0]
                                            } catch {
                                            })
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'ActiveDirectoryRights' -Value $ace.ActiveDirectoryRights
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'InheritanceType' -Value $ace.InheritanceType
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'ObjectType' -Value $ace.ObjectType
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'InheritedObjectType' -Value $ace.InheritedObjectType
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'ObjectFlags' -Value $ace.ObjectFlags
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'AccessControlType' -Value $ace.AccessControlType
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'IsInherited' -Value $ace.IsInherited
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'InheritanceFlags' -Value $ace.InheritanceFlags
                                        Add-Member -InputObject $recursiveobject -MemberType NoteProperty -Name 'PropagationFlags' -Value $ace.PropagationFlags
                                        [Void]$RecursiveData.add($recursiveobject)
                                        $recursiveobject = $null
                                    }
                                }
                            }

                        }

                    }

                }
                $SD = $RecursiveData | Sort-Object -Property InheritedObjectType, ObjectType, IdentityReference, ObjectFlags, ActiveDirectoryRights -Unique
                $RecursiveData = $null
            }
            
            If (($FilterTrustee -eq $true) -and ($bolEffectiveR -eq $false)) {
                if ($FilterTrustee.Length -gt 0) {
                    $sd = @($sd | Where-Object { if ($_.IdentityReference -like 'S-1-*') {
`
                                $(Convert-SidToName -server $global:strDomainFQDN -Sid $_.IdentityReference -CREDS $CREDS) -like $FilterTrustee
                            }`
                                else {
                                $_.IdentityReference -like $FilterTrustee
                            } })

                }
            }

            if ($ReturnObjectType) {
                if ($ReturnObjectType -ne '*') {
                    $sd = @($sd | Where-Object { (Get-ObjectTypeFromSid -server $global:strDC -Sid $_.IdentityReference.toString() -CREDS $CREDS) -eq $ReturnObjectType })
                }
            }


            If ($bolAssess) {
                Switch ($AssessLevel) {
                    'Info' {
                        $CriticalityFilter = 0
                    }
                    'Low' {
                        $CriticalityFilter = 1
                    }
                    'Medium' {
                        $CriticalityFilter = 2
                    }
                    'Warning' {
                        $CriticalityFilter = 3
                    }
                    'Critical' {
                        $CriticalityFilter = 4
                    }
                }
                $sd = @($sd | Where-Object { Get-Criticality -Returns 'Filter' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() $CriticalityFilter })
            }

            if ($bolEffectiveR -eq $true) {

                if ($global:tokens.count -gt 0) {

                    $sdtemp2 = New-Object System.Collections.ArrayList

                    if ($global:strPrincipalDN -eq $ADObjDN) {
                        $sdtemp = ''
                        $sdtemp = $sd | Where-Object { $_.IdentityReference -eq 'S-1-5-10' }
                        if ($sdtemp) {
                            [void]$sdtemp2.Add( $sdtemp)
                        }
                    }
                    foreach ($tok in $global:tokens) {

                        $sdtemp = ''
                        $sdtemp = $sd | Where-Object { $_.IdentityReference -eq $tok }
                        if ($sdtemp) {
                            [void]$sdtemp2.Add( $sdtemp)
                        }


                    }
                    $sd = $sdtemp2
                }

            }
            $intSDCount = $sd.count

            if (!($null -eq $sd)) {
                $index = 0
                $permcount = 0

                if ($intSDCount -gt 0) {
                    if ($SDDL) {
                        $sd = @($sd[0])
                    }
                    while ($index -le $sd.count - 1) {
                        if ($GPO) {
                            $strDistinguishedName = $GPOTarget
                        } else {
                            $strDistinguishedName = $DSobject.distinguishedname.toString()
                        }
                        $bolMatchDef = $false
                        $bolMatchprotected = $false
                        if ($UseCanonicalName) {
                            if ($DSobject.attributes.canonicalname) {
                                $CanonicalName = $DSobject.attributes.canonicalname[0]
                            } else {
                                $CanonicalName = Create-CanonicalName $DSobject.distinguishedname.toString()
                            }
                        }
                        $strNTAccount = $sd[$index].IdentityReference.ToString()
                        If ($strNTAccount.contains('S-1-')) {
                            $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strNTAccount -CREDS $CREDS
                        }
                        #Remove Default Permissions if SkipDefaultPerm selected
                        if($SkipDefaultPerm -and (-not($SDDL))) {
                            if ($strObjectClass -ne $strTemoObjectClass) {
                                $sdOUDef = Get-DefaultPermissions -strObjectClass $strObjectClass -CREDS $CREDS
                            }
                            $strTemoObjectClass = $strObjectClass
                            $indexDef = 0
                            while ($indexDef -le $sdOUDef.count - 1) {
                                if (($sdOUDef[$indexDef].IdentityReference -eq $sd[$index].IdentityReference) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sd[$index].ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sd[$index].AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sd[$index].ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sd[$index].InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sd[$index].InheritedObjectType)) {
                                    $bolMatchDef = $true
                                } #End If
                                $indexDef++
                            } #End While
                        }

                        if ($bolMatchDef) {
                        } else {
                            #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                            if($SkipProtectedPerm -and (-not($SDDL))) {
                                if ($sdOUProtect -eq '') {
                                    $sdOUProtect = Get-ProtectedPerm
                                }
                                $indexProtected = 0
                                while ($indexProtected -le $sdOUProtect.count - 1) {
                                    if (($sdOUProtect[$indexProtected].IdentityReference -eq $sd[$index].IdentityReference) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sd[$index].ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sd[$index].AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sd[$index].ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sd[$index].InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sd[$index].InheritedObjectType)) {
                                        $bolMatchprotected = $true
                                    }#End If
                                    $indexProtected++
                                } #End While
                            }

                            if ($bolMatchprotected) {
                            } else {
                                If ($bolCSV) {
                                    $intCSV++

                                    if ($OutType -eq 'CSVTEMPLATE') {
                                        Write-PermCSV $sd[$index] $strDistinguishedName $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $false $bolToFile $GPO $GPOdisplayname $TranslateGUID -CREDS $CREDS
                                    } else {
                                        $bolOUHeader = $false
                                        Write-ToFile -bolACLExist $bolACLExist -sd $sd[$index] -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp $strColorTemp -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor 
                                    }

                                }# End If
                                Else {
                                    If ($strColorTemp -eq '1') {
                                        $strColorTemp = '2'
                                    }# End If
                                    else {
                                        $strColorTemp = '1'
                                    }# End If
                                    if ($permcount -eq 0) {
                                        $bolOUHeader = $true
                                        Write-ToFile -bolACLExist $bolACLExist -sd $sd[$index] -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp $strColorTemp -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor 

                                    } else {
                                        $bolOUHeader = $false
                                        Write-ToFile -bolACLExist $bolACLExist -sd $sd[$index] -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp $strColorTemp -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor

                                    }# End If
                                }
                                $aclcount++
                                $permcount++
                            }# End If SkipProtectedPerm
                        }# End If SkipDefaultPerm
                        $index++
                    }# End while

                } else {
                    If (!($bolCSV)) {
                        If ($strColorTemp -eq '1') {
                            $strColorTemp = '2'
                        } else {
                            $strColorTemp = '1'
                        }
                        if ($permcount -ne 0) {
                            $bolOUHeader = $false
                            $GetOwnerEna = $false
                            Write-ToFile -bolACLExist $bolACLExist -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp $strColorTemp -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor

                        }
                    }

                    $permcount++
                }#End if array

                If (!($bolCSV)) {
                    $bolACLExist = $false
                    if (($permcount -eq 0) -and ($index -gt 0)) {
                        $bolOUHeader = $true
                        Write-ToFile -bolACLExist $bolACLExist -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -OUHeader $bolOUHeader -strColorTemp "1"  -htmfileout $strFileHTA -CompareMode $bolCompare -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -boolACLSize $bolACLsize -strACLSize $strACLSize -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -bolShowCriticalityColor $bolShowCriticalityColor -bolTranslateGUID $bolGUIDtoText -strObjClass $strObjectClass $OutputFormat -GPO $GPO -GPODisplayname $GPOdisplayname -bolCriticalityLevel $bolShowCriticalityColor -strSDDL $strSDDL -CREDS $CREDS
                        $aclcount++
                    }# End If
                }# End if bolCSVOnly
            }
        }#End $global:GetSecErr
        $count++
    }# End while


    if (($count -gt 0)) {
        if ($aclcount -eq 0) {
            if ($bolCMD) {
                Write-Host 'No Permissions found!' -ForegroundColor red
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'No Permissions found!' -strType 'Error' -DateStamp ))
                if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                    $global:ProgressBarWindow.Window.Dispatcher.invoke([action] { $global:ProgressBarWindow.Window.Close() }, 'Normal')
                    $ProgressBarWindow = $null
                    Remove-Variable -Name 'ProgressBarWindow' -Scope Global
                }
            }
        } else {
            if (-not $bolCMD) {
                if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {

                    $global:ProgressBarWindow.Window.Dispatcher.invoke([action] { $global:ProgressBarWindow.Window.Close() }, 'Normal')
                }
            }

            if ($bolCSV) {
                if ($OutType -eq 'CSVTEMPLATE') {
                    if ($bolCMD) {
                        if ($bolToFile) {
                            Write-Host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                            Write-Output $strFileCSV
                        }
                    } else {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileCSV" -strType 'Warning' -DateStamp ))
                    }
                    #If Get-Perm was called with Show then open the CSV file.
                    if ($Show) {
                        Invoke-Item $strFileCSV
                    }
                } else {
                    if ($bolCMD) {
                        if ($bolToFile) {
                            $global:ArrayAllACE | Export-Csv -Path $strFileCSV -NoTypeInformation -NoClobber
                            Write-Host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                            Write-Output $strFileCSV
                        } else {
                            $global:ArrayAllACE
                        }
                    } else {
                        $global:ArrayAllACE | Export-Csv -Path $strFileCSV -NoTypeInformation -NoClobber
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileCSV" -strType 'Warning' -DateStamp ))
                    }
                    #If Get-Perm was called with Show then open the CSV file.
                    if ($Show) {
                        Invoke-Item $strFileCSV
                    }
                }
            } else {
                #If excel output
                if ($OutType -eq 'EXCEL') {
                    $tablename = $($strNode + 'acltbl') -replace '[^a-zA-Z]+', ''

                    if ($bolShowCriticalityColor) {
                        # Array with alphabet characters
                        $ExcelColumnAlphabet = @()
                        for ([byte]$c = [char]'A'; $c -le [char]'Z'; $c++) {
                            $ExcelColumnAlphabet += [char]$c
                        }

                        #Define Column name for "criticality" by using position in array
                        $RangeColumnCriticality = $ExcelColumnAlphabet[$(($global:ArrayAllACE | Get-Member -MemberType NoteProperty ).count - 1 )]

                        $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode + '_ACL') -BoldTopRow -TableStyle Medium2 -TableName $($strNode + 'acltbl') -NoLegend -AutoSize -FreezeTopRow -ConditionalText $(
                            New-ConditionalText -RuleType Equal -ConditionValue Low -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor DeepSkyBlue -ConditionalTextColor Black
                            New-ConditionalText -RuleType Equal -ConditionValue Critical -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Red -ConditionalTextColor Black
                            New-ConditionalText -RuleType Equal -ConditionValue Warning -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Gold -ConditionalTextColor Black
                            New-ConditionalText -RuleType Equal -ConditionValue Medium -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Yellow -ConditionalTextColor Black
                            New-ConditionalText -RuleType Equal -ConditionValue Info -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor LightGray -ConditionalTextColor Black
                        )
                    } else {
                        $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode + '_ACL') -BoldTopRow -TableStyle Medium2 -TableName $tablename -NoLegend -AutoSize -FreezeTopRow -Append
                    }

                    if ($bolCMD) {
                        Write-Host "Report saved in: $strFileEXCEL" -ForegroundColor Yellow
                        Write-Output $strFileEXCEL
                    } else {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileEXCEL" -strType 'Warning' -DateStamp ))
                    }
                    if ($Show) {
                        If (Test-Path HKLM:SOFTWARE\Classes\Excel.Application) {
                            Invoke-Item $strFileEXCEL
                        }
                    }
                }#End if EXCEL
                else {
                    if ($bolShowCriticalityColor) {
                        Switch ($global:intShowCriticalityLevel) {
                            0 {
                    (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
                    (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
                            }
                            1 {
                    (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
                    (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
                            }
                            2 {
                    (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
                    (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
                            }
                            3 {
                    (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
                    (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
                            }
                            4 {
                    (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
                    (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
                            }
                        }
                    }
                    #If Get-Perm was called with Show then open the HTA file.
                    if ($Show) {
                        try {
                            Invoke-Item $strFileHTA
                        } catch {
                            if ($bolCMD) {
                                Write-Host 'Failed to launch MSHTA.exe' -ForegroundColor Red
                                Write-Host "Instead opening the following file directly: $strFileHTM" -ForegroundColor Yellow
                            } else {
                                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed to launch MSHTA.exe' -strType 'Error' -DateStamp ))
                                $global:observableCollection.Insert(0, (LogMessage -strMessage "Instead opening the following file directly: $strFileHTM" -strType 'Ino' -DateStamp ))
                            }
                            Invoke-Item $strFileHTM
                        }
                    }
                }
            }

        }# End If
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'No objects found!' -strType 'Error' -DateStamp ))
    }
    $i = $null
    Remove-Variable -Name 'i'
    $secd = $null




}

#==========================================================================
# Function		: Get-PermCompare
# Arguments     : OU Path
# Returns   	: N/A
# Description   : Compare Permissions on node with permissions in CSV file
#==========================================================================
Function Get-PermCompare {
    Param([System.Collections.ArrayList]$AllObjectDn, [boolean]$SkipDefaultPerm, [boolean]$SkipProtectedPerm, [boolean]$bolReplMeta, [boolean]$bolGetOwnerEna, [boolean]$bolCSV, [boolean]$bolGetOUProtected, [boolean]$bolACLsize, [boolean] $bolGUIDtoText, [boolean]$Show, [string] $OutType, [string] $TemplateFilter, [bool]$bolToFile, [bool]$bolShowCriticalityColor, [bool]$bolAssess, [string] $AssessLevel, [bool]$GPO, [bool]$TranslateGUID, 
        [Parameter(Mandatory = $false)]
        #Get Discretionary ACL (DACL)
        [boolean]
        $DACL = $True,
        [Parameter(Mandatory=$false)]
        [pscredential]
        $CREDS)

    & { #Try
        $arrOUList = New-Object System.Collections.ArrayList
        $bolCompare = $true
        $bolCompareDelegation = $false
        $bolFilter = $false
        $bolOUPRotected = $false
        $strACLSize = ''
        $bolAClMeta = $false
        $strOwner = ''
        $count = 0
        $aclcount = 0
        $SDUsnCheck = $false
        $ExitCompare = $false
        $sdOUProtect = ''
        $global:ArrayAllACE = New-Object System.Collections.ArrayList

        if(($null -eq $global:ForestRootDomainSID) -or ($global:ForestRootDomainSID -eq '')) {
                $forestdata = New-LDAPSearch -Server $Global:ForestObject.Domain -creds $CREDS  -LDAPFilter "(objectClass=*)" -Scope base -BaseDN $global:ForestRootDomainDN -Attributes "objectsid"

                if($forestdata) {
                    $objectForestSid = [byte[]]$forestdata.Attributes.objectsid[0]
                    $global:ForestRootDomainSID = (New-Object System.Security.Principal.SecurityIdentifier($objectForestSid, 0)).value
                } else  {
                    $global:ForestRootDomainSID = ''
                }
        }

        if (($OutType -eq 'EXCEL') -or ($OutType -eq 'CSV')) {
            $OutputFormat = 'Object'
        } else {
            $OutputFormat = 'HTML'
        }

        If ($bolAssess) {
            Switch ($AssessLevel) {
                'Info' {
                    $CriticalityFilter = 0
                }
                'Low' {
                    $CriticalityFilter = 1
                }
                'Medium' {
                    $CriticalityFilter = 2
                }
                'Warning' {
                    $CriticalityFilter = 3
                }
                'Critical' {
                    $CriticalityFilter = 4
                }
            }
            $global:csvHistACLs = @($global:csvHistACLs | Where-Object { Get-Criticality -Returns 'Filter' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() $CriticalityFilter })
        }

        if ($chkBoxTemplateNodes.IsChecked -eq $true) {

            $index = 0
            #Enumerate all Nodes in CSV
            if ($global:csvHistACLs[0].Object) {
                while ($index -le $global:csvHistACLs.count - 1) {
                    $arrOUList.Add($global:csvHistACLs[$index].Object)
                    $index++
                }
            } else {
                while ($index -le $global:csvHistACLs.count - 1) {
                    $arrOUList.Add($global:csvHistACLs[$index].OU)
                    $index++
                }
            }


            $arrOUListUnique = $arrOUList | Select-Object -Unique

            #Replace any existing strings matching <DOMAIN-DN>
            $arrOUListUnique = $arrOUListUnique -replace '<DOMAIN-DN>', $global:strDomainDNName

            #Replace any existing strings matching <ROOT-DN>
            $arrOUListUnique = $arrOUListUnique -replace '<ROOT-DN>', $global:ForestRootDomainDN
            #If the user entered any text replace matching string from CSV

            if ($txtReplaceDN.text.Length -gt 0) {

                $arrOUListUnique = $arrOUListUnique -replace $txtReplaceDN.text, $global:strDomainDNName

            }
            $AllObjectDn = @($arrOUListUnique)
        }

        If ($bolReplMeta -eq $true) {
            If ($global:csvHistACLs[0].SDDate.length -gt 1) {
                $bolAClMeta = $true
            }
            $arrUSNCheckList = $global:csvHistACLs | Select-Object -Property OU, OrgUSN -Unique
        }
        #Verify that USN exist in file and that Meta data will be retreived
        if ($chkBoxScanUsingUSN.IsChecked -eq $true) {
            if ($bolAClMeta -eq $true) {
                $SDUsnCheck = $true
            } else {
                If ($bolReplMeta -eq $true) {
                    $MsgBox = [System.Windows.Forms.MessageBox]::Show("Could not compare using USN.`nDid not find USNs in template.`nDo you want to continue?", 'Information', 3, 'Warning')
                    Switch ($MsgBOx) {
                        'YES' {
                            $ExitCompare = $false
                        }
                        'NO' {
                            $ExitCompare = $true
                        }
                        Default {
                            $ExitCompare = $true
                        }
                    }
                } else {
                    $MsgBox = [System.Windows.Forms.MessageBox]::Show("Could not compare using USN.`nMake sure scan option SD Modified is selected.`nDo you want to continue?", 'Information', 3, 'Warning')
                    Switch ($MsgBOx) {
                        'YES' {
                            $ExitCompare = $false
                        }
                        'NO' {
                            $ExitCompare = $true
                        }
                        Default {
                            $ExitCompare = $true
                        }
                    }
                }
            }
        }
        if (!($ExitCompare)) {
            If ($bolCSV) {
                If ((Test-Path $strFileCSV) -eq $true) {
                    Remove-Item $strFileCSV
                }
            }


            $i = 0
            $intCSV = 0
            $intReturned = 0
            if ($global:bolCMD) {
                $intTot = 0
                #calculate percentage
                $intTot = $AllObjectDn.count
            } else {
                if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                    $intTot = 0
                    #calculate percentage
                    $intTot = $AllObjectDn.count
                    if ($intTot -gt 0) {
                        LoadProgressBar

                    }
                }
            }

            while ($count -le $AllObjectDn.count - 1) {
                $global:GetSecErr = $false
                $global:secd = ''

                if (($global:bolCMD) -and ($global:bolProgressBar)) {

                    $i++
                    [int]$pct = ($i / $intTot) * 100
                    Write-Progress -Activity 'Collecting objects' -Status "Currently scanning $i of $intTot objects" -Id 0 -CurrentOperation "Reading ACL on: $ADObjDN" -PercentComplete $pct
                } else {
                    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                        $i++
                        [int]$pct = ($i / $intTot) * 100
                        #Update the progress bar
                        while (($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20)) {
                            Start-Sleep -Milliseconds 1
                            $cc++
                        }
                        if ($global:ProgressBarWindow.Window.IsInitialized -eq $true) {
                            Update-ProgressBar "Currently scanning $i of $intTot objects" $pct
                        }

                    }
                }


                $OUMatchResultOverall = $false

                $sd = New-Object System.Collections.ArrayList
                $GetOwnerEna = $bolGetOwnerEna
                if ($GPO) {
                    $ADObjDN = $AllObjectDn[$count].Split(';')[0]
                    $GPOTarget = $AllObjectDn[$count].Split(';')[1]
                    if ($GPO) {
                        $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                        $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                        $request = New-Object System.directoryServices.Protocols.SearchRequest
                        $request.DistinguishedName = $ADObjDN
                        $request.Filter = '(objectClass=*)'
                        $request.Scope = 'Base'
                        [void]$request.Attributes.Add('displayname')
                        $response = $LDAPConnection.SendRequest($request)
                        $result = $response.Entries[0]
                        try {
                            $GPOdisplayname = $result.attributes.displayname[0]
                        } catch {
                        }
                    }
                } else {
                    $ADObjDN = $($AllObjectDn[$count])
                }
                $OUdnorgDN = $ADObjDN

                #Counter used for fitlerout Nodes with only defaultpermissions configured
                $intAclOccurence = 0

                $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                $request = New-Object System.directoryServices.Protocols.SearchRequest("$ADObjDN", '(name=*)', 'base')
                if ($global:bolShowDeleted) {
                    [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                    [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                }
                [void]$request.Attributes.Add('objectclass')
                if ($UseCanonicalName) {
                    [void]$request.Attributes.Add('canonicalname')
                }
                [void]$request.Attributes.Add('ntsecuritydescriptor')

                $response = $null
                $DSobject = $null

                if ($DACL -eq $True) {
                    $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
                    $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
                    [void]$request.Controls.Add($control)
                    $SendRequest = $false
                    try {
                        $response = $LDAPConnection.SendRequest($request)
                        $SendRequest = $true
                    } catch {
                        if ($global:bolCMD) {
                            Write-Host "Failed to connect to:$ADObjDN"
                        } else {
                            $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to connect to:$ADObjDN" -strType 'Error' -DateStamp ))
                        }
                    }
                    if ($SendRequest) {
                        $DSobject = $response.Entries[0]
                        if ($GPO) {
                            $strDistinguishedName = $GPOTarget
                        } else {
                            $strDistinguishedName = $DSobject.distinguishedname.toString()
                        }
                        #Check if any NTsecuritydescr
                        if ($null -ne $DSobject.Attributes.ntsecuritydescriptor) {
                            if ($null -ne $DSobject.Attributes.objectclass) {
                                $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count - 1]
                            } else {
                                $strObjectClass = 'unknown'
                            }

                            if ($UseCanonicalName) {
                                if ($DSobject.attributes.canonicalname) {
                                    $CanonicalName = $DSobject.attributes.canonicalname[0]
                                } else {
                                    $CanonicalName = Create-CanonicalName $DSobject.distinguishedname.toString()
                                }
                            }
                            $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity

                            if ($chkBoxRAWSDDL.IsChecked) {

                                $secSDDL = New-Object System.DirectoryServices.ActiveDirectorySecurity
                                $objSd = $DSobject.Attributes.ntsecuritydescriptor[0]
                                if ($objSD -is [Byte[]]) {
                                    $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd, 0)
                                } elseif ($objSD -is [string]) {
                                    $SDDLSec = New-Object System.Security.AccessControl.RawSecurityDescriptor @($objSd)
                                }
                                $strSDDL = $SDDLSec.GetSddlForm('Access,Owner')

                                $arrSplitedSDDL = $strSDDL.Split('(')
                                $intI = 0
                                Foreach ($strSDDLPart in $arrSplitedSDDL) {
                                    if ($intI -gt 0) {
                                        if ($sec.Owner -eq $null) {
                                            $sec.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                        } else {
                                            if (!($chkInheritedPerm.IsChecked)) {
                                                if (($strSDDLPart.split(';')[1] -ne 'CIID') -and ($strSDDLPart.split(';')[1] -ne 'CIIOID')) {
                                                    $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                                    $sd = $secSDDL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                                                    $sec.AddAccessRule($sd[0])
                                                }
                                            } else {
                                                $secSDDL.SetSecurityDescriptorSDDLForm("$($arrSplitedSDDL[0])($strSDDLPart")
                                                $sd = $secSDDL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                                                $sec.AddAccessRule($sd[0])
                                            }
                                        }
                                    }
                                    $intI++
                                }

                            } else {
                                $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
                            }
                            & { #Try
                                $global:secd = $sec.GetAccessRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])

                            }
                            Trap [SystemException] {
                                $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                                & { #Try
                                    $global:secd = $sec.GetAccessRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
                                }
                                Trap [SystemException] {
                                    $global:GetSecErr = $true
                                    Continue
                                }
                                Continue
                            }
                        } else {
                            #Fail futher scan when NTsecurityDescriptor is null
                            $global:GetSecErr = $true
                        }
                    }#End If failed Send Request

                } else {
                    $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
                    $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
                    [void]$request.Controls.Add($control)
                    $response = $LDAPConnection.SendRequest($request)
                    $DSobject = $response.Entries[0]
                    if ($null -ne $DSobject.Attributes.objectclass) {
                        $strObjectClass = $DSobject.Attributes.objectclass[$DSobject.Attributes.objectclass.count - 1]
                    } else {
                        $strObjectClass = 'unknown'
                    }
                    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sec.SetSecurityDescriptorBinaryForm($DSobject.Attributes.ntsecuritydescriptor[0])
                    & { #Try
                        $global:secd = $sec.GetAuditRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
                    }
                    Trap [SystemException] {
                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                        & { #Try
                            $global:secd = $sec.GetAuditRules($true, $chkInheritedPerm.IsChecked, [System.Security.Principal.SecurityIdentifier])
                        }
                        Trap [SystemException] {
                            $global:GetSecErr = $true
                            Continue
                        }
                        Continue
                    }
                }
                if ($DSobject.attributes.count -gt 0) {
                    if (($global:GetSecErr -ne $true) -or ($global:secd -ne '')) {
                        $sd.clear()
                        if ($null -ne $global:secd) {
                            $(ConvertTo-ObjectArrayListFromPsCustomObject $global:secd) | ForEach-Object { [void]$sd.add($_) }
                        }
                        If ($GetOwnerEna -eq $true) {

                            & { #Try
                                $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                            }

                            Trap [SystemException] {
                                if ($global:bolADDSType) {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType 'Warning' -DateStamp ))
                                }
                                $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                                Continue
                            }


                            $newSdOwnerObject = New-Object PSObject -Property @{ActiveDirectoryRights = 'Read permissions, Modify permissions'; InheritanceType = 'None'; ObjectType = 'None'; `
                                    InheritedObjectType = 'None'; ObjectFlags = 'None'; AccessControlType = 'Owner'; IdentityReference = $global:strOwner; IsInherited = 'False'; `
                                    InheritanceFlags = 'None'; PropagationFlags = 'None'
                            }

                            [void]$sd.insert(0, $newSdOwnerObject)

                        }
                        If ($SkipDefaultPerm) {
                            If ($GetOwnerEna -eq $false) {

                                & { #Try
                                    $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                                }

                                Trap [SystemException] {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed to translate owner identity:$ADObjDN" -strType 'Error' -DateStamp ))
                                    $global:strOwner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).value
                                    Continue
                                }
                            }
                        }

                        If ($bolAssess) {
                            Switch ($AssessLevel) {
                                'Info' {
                                    $CriticalityFilter = 0
                                }
                                'Low' {
                                    $CriticalityFilter = 1
                                }
                                'Medium' {
                                    $CriticalityFilter = 2
                                }
                                'Warning' {
                                    $CriticalityFilter = 3
                                }
                                'Critical' {
                                    $CriticalityFilter = 4
                                }
                            }
                            $sd = @($sd | Where-Object { Get-Criticality -Returns 'Filter' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() $CriticalityFilter })
                        }

                        if ($bolACLsize -eq $true) {
                            $strACLSize = $SDDLSec.BinaryLength
                        }
                        if ($bolGetOUProtected -eq $true) {
                            $bolOUProtected = $sec.AreAccessRulesProtected
                        }

                        if ($bolReplMeta -eq $true) {

                                $objACLMeta = $(Get-ACLMeta  $global:strDC $ADObjDN -CREDS $CREDS)

                                $objLastChange = $objACLMeta.LastChangeDate
                                $strOrigInvocationID = $objACLMeta.InvocationID
                                $strOrigUSN = $objACLMeta.OriginatingChange
                                $strVersion = $objACLMeta.Version
                        }

                        $index = 0
                        $SDResult = $false
                        $OUMatchResult = $false


                        $SDUsnNew = $true
                        if ($SDUsnCheck -eq $true) {



                            while ($index -le $arrUSNCheckList.count - 1) {
                                $SDHistResult = $false


                                if ($arrUSNCheckList[$index].Object) {
                                    $strOUcol = $arrUSNCheckList[$index].Object
                                } else {
                                    $strOUcol = $arrUSNCheckList[$index].OU
                                }
                                if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                                }
                                if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                                }
                                if ($txtReplaceDN.text.Length -gt 0) {
                                    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                                }
                                if ($OUdnorgDN -eq $strOUcol ) {
                                    $OUMatchResult = $true
                                    $SDResult = $true

                                    if ($strOrigUSN -eq $arrUSNCheckList[$index].OrgUSN) {
                                        $aclcount++
                                        foreach ($sdObject in $sd) {


                                            if ($null -ne $sdObject.AccessControlType) {
                                                $ACEType = $sdObject.AccessControlType
                                            } else {
                                                $ACEType = $sdObject.AuditFlags
                                            }
                                            $strNTAccount = $sdObject.IdentityReference
                                            If ($strNTAccount.contains('S-1-')) {
                                                $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strNTAccount -CREDS $CREDS

                                            }
                                            $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $sdObject.ActiveDirectoryRights; InheritanceType = $sdObject.InheritanceType; ObjectType = $sdObject.ObjectType; `
                                                    InheritedObjectType = $sdObject.InheritedObjectType; ObjectFlags = $sdObject.ObjectFlags; AccessControlType = $ACEType; IdentityReference = $sdObject.IdentityReference; PrincipalName = $strNTAccount; IsInherited = $sdObject.IsInherited; `
                                                    InheritanceFlags = $sdObject.InheritanceFlags; PropagationFlags = $sdObject.PropagationFlags; State = 'Match'
                                            }

                                            if (($TemplateFilter -eq 'MATCH') -or ($TemplateFilter -eq 'ALL')) {
                                                $OUMatchResultOverall = $true
                                                $intReturned++
                                                If ($bolCSV) {
                                                    $intCSV++
                                                    if ($OutType -eq 'CSVTEMPLATE') {
                                                        Write-PermCSV $newSdObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                    } else {
                                                        $bolOUHeader = $false
                                                        Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp "4" -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                }# End If
                                                Else {
                                                    if ($intAclOccurence -eq 0) {
                                                        $intAclOccurence++
                                                        $bolOUHeader = $true
                                                        Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp $strColorTemp -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor

                                                    }
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -strColorTemp "4" -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }#End !$bolCSVOnly
                                            }#End Returns
                                        }
                                        $SDUsnNew = $false
                                        break
                                    } else {
                                        $aclcount++

                                        $SDUsnNew = $true
                                        break
                                    }

                                }
                                $index++
                            }


                        }

                        If (($SDUsnCheck -eq $false) -or ($SDUsnNew -eq $true)) {
                            foreach ($sdObject in $sd) {
                                $bolMatchDef = $false
                                $bolMatchprotected = $false
                                $strIdentityReference = $sdObject.IdentityReference.toString()
                                If ($strIdentityReference.contains('S-1-')) {
                                    $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strIdentityReference -CREDS $CREDS
                                }
                                #Remove Default Permissions if SkipDefaultPerm selected
                                if ($SkipDefaultPerm) {
                                    if ($strObjectClass -ne $strTemoObjectClass) {
                                        $sdOUDef = Get-DefaultPermissions -strObjectClass $strObjectClass -CREDS $CREDS
                                    }
                                    $strTemoObjectClass = $strObjectClass
                                    $indexDef = 0
                                    while ($indexDef -le $sdOUDef.count - 1) {
                                        if (($sdOUDef[$indexDef].IdentityReference -eq $sdObject.IdentityReference) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sdObject.ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sdObject.InheritedObjectType)) {
                                            $bolMatchDef = $true
                                        } #End If
                                        $indexDef++
                                    } #End While
                                }

                                if ($bolMatchDef) {
                                } else {
                                    #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                                    if ($SkipProtectedPerm) {
                                        if ($sdOUProtect -eq '') {
                                            $sdOUProtect = Get-ProtectedPerm
                                        }
                                        $indexProtected = 0
                                        while ($indexProtected -le $sdOUProtect.count - 1) {
                                            if (($sdOUProtect[$indexProtected].IdentityReference -eq $sdObject.IdentityReference) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sdObject.ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sdObject.InheritedObjectType)) {
                                                $bolMatchprotected = $true
                                            }#End If
                                            $indexProtected++
                                        } #End While
                                    }

                                    if ($bolMatchprotected) {
                                    } else {

                                        $index = 0
                                        $SDResult = $false
                                        $OUMatchResult = $false
                                        $aclcount++
                                        if ($null -ne $sdObject.AccessControlType) {
                                            $ACEType = $sdObject.AccessControlType
                                        } else {
                                            $ACEType = $sdObject.AuditFlags
                                        }

                                        $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $sdObject.ActiveDirectoryRights; InheritanceType = $sdObject.InheritanceType; ObjectType = $sdObject.ObjectType; `
                                                InheritedObjectType = $sdObject.InheritedObjectType; ObjectFlags = $sdObject.ObjectFlags; AccessControlType = $ACEType; IdentityReference = $strIdentityReference; PrincipalName = $strNTAccount; IsInherited = $sdObject.IsInherited; `
                                                InheritanceFlags = $sdObject.InheritanceFlags; PropagationFlags = $sdObject.PropagationFlags; State = 'Match'
                                        }

                                        while ($index -le $global:csvHistACLs.count - 1) {
                                            if ($global:csvHistACLs[$index].Object) {
                                                $strOUcol = $global:csvHistACLs[$index].Object
                                            } else {
                                                $strOUcol = $global:csvHistACLs[$index].OU
                                            }
                                            if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                                                $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                                            }
                                            if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                                                $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                                            }
                                            if ($txtReplaceDN.text.Length -gt 0) {
                                                $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                                            }
                                            if ($OUdnorgDN -eq $strOUcol ) {
                                                $OUMatchResult = $true
                                                $OUMatchResultOverall = $true
                                                $strPrincipalName = $global:csvHistACLs[$index].PrincipalName
                                                if ($strPrincipalName.Contains('<DOMAIN-NETBIOS>')) {
                                                    $strPrincipalName = ($strPrincipalName -Replace '<DOMAIN-NETBIOS>', $global:strDomainShortName)

                                                }
                                                if ($strPrincipalName.Contains('<ROOT-NETBIOS>')) {
                                                    $strPrincipalName = ($strPrincipalName -Replace '<ROOT-NETBIOS>', $global:strRootDomainShortName)

                                                }
                                                if ($strPrincipalName.Contains('<DOMAINSID>')) {
                                                    $strPrincipalName = ($strPrincipalName -Replace '<DOMAINSID>', $global:DomainSID)

                                                }
                                                if ($strPrincipalName.Contains('<ROOTDOMAINSID>')) {
                                                    $strPrincipalName = ($strPrincipalName -Replace '<ROOTDOMAINSID>', $global:ForestRootDomainSID)

                                                }
                                                If ($strPrincipalName.contains('S-1-')) {
                                                    $strPrincipalName = Convert-SidToName -server $global:strDomainFQDN -Sid $strPrincipalName -CREDS $CREDS

                                                }
                                                if ($txtReplaceNetbios.text.Length -gt 0) {
                                                    $strPrincipalName = ($strPrincipalName -Replace $txtReplaceNetbios.text, $global:strDomainShortName)

                                                }
                                                $strTmpActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights
                                                $strTmpInheritanceType = $global:csvHistACLs[$index].InheritanceType
                                                $strTmpObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
                                                $strTmpInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
                                                $strTmpAccessControlType = $global:csvHistACLs[$index].AccessControlType
                                                if ($strTmpAccessControlType -eq 'Owner' ) {
                                                    $global:strOwnerTemplate = $strPrincipalName
                                                }

                                                If (($newSdObject.PrincipalName -eq $strPrincipalName) -and ($newSdObject.ActiveDirectoryRights -eq $strTmpActiveDirectoryRights) -and ($newSdObject.AccessControlType -eq $strTmpAccessControlType) -and ($newSdObject.ObjectType -eq $strTmpObjectTypeGUID) -and ($newSdObject.InheritanceType -eq $strTmpInheritanceType) -and ($newSdObject.InheritedObjectType -eq $strTmpInheritedObjectTypeGUID)) {
                                                    $SDResult = $true
                                                }
                                            }
                                            $index++
                                        }# End While
                                        if (($TemplateFilter -eq 'MATCH') -or ($TemplateFilter -eq 'ALL')) {
                                            if ($SDResult) {
                                                $intReturned++
                                                If ($bolCSV) {
                                                    $intCSV++
                                                    if ($OutType -eq 'CSVTEMPLATE') {
                                                        Write-PermCSV $newSdObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                    } else {
                                                        $bolOUHeader = $false
                                                        Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName  -strColorTemp "4" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                }# End If
                                                Else {
                                                    if ($intAclOccurence -eq 0) {
                                                        $intAclOccurence++
                                                        $bolOUHeader = $true
                                                        Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName  -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor

                                                    }
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName  -strColorTemp "4" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }#End !$bolCSVOnly

                                            }
                                        }#End Retrunrs
                                        If ($OUMatchResult -And !($SDResult)) {
                                            if (($TemplateFilter -eq 'NEW') -or ($TemplateFilter -eq 'ALL')) {
                                                $newSdObject.State = 'New'
                                                $intReturned++
                                                If ($bolCSV) {
                                                    $intCSV++
                                                    if ($OutType -eq 'CSVTEMPLATE') {
                                                        Write-PermCSV $newSdObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                    } else {
                                                        $bolOUHeader = $false
                                                        Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "5" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                }# End If
                                                Else {
                                                    if ($intAclOccurence -eq 0) {
                                                        $intAclOccurence++
                                                        $bolOUHeader = $true
                                                        Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $newSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "5" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }#End !$bolCSVO
                                            }#End Returns

                                        }
                                    }# End If SkipProtectedPerm
                                }# End If SkipDefaultPerm
                            }
                        } # if $SDUsnCheck -eq $true

                        If (($SDUsnCheck -eq $false) -or ($SDUsnNew -eq $true)) {
                            $index = 0

                            while ($index -le $global:csvHistACLs.count - 1) {
                                $SDHistResult = $false

                                if ($global:csvHistACLs[$index].Object) {
                                    $strOUcol = $global:csvHistACLs[$index].Object
                                } else {
                                    $strOUcol = $global:csvHistACLs[$index].OU
                                }

                                if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                                }
                                if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                                    $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                                }
                                if ($txtReplaceDN.text.Length -gt 0) {
                                    $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                                }
                                if ($OUdnorgDN -eq $strOUcol ) {
                                    $OUMatchResult = $true
                                    $strIdentityReference = $global:csvHistACLs[$index].IdentityReference

                                    if ($strIdentityReference.Contains('<DOMAIN-NETBIOS>')) {
                                        $strIdentityReference = ($strIdentityReference -Replace '<DOMAIN-NETBIOS>', $global:strDomainShortName)
                                    }
                                    if ($strIdentityReference.Contains('<ROOT-NETBIOS>')) {
                                        $strIdentityReference = ($strIdentityReference -Replace '<ROOT-NETBIOS>', $global:strRootDomainShortName)

                                    }
                                    if ($strIdentityReference.Contains('<DOMAINSID>')) {
                                        $strIdentityReference = ($strIdentityReference -Replace '<DOMAINSID>', $global:DomainSID)

                                    }
                                    if ($strIdentityReference.Contains('<ROOTDOMAINSID>')) {
                                        $strIdentityReference = ($strIdentityReference -Replace '<ROOTDOMAINSID>', $global:ForestRootDomainSID)

                                    }

                                    if ($txtReplaceNetbios.text.Length -gt 0) {
                                        $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text, $global:strDomainShortName)

                                    }
                                    $strTmpActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights
                                    $strTmpInheritanceType = $global:csvHistACLs[$index].InheritanceType
                                    $strTmpObjectTypeGUID = $global:csvHistACLs[$index].ObjectType
                                    $strTmpInheritedObjectTypeGUID = $global:csvHistACLs[$index].InheritedObjectType
                                    $strTmpAccessControlType = $global:csvHistACLs[$index].AccessControlType
                                    if ($strTmpAccessControlType -eq 'Owner' ) {
                                        $global:strOwnerTemplate = $strIdentityReference
                                    }

                                    foreach ($sdObject in $sd) {
                                        $bolMatchDef = $false
   
                                        #Remove Default Permissions if SkipDefaultPerm selected
                                        if ($SkipDefaultPerm) {
                                            if ($strObjectClass -ne $strTemoObjectClass) {
                                                $sdOUDef = Get-DefaultPermissions -strObjectClass $strObjectClass -CREDS $CREDS
                                            }
                                            $strTemoObjectClass = $strObjectClass
                                            $indexDef = 0
                                            while ($indexDef -le $sdOUDef.count - 1) {
                                                if (($sdOUDef[$indexDef].IdentityReference -eq $sdObject.IdentityReference) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sdObject.ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sdObject.InheritedObjectType)) {
                                                    $bolMatchDef = $true
                                                }#} #End If
                                                $indexDef++
                                            } #End While
                                        }

                                        if ($bolMatchDef) {
                                        } else {
                                            #Remove Protect Against Accidental Deletaions Permissions if SkipProtectedPerm selected
                                            if ($SkipProtectedPerm) {
                                                if ($sdOUProtect -eq '') {
                                                    $sdOUProtect = Get-ProtectedPerm
                                                }
                                                $indexProtected = 0
                                                while ($indexProtected -le $sdOUProtect.count - 1) {
                                                    if (($sdOUProtect[$indexProtected].IdentityReference -eq $strNTAccount) -and ($sdOUProtect[$indexProtected].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUProtect[$indexProtected].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUProtect[$indexProtected].ObjectType -eq $sdObject.ObjectType) -and ($sdOUProtect[$indexProtected].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUProtect[$indexProtected].InheritedObjectType -eq $sdObject.InheritedObjectType)) {
                                                        $bolMatchprotected = $true
                                                    }#End If
                                                    $indexProtected++
                                                } #End While
                                            }

                                            if ($bolMatchprotected) {
                                            } else {
                                                if ($null -ne $sdObject.AccessControlType) {
                                                    $ACEType = $sdObject.AccessControlType
                                                } else {
                                                    $ACEType = $sdObject.AuditFlags
                                                }

                                                $newSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $sdObject.ActiveDirectoryRights; InheritanceType = $sdObject.InheritanceType; ObjectType = $sdObject.ObjectType; `
                                                        InheritedObjectType = $sdObject.InheritedObjectType; ObjectFlags = $sdObject.ObjectFlags; AccessControlType = $ACEType; IdentityReference = $sdObject.IdentityReference; PrincipalName = $strNTAccount; IsInherited = $sdObject.IsInherited; `
                                                        InheritanceFlags = $sdObject.InheritanceFlags; PropagationFlags = $sdObject.PropagationFlags
                                                }

                                                If (($newSdObject.IdentityReference -eq $strIdentityReference) -and ($newSdObject.ActiveDirectoryRights -eq $strTmpActiveDirectoryRights) -and ($newSdObject.AccessControlType -eq $strTmpAccessControlType) -and ($newSdObject.ObjectType -eq $strTmpObjectTypeGUID) -and ($newSdObject.InheritanceType -eq $strTmpInheritanceType) -and ($newSdObject.InheritedObjectType -eq $strTmpInheritedObjectTypeGUID)) {
                                                    $SDHistResult = $true
                                                }#End If $newSdObject
                                            }# End If SkipProtectedPerm
                                        }# End If SkipDefaultPerm
                                    }# End foreach

                                    #If OU exist in CSV but no matching ACE found
                                    If ($OUMatchResult -And !($SDHistResult)) {

                                        $strIdentityReference = $global:csvHistACLs[$index].IdentityReference
                                        if ($strIdentityReference.Contains('<DOMAIN-NETBIOS>')) {
                                            $strIdentityReference = ($strIdentityReference -Replace '<DOMAIN-NETBIOS>', $global:strDomainShortName)

                                        }
                                        if ($strIdentityReference.Contains('<ROOT-NETBIOS>')) {
                                            $strIdentityReference = ($strIdentityReference -Replace '<ROOT-NETBIOS>', $global:strRootDomainShortName)

                                        }
                                        if ($strIdentityReference.Contains('<DOMAINSID>')) {
                                            $strIdentityReference = ($strIdentityReference -Replace '<DOMAINSID>', $global:DomainSID)

                                        }
                                        if ($strIdentityReference.Contains('<ROOTDOMAINSID>')) {
                                            $strIdentityReference = ($strIdentityReference -Replace '<ROOTDOMAINSID>', $global:ForestRootDomainSID)

                                        }
                                        if ($txtReplaceNetbios.text.Length -gt 0) {
                                            $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text, $global:strDomainShortName)

                                        }
                                        If ($strIdentityReference.contains('S-1-')) {
                                            $strIdentityReference = Convert-SidToName -server $global:strDomainFQDN -Sid $strIdentityReference -CREDS $CREDS

                                        }
                                        $histSDObject = New-Object PSObject -Property @{ActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights; InheritanceType = $global:csvHistACLs[$index].InheritanceType; ObjectType = $global:csvHistACLs[$index].ObjectType; `
                                                InheritedObjectType = $global:csvHistACLs[$index].InheritedObjectType; ObjectFlags = $global:csvHistACLs[$index].ObjectFlags; AccessControlType = $global:csvHistACLs[$index].AccessControlType; IdentityReference = $strIdentityReference; PrincipalName = $strNTAccount; IsInherited = $global:csvHistACLs[$index].IsInherited; `
                                                InheritanceFlags = $global:csvHistACLs[$index].InheritanceFlags; PropagationFlags = $global:csvHistACLs[$index].PropagationFlags; State = 'Missing'
                                        }
                                        if (($TemplateFilter -eq 'MISSING') -or ($TemplateFilter -eq 'ALL')) {
                                            $intReturned++
                                            If ($bolCSV) {
                                                $intCSV++
                                                if ($OutType -eq 'CSVTEMPLATE') {
                                                    Write-PermCSV $histSDObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                } else {
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $histSDObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "3" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }
                                            }# End If
                                            Else {
                                                if ($intAclOccurence -eq 0) {
                                                    $intAclOccurence++
                                                    $bolOUHeader = $true
                                                    Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }
                                                $bolOUHeader = $false
                                                Write-ToFile -bolACLExist $true -sd $histSDObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "3" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                            }#End !$bolCSVOnly
                                        }#End Returns
                                        $histSDObject = ''
                                    }# End If $OUMatchResult
                                }# End if $OUdn
                                $index++
                            }# End While

                        } #End If If ($SDUsnCheck -eq $false)

                        #If the OU was not found in the CSV
                        If (!$OUMatchResultOverall) {

                            foreach ($sdObject in $sd) {
                                $bolMatchDef = $false
                                if ($sdObject.IdentityReference.value) {
                                    $strNTAccount = $sdObject.IdentityReference.value
                                } else {
                                    $strNTAccount = $sdObject.IdentityReference
                                }
                                If ($strNTAccount.contains('S-1-')) {
                                    $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strNTAccount -CREDS $CREDS

                                }

                                #Remove Default Permissions if SkipDefaultPerm selected
                                if ($SkipDefaultPerm -or $bolCompareDelegation) {
                                    if ($strObjectClass -ne $strTemoObjectClass) {
                                        $sdOUDef = Get-DefaultPermissions -strObjectClass $strObjectClass -CREDS $CREDS
                                    }
                                    $strTemoObjectClass = $strObjectClass
                                    $indexDef = 0
                                    while ($indexDef -le $sdOUDef.count - 1) {
                                        if (($sdOUDef[$indexDef].IdentityReference -eq $sdObject.IdentityReference) -and ($sdOUDef[$indexDef].ActiveDirectoryRights -eq $sdObject.ActiveDirectoryRights) -and ($sdOUDef[$indexDef].AccessControlType -eq $sdObject.AccessControlType) -and ($sdOUDef[$indexDef].ObjectType -eq $sdObject.ObjectType) -and ($sdOUDef[$indexDef].InheritanceType -eq $sdObject.InheritanceType) -and ($sdOUDef[$indexDef].InheritedObjectType -eq $sdObject.InheritedObjectType)) {
                                            $bolMatchDef = $true
                                        }#} #End If
                                        $indexDef++
                                    } #End While
                                }

                                if ($bolMatchDef) {
                                } else {
                                    if ($SkipDefaultPerm -or $bolCompareDelegation) {
                                        $strDelegationNotation = 'Node not in file'


                                        If (($strNTAccount -eq $global:strOwnerTemplate) -and ($sdObject.ActiveDirectoryRights -eq 'Read permissions, Modify permissions') -and ($sdObject.AccessControlType -eq 'Owner') -and ($sdObject.ObjectType -eq 'None') -and ($sdObject.InheritanceType -eq 'None') -and ($sdObject.InheritedObjectType -eq 'None')) {

                                        }#End If $newSdObject
                                        else {

                                            $MissingOUSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $sdObject.ActiveDirectoryRights; InheritanceType = $sdObject.InheritanceType; ObjectType = $sdObject.ObjectType; `
                                                    InheritedObjectType = $sdObject.InheritedObjectType; ObjectFlags = $sdObject.ObjectFlags; AccessControlType = $sdObject.AccessControlType; IdentityReference = $sdObject.IdentityReference; PrincipalName = $strNTAccount; IsInherited = $sdObject.IsInherited; `
                                                    InheritanceFlags = $sdObject.InheritanceFlags; PropagationFlags = $sdObject.PropagationFlags; State = $strDelegationNotation
                                            }
                                            $intReturned++
                                            If ($bolCSV) {
                                                $intCSV++

                                                if ($OutType -eq 'CSVTEMPLATE') {
                                                    Write-PermCSV $MissingOUSdObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                } else {
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $MissingOUSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "5" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }
                                            }# End If
                                            Else {
                                                if ($intAclOccurence -eq 0) {
                                                    $intAclOccurence++
                                                    $bolOUHeader = $true
                                                    Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }
                                                $bolOUHeader = $false
                                                Write-ToFile -bolACLExist $true -sd $MissingOUSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "5" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                            }#End !$bolCSVOnly
                                        }
                                    } else {
                                        if ($SDUsnCheck -eq $false) {
                                            $strDelegationNotation = 'Node not in file'


                                            $MissingOUSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $sdObject.ActiveDirectoryRights; InheritanceType = $sdObject.InheritanceType; ObjectType = $sdObject.ObjectType; `
                                                    InheritedObjectType = $sdObject.InheritedObjectType; ObjectFlags = $sdObject.ObjectFlags; AccessControlType = $sdObject.AccessControlType; IdentityReference = $sdObject.IdentityReference; PrincipalName = $strNTAccount; IsInherited = $sdObject.IsInherited; `
                                                    InheritanceFlags = $sdObject.InheritanceFlags; PropagationFlags = $sdObject.PropagationFlags; State = $strDelegationNotation
                                            }
                                            if (($TemplateFilter -eq 'MISSING') -or ($TemplateFilter -eq 'ALL')) {
                                                $intReturned++
                                                If ($bolCSV) {
                                                    $intCSV++
                                                    if ($OutType -eq 'CSVTEMPLATE') {
                                                        Write-PermCSV $MissingOUSdObject $strDistinguishedname $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                                    } else {
                                                        $bolOUHeader = $false
                                                        Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                }# End If
                                                Else {
                                                    if ($intAclOccurence -eq 0) {
                                                        $intAclOccurence++
                                                        $bolOUHeader = $true
                                                        Write-ToFile -bolACLExist $false -sd $sd -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                    }
                                                    $bolOUHeader = $false
                                                    Write-ToFile -bolACLExist $true -sd $MissingOUSdObject -DSObject $strDistinguishedName -Canonical $CanonicalName -strColorTemp "5" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                                }#End !$bolCSVOnly
                                            }#End Returns
                                        }
                                    }
                                }#Skip Default or bolComparedelegation
                            }#End Forech $sd
                        } #End If not OUMatchResultOverall
                    }#End Global:GetSecErr
                }#else if adobject missing name
                else {
                    $index = 0

                    while ($index -le $global:csvHistACLs.count - 1) {
                        $SDHistResult = $false

                        if ($global:csvHistACLs[$index].Object) {
                            $strOUcol = $global:csvHistACLs[$index].Object
                        } else {
                            $strOUcol = $global:csvHistACLs[$index].OU
                        }
                        if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                            $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                        }
                        if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                            $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                        }
                        if ($txtReplaceDN.text.Length -gt 0) {
                            $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                        }
                        if ($OUdnorgDN -eq $strOUcol ) {

                            $strIdentityReference = $global:csvHistACLs[$index].IdentityReference
                            if ($strIdentityReference.Contains('<DOMAIN-NETBIOS>')) {
                                $strIdentityReference = ($strIdentityReference -Replace '<DOMAIN-NETBIOS>', $global:strDomainShortName)

                            }
                            if ($strIdentityReference.Contains('<ROOT-NETBIOS>')) {
                                $strIdentityReference = ($strIdentityReference -Replace '<ROOT-NETBIOS>', $global:strRootDomainShortName)

                            }
                            if ($strIdentityReference.Contains('<DOMAINSID>')) {
                                $strIdentityReference = ($strIdentityReference -Replace '<DOMAINSID>', $global:DomainSID)

                            }
                            if ($strIdentityReference.Contains('<ROOTDOMAINSID>')) {
                                $strIdentityReference = ($strIdentityReference -Replace '<ROOTDOMAINSID>', $global:ForestRootDomainSID)

                            }
                            if ($txtReplaceNetbios.text.Length -gt 0) {
                                $strIdentityReference = ($strIdentityReference -Replace $txtReplaceNetbios.text, $global:strDomainShortName)

                            }
                            If ($strIdentityReference.contains('S-1-')) {
                                $strIdentityReference = Convert-SidToName -server $global:strDomainFQDN -Sid $strIdentityReference -CREDS $CREDS

                            }
                            $histSDObject = New-Object PSObject -Property @{ActiveDirectoryRights = $global:csvHistACLs[$index].ActiveDirectoryRights; InheritanceType = $global:csvHistACLs[$index].InheritanceType; ObjectType = $global:csvHistACLs[$index].ObjectType; `
                                    InheritedObjectType = $global:csvHistACLs[$index].InheritedObjectType; ObjectFlags = $global:csvHistACLs[$index].ObjectFlags; AccessControlType = $global:csvHistACLs[$index].AccessControlType; IdentityReference = $global:csvHistACLs[$index].IdentityReference; PrincipalName = $strNTAccount; IsInherited = $global:csvHistACLs[$index].IsInherited; `
                                    InheritanceFlags = $global:csvHistACLs[$index].InheritanceFlags; PropagationFlags = $global:csvHistACLs[$index].PropagationFlags; State = 'Node does not exist in AD'
                            }
                            $intReturned++
                            If ($bolCSV) {
                                if ($OutType -eq 'CSVTEMPLATE') {
                                    Write-PermCSV $histSDObject $DSobject.distinguishedname.toString() $CanonicalName $strObjectClass $strFileCSV $bolReplMeta $objLastChange $strOrigInvocationID $strOrigUSN $bolGetOUProtected $bolOUProtected $true $bolToFile $GPO $GPODisplayname $TranslateGUID -CREDS $CREDS
                                } else {
                                    $bolOUHeader = $false
                                    Write-ToFile -bolACLExist $true -sd $histSDObject -DSObject $strOUcol -Canonical $CanonicalName -strColorTemp "3" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                }


                            }# End If
                            Else {
                                if ($intAclOccurence -eq 0) {
                                    $intAclOccurence++
                                    $bolOUHeader = $true
                                    Write-ToFile -bolACLExist $false -sd $histSDObject -DSObject $strOUcol -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                                }
                                $bolOUHeader = $false
                                Write-ToFile -bolACLExist $true -sd $histSDObject -DSObject $strOUcol -Canonical $CanonicalName -strColorTemp "3" -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor
                            }#End !$bolCSVOnly
                            $histSDObject = ''
                        }
                        $index++
                    }
                }#End if adobject missing name
                $count++
            }# End While $AllObjectDn.count

            if (($count -gt 0)) {
                if (-not $bolCMD) {
                    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {

                        $global:ProgressBarWindow.Window.Dispatcher.invoke([action] { $global:ProgressBarWindow.Window.Close() }, 'Normal')
                    }
                }
                if ($aclcount -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show('No Permissions found!' , 'Status')
                } else {

                    if ($intReturned -gt 0) {
                        if ($bolCSV) {
                            if ($OutType -eq 'CSVTEMPLATE') {
                                if ($bolCMD) {
                                    if ($bolToFile) {
                                        Write-Host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                                        Write-Output $strFileCSV
                                    }
                                } else {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileCSV" -strType 'Warning' -DateStamp ))
                                }
                                #If Get-Perm was called with Show then open the CSV file.
                                if ($Show) {
                                    Invoke-Item $strFileCSV
                                }
                            } else {
                                if ($bolCMD) {
                                    if ($bolToFile) {
                                        $global:ArrayAllACE | Export-Csv -Path $strFileCSV -NoTypeInformation -NoClobber
                                        Write-Host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                                        Write-Output $strFileCSV
                                    } else {
                                        $global:ArrayAllACE
                                    }
                                } else {
                                    $global:ArrayAllACE | Export-Csv -Path $strFileCSV -NoTypeInformation -NoClobber
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileCSV" -strType 'Warning' -DateStamp ))
                                }
                                #If Get-Perm was called with Show then open the CSV file.
                                if ($Show) {
                                    Invoke-Item $strFileCSV
                                }
                            }
                        } else {
                            #If excel output
                            if ($OutType -eq 'EXCEL') {
                                # Array with alphabet characters
                                $ExcelColumnAlphabet = @()
                                for ([byte]$c = [char]'A'; $c -le [char]'Z'; $c++) {
                                    $ExcelColumnAlphabet += [char]$c
                                }

                                if ($bolShowCriticalityColor) {

                                    #Define Column name for "criticality" by using position in array
                                    $RangeColumnCriticality = $ExcelColumnAlphabet[$(($global:ArrayAllACE | Get-Member -MemberType NoteProperty ).count - 1 )]
                                    #Define Column name for "state" by using position in array
                                    $RangeColumnState = $ExcelColumnAlphabet[$(($global:ArrayAllACE | Get-Member -MemberType NoteProperty ).count - 2 )]

                                    $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode + '_ACL') -BoldTopRow -TableStyle Medium2 -TableName $($strNode + 'acltbl') -NoLegend -AutoSize -FreezeTopRow -ConditionalText $(
                                        New-ConditionalText -RuleType Equal -ConditionValue Low -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor DeepSkyBlue -ConditionalTextColor Black
                                        New-ConditionalText -RuleType Equal -ConditionValue Critical -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Red -ConditionalTextColor Black
                                        New-ConditionalText -RuleType Equal -ConditionValue Warning -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Gold -ConditionalTextColor Black
                                        New-ConditionalText -RuleType Equal -ConditionValue Medium -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Yellow -ConditionalTextColor Black
                                        New-ConditionalText -RuleType Equal -ConditionValue Info -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor LightGray -ConditionalTextColor Black
                                        New-ConditionalText Missing -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Red -ConditionalTextColor Black
                                        New-ConditionalText Match -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Green -ConditionalTextColor Black
                                        New-ConditionalText New -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Yellow -ConditionalTextColor Black
                                    )
                                } else {
                                    #Define Column name for "state" by using position in array
                                    $RangeColumnState = $ExcelColumnAlphabet[$(($global:ArrayAllACE | Get-Member -MemberType NoteProperty ).count - 1 )]

                                    $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode + '_ACL') -BoldTopRow -TableStyle Medium2 -TableName $($strNode + 'acltbl') -NoLegend -AutoSize -FreezeTopRow -Append -ConditionalText $(
                                        New-ConditionalText Missing -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Red -ConditionalTextColor Black
                                        New-ConditionalText Match -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Green -ConditionalTextColor Black
                                        New-ConditionalText New -Range "$($RangeColumnState):$($RangeColumnState)" -BackgroundColor Yellow -ConditionalTextColor Black
                                    )
                                }

                                if ($bolCMD) {
                                    Write-Host "Report saved in: $strFileEXCEL" -ForegroundColor Yellow
                                    Write-Output $strFileEXCEL
                                } else {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Report saved in $strFileEXCEL" -strType 'Warning' -DateStamp ))
                                }
                            }#End if EXCEL
                            else {
                                if ($bolShowCriticalityColor) {
                                    Switch ($global:intShowCriticalityLevel) {
                                        0 {
                        (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
                        (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
                                        }
                                        1 {
                        (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
                        (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
                                        }
                                        2 {
                        (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
                        (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
                                        }
                                        3 {
                        (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
                        (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
                                        }
                                        4 {
                        (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
                        (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
                                        }
                                    }
                                }
                                #If Get-Perm was called with Show then open the HTA file.
                                if ($Show) {
                                    try {
                                        Invoke-Item $strFileHTA
                                    } catch {
                                        if ($bolCMD) {
                                            Write-Host 'Failed to launch MSHTA.exe' -ForegroundColor Red
                                            Write-Host "Instead opening the following file directly: $strFileHTM" -ForegroundColor Yellow
                                        } else {
                                            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Failed to launch MSHTA.exe' -strType 'Error' -DateStamp ))
                                            $global:observableCollection.Insert(0, (LogMessage -strMessage "Instead opening the following file directly: $strFileHTM" -strType 'Ino' -DateStamp ))
                                        }
                                        Invoke-Item $strFileHTM
                                    }
                                }
                            }
                        }
                    } else {
                        if ($bolCMD) {
                            Write-Host 'No results' -ForegroundColor Red
                        } else {
                            $global:observableCollection.Insert(0, (LogMessage -strMessage 'No results' -strType 'Error' -DateStamp ))
                        }
                    }
                }# End If
            } else {
                [System.Windows.Forms.MessageBox]::Show('No objects found!' , 'Status')


            }
        }#End if ExitCompare
    }# End Try


    $histSDObject = ''
    $sdObject = ''
    $MissingOUSdObject = ''
    $newSdObject = ''
    $DSobject = ''
    $global:strOwner = ''
    $global:csvHistACLs = ''


    $secd = $null
    Remove-Variable -Name 'secd' -Scope Global
}

#==========================================================================
# Function		:  ConvertCSVtoHTM
# Arguments     : Fle Path
# Returns   	: N/A
# Description   : Convert CSV file to HTM Output
#==========================================================================
Function ConvertCSVtoHTM {
    Param($CSVInput, [boolean] $bolGUIDtoText, [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $OutputFormat = 'HTML'
    $bolReplMeta = $false
    $bolCompare = $false
    $bolFilter = $false
    $bolACLsize = $false
    $bolGetOUProtected = $false
    $bolOUProtected = $false

    if(($null -eq $global:ForestRootDomainSID) -or ($global:ForestRootDomainSID -eq '')) {
        $forestdata = New-LDAPSearch -Server $Global:ForestObject.Domain -creds $CREDS  -LDAPFilter "(objectClass=*)" -Scope base -BaseDN $global:ForestRootDomainDN -Attributes "objectsid"

        if($forestdata) {
            $objectForestSid = [byte[]]$forestdata.Attributes.objectsid[0]
            $global:ForestRootDomainSID = (New-Object System.Security.Principal.SecurityIdentifier($objectForestSid, 0)).value
        } else  {
            $global:ForestRootDomainSID = ''
        }
    }

    if ($chkBoxSeverity.isChecked -or $chkBoxEffectiveRightsColor.isChecked) {
        $bolShowCriticalityColor = $true
    } else {
        $bolShowCriticalityColor = $false
    }
    If (Test-Path $CSVInput) {

        $fileName = $(Get-ChildItem $CSVInput).BaseName
        $strFileHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'
        $strFileHTM = $env:temp + '\' + "$fileName" + '.htm'

        $global:csvHistACLs = Import-Csv $CSVInput
        #Test CSV file format



        if (TestCSVColumns $global:csvHistACLs) {
            If ($global:csvHistACLs[0].SDDate.length -gt 1) {
                $bolReplMeta = $true
            }

            $colHeaders = ( $global:csvHistACLs | Get-Member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')
            $bolObjType = $false
            Foreach ($ColumnName in $colHeaders ) {

                if ($ColumnName.Trim() -eq 'ObjectClass') {
                    $bolObjType = $true
                }
            }

            CreateHTM $fileName $strFileHTM
            CreateHTA $fileName $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
            $UseCanonicalName = $chkBoxUseCanonicalName.IsChecked
            InitiateHTM $strFileHTM $fileName $fileName $bolReplMeta $false $Protected $bolShowCriticalityColor $false $false $false $strCompareFile $false $false $bolObjType -bolCanonical:$UseCanonicalName $GPO
            InitiateHTM $strFileHTA $fileName $fileName $bolReplMeta $false $Protected $bolShowCriticalityColor $false $false $false $strCompareFile $false $false $bolObjType -bolCanonical:$UseCanonicalName $GPO



            $tmpOU = ''
            $index = 0
            while ($index -le $global:csvHistACLs.count - 1) {

                if ($global:csvHistACLs[$index].Object) {
                    $strOUcol = $global:csvHistACLs[$index].Object
                } else {
                    $strOUcol = $global:csvHistACLs[$index].OU
                }

                if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                    $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                }

                if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                    $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)
                }


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

                If ($bolReplMeta -eq $true) {
                    $objLastChange = $global:csvHistACLs[$index].SDDate
                }

                If ($UseCanonicalName -eq $true) {
                    $CanonicalName = $global:csvHistACLs[$index].CanonicalName

                }


                If ($bolObjType -eq $true) {

                    $strObjectClass = $global:csvHistACLs[$index].ObjectClass
                }
                if ($strTrustee.Contains('<DOMAIN-NETBIOS>')) {
                    $strTrustee = ($strTrustee -Replace '<DOMAIN-NETBIOS>', $global:strDomainShortName)

                }
                if ($strTrustee.Contains('<ROOT-NETBIOS>')) {
                    $strTrustee = ($strTrustee -Replace '<ROOT-NETBIOS>', $global:strRootDomainShortName)

                }
                if ($strTrustee.Contains('<DOMAINSID>')) {
                    $strTrustee = ($strTrustee -Replace '<DOMAINSID>', $global:DomainSID)

                }
                if ($strTrustee.Contains('<ROOTDOMAINSID>')) {
                    $strTrustee = ($strTrustee -Replace '<ROOTDOMAINSID>', $global:ForestRootDomainSID)

                }
                $txtSdObject = New-Object PSObject -Property @{ActiveDirectoryRights = $strRights; InheritanceType = $strInheritanceType; ObjectType = $strObjectTypeGUID; `
                        InheritedObjectType = $strInheritedObjectTypeGUID; ObjectFlags = $strObjectFlags; AccessControlType = $strAccessControlType; IdentityReference = $strTrustee; IsInherited = $strIsInherited; `
                        InheritanceFlags = $strInheritedFlags; PropagationFlags = $strPropFlags
                }

                If ($strColorTemp -eq '1') {
                    $strColorTemp = '2'
                }# End If
                else {
                    $strColorTemp = '1'
                }# End If
                if ($tmpOU -ne $strOU) {

                    $bolOUHeader = $true
                    Write-ToFile -bolACLExist $true -sd $txtSdObject -DSObject $strOU -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor


                    $tmpOU = $strOU
                } else {
                    $bolOUHeader = $false
                    Write-ToFile -bolACLExist $true -sd $txtSdObject -DSObject $strOU -Canonical $CanonicalName -strColorTemp $strColorTemp -boolReplMetaDate $bolReplMeta -strReplMetaDate $objLastChange -strObjClass $strObjectClass -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion -bolShowOUProtected $bolGetOUProtected -bolOUPRotected $bolOUProtected -boolACLSize $bolACLsize -strACLSize $strACLSize -CompareMode $bolCompare -OUHeader $bolOUHeader -FilterMode $bolFilter -bolTranslateGUID $bolGUIDtoText -GPO $GPO -GPODisplayname $GPOdisplayname -strSDDL $strSDDL -htmfileout $strFileHTA -bolCriticalityLevel $ShowCriticalityColor


                }

                $index++

            }#End While


            if ($bolShowCriticalityColor) {
                Switch ($global:intShowCriticalityLevel) {
                    0 {
                (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "grey">INFO' | Set-Content $strFileHTM
                    }
                    1 {
                (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "blue">LOW' | Set-Content $strFileHTM
                    }
                    2 {
                (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileHTM
                    }
                    3 {
                (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileHTM
                    }
                    4 {
                (Get-Content $strFileHTA) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTA
                (Get-Content $strFileHTM) -replace '20141220T021111056594002014122000', '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileHTM
                    }
                }
            }

            Invoke-Item $strFileHTA
        }#else if test column names exist
        else {
            $global:observableCollection.Insert(0, (LogMessage -strMessage "CSV file got wrong format! File:  $CSVInput" -strType 'Error' -DateStamp ))
        } #End if test column names exist
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage "Failed! $CSVInput does not exist!" -strType 'Error' -DateStamp ))
    }

}# End Function


#==========================================================================
# Function		: Get-ACLMeta
# Arguments     : Domain Controller, AD Object DN 
# Returns   	: Semi-colon separated string
# Description   : Get AD Replication Meta data LastOriginatingChange, LastOriginatingDsaInvocationID
#                  usnOriginatingChange and returns as string
#==========================================================================
Function Get-ACLMeta {
    Param($DomainController, $objDN,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    $objACLMeta = [pscustomobject][ordered]@{
    LastChangeDate = "" ;`
    InvocationID = "" ;`
    OriginatingChange = "";`
    Version = ""}

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($objDN, '(name=*)', 'base')
    $SecurityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' #-bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
    $control = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($SecurityMasks)
    [void]$request.Controls.Add($control)
    [void]$request.Attributes.Add('ntsecuritydescriptor')
    [void]$request.Attributes.Add('name')

    [void]$request.Attributes.Add('msDS-ReplAttributeMetaData')
    $response = $LDAPConnection.SendRequest($request)

    foreach ($entry  in $response.Entries) {

        $index = 0
        while ($index -le $entry.attributes.'msds-replattributemetadata'.count - 1) {
            $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
            $childMember = $childMember.replace("$($childMember[-1])", '')
            If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq 'nTSecurityDescriptor') {
                $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                $strInvocationID = $([xml]$childMember).DS_REPL_ATTR_META_DATA.uuidLastOriginatingDsaInvocationID
                $strOriginatingChange = $([xml]$childMember).DS_REPL_ATTR_META_DATA.usnOriginatingChange
            }
            $index++
        }
    }
    if ($strLastChangeDate -eq $nul) {
        $ACLdate = $(Get-Date '1601-01-01' -UFormat '%Y-%m-%d %H:%M:%S')
        $strInvocationID = '00000000-0000-0000-0000-000000000000'
        $strOriginatingChange = '000000'
    } else {
        $ACLdate = $(Get-Date $strLastChangeDate -UFormat '%Y-%m-%d %H:%M:%S')
    }

    $objACLMeta.LastChangeDate = $ACLdate    
    $objACLMeta.InvocationID = $strInvocationID
    $objACLMeta.OriginatingChange = $strOriginatingChange
    $objACLMeta.Version = $strVersion

  return $objACLMeta
}

#==========================================================================
# Function		: Get-DefaultSD
# Arguments     : string ObjectClass
# Returns   	:
# Description   : Create report of default Security Descriptor
#==========================================================================
Function Get-DefaultSD {
  Param( [String[]] $strObjectClass,
    [bool] $bolChangedDefSD,
    [bool]$bolSDDL,
    [string]$File,
    [boolean]$Show,
    [string] $OutType,
    [bool]$bolShowCriticalityColor,
    [bool]$Assess,
    [string]$Criticality,
    [bool]$FilterBuiltin,
    [bool]$bolReplMeta,
    [Parameter(Mandatory=$false)]
    [pscredential] 
    $CREDS)

    if(($OutType -eq "CSVTEMPLATE") -or ($OutType -eq "CSV")) {
        $bolCSV = $true
        $bolToFile = $True
        If ((Test-Path $File) -eq $true) {
            Remove-Item $File
        }
    } else {
        $bolCSV = $false
        $bolToFile = $False
    }


    $bolOUHeader = $true

    $bolCompare = $false
    $intNumberofDefSDFound = 0
    $global:ArrayAllACE = New-Object System.Collections.ArrayList


    $strColorTemp = 1

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('msds-replattributemetadata')

    $CountadObject = 0
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

        $CountadObject = $CountadObject + $response.Entries.Count

        if ($global:PageSize -gt 0) {
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

    #Load Progressbar
    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
        $intTot = 0
        #calculate percentage
        $intTot = $CountadObject
        if ($intTot -gt 0) {
            LoadProgressBar

        }
    }

    $response = $null




    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('msds-replattributemetadata')
    if($UseCanonicalName) {
        [void]$request.Attributes.Add("canonicalname")
    }    

    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

        foreach ($entry  in $response.Entries) {

            #Update Progressbar
            if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                $i++
                [int]$pct = ($i / $intTot) * 100
                #Update the progress bar
                while (($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20)) {
                    Start-Sleep -Milliseconds 1
                    $cc++
                }
                if ($global:ProgressBarWindow.Window.IsInitialized -eq $true) {
                    Update-ProgressBar "Currently scanning $i of $intTot objects" $pct
                }

            }

            if($UseCanonicalName) {
                if($entry.attributes.canonicalname) {
                    $CanonicalName = $entry.attributes.canonicalname[0]
                } else {
                    $CanonicalName = Create-CanonicalName  $entry.distinguishedname.toString()
                }
            }

            $index = 0
            while($index -le $entry.attributes.'msds-replattributemetadata'.count -1) {
                $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
                $childMember = $childMember.replace("$($childMember[-1])","")
                If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq "defaultSecurityDescriptor") {
                    $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                    $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                    if ($strLastChangeDate -eq $nul) {
                        $strLastChangeDate = $(get-date "1601-01-01" -UFormat "%Y-%m-%d %H:%M:%S")
     
                    } else {
                        $strLastChangeDate = $(get-date $strLastChangeDate -UFormat "%Y-%m-%d %H:%M:%S")
                    }             
                }

                $index++

            } 

            if ($bolChangedDefSD -eq $true) {

                if ($strVersion -gt 1) {
                    $strObjectClassName = $entry.Attributes.name[0]
                    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity

                    if ($bolSDDL -eq $true) {
                        $strSDDL = ''
                        if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                            $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
                        }
                        #Indicate that a defaultsecuritydescriptor was found
                        $intNumberofDefSDFound++
                        WriteDefSDSDDLHTM $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $strObjectClassName $strVersion $strLastChangeDate $strSDDL
                        Switch ($strColorTemp) {

                            '1' {
                                $strColorTemp = '2'
                            }
                            '2' {
                                $strColorTemp = '1'
                            }
                        }
                    } else {
                        $sd = ''
                        if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                            $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                        }
                        $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

                        # Filter out Builtin SIDs
                        if ($FilterBuiltin) {
                            # Filter out default and built-in security principals
                            $sd = @($sd | Where-Object {`
                                    ($_.IdentityReference -match 'S-1-5-21-') -and `
                                    ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^5\d{2}$')) -and
                        ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^4\d{2}$'))
                                })
                        }

                        If ($Assess) {
                            Switch ($Criticality) {
                                'Info' {
                                    $CriticalityFilter = 0
                                }
                                'Low' {
                                    $CriticalityFilter = 1
                                }
                                'Medium' {
                                    $CriticalityFilter = 2
                                }
                                'Warning' {
                                    $CriticalityFilter = 3
                                }
                                'Critical' {
                                    $CriticalityFilter = 4
                                }
                            }
                            $sd = @($sd | Where-Object { Get-Criticality -Returns 'Filter' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() $CriticalityFilter })
                        }

                        #Indicate that a defaultsecuritydescriptor was found
                        $intNumberofDefSDFound++

                If ($bolCSV)
                {
                    if($OutType -eq "CSVTEMPLATE") {
                        Write-PermCSVTemplate -sd $sd -object $entry.distinguishedName -canonical $CanonicalName -objType $strObjectClassName -fileout $File -ACLMeta $bolReplMeta -strACLDate $strLastChangeDate -strInvocationID $strOrigInvocationID -strOrgUSN $strOrigUSN -Outfile $true -GPO $GPO -GPOdisplayname $GPOdisplayname -CREDS $CREDS
                    } else {
                        $OutputFormat = "Object"
                        Write-ToFile -bolACLExist $True -sd $sd -DSObject $entry.distinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $strLastChangeDate -strObjClass $strObjectClassName -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion
                    }
                    } else {
                            Write-DefSDAccessHTM -bolACLExist $true -sd $sd -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                        }
                    }

                }
            } else {

                $strObjectClassName = $entry.Attributes.name[0]
                $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                if ($bolSDDL -eq $true) {
                    $strSDDL = ''
                    if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                        $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
                    }
                    #Indicate that a defaultsecuritydescriptor was found
                    $intNumberofDefSDFound++
                    WriteDefSDSDDLHTM $strColorTemp $strFileDefSDHTA $strFileDefSDHTM $strObjectClassName $strVersion $strLastChangeDate $strSDDL
                    Switch ($strColorTemp) {

                        '1' {
                            $strColorTemp = '2'
                        }
                        '2' {
                            $strColorTemp = '1'
                        }
                    }
                } else {
                    $sd = ''
                    if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                        Try {
                            $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                        } catch {

                            if ($bolCMD) {
                                Write-Host 'The SDDL string contains an invalid sid or a sid that cannot be translated.' -ForegroundColor Red
                                Write-Host 'Only domain-joined computers can translate some sids.' -ForegroundColor Red
                            } else {
                                $global:observableCollection.Insert(0, (LogMessage -strMessage 'The SDDL string contains an invalid sid or a sid that cannot be translated.' -strType 'Error' -DateStamp ))
                                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Only domain-joined computers can translate some sids.' -strType 'Error' -DateStamp ))
                            }
                        }
                    

                        $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                        #If any access has been added report it
                        if ($sd.count -gt 0) {

                            
                            # Filter out Builtin SIDs
                            if ($FilterBuiltin) {
                                # Filter out default and built-in security principals
                                $sd = @($sd | Where-Object {`
                                        ($_.IdentityReference -match 'S-1-5-21-') -and `
                                        ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^5\d{2}$')) -and
                            ($_.IdentityReference.value.tostring().split('-')[-1] -notmatch $('^4\d{2}$'))
                                    })
                            }

                            If ($Assess) {
                                Switch ($Criticality) {
                                    'Info' {
                                        $CriticalityFilter = 0
                                    }
                                    'Low' {
                                        $CriticalityFilter = 1
                                    }
                                    'Medium' {
                                        $CriticalityFilter = 2
                                    }
                                    'Warning' {
                                        $CriticalityFilter = 3
                                    }
                                    'Critical' {
                                        $CriticalityFilter = 4
                                    }
                                }
                                $sd = @($sd | Where-Object { Get-Criticality -Returns 'Filter' $_.IdentityReference.toString() $_.ActiveDirectoryRights.toString() $_.AccessControlType.toString() $_.ObjectFlags.toString() $_.InheritanceType.toString() $_.ObjectType.toString() $_.InheritedObjectType.toString() $CriticalityFilter })
                            }

                            #Indicate that a defaultsecuritydescriptor was found
                            $intNumberofDefSDFound++

                            If ($bolCSV) {
                                if($OutType -eq "CSVTEMPLATE") {
                                    Write-DefSDPermCSV $sd $entry.distinguishedName $strObjectClassName $File $bolReplMeta $strVersion $strLastChangeDate $BolToFile $bolShowCriticalityColor -CREDS $CREDS
                                } else {
                                    $OutputFormat = "Object"
                                    Write-ToFile -bolACLExist $True -sd $sd -DSObject $entry.distinguishedName -Canonical $CanonicalName -boolReplMetaDate $bolReplMeta -strReplMetaDate $strLastChangeDate -strObjClass $strObjectClassName  -Type $OutputFormat -bolShowCriticalityColor $bolShowCriticalityColor -CREDS $CREDS -Version $strVersion
                                }
                            } else {
                                Write-DefSDAccessHTM -bolACLExist $true -sd $sd -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                            }
                        }#End if $sd count gt 0
                    }#End if defaultsecuritydescriptor exist
                }#End if bolSDDL
            }
        }

        if ($global:PageSize -gt 0) {
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

    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
        $global:ProgressBarWindow.Window.Dispatcher.invoke([action] { $global:ProgressBarWindow.Window.Close() }, 'Normal')
        $ProgressBarWindow = $null
        Remove-Variable -Name 'ProgressBarWindow' -Scope Global
    }
if (($intNumberofDefSDFound -gt 0))
{

    if($bolCSV)
    {
        if($OutType -eq "CSVTEMPLATE")
        {
            if($bolCMD)
            {
                if($bolToFile)
                {
                    Write-host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                    Write-output $strFileCSV
                }
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileCSV" -strType "Warning" -DateStamp ))
            }
            #If Get-Perm was called with Show then open the CSV file.
            if($Show)
            {
	            Invoke-Item $strFileCSV
            }
        }
        else
        {
            if($bolCMD)
            {
                if($bolToFile)
                {
                    $global:ArrayAllACE | export-csv -Path $strFileCSV -NoTypeInformation -NoClobber
                    Write-host "Report saved in: $strFileCSV" -ForegroundColor Yellow
                    Write-output $strFileCSV
                }
                else
                {
                    $global:ArrayAllACE
                }
            }
            else
            {
                $global:ArrayAllACE | export-csv -Path $strFileCSV -NoTypeInformation -NoClobber
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileCSV" -strType "Warning" -DateStamp ))
            }
            #If Get-Perm was called with Show then open the CSV file.
            if($Show)
            {
	            Invoke-Item $strFileCSV
            }
        }
    }
    else
    {
        #If excel output
        if($OutType -eq "EXCEL")
        {
            $tablename  = $($strNode+"acltbl") -replace '[^a-zA-Z]+',''

            if($bolShowCriticalityColor)
            {
                # Array with alphabet characters
                $ExcelColumnAlphabet = @()  
                for ([byte]$c = [char]'A'; $c -le [char]'Z'; $c++)  
                {  
                    $ExcelColumnAlphabet += [char]$c  
                }  
                
                #Define Column name for "criticality" by using position in array
                $RangeColumnCriticality = $ExcelColumnAlphabet[$(($global:ArrayAllACE | get-member -MemberType NoteProperty ).count -1 )]

                $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode+"_ACL") -BoldTopRow -TableStyle Medium2 -TableName $($strNode+"acltbl") -NoLegend -AutoSize -FreezeTopRow -ConditionalText $( 
                New-ConditionalText -RuleType Equal -ConditionValue Low -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor DeepSkyBlue -ConditionalTextColor Black
                New-ConditionalText -RuleType Equal -ConditionValue Critical -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Red -ConditionalTextColor Black
                New-ConditionalText -RuleType Equal -ConditionValue Warning -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Gold -ConditionalTextColor Black
                New-ConditionalText -RuleType Equal -ConditionValue Medium -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor Yellow -ConditionalTextColor Black
                New-ConditionalText -RuleType Equal -ConditionValue Info -Range "$($RangeColumnCriticality):$($RangeColumnCriticality)" -BackgroundColor LightGray -ConditionalTextColor Black
                )
            }
            else
            {
                $global:ArrayAllACE | Export-Excel -path $strFileEXCEL -WorkSheetname $($strNode+"_ACL") -BoldTopRow -TableStyle Medium2 -TableName $tablename -NoLegend -AutoSize -FreezeTopRow -Append
            }

            if($bolCMD)
            {
                Write-host "Report saved in: $strFileEXCEL" -ForegroundColor Yellow
                Write-output $strFileEXCEL
            }
            else
            {
                $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $strFileEXCEL" -strType "Warning" -DateStamp ))
            }
            if($Show)
            {
                If (test-path HKLM:SOFTWARE\Classes\Excel.Application) 
                {
	                Invoke-Item $strFileEXCEL
                }
            }
        }#End if EXCEL
        else
        {
            if($bolShowCriticalityColor)
            {
                Switch ($global:intShowCriticalityLevel)
                {
                    0
                    {
                    (Get-Content $strFileDefSDHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileDefSDHTA
                    (Get-Content $strFileDefSDHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "grey">INFO' | Set-Content $strFileDefSDHTM
                    }
                    1
                    {
                    (Get-Content $strFileDefSDHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileDefSDHTA
                    (Get-Content $strFileDefSDHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "blue">LOW' | Set-Content $strFileDefSDHTM
                    }
                    2
                    {
                    (Get-Content $strFileDefSDHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileDefSDHTA
                    (Get-Content $strFileDefSDHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "yellow">MEDIUM' | Set-Content $strFileDefSDHTM
                    }
                    3
                    {
                    (Get-Content $strFileDefSDHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileDefSDHTA
                    (Get-Content $strFileDefSDHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "orange">WARNING' | Set-Content $strFileDefSDHTM
                    }
                    4
                    {
                    (Get-Content $strFileDefSDHTA) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileDefSDHTA
                    (Get-Content $strFileDefSDHTM) -replace "20141220T021111056594002014122000", '<FONT size="6" color= "red">CRITICAL' | Set-Content $strFileDefSDHTM
                    }
                }
            }
            

            #If Get-Perm was called with Show then open the HTA file.
            if($Show)
            {
	            try
                {
                    Invoke-Item $strFileDefSDHTA
                }
                catch
                {
                    if($bolCMD)
                    {
                        Write-host "Failed to launch MSHTA.exe" -ForegroundColor Red
                        Write-host "Instead opening the following file directly: $strFileDefSDHTM" -ForegroundColor Yellow
                    }
                    else
                    {
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Failed to launch MSHTA.exe" -strType "Error" -DateStamp ))
                        $global:observableCollection.Insert(0,(LogMessage -strMessage "Instead opening the following file directly: $strFileDefSDHTM" -strType "Ino" -DateStamp ))
                    }   
                    invoke-item $strFileDefSDHTM
                }
            }
            else
            {
                if($bolCMD)
                {
                    Write-host "Report saved in: $strFileDefSDHTM" -ForegroundColor Yellow
                    Write-output $strFileDefSDHTM
                }

            }
            
        }
    }

}
else
{
    $global:observableCollection.Insert(0,(LogMessage -strMessage "No objects found!" -strType "Error" -DateStamp ))
}
}

#==========================================================================
# Function		: Get-DefaultSDCompare
# Arguments     : string ObjectClass
# Returns   	:
# Description   : Compare the default Security Descriptor
#==========================================================================
Function Get-DefaultSDCompare {
    Param( [String[]] $strObjectClass = '*',
        [string] $strTemplate,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )
    $strFileDefSDHTA = $env:temp + '\' + $global:ModifiedDefSDAccessFileName + '.hta'
    $strFileDefSDHTM = $env:temp + '\' + $global:ModifiedDefSDAccessFileName + '.htm'
    #Set type to HTML
    $OutType = "HTML"
    $bolOUHeader = $true
    $bolReplMeta = $true
    $bolCompare = $true
    #Indicator that a defaultsecuritydescriptor was found
    if($chkBoxSeverity.isChecked -or $chkBoxEffectiveRightsColor.isChecked) {
        $bolShowCriticalityColor = $true
    } else {
        $bolShowCriticalityColor = $false
    }

    if(Test-Path -Path $strTemplate) {
        $csvdefSDTemplate = Import-CSV -Path $strTemplate
    }

    $intNumberofDefSDFound = 0

    CreateHTM 'strObjectClass' $strFileDefSDHTM
    CreateHTA "$strObjectClass" $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath $global:strDomainDNName $global:strDC
    Initialize-DefSDAccessHTM $strFileDefSDHTA $strObjectClass $bolReplMeta $true $strTemplate
    Initialize-DefSDAccessHTM $strFileDefSDHTM $strObjectClass $bolReplMeta $true $strTemplate

    #Default color
    $strColorTemp = 1

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('msds-replattributemetadata')

    $CountadObject = 0
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

        $CountadObject = $CountadObject + $response.Entries.Count

        if ($global:PageSize -gt 0) {
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

    #Load Progressbar
    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
        $intTot = 0
        #calculate percentage
        $intTot = $CountadObject
        if ($intTot -gt 0) {
            LoadProgressBar

        }
    }


    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('msds-replattributemetadata')

    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

        foreach ($entry  in $response.Entries) {
            $ObjectMatchResult = $false
            #Update Progressbar
            if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
                $i++
                [int]$pct = ($i / $intTot) * 100
                #Update the progress bar
                while (($null -eq $global:ProgressBarWindow.Window.IsInitialized) -and ($intLoop -lt 20)) {
                    Start-Sleep -Milliseconds 1
                    $cc++
                }
                if ($global:ProgressBarWindow.Window.IsInitialized -eq $true) {
                    Update-ProgressBar "Currently scanning $i of $intTot objects" $pct
                }

            }
            #Counter for Metadata
            $index = 0
            #Get metadata for defaultSecurityDescriptor
            while ($index -le $entry.attributes.'msds-replattributemetadata'.count - 1) {
                $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
                $childMember = $childMember.replace("$($childMember[-1])", '')
                If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq 'defaultSecurityDescriptor') {
                    $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                    $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                    if ($strLastChangeDate -eq $nul) {
                        $strLastChangeDate = $(Get-Date '1601-01-01' -UFormat '%Y-%m-%d %H:%M:%S')

                    } else {
                        $strLastChangeDate = $(Get-Date $strLastChangeDate -UFormat '%Y-%m-%d %H:%M:%S')
                    }
                }
                $index++
            }
            #Get object name
            $strObjectClassName = $entry.Attributes.name[0]


            #Make sure strSDDL is empty
            $strSDDL = ''
            if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
            }
            $index = 0
            #Enumerate template file
            $ObjectMatchResult = $false
            while ($index -le $csvdefSDTemplate.count - 1) {
                $strNamecol = $csvdefSDTemplate[$index].Name
                #Check for matching object names
                if ($strObjectClassName -eq $strNamecol ) {
                    $ObjectMatchResult = $true
                    $strSDDLcol = $csvdefSDTemplate[$index].SDDL
                    #Replace any <ROOT-DOAMIN> strngs with Forest Root Domain SID
                    if ($strSDDLcol.Contains('<ROOTDOMAINSID>')) {
                        if ($global:ForestRootDomainSID -gt '') {
                            $strSDDLcol = $strSDDLcol.Replace('<ROOTDOMAINSID>', $global:ForestRootDomainSID)
                        }
                    }
                    #Compare SDDL
                    if ($strSDDL -eq $strSDDLcol) {
                        $sd = ''
                        #Create ad security object
                        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                            $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                        }
                        $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                        #Count ACE for applying header on fist
                        $intACEcount = 0
                        foreach ($ObjectDefSD in $sd) {
                            $strNTAccount = $ObjectDefSD.IdentityReference.toString()
                            If ($strNTAccount.contains('S-1-')) {
                                $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strNTAccount -CREDS $CREDS

                            }
                            $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights = $ObjectDefSD.ActiveDirectoryRights; InheritanceType = $ObjectDefSD.InheritanceType; ObjectType = $ObjectDefSD.ObjectType; `
                                    InheritedObjectType = $ObjectDefSD.InheritedObjectType; ObjectFlags = $ObjectDefSD.ObjectFlags; AccessControlType = $ObjectDefSD.AccessControlType; IdentityReference = $strNTAccount; IsInherited = $ObjectDefSD.IsInherited; `
                                    InheritanceFlags = $ObjectDefSD.InheritanceFlags; PropagationFlags = $ObjectDefSD.PropagationFlags; State = 'Match'
                            }

                            #Matching color "green"
                            $strColorTemp = 4
                            #If first ACE add header
                            if ($intACEcount -eq 0) {
                                #Indicate that a defaultsecuritydescriptor was found
                                $intNumberofDefSDFound++
                                $bolOUHeader = $true
                                Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                            } else {
                                $bolOUHeader = $false
                                Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                            }
                            #Count ACE to not ad a header
                            $intACEcount++
                        }
                        $newObjectDefSD = $null
                        $sd = $null
                        $sec = $null
                    } else {
                        $sd = ''
                        #Create ad security object
                        $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                            $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                        }
                        $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                        #Count ACE for applying header on fist
                        $intACEcount = 0
                        #Comare DefaultSecurityDesriptor in schema with template looking for matching and new ACE's
                        foreach ($ObjectDefSD in $sd) {
                            #Check if matchin ACE exits, FALSE until found
                            $SDCompareResult = $false

                            $strNTAccount = $ObjectDefSD.IdentityReference.toString()
                            If ($strNTAccount.contains('S-1-')) {
                                $strNTAccount = Convert-SidToName -server $global:strDomainFQDN -Sid $strNTAccount -CREDS $CREDS

                            }

                            $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights = $ObjectDefSD.ActiveDirectoryRights; InheritanceType = $ObjectDefSD.InheritanceType; ObjectType = $ObjectDefSD.ObjectType; `
                                    InheritedObjectType = $ObjectDefSD.InheritedObjectType; ObjectFlags = $ObjectDefSD.ObjectFlags; AccessControlType = $ObjectDefSD.AccessControlType; IdentityReference = $strNTAccount; IsInherited = $ObjectDefSD.IsInherited; `
                                    InheritanceFlags = $ObjectDefSD.InheritanceFlags; PropagationFlags = $ObjectDefSD.PropagationFlags; State = 'New'
                            }

                            $sdFile = ''
                            #Create ad security object
                            $secFile = New-Object System.DirectoryServices.ActiveDirectorySecurity
                            if ($null -ne $strSDDLcol) {
                                try {
                                $secFile.SetSecurityDescriptorSddlForm($strSDDLcol)
                                }
                                catch
                                {
                                    if ($bolCMD) {
                                        Write-host "Could not import SDDL for Schema Object $strNamecol. Error:`n$($_.Exception.InnerException.Message.ToString())"
                                    } else {
                                        $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not import SDDL for Schema Object $strNamecol. Error:`n$($_.Exception.InnerException.Message.ToString())" -strType 'Warning' -DateStamp ))
                                    }
                                }
                            }
                            $sdFile = $secFile.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                            foreach ($ObjectDefSDFile in $sdFile) {
                                If (($newObjectDefSD.IdentityReference -eq $ObjectDefSDFile.IdentityReference) -and ($newObjectDefSD.ActiveDirectoryRights -eq $ObjectDefSDFile.ActiveDirectoryRights) -and ($newObjectDefSD.AccessControlType -eq $ObjectDefSDFile.AccessControlType) -and ($newObjectDefSD.ObjectType -eq $ObjectDefSDFile.ObjectType) -and ($newObjectDefSD.InheritanceType -eq $ObjectDefSDFile.InheritanceType) -and ($newObjectDefSD.InheritedObjectType -eq $ObjectDefSDFile.InheritedObjectType)) {
                                    $SDCompareResult = $true
                                }
                            }
                            if ($SDCompareResult) {
                                #Change from New to Match
                                $newObjectDefSD.State = 'Match'
                                #Match color "Green"
                                $strColorTemp = 4
                                #If first ACE add header
                                if ($intACEcount -eq 0) {
                                    #Indicate that a defaultsecuritydescriptor was found
                                    $intNumberofDefSDFound++
                                    $bolOUHeader = $true
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                                } else {
                                    $bolOUHeader = $false
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                                }
                                #Count ACE to not ad a header
                                $intACEcount++
                            } else {
                                #New color "Yellow"
                                $strColorTemp = 5
                                #If first ACE add header
                                if ($intACEcount -eq 0) {
                                    #Indicate that a defaultsecuritydescriptor was found
                                    $intNumberofDefSDFound++
                                    $bolOUHeader = $true
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                                } else {
                                    $bolOUHeader = $false
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                                }
                                #Count ACE to not ad a header
                                $intACEcount++
                            }
                        }
                        $newObjectDefSD = $null
                        #Comare DefaultSecurityDesriptor in template with schema looking for missing ACE's
                        $secFile = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        if ($null -ne $strSDDLcol) {
                            try {
                            $secFile.SetSecurityDescriptorSddlForm($strSDDLcol)
                            }
                            catch
                            {
                                if ($bolCMD) {
                                    Write-host "Could not import SDDL for Schema Object $strNamecol. Error:`n$($_.Exception.InnerException.Message.ToString())"
                                } else {
                                    $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not import SDDL for Schema Object $strNamecol. Error:`n$($_.Exception.InnerException.Message.ToString())" -strType 'Warning' -DateStamp ))
                                }
                            }
                        }
                        $sdFile = $secFile.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                        foreach ($ObjectDefSDFromFile in $sdFile) {
                            #Check if matchin ACE missing, TRUE until found
                            $SDMissingResult = $true

                            $ObjectDefSDFile = New-Object PSObject -Property @{ActiveDirectoryRights = $ObjectDefSDFromFile.ActiveDirectoryRights; InheritanceType = $ObjectDefSDFromFile.InheritanceType; ObjectType = $ObjectDefSDFromFile.ObjectType; `
                                    InheritedObjectType = $ObjectDefSDFromFile.InheritedObjectType; ObjectFlags = $ObjectDefSDFromFile.ObjectFlags; AccessControlType = $ObjectDefSDFromFile.AccessControlType; IdentityReference = $ObjectDefSDFromFile.IdentityReference; IsInherited = $ObjectDefSDFromFile.IsInherited; `
                                    InheritanceFlags = $ObjectDefSDFromFile.InheritanceFlags; PropagationFlags = $ObjectDefSDFromFile.PropagationFlags; State = 'Missing'
                            }

                            foreach ($ObjectDefSD in $sd) {

                                If (($ObjectDefSD.IdentityReference -eq $ObjectDefSDFile.IdentityReference) -and ($ObjectDefSD.ActiveDirectoryRights -eq $ObjectDefSDFile.ActiveDirectoryRights) -and ($ObjectDefSD.AccessControlType -eq $ObjectDefSDFile.AccessControlType) -and ($ObjectDefSD.ObjectType -eq $ObjectDefSDFile.ObjectType) -and ($ObjectDefSD.InheritanceType -eq $ObjectDefSDFile.InheritanceType) -and ($ObjectDefSD.InheritedObjectType -eq $ObjectDefSDFile.InheritedObjectType)) {
                                    $SDMissingResult = $false
                                }
                            }
                            if ($SDMissingResult) {
                                #Missig´ng color "Red"
                                $strColorTemp = 3
                                #If first ACE add header
                                if ($intACEcount -eq 0) {
                                    #Indicate that a defaultsecuritydescriptor was found
                                    $intNumberofDefSDFound++
                                    $bolOUHeader = $true
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $ObjectDefSDFile -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                                } else {
                                    $bolOUHeader = $false
                                    Write-DefSDAccessHTM -bolACLExist $true -sd $ObjectDefSDFile -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
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
            if ($ObjectMatchResult -eq $false) {
                $sd = ''
                #Create ad security object
                $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                    $sec.SetSecurityDescriptorSddlForm($entry.Attributes.defaultsecuritydescriptor[0])
                }
                $sd = $sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                #Count ACE for applying header on fist
                $intACEcount = 0
                foreach ($ObjectDefSD in $sd) {

                    $newObjectDefSD = New-Object PSObject -Property @{ActiveDirectoryRights = $ObjectDefSD.ActiveDirectoryRights; InheritanceType = $ObjectDefSD.InheritanceType; ObjectType = $ObjectDefSD.ObjectType; `
                            InheritedObjectType = $ObjectDefSD.InheritedObjectType; ObjectFlags = $ObjectDefSD.ObjectFlags; AccessControlType = $ObjectDefSD.AccessControlType; IdentityReference = $ObjectDefSD.IdentityReference; IsInherited = $ObjectDefSD.IsInherited; `
                            InheritanceFlags = $ObjectDefSD.InheritanceFlags; PropagationFlags = $ObjectDefSD.PropagationFlags; State = 'Missing in file'
                    }

                    #Matching color "green"
                    $strColorTemp = 5
                    #If first ACE add header
                    if ($intACEcount -eq 0) {
                        $bolOUHeader = $true
                        #Indicate that a defaultsecuritydescriptor was found
                        $intNumberofDefSDFound++
                        Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                    } else {
                        $bolOUHeader = $false
                        Write-DefSDAccessHTM -bolACLExist $true -sd $newObjectDefSD -bolObjClass $true -strObjectClass $strObjectClassName -strColorTemp $strColorTemp -htmfileout $strFileDefSDHTA -strFileHTM $strFileDefSDHTM -OUHeader $bolOUHeader -boolReplMetaDate $bolReplMeta -strReplMetaVer $strVersion -strReplMetaDate $strLastChangeDate -bolCriticalityLevel $bolShowCriticalityColor -CompareMode $bolCompare -xlsxout $strFileEXCEL -Type $OutType
                    }
                    #Count ACE to not ad a header
                    $intACEcount++
                }
                $newObjectDefSD = $null
                $sd = $null
            }

        }#End foreach
        if ($global:PageSize -gt 0) {
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
    if (($PSVersionTable.PSVersion -ne '2.0') -and ($global:bolProgressBar)) {
        $global:ProgressBarWindow.Window.Dispatcher.invoke([action] { $global:ProgressBarWindow.Window.Close() }, 'Normal')
        $ProgressBarWindow = $null
        Remove-Variable -Name 'ProgressBarWindow' -Scope Global
    }

    if ($intNumberofDefSDFound -gt 0) {
        Invoke-Item $strFileDefSDHTA
    } else {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'No defaultsecuritydescriptor found!' -strType 'Error' -DateStamp ))
    }
}
#==========================================================================
# Function		: Write-DefaultSDCSV
# Arguments     : string ObjectClass
# Returns   	:
# Description   : Write the default Security Descriptor to a CSV
#==========================================================================
Function Write-DefaultSDCSV {
    Param(
        [string]
        $fileout,

        $strObjectClass = '*',
        
        # run from command line
        [bool]
        $bolCMD,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    #Number of columns in CSV import
    $strCSVHeaderDefsd = @'
"Name","distinguishedName","Version","ModifiedDate","SDDL"
'@


    If ((Test-Path $fileout) -eq $true) {
        Remove-Item $fileout
    }

    $strCSVHeaderDefsd | Out-File -FilePath $fileout -Encoding UTF8

    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $request = New-Object System.directoryServices.Protocols.SearchRequest($global:SchemaDN, "(&(objectClass=classSchema)(name=$strObjectClass))", 'Subtree')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('defaultsecuritydescriptor')
    [void]$request.Attributes.Add('name')
    [void]$request.Attributes.Add('msds-replattributemetadata')
    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval

        foreach ($entry  in $response.Entries) {
            $index = 0
            while ($index -le $entry.attributes.'msds-replattributemetadata'.count - 1) {
                $childMember = $entry.attributes.'msds-replattributemetadata'[$index]
                $childMember = $childMember.replace("$($childMember[-1])", '')
                If ($([xml]$childMember).DS_REPL_ATTR_META_DATA.pszAttributeName -eq 'defaultSecurityDescriptor') {
                    $strLastChangeDate = $([xml]$childMember).DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                    $strVersion = $([xml]$childMember).DS_REPL_ATTR_META_DATA.dwVersion
                    if ($strLastChangeDate -eq $nul) {
                        $strLastChangeDate = $(Get-Date '1601-01-01' -UFormat '%Y-%m-%d %H:%M:%S')

                    } else {
                        $strLastChangeDate = $(Get-Date $strLastChangeDate -UFormat '%Y-%m-%d %H:%M:%S')
                    }
                }
                $index++
            }

            $strSDDL = ''
            if ($null -ne $entry.Attributes.defaultsecuritydescriptor) {
                $strSDDL = $entry.Attributes.defaultsecuritydescriptor[0]
            }
            $strName = $entry.Attributes.name[0]
            $strDistinguishedName = $entry.distinguishedname

            #Write to file
            [char]34 + $strName + [char]34 + ',' + [char]34 + `
                $strDistinguishedName + [char]34 + ',' + [char]34 + `
                $strVersion + [char]34 + ',' + [char]34 + `
                $strLastChangeDate + [char]34 + ',' + [char]34 + `
                $strSDDL + [char]34 | Out-File -Append -FilePath $fileout -Encoding UTF8


        }

        if ($global:PageSize -gt 0) {
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

    if($bolCMD) {
        Write-host "Report saved in: $fileout" -ForegroundColor Yellow
        Write-output $fileout    
    } else {
        $global:observableCollection.Insert(0,(LogMessage -strMessage "Report saved in $fileout" -strType "Warning" -DateStamp ))
    }

}
#==========================================================================
# Function		: GetEffectiveRightSP
# Arguments     :
# Returns   	:
# Description   : Rs
#==========================================================================
Function GetEffectiveRightSP {
    param(
        [string] $strPrincipal,
        [string] $strDomainDistinguishedName,
        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS
    )
    $global:strEffectiveRightSP = ''
    $global:strEffectiveRightAccount = ''
    $global:strSPNobjectClass = ''
    $global:strPrincipalDN = ''
    $strPrinName = ''
    $SPFound = $false

    if ($global:strPrinDomDir -eq 2) {
        & { #Try

            $Script:CredsExt = $host.ui.PromptForCredential('Need credentials', 'Please enter your user name and password.', '', "$global:strPrinDomFlat")
            $Window.Activate()
        }
        Trap [SystemException] {
            continue
        }
        $h = (Get-Process -Id $global:myPID).MainWindowHandle # just one notepad must be opened!
        [SFW]::SetForegroundWindow($h)
        if ($null -ne $Script:CredsExt.UserName) {
            if (TestCreds $CredsExt) {
                $global:strPinDomDC = $(GetDomainController $global:strDomainPrinDNName $true $Script:CredsExt)
                $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $true -CREDS $Script:CredsExt)
            } else {
                $global:observableCollection.Insert(0, (LogMessage -strMessage 'Bad user name or password!' -strType 'Error' -DateStamp ))
                $lblEffectiveSelUser.Content = ''
            }
        } else {
            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Faild to insert credentials!' -strType 'Error' -DateStamp ))

        }
    } else {
        if ( $global:strDomainPrinDNName -eq $global:strDomainDNName ) {
            $lblSelectPrincipalDom.Content = $global:strDomainShortName + ':'
            $global:strPinDomDC = $global:strDC
            $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $false -CREDS $CREDS)
        } else {
            $global:strPinDomDC = $global:strDC
            $global:strPrincipalDN = (GetSecPrinDN $strPrincipal $global:strPinDomDC $false -CREDS $CREDS)
        }
    }
    if ($global:strPrincipalDN -eq '') {
        if ($global:bolCMD) {
            Write-Host "Could not find $strPrincipal!" -ForegroundColor Red
        } else {
            $global:observableCollection.Insert(0, (LogMessage -strMessage "Could not find $strPrincipal!" -strType 'Error' -DateStamp ))
            $lblEffectiveSelUser.Content = ''
        }
    } else {
        $SPFound = $true
        $global:strEffectiveRightAccount = $strPrincipal
        if ($global:bolCMD) {
            #Write-host "Found security principal"
        } else {
            $global:observableCollection.Insert(0, (LogMessage -strMessage 'Found security principal' -strType 'Info' -DateStamp ))
        }

        if ($global:strPrinDomDir -eq 2) {
            [System.Collections.ArrayList] $global:tokens = @(GetTokenGroups -PrincipalDomDC $global:strPinDomDC -PrincipalDN $global:strPrincipalDN -bolCreds $true -GetTokenCreds $Script:CredsExt -CREDS $CREDS)

            if ($CREDS) {
                $objADPrinipal = New-Object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN", $Script:CredsExt.UserName, $Script:CredsExt.GetNetworkCredential().Password)
            } else {
                $objADPrinipal = New-Object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN")
            }

            $objADPrinipal.psbase.RefreshCache('msDS-PrincipalName')
            $strPrinName = $($objADPrinipal.psbase.Properties.Item('msDS-PrincipalName'))
            $global:strSPNobjectClass = $($objADPrinipal.psbase.Properties.Item('objectClass'))[$($objADPrinipal.psbase.Properties.Item('objectClass')).count - 1]
            if (($strPrinName -eq '') -or ($null -eq $strPrinName)) {
                $strPrinName = "$global:strPrinDomFlat\$($objADPrinipal.psbase.Properties.Item('samAccountName'))"
            }
            $global:strEffectiveRightSP = $strPrinName
            $lblEffectiveSelUser.Content = $strPrinName
        } else {
            [System.Collections.ArrayList] $global:tokens = @(GetTokenGroups -PrincipalDomDC $global:strPinDomDC -PrincipalDN $global:strPrincipalDN -bolCreds $false -CREDS $CREDS)

            if ($CREDS) {
                $objADPrinipal = New-Object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN", $CREDS.UserName, $CREDS.GetNetworkCredential().Password)
            } else {
                $objADPrinipal = New-Object DirectoryServices.DirectoryEntry("LDAP://$global:strPinDomDC/$global:strPrincipalDN")
            }

            $objADPrinipal.psbase.RefreshCache('msDS-PrincipalName')
            $strPrinName = $($objADPrinipal.psbase.Properties.Item('msDS-PrincipalName'))
            $global:strSPNobjectClass = $($objADPrinipal.psbase.Properties.Item('objectClass'))[$($objADPrinipal.psbase.Properties.Item('objectClass')).count - 1]
            if (($strPrinName -eq '') -or ($null -eq $strPrinName)) {
                $strPrinName = "$global:strPrinDomFlat\$($objADPrinipal.psbase.Properties.Item('samAccountName'))"
            }
            $global:strEffectiveRightSP = $strPrinName
            $lblEffectiveSelUser.Content = $strPrinName
        }

    }
    return $SPFound
}

#==========================================================================
# Function		: LoadProgressBar
# Arguments     : n/a
# Returns   	: n/a
# Description   : Open up a progress bar in a XAML window
#==========================================================================
Function LoadProgressBar {
    $global:ProgressBarWindow = [hashtable]::Synchronized(@{})
    $newRunspace = [runspacefactory]::CreateRunspace()
    $newRunspace.ApartmentState = 'STA'
    $newRunspace.ThreadOptions = 'ReuseThread'
    $newRunspace.Open()
    $newRunspace.SessionStateProxy.SetVariable('global:ProgressBarWindow', $global:ProgressBarWindow)
    $psCmd = [PowerShell]::Create().AddScript({
            [xml]$xamlProgressBar = @'
<Window x:Class="WpfApplication1.StatusBar"
         xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Scanning..." WindowStartupLocation = "CenterScreen"
        Width = "350" Height = "150" ShowInTaskbar = "True" ResizeMode="NoResize" WindowStyle="ToolWindow" Opacity="0.9" Background="#2A3238">
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
            <Label x:Name="lblSkipProgressBar" Content="For increased speed, turn off the progress bar.&#10;Additional Options -> Use Progress Bar" Foreground="white" Margin="10,5,0,0"/>
        </StackPanel>

    </Grid>
</Window>
'@

            $xamlProgressBar.Window.RemoveAttribute('x:Class')
            $reader = (New-Object System.Xml.XmlNodeReader $xamlProgressBar)
            $global:ProgressBarWindow.Window = [Windows.Markup.XamlReader]::Load( $reader )
            $global:ProgressBarWindow.lblProgressBarInfo = $global:ProgressBarWindow.window.FindName('lblProgressBarInfo')
            $global:ProgressBarWindow.ProgressBar = $global:ProgressBarWindow.window.FindName('ProgressBar')
            $global:ProgressBarWindow.ProgressBar.Value = 0
            $global:ProgressBarWindow.Window.ShowDialog() | Out-Null
            $global:ProgressBarWindow.Error = $Error


        })



    $psCmd.Runspace = $newRunspace

    [void]$psCmd.BeginInvoke()



}

#==========================================================================
# Function		: Update-ProgressBar
# Arguments     : n/a
# Returns   	: n/a
# Description   : Update progress bar in a XAML window
#==========================================================================
Function Update-ProgressBar {
    Param ($txtlabel, $valProgress)

    & { #Try
        $global:ProgressBarWindow.ProgressBar.Dispatcher.invoke([action] { $global:ProgressBarWindow.lblProgressBarInfo.Content = $txtlabel; $global:ProgressBarWindow.ProgressBar.Value = $valProgress }, 'Normal')
    }
    Trap [SystemException] {
        $global:observableCollection.Insert(0, (LogMessage -strMessage 'Progressbar Failed!' -strType 'Error' -DateStamp ))

    }

}

#==========================================================================
# Function		: Find-RiskyTemplates
# Arguments     : Configuration partition distinguishedname
# Returns   	: An array of distinguishednames for templates that are published
# Description   : Find and returns an array of distinguishednames for templates that are published and have supply in request without certificate manage approval
#==========================================================================
Function Find-RiskyTemplates {
    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0,
            ParameterSetName = 'Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String]
        $ConfigurationDN = '',

        [Parameter(Mandatory = $false)]
        [pscredential]
        $CREDS)

    #array Published templates names
    $arrPublishedPKITemplates = New-Object System.Collections.ArrayList

    #array Published templates DN
    $arrPublishedTemplatesDN = New-Object System.Collections.ArrayList

    # Search published for PKI templates
    $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
    $LDAPConnection.SessionOptions.ReferralChasing = 'None'
    $SearchFilter = '(objectClass=pKIEnrollmentService)'
    $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigurationDN", $SearchFilter, 'OneLevel')
    [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
    $request.Controls.Add($pagedRqc) | Out-Null
    [void]$request.Attributes.Add('certificatetemplates')

    while ($true) {
        $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

        #for paged search, the response for paged search result control - we will need a cookie from result later
        if ($global:PageSize -gt 0) {
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
            if ($response.Controls.Length -gt 0) {
                foreach ($ctrl in $response.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $prrc = $ctrl;
                        break;
                    }
                }
            }
            if ($null -eq $prrc) {
                #server was unable to process paged search
                throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
            }
        }
        #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
        $colResults = $response.Entries
        foreach ($objResult in $colResults) {
            for ($i = 0; $i -lt $objResult.attributes.certificatetemplates.count; $i++) {
                [void]$arrPublishedPKITemplates.Add($objResult.attributes.certificatetemplates[$i])
            }


        }
        if ($global:PageSize -gt 0) {
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

    #if any results found in published template names continue to a search for the object
    if ($arrPublishedPKITemplates) {
        # For each template name searc for the object
        Foreach ($PublishedTemplate in $arrPublishedPKITemplates) {
            # Search for PKI templates objects
            $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
            $LDAPConnection.SessionOptions.ReferralChasing = 'None'
            $SearchFilter = "(&(objectClass=pKICertificateTemplate)(cn=$PublishedTemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))"
            $request = New-Object System.directoryServices.Protocols.SearchRequest("CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationDN", $SearchFilter, 'OneLevel')
            [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($global:PageSize)
            $request.Controls.Add($pagedRqc) | Out-Null
            [void]$request.Attributes.Add('mspki-enrollment-flag')


            $arrPublishedPKITemplates = New-Object System.Collections.ArrayList
            while ($true) {
                $response = $LdapConnection.SendRequest($request, (New-Object System.Timespan(0, 0, $global:TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];

                #for paged search, the response for paged search result control - we will need a cookie from result later
                if ($global:PageSize -gt 0) {
                    [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $null;
                    if ($response.Controls.Length -gt 0) {
                        foreach ($ctrl in $response.Controls) {
                            if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                                $prrc = $ctrl;
                                break;
                            }
                        }
                    }
                    if ($null -eq $prrc) {
                        #server was unable to process paged search
                        throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                    }
                }
                #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
                $colResults = $response.Entries
                foreach ($objResult in $colResults) {
                    for ($i = 0; $i -le $objResult.attributes.certificatetemplates.count; $i++) {
                        $strEnrollmentFlag = $(GetEnrollmentFlag $objResult.attributes.'mspki-enrollment-flag'[0])
                        if (($strEnrollmentFlag -eq '') -or (-not($strEnrollmentFlag -match 'CT_FLAG_PEND_ALL_REQUESTS'))) {
                            [void]$arrPublishedTemplatesDN.Add($objResult.distinguishedname)
                        }
                    }


                }
                if ($global:PageSize -gt 0) {
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
    }

    # Return all published template objects
    return $arrPublishedTemplatesDN

}

#==========================================================================
# Function		: GetEnrollmentFlag
# Arguments     : Enrollment flags of a certificate template
# Returns   	: String of the translated values
# Description   : Returns a certificate enrollment flag status
#==========================================================================
Function GetEnrollmentFlag ($EnrollmentFlag) {


    [string] $strStatus = ''

    if ($EnrollmentFlag -band 0x00000001) {
        $strStatus = $strStatus + ',CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS'
    }
    if ($EnrollmentFlag -band 0x00000002) {
        $strStatus = $strStatus + ',CT_FLAG_PEND_ALL_REQUESTS'
    }
    if ($EnrollmentFlag -band 0x00000004) {
        $strStatus = $strStatus + ',CT_FLAG_PUBLISH_TO_KRA_CONTAINER'
    }
    if ($EnrollmentFlag -band 0x00000008) {
        $strStatus = $strStatus + ',CT_FLAG_PUBLISH_TO_DS'
    }
    if ($EnrollmentFlag -band 0x00000010) {
        $strStatus = $strStatus + ',CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE'
    }
    if ($EnrollmentFlag -band 0x00000020) {
        $strStatus = $strStatus + ',CT_FLAG_AUTO_ENROLLMENT'
    }
    if ($EnrollmentFlag -band 0x00000040) {
        $strStatus = $strStatus + ',CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT'
    }
    if ($EnrollmentFlag -band 0x00000100) {
        $strStatus = $strStatus + ',CT_FLAG_USER_INTERACTION_REQUIRED'
    }
    if ($EnrollmentFlag -band 0x00000400) {
        $strStatus = $strStatus + ',CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE'
    }
    if ($EnrollmentFlag -band 0x00000800) {
        $strStatus = $strStatus + ',CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF'
    }
    if ($EnrollmentFlag -band 0x00001000) {
        $strStatus = $strStatus + ',CT_FLAG_ADD_OCSP_NOCHECK'
    }
    if ($EnrollmentFlag -band 0x00002000) {
        $strStatus = $strStatus + ',CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL'
    }
    if ($EnrollmentFlag -band 0x00004000) {
        $strStatus = $strStatus + ',CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS'
    }
    if ($EnrollmentFlag -band 0x00008000) {
        $strStatus = $strStatus + ',CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS'
    }
    if ($EnrollmentFlag -band 0x00010000) {
        $strStatus = $strStatus + ',CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT'
    }
    if ($EnrollmentFlag -band 0x00020000) {
        $strStatus = $strStatus + ',CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST'
    }
    if ($EnrollmentFlag -band 0x00040000) {
        $strStatus = $strStatus + ',CT_FLAG_SKIP_AUTO_RENEWAL'
    }


    [int] $index = $strStatus.IndexOf(',')
    If ($index -eq 0) {
        $strStatus = $strStatus.substring($strStatus.IndexOf(',') + 1, $strStatus.Length - 1 )
    }


    return $strStatus

}#End function




#Number of columns in CSV import
$strCSVHeader = @'
"Object","ObjectClass","IdentityReference","PrincipalName","ActiveDirectoryRights","InheritanceType","ObjectType","InheritedObjectType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags","SDDate","InvocationID","OrgUSN","Criticality","CanonicalName","Inheritance Disabled"
'@


$strCSVCompareHeader = @'
"Object","ObjectClass","IdentityReference","PrincipalName","ActiveDirectoryRights","InheritanceType","ObjectType","InheritedObjectType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags","SDDate","InvocationID","OrgUSN","Criticality","CanonicalName","Inheritance Disabled","State"
'@


$global:myPID = $PID
$global:csvHistACLs = New-Object System.Collections.ArrayList

$strLastCacheGuidsDom = ''
$sd = ''
$global:intObjeComputer = 0

$null = Add-Type -AssemblyName System.DirectoryServices.Protocols
if ($base -or $GPO) {
    
    # Display script info
    if(-not($NoBanner)) {
        Write-Host $ADACLScanVersion
    }

    # Check if Depth is provided and Scope is not 'onelevel'
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Depth') -and $Scope -ne 'onelevel') {
        throw "The parameter 'Depth' requires the parameter 'Scope' to be 'onelevel'."
    }

    $CREDS = $null
    if ($credentials) {
        $CREDS = $Credentials
    }

    if ($Criticality) {
        $ShowCriticalityColor = $true
    }

    if ($Output -eq '') {
        $Show = $false
    }

    if ($Permission) {
        $ACLFilter = $True
    } else {
        $ACLFilter = $False
    }

    if ($ShowProgressBar) {
        $global:bolProgressBar = $true
    } else {
        $global:bolProgressBar = $false
    }

    #Connect to Custom Naming Context
    $global:bolCMD = $true

    
    $bolConnected = Connect-DirectoryServices -Base $Base -Server $Server -Port $Port -CREDS $CREDS 


    $bolEffective = $false
    if ($EffectiveRightsPrincipal.Length -gt 0) {
        if ($(GetEffectiveRightSP $EffectiveRightsPrincipal $global:strDomainDNName -CREDS $CREDS)) {
            $bolEffective = $true
            $IncludeInherited = $true
        } else {
            break;
        }
    }
    #Check if a naming context is selected
    If ($bolConnected -eq $true) {
        If (!($strLastCacheGuidsDom -eq $global:strDomainDNName)) {
            $global:dicRightsGuids = @{'Seed' = 'xxx' }
            CacheRightsGuids -CREDS $CREDS
            $strLastCacheGuidsDom = $global:strDomainDNName
        }

        if ($GPO -or ($base -eq 'RootDSE')) {
            if (($base -eq '') -or ($base -eq 'RootDSE')) {
                $base = $global:strDomainDNName
            }
        }

        ############### COMPARE THINGS ##########
        if ($Template) {
            if ($(Test-Path $Template) -eq $true) {
                $global:bolCSVLoaded = $false
                $strCompareFile = $Template
                & { #Try
                    $global:bolCSVLoaded = $true
                    $global:csvHistACLs = Import-Csv $strCompareFile
                }
                Trap [SystemException] {
                    $strCSVErr = $_.Exception.Message
                    Write-Host "Failed to load CSV. $strCSVErr" -ForegroundColor Red
                    $global:bolCSVLoaded = $false
                    continue
                }
                #Verify that a successful CSV import is performed before continue
                if ($global:bolCSVLoaded) {
                    #Test CSV file format
                    if (TestCSVColumns $global:csvHistACLs) {

                        $bolContinue = $true

                        if ($global:csvHistACLs[0].Object) {
                            $strOUcol = $global:csvHistACLs[0].Object
                        } else {
                            $strOUcol = $global:csvHistACLs[0].OU
                        }
                        if ($strOUcol.Contains('<DOMAIN-DN>') -gt 0) {
                            $strOUcol = ($strOUcol -Replace '<DOMAIN-DN>', $global:strDomainDNName)

                        }

                        if ($strOUcol.Contains('<ROOT-DN>') -gt 0) {
                            $strOUcol = ($strOUcol -Replace '<ROOT-DN>', $global:ForestRootDomainDN)

                            if ($global:strDomainDNName -ne $global:ForestRootDomainDN) {
                                if ($global:IS_GC -eq 'TRUE') {
                                    Write-Host "You are not connected to the forest root domain: $global:ForestRootDomainDN.`n`nYour DC is a Global Catalog.`nDo you want to use Global Catalog and  continue?"
                                    $a = Read-Host 'Do you want to continue? Press Y[Yes] or N[NO]:'
                                    if ($a -eq 'Y') {
                                        if ($global:strDC.contains(':')) {
                                            $global:strDC = $global:strDC.split(':')[0] + ':3268'
                                        } else {
                                            $global:strDC = $global:strDC + ':3268'
                                        }

                                    } else {
                                        $bolContinue = $false
                                    }

                                } else {
                                    Write-Host "You are not connected to the forest root domain: $global:ForestRootDomainDN." -ForegroundColor Yellow
                                    $bolContinue = $false
                                }
                            }

                        }


                        if ($txtReplaceDN.text.Length -gt 0) {
                            $strOUcol = ($strOUcol -Replace $txtReplaceDN.text, $global:strDomainDNName)

                        }
                        $sADobjectName = $strOUcol
                        #Verify if the connection can be done
                        if ($bolContinue) {
                            $LDAPConnection = Connect-SecureLDAP -Server $global:strDC -Credential $CREDS ; Write-verbose "Calling Connect-SecureLDAP at: $((Get-PSCallStack).ScriptLineNumber[0])"
                            $LDAPConnection.SessionOptions.ReferralChasing = 'None'
                            $request = New-Object System.directoryServices.Protocols.SearchRequest
                            if ($global:bolShowDeleted) {
                                [string] $LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
                                [void]$request.Controls.Add((New-Object 'System.DirectoryServices.Protocols.DirectoryControl' -ArgumentList "$LDAP_SERVER_SHOW_DELETED_OID", $null, $false, $true ))
                            }
                            $request.DistinguishedName = $sADobjectName
                            $request.Filter = '(name=*)'
                            $request.Scope = 'Base'
                            [void]$request.Attributes.Add('name')

                            $response = $LDAPConnection.SendRequest($request)

                            $ADobject = $response.Entries[0]
                            $strNode = fixfilename $ADobject.attributes.name[0]
                        } else {
                            #Set the node to empty , no connection will be done
                            $strNode = ''
                        }

                    } else {
                        Write-Host "Wrong format in: $Template" -ForegroundColor Red
                        exit
                    }
                }
            } else {
                Write-Host "File not found $Template" -ForegroundColor Red
                exit
            }
        }

        ############### COMPARE THINGS ##########

        #Get current date
        $date = Get-Date -UFormat %Y%m%d_%H%M%S

        if ($Targets) {
            if ($Targets -eq 'RiskyTemplates') {
                $allSubOU = Find-RiskyTemplates -ConfigurationDN $global:ConfigDN -CREDS $CREDS
            }
        } else {
            if($SearchDepth) {
                if($SearchDepth -match "^\d{1,3}$") {
                    $Depth = $SearchDepth
                } else {
                    Write-host "SearchDepth does not meet the required range of 0-999!" -ForegroundColor red
                    $bolDepthError = $true
                }
            }
            if(-not($bolDepthError)) {
                if(-not($GPO)) {
                    if($Depth) {
                        #Get all LDAP objects to read ACL's on
                        $allSubOU = @(GetAllChildNodes -firstnode $base -Scope $Scope -CustomFilter $LDAPFilter -CREDS $CREDS -Depth $Depth)
                    } else {
                        $allSubOU = @(GetAllChildNodes -firstnode $base -Scope $Scope -CustomFilter $LDAPFilter -CREDS $CREDS)
    
                    }
                } else {
                    if($Depth) {
                        #Get all LDAP objects to read ACL's on
                        $allSubOU = @(GetAllChildNodes -firstnode $base -Scope $Scope -CustomFilter "(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gplink=*LDAP*))" -CREDS $CREDS -Depth $Depth)
                    } else {
                        $allSubOU = @(GetAllChildNodes -firstnode $base -Scope $Scope -CustomFilter "(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gplink=*LDAP*))" -CREDS $CREDS -Depth $Depth)
                    }
                }
            }
        }

        if ($CanonicalNames) {
            $UseCanonicalName = $true
        } else {
            $UseCanonicalName = $false
        }


        #If more than 0 objects returned send it to Get-Perm to read ACL's
        if ($allSubOU.count -gt 0) {
            #Set the path for the CSV file name
            if ($OutputFolder -gt '') {
                #Check if foler exist if not use current folder
                if (Test-Path $OutputFolder) {
                    $strFileCSV = $OutputFolder + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.csv'
                } else {
                    Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                    $strFileCSV = $CurrentFSPath + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.csv'
                }
            } else{
                if($Output -eq "CSVTEMPLATE") {
                    $strFileCSV = $CurrentFSPath + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date + "_Template.csv" 
                } else {
                    $strFileCSV = $CurrentFSPath + "\" +$strNode + "_" + $global:strDomainShortName + "_adAclOutput" + $date + ".csv" 
                }
            }
            $bolAssess = if ($Criticality) {
                $true
            } else {
                $false
            }
            if (($Output -eq 'CSV') -or ($Output -eq 'CSVTEMPLATE') -or ($Output -eq 'HTML') -or ($Output -eq 'EXCEL')) {
                $file = $true
                # Check if HTML switch is selected , creates a HTML file
                Switch ($Output) {
                    'HTML' {
                        $bolCSV = $false
                        $strFileHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'
                        #Set the path for the HTM file name
                        if ($OutputFolder -gt '') {
                            #Check if foler exist if not use current folder
                            if (Test-Path $OutputFolder) {
                                $strFileHTM = $OutputFolder + '\' + "$global:strDomainShortName-$strNode-$global:SessionID" + '.htm'
                            } else {
                                Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                $strFileHTM = $CurrentFSPath + '\' + "$global:strDomainShortName-$strNode-$global:SessionID" + '.htm'
                            }
                        } else {
                            $strFileHTM = $CurrentFSPath + '\' + "$global:strDomainShortName-$strNode-$global:SessionID" + '.htm'
                        }
                        CreateHTA "$global:strDomainShortName-$strNode" $strFileHTA $strFileHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                        CreateHTM "$global:strDomainShortName-$strNode" $strFileHTM
                        if ($Template) {
                            InitiateHTM $strFileHTA $strNode $Base $SDDate $false $Protected $ShowCriticalityColor $true $false $false $Template $false $bolEffective $false -bolCanonical:$UseCanonicalName $GPO
                            InitiateHTM $strFileHTM $strNode $Base $SDDate $false $Protected $ShowCriticalityColor $true $false $false $Template $false $bolEffective $false -bolCanonical:$UseCanonicalName $GPO
                        } else {

                            InitiateHTM $strFileHTA $strNode $Base $SDDate $false $Protected $ShowCriticalityColor $false $false $false '' $false $bolEffective $false -bolCanonical:$UseCanonicalName $GPO
                            InitiateHTM $strFileHTM $strNode $Base $SDDate $false $Protected $ShowCriticalityColor $false $false $false '' $false $bolEffective $false -bolCanonical:$UseCanonicalName $GPO
                        }

                        if ($Template) {
                            Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $false $Owner $bolCSV $Protected $false $false $Show 'HTML' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                        } else {
                            Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType 'HTML' -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType -SDDL $SDDL
                        }

                        Write-Host "Report saved in: $strFileHTM" -ForegroundColor Yellow
                        Write-Output $strFileHTM
                    }
                    'EXCEL' {
                        $bolCSV = $false
                        $ExcelModuleExist = $true
                        if (!$(Get-Module ImportExcel)) { 
                            Write-Host 'Checking for ImportExcel PowerShell Module...' 
                            if (!$(Get-Module -ListAvailable | Where-Object name -EQ 'ImportExcel')) {
                                Write-Host 'You need to install the PowerShell module ImportExcel found in the PSGallery' -ForegroundColor red 
                                $ExcelModuleExist = $false
                            } else {
                                Import-Module ImportExcel
                                $ExcelModuleExist = $true
                            }

                        }
                        if ($ExcelModuleExist) {
                            if ($ExcelFile -eq '') {
                                #Set the path for the Excel file name
                                if ($OutputFolder -gt '') {
                                    #Check if foler exist if not use current folder
                                    if (Test-Path $OutputFolder) {
                                        $strFileEXCEL = $OutputFolder + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.xlsx'
                                    } else {
                                        Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                        $strFileEXCEL = $CurrentFSPath + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.xlsx'
                                    }
                                } else {
                                    $strFileEXCEL = $CurrentFSPath + '\' + $strNode + '_' + $global:strDomainShortName + '_adAclOutput' + $date + '.xlsx'
                                }
                            } else {
                                $strFileEXCEL = $ExcelFile
                            }

                            if ($Template) {
                                Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $SDDate $Owner $bolCSV $Protected $false $false $Show 'EXCEL' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                            } else {
                                Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected  -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType 'EXCEL' -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType  -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType
                            }
                        }
                    }
                    'CSVTEMPLATE' {
                        $bolCSV = $true
                        if ($Template) {
                            Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $false $Owner $bolCSV $Protected $false $false $Show 'CSVTEMPLATE' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                        } else {
                            Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected  -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType "CSVTEMPLATE" -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType  -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType  -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType -SDDL $SDDL

                        }


                    }
                    default {
                        $bolCSV = $true
                        if ($Template) {
                            Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $false $Owner $bolCSV $Protected $false $false $Show 'CSV' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                        } else {
                            Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected  -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType "CSV" -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType  -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType  -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType -SDDL $SDDL

                        }


                    }

                }
            } else {
                if ($RAW) {
                    $bolCSV = $true
                    $file = $false
                    if ($Template) {
                        Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $false $Owner $bolCSV $Protected $false $false $Show 'CSVTEMPLATE' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                    } else {
                        Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected  -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType 'CSVTEMPLATE' -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType  -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType -SDDL $SDDL
                    }
                } else {
                    $bolCSV = $true
                    $file = $false
                    if ($Template) {
                        Get-PermCompare $allSubOU $SkipDefaults $SkipProtected $false $Owner $bolCSV $Protected $false $false $Show 'CSV' $TemplateFilter $file $ShowCriticalityColor $bolAssess $Criticality $GPO -CREDS $CREDS
                    } else {
                        Get-Perm -AllObjectDn $allSubOU -DomainNetbiosName $global:strDomainShortName -IncludeInherited $IncludeInherited -SkipDefaultPerm $SkipDefaults -SkipProtectedPerm $SkipProtected  -bolGetOwnerEna $Owner -bolReplMeta $SDDate -bolACLsize $false -bolEffectiveR $bolEffective -bolGetOUProtected $Protected -bolGUIDtoText $false -Show $Show -OutType 'CSV' -bolToFile $file -bolAssess $bolAssess -AssessLevel $Criticality -bolShowCriticalityColor $ShowCriticalityColor -GPO $GPO -FilterBuiltin $SkipBuiltIn -TranslateGUID $Translate -RecursiveFind $RecursiveFind -RecursiveObjectType $RecursiveObjectType -ApplyTo $ApplyTo -PropertyFilter $PropertyFilter -FilterTrustee $FilterTrustee -AccessType $AccessType  -ACLPermissionFilter $Permission -CREDS $CREDS -ReturnObjectType $ReturnObjectType -SDDL $SDDL
                    }
                }

            }
        } else {
            Write-Host 'No objects returned! Does your filter relfect the objects you are searching for?' -ForegroundColor red
        }
    }#end if $Global:bolLDAPConnection
    else {
        Write-Verbose 'Could not connect! Check your credentials'
    }

}# End if D
else {
    if ($DefaultSecurityDescriptor) {

        if(-not($NoBanner)) {
            Write-Host $ADACLScanVersion
        }

        $CREDS = $null
        if ($credentials) {
            $CREDS = $Credentials
        }

        $global:bolProgressBar = $false


        $global:bolCMD = $true
        $bolReplMeta = $true
        if($CanonicalNames) {
            $UseCanonicalName = $true
        } else {
            $UseCanonicalName = $false
        }

        if($Criticality) {
            $ShowCriticalityColor = $true
        }

        if ($Criticality) {
            $CriticalitySelected = $true
        } else {
            $CriticalitySelected = $false
        }


        #Connect to Custom Naming Context
        $global:bolCMD = $true

        #If use provides a server name, maintain ther usage of the server.
        if($Server) {
            $PreferSpecificDC = $true
        }

        if (Test-DomainJoined) {
            Write-Verbose "Machine is domain joined - using standard conversion"

            $bolConnected = Connect-DirectoryServices -Base '' -Server $Server -Port $Port -CREDS $CREDS -PreferSpecificDC:$PreferSpecificDC -NamingContext Schema

            If ($bolConnected -eq $true) {
                Write-Verbose "Connected"
                If (!($strLastCacheGuidsDom -eq $global:strDomainDNName)) {
                    $global:dicRightsGuids = @{'Seed' = 'xxx' }
                    CacheRightsGuids -CREDS $CREDS
                    $strLastCacheGuidsDom = $global:strDomainDNName
                }

                $strNode = ($domainlist | ?{$_.IsCurrentDomain -eq "true"}).NetBIOSName

                #Get current date
                $date = Get-Date -UFormat %Y%m%d_%H%M%S

                Switch ($Output) {
                    'HTML' {
                        #Set the path for the HTM file name
                        if ($OutputFolder -gt '') {
                            #Check if foler exist if not use current folder
                            if (Test-Path $OutputFolder) {
                                $strFileDefSDHTM = $OutputFolder + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.htm'
                            } else {
                                Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                $strFileDefSDHTM = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.htm'
                            }
                        } else {
                            $strFileDefSDHTM = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.htm'
                        }
                        $strFileDefSDHTA = $env:temp + '\' + $global:ACLHTMLFileName + '.hta'

                        if ($bolSDDL -eq $true) {
                            CreateDefaultSDReportHTA $global:strDomainFQDN $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath
                            CreateDefSDHTM $global:strDomainFQDN $strFileDefSDHTM
                            InitiateDefSDHTM $strFileDefSDHTM $strObjectClass
                            InitiateDefSDHTM $strFileDefSDHTA $strObjectClass
                        } else {
                            CreateHTM $strNode $strFileDefSDHTM
                            CreateHTA $strNode $strFileDefSDHTA $strFileDefSDHTM $CurrentFSPath $global:strDomainDNName $global:strDC
                            Initialize-DefSDAccessHTM $strFileDefSDHTA $strObjectClass $bolReplMeta $false '' $ShowCriticalityColor
                            Initialize-DefSDAccessHTM $strFileDefSDHTM $strObjectClass $bolReplMeta $false '' $ShowCriticalityColor
                        }

                        Get-DefaultSD -strObjectClass $SchemaObjectName -bolChangedDefSD $OnlyModified -bolSDDL $false -Show $Show -File $strFileDefSDHTM -OutType $Output -bolShowCriticalityColor $ShowCriticalityColor -Assess $CriticalitySelected -Criticality $Criticality -FilterBuiltin $SkipBuiltIn -bolReplMeta $bolReplMeta -CREDS $CREDS

                    }
                    'EXCEL' {
                        $bolCSV = $false
                        $ExcelModuleExist = $true
                        if (!$(Get-Module ImportExcel)) { 
                            Write-Host 'Checking for ImportExcel PowerShell Module...' 
                            if (!$(Get-Module -ListAvailable | Where-Object name -EQ 'ImportExcel')) {
                                Write-Host 'You need to install the PowerShell module ImportExcel found in the PSGallery' -ForegroundColor red 
                                $ExcelModuleExist = $false
                            } else {
                                Import-Module ImportExcel
                                $ExcelModuleExist = $true
                            }

                        }
                        if ($ExcelModuleExist) {
                            if ($ExcelFile -eq '') {
                                #Set the path for the Excel file name
                                if ($OutputFolder -gt '') {
                                    #Check if foler exist if not use current folder
                                    if (Test-Path $OutputFolder) {
                                        $strFileEXCEL = $OutputFolder + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.xlsx'
                                    } else {
                                        Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                        $strFileEXCEL = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.xlsx' 
                                    }
                                } else {
                                    $strFileEXCEL = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.xlsx'
                                }
                            } else {
                                $strFileEXCEL = $ExcelFile
                            }
                            
                            Get-DefaultSD -strObjectClass $SchemaObjectName -bolChangedDefSD $OnlyModified -bolSDDL $false -Show $Show -File $strFileDefSDHTM -OutType $Output -bolShowCriticalityColor $ShowCriticalityColor -Assess $CriticalitySelected -Criticality $Criticality -FilterBuiltin $SkipBuiltIn -bolReplMeta $bolReplMeta -CREDS $CREDS
                        }
                    }
                    "CSVTEMPLATE" {
                        
                        #Set the path for the CSV file name
                        if($OutputFolder -gt "") {
                            #Check if foler exist if not use current folder
                            if(Test-Path $OutputFolder) {
                                $strFileCSV = $OutputFolder + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '_Template.csv' 
                            } else {
                                Write-host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                $strFileCSV = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '_Template.csv' 
                            }
                        } else {
                            $strFileCSV = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '_Template.csv' 
                        }

                        Write-DefaultSDCSV -fileout $strFileCSV -CREDS $CREDS -bolCMD $true
                    }                
                    default {


                        #Set the path for the CSV file name
                        if ($OutputFolder -gt '') {
                            #Check if foler exist if not use current folder
                            if (Test-Path $OutputFolder) {
                                $strFileCSV = $OutputFolder + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.csv' 
                            } else {
                                Write-Host "Path:$OutputFolder was not found! Writting to current folder." -ForegroundColor red
                                $strFileCSV = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.csv'
                            }
                        } else {
                            $strFileCSV = $CurrentFSPath + '\' +$strNode + '_DefaultSecDescriptor_' + $date + '.csv' 
                        }


                        Get-DefaultSD -strObjectClass $SchemaObjectName -bolChangedDefSD $OnlyModified -bolSDDL $false -File $strFileCSV -Show $Show -OutType $Output -bolShowCriticalityColor $ShowCriticalityColor -Assess $CriticalitySelected -Criticality $Criticality -FilterBuiltin $SkipBuiltIn -bolReplMeta $bolReplMeta -CREDS $CREDS

                    }
                }

                Write-Verbose "No -DefaultSecurityDescriptor check"
            }#End if $bolConnected
        } else {
            Write-Verbose "Machine is not domain joined"
            Write-Host "Failed! - Machine is not domain joined and will not be able to translate SDDL"
        }
    }# End if Not $Base
    else {
        # Else GUI will open
        $global:bolCMD = $false
        [void]$Window.ShowDialog()
    }
}

