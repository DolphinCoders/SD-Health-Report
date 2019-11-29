<#
.SYNOPSIS
    Generate graphed report for all Active Directory objects.

.DESCRIPTION
    Generate graphed report for all Active Directory objects.

.PARAMETER CompanyLogo
    Enter URL or UNC path to your desired Company Logo for generated report.

    -CompanyLogo "\\Server01\Admin\Files\CompanyLogo.png"

.PARAMETER RightLogo
    Enter URL or UNC path to your desired right-side logo for generated report.

    -RightLogo "https://www.psmpartners.com/wp-content/uploads/2017/10/porcaro-stolarek-mete.png"

.PARAMETER ReportTitle
    Enter desired title for generated report.

    -ReportTitle "Active Directory Report"

.PARAMETER Days
    Users that have not logged in [X] amount of days or more.

    -Days "30"

.PARAMETER UserCreatedDays
    Users that have been created within [X] amount of days.

    -UserCreatedDays "7"

.PARAMETER DaysUntilPWExpireINT
    Users password expires within [X] amount of days

    -DaysUntilPWExpireINT "7"

.PARAMETER ADModNumber
    Active Directory Objects that have been modified within [X] amount of days.

    -ADModNumber "3"

.NOTES
    Version: 1.1.0
    Author: Bradley Wyatt
    Date: 12/4/2018
    Modified: JBear 12/5/2018
    Bradley Wyatt 12/8/2018
	jporgand 12/6/2018
	Daniel Knippshild 11/20/2019
#>

#Requires -Version 5.1
#Requires -Module ActiveDirectory

param (
	
	#Company logo that will be displayed on the left, can be URL or UNC
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Enter URL or UNC path to Company Logo")]
	[String]$CompanyLogo = "https://lt.smartdolphins.com/WCC2/images/logo.png",
	
	#Logo that will be on the right side, UNC or URL
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Enter URL or UNC path for Side Logo")]
	[String]$RightLogo = "",
	
	#Title of generated report
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Enter desired title for report")]
	[String]$ReportTitle = "SD Health Report",
	
	#Location the report will be saved to
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Enter desired directory path to save; Default: C:\Reports\")]
	[String]$ReportSavePath = "c:\reports\" + (Get-Date -f 'yyyy-MM-dd') + "\",
	
	#Find users that have not logged in X Amount of days, this sets the days
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Users that have not logged on in more than [X] days. amount of days; Default: 30")]
	$Days = 30,
	
	#Get users who have been created in X amount of days and less
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Users that have been created within [X] amount of days; Default: 7")]
	$UserCreatedDays = 30,
	
	#Get users whos passwords expire in less than X amount of days
	[Parameter(ValueFromPipeline = $true, HelpMessage = "Users password expires within [X] amount of days; Default: 7")]
	$DaysUntilPWExpireINT = 7,
	
	#Get AD Objects that have been modified in X days and newer
	[Parameter(ValueFromPipeline = $true, HelpMessage = "AD Objects that have been modified within [X] amount of days; Default: 3")]
	$ADModNumber = 3
	
	#CSS template located C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.1\
	#Default template is orange and named "Sample"
)

#Enable WinRM
winrm quickconfig -quiet

#Enable PSRemoting
Enable-PSRemoting -Force

#Check for ReportHTML Module
$Mod = Get-Module -ListAvailable -Name "ReportHTML"

If ($null -eq $Mod)
{	
	Write-Host "ReportHTML Module is not present, attempting to install it"
	
	Install-Module -Name ReportHTML -Force
	Import-Module ReportHTML -ErrorAction SilentlyContinue
}

Write-Host "Gathering Report Customization..." -ForegroundColor White
Write-Host "__________________________________" -ForegroundColor White
(Write-Host -NoNewline "Company Logo (left): " -ForegroundColor Yellow), (Write-Host  $CompanyLogo -ForegroundColor White)
(Write-Host -NoNewline "Company Logo (right): " -ForegroundColor Yellow), (Write-Host  $RightLogo -ForegroundColor White)
(Write-Host -NoNewline "Report Title: " -ForegroundColor Yellow), (Write-Host  $ReportTitle -ForegroundColor White)
(Write-Host -NoNewline "Report Save Path: " -ForegroundColor Yellow), (Write-Host  $ReportSavePath -ForegroundColor White)
(Write-Host -NoNewline "Amount of Days from Last User Logon Report: " -ForegroundColor Yellow), (Write-Host  $Days -ForegroundColor White)
(Write-Host -NoNewline "Amount of Days for New User Creation Report: " -ForegroundColor Yellow), (Write-Host  $UserCreatedDays -ForegroundColor White)
(Write-Host -NoNewline "Amount of Days for User Password Expiration Report: " -ForegroundColor Yellow), (Write-Host  $DaysUntilPWExpireINT -ForegroundColor White)
(Write-Host -NoNewline "Amount of Days for Newly Modified AD Objects Report: " -ForegroundColor Yellow), (Write-Host  $ADModNumber -ForegroundColor White)
Write-Host "__________________________________" -ForegroundColor White


function Convert-Date ($ftDate)
{
	
	$Date = [DateTime]::FromFileTime($ftDate)
	
	if ($Date -lt (Get-Date '1/1/1900') -or $Date -eq 0 -or $Null -eq $Date)
	{
		
		"Never"
	}
	else
	{
		
		$Date.ToString('yyyy-MM-dd hh:mm:ss tt')
	}
	
} #End function Convert-Date

Function Update-Progress($Title, $Percent) {
	if ($Percent -eq 100) {
			Write-Progress -Activity "$Title" -Status "Ready" -Completed
	} else {
			Write-Progress -Activity "$Title" -Status "($Percent% Complete: " -PercentComplete $Percent;
	}

}

Function CheckPathExists($Path, $File) {
	# Checks if the report file path exists, if not it creates it
	$CheckReportPath = Test-Path $Path -ErrorAction SilentlyContinue
	If ($CheckReportPath -eq $False)
	{
		Write-Host "$File path not found! - Creating $Path!"
		New-Item -Path $Path -Force -ItemType Directory | Out-Null
	}
	Else
	{
		Write-Host "$File file path is already present, continuing"
	}
}

Function Invoke-DcDiag {
    param(
        [Parameter(Mandatory=$False)]
        [ValidateScript({
        $EAP = $ErrorActionPreference
        $retval = $true
        $ErrorActionPreference = 'Stop'
        Try{ ForEach($DCName in $_) { Get-ADDomainController $DCName } } Catch { $retval = $false; Throw "$DCName doesn't exist or other error" } Finally { $ErrorActionPreference = $EAP }    
        $retval
        })]
        [string[]]$DomainControllers = $(Get-ADDomainController -Filter { IsReadOnly -ne $true } | Select-Object -ExpandProperty Name)
    )
    Begin {
#Ref:  http://blogs.microsoft.co.il/scriptfanatic/2012/04/13/custom-objects-default-display-in-powershell-30/
        [string[]]$DefaultProperties = 'DomainController','Entity','TestName','TestResult'
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]$(New-Object System.Management.Automation.PSPropertySet DefaultDisplayPropertySet,$DefaultProperties)
    }
    Process {
        $DCDiagResults = Invoke-Command -ScriptBlock { dcdiag /v } -ComputerName $DomainControllers
        ForEach ($DCDiagResult in $DCDiagResults | Group-Object -Property PSComputerName ) {
            $DCDiagResult.Group | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
                [pscustomobject]@{
                    DomainController = $DCDiagResult.Name
                    Entity = $_.Matches.Groups[1].Value
                    TestName = $_.Matches.Groups[3].Value
                    TestResult = $_.Matches.Groups[2].Value
                    FullLog = $DCDiagResult.Group -join "`n"
                } | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers -PassThru  # With PassThru will also return data to pipeline
            }
        }
    }
}

#Array of default Security Groups
$DefaultSGs = @(
	
	"Access Control Assistance Operators"
	"Account Operators"
	"Administrators"
	"Allowed RODC Password Replication Group"
	"Backup Operators"
	"Certificate Service DCOM Access"
	"Cert Publishers"
	"Cloneable Domain Controllers"
	"Cryptographic Operators"
	"Denied RODC Password Replication Group"
	"Distributed COM Users"
	"DnsUpdateProxy"
	"DnsAdmins"
	"Domain Admins"
	"Domain Computers"
	"Domain Controllers"
	"Domain Guests"
	"Domain Users"
	"Enterprise Admins"
	"Enterprise Key Admins"
	"Enterprise Read-only Domain Controllers"
	"Event Log Readers"
	"Group Policy Creator Owners"
	"Guests"
	"Hyper-V Administrators"
	"IIS_IUSRS"
	"Incoming Forest Trust Builders"
	"Key Admins"
	"Network Configuration Operators"
	"Performance Log Users"
	"Performance Monitor Users"
	"Print Operators"
	"Pre-Windows 2000 Compatible Access"
	"Protected Users"
	"RAS and IAS Servers"
	"RDS Endpoint Servers"
	"RDS Management Servers"
	"RDS Remote Access Servers"
	"Read-only Domain Controllers"
	"Remote Desktop Users"
	"Remote Management Users"
	"Replicator"
	"Schema Admins"
	"Server Operators"
	"Storage Replica Administrators"
	"System Managed Accounts Group"
	"Terminal Server License Servers"
	"Users"
	"Windows Authorization Access Group"
	"WinRMRemoteWMIUsers"
)

$Table = New-Object 'System.Collections.Generic.List[System.Object]'
$OUTable = New-Object 'System.Collections.Generic.List[System.Object]'
$UserTable = New-Object 'System.Collections.Generic.List[System.Object]'
$GroupTypetable = New-Object 'System.Collections.Generic.List[System.Object]'
$DefaultGrouptable = New-Object 'System.Collections.Generic.List[System.Object]'
$EnabledDisabledUsersTable = New-Object 'System.Collections.Generic.List[System.Object]'
$DomainAdminTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ExpiringAccountsTable = New-Object 'System.Collections.Generic.List[System.Object]'
$CompanyInfoTable = New-Object 'System.Collections.Generic.List[System.Object]'
$securityeventtable = New-Object 'System.Collections.Generic.List[System.Object]'
$DomainTable = New-Object 'System.Collections.Generic.List[System.Object]'
$OUGPOTable = New-Object 'System.Collections.Generic.List[System.Object]'
$GroupMembershipTable = New-Object 'System.Collections.Generic.List[System.Object]'
$PasswordExpirationTable = New-Object 'System.Collections.Generic.List[System.Object]'
$PasswordExpireSoonTable = New-Object 'System.Collections.Generic.List[System.Object]'
$userphaventloggedonrecentlytable = New-Object 'System.Collections.Generic.List[System.Object]'
$EnterpriseAdminTable = New-Object 'System.Collections.Generic.List[System.Object]'
$NewCreatedUsersTable = New-Object 'System.Collections.Generic.List[System.Object]'
$GroupProtectionTable = New-Object 'System.Collections.Generic.List[System.Object]'
$OUProtectionTable = New-Object 'System.Collections.Generic.List[System.Object]'
$GPOTable = New-Object 'System.Collections.Generic.List[System.Object]'
$DCDiagTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ADObjectTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ProtectedUsersTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ComputersTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ComputerProtectedTable = New-Object 'System.Collections.Generic.List[System.Object]'
$ComputersEnabledTable = New-Object 'System.Collections.Generic.List[System.Object]'
$DefaultComputersinDefaultOUTable = New-Object 'System.Collections.Generic.List[System.Object]'
$DefaultUsersinDefaultOUTable = New-Object 'System.Collections.Generic.List[System.Object]'
$TOPUserTable = New-Object 'System.Collections.Generic.List[System.Object]'
$TOPGroupsTable = New-Object 'System.Collections.Generic.List[System.Object]'
$TOPComputersTable = New-Object 'System.Collections.Generic.List[System.Object]'
$GraphComputerOS = New-Object 'System.Collections.Generic.List[System.Object]'

CheckPathExists $ReportSavePath "Report Directory"

#Retrieve all known Domain Controllers
$DCs = (Get-ADDomainController -Filter *).Name

#Loop through all Domain Controllers for user data; ensures most recent LastLogon attribute value is used for accuracy
$AllDCUsers = foreach($DC in $DCs) {

    #Get all AD User Data from each Domain Controller
    Get-ADUser -Server $DC -Filter * -Properties * | Sort-Object Name
}

#Retrieve all users
$AllUsers = $(

    #Select unique accountnames; all user data will be in multiples of the number of Domain Controllers you have
	$Unique = ($AllDCUsers | Select-Object SamAccountName -Unique | Sort-Object SamAccountName).SamAccountName

    foreach($U in $Unique) {

        #Selects most recent LastLogon time User Object from all Domain Controllers AD User Data; LastLogon does NOT replicate across Domain Controllers
        ($AllDCUsers | Where-Object { $_.SamAccountName -Match $U } | Sort-Object LastLogon -Descending | Select-Object -First 1)
	}

)


#Retrieve all computers
$Computers = Get-ADComputer -Filter * -Properties *

$GPOs = Get-GPO -All | Select-Object DisplayName, GPOStatus, ModificationTime, @{ Label = "ComputerVersion"; Expression = { $_.computer.dsversion } }, @{ Label = "UserVersion"; Expression = { $_.user.dsversion } }

<###########################
         Dashboard
############################>

Write-Host "Working on Dashboard Report..." -ForegroundColor Green

$dte = (Get-Date).AddDays(- $ADModNumber)

$ADObjs = Get-ADObject -Filter { whenchanged -gt $dte -and ObjectClass -ne "domainDNS" -and ObjectClass -ne "rIDManager" -and ObjectClass -ne "rIDSet" } -Properties *

$CurrentADObjs = 0
$TotalADObjs = $ADObjs.Count

foreach ($ADObj in $ADObjs)
{

	$Title = "Processing $($CurrentADObjs++) of $($TotalADObjs) AD Objects..."
	$Percent = [math]::Round($CurrentADObjs / $TotalADObjs * 100, 2)
	Update-Progress $Title $Percent
 
#	Write-Progress -Activity "Processing $($CurrentADObjs++) of $($TotalADObjs) AD Objects..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalADObjs - $CurrentADObjs) / $TotalADObjs) * 100) + "%") -PercentComplete ((($TotalADObjs - $CurrentADObjs) / $TotalADObjs) * 100) -ErrorAction SilentlyContinue
	
	if ($ADObj.ObjectClass -eq "GroupPolicyContainer")
	{
		
		$Name = $ADObj.DisplayName
	}
	
	else
	{
		
		$Name = $ADObj.Name
	}
	
	$obj = [PSCustomObject]@{
		
		'Name'	      = $Name
		'Object Type' = $ADObj.ObjectClass
		'When Changed' = Convert-Date $ADObj.WhenChanged.ToFileTime()
	}
	
	$ADObjectTable.Add($obj)
}
if (($ADObjectTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No AD Objects have been modified recently'
	}
	
	$ADObjectTable.Add($obj)
}


$ADRecycleBinStatus = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes

if ($ADRecycleBinStatus.Count -lt 1)
{
	
	$ADRecycleBin = "Disabled"
}

else
{
	
	$ADRecycleBin = "Enabled"
}

#Company Information
$ADInfo = Get-ADDomain
$ForestObj = Get-ADForest
$DomainControllerobj = Get-ADDomain
$Forest = $ADInfo.Forest
$InfrastructureMaster = $DomainControllerobj.InfrastructureMaster
$RIDMaster = $DomainControllerobj.RIDMaster
$PDCEmulator = $DomainControllerobj.PDCEmulator
$DomainNamingMaster = $ForestObj.DomainNamingMaster
$SchemaMaster = $ForestObj.SchemaMaster

$obj = [PSCustomObject]@{
	
	'Domain'			    = $Forest
	'AD Recycle Bin'	    = $ADRecycleBin
	'Infrastructure Master' = $InfrastructureMaster
	'RID Master'		    = $RIDMaster
	'PDC Emulator'		    = $PDCEmulator
	'Domain Naming Master'  = $DomainNamingMaster
	'Schema Master'		    = $SchemaMaster
}

$CompanyInfoTable.Add($obj)

if (($CompanyInfoTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: Could not get items for table'
	}
	$CompanyInfoTable.Add($obj)
}

#Get newly created users
$When = ((Get-Date).AddDays(- $UserCreatedDays)).Date
$NewUsers = $AllUsers | Where-Object { $_.whenCreated -ge $When }

$TotalNewUsers = @($NewUsers).Count
$CurrentUserCount = 0

foreach ($Newuser in $Newusers)
{

	$Title = "Processing $($CurrentUserCount++) of $($TotalNewUsers) New Users..."
	$Percent = [math]::Round($CurrentUserCount / $TotalNewUsers * 100, 2)
	Update-Progress $Title $Percent

	#Write-Progress -Activity "Processing $($CurrentUserCount++) of $($TotalNewUsers) New Users..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalNewUsers - $CurrentUserCount) / $TotalNewUsers) * 100) + "%") -PercentComplete ((($TotalNewUsers - $CurrentUserCount) / $TotalNewUsers) * 100) -ErrorAction SilentlyContinue

	$obj = [PSCustomObject]@{
		
		'Name' = $Newuser.Name
		'Enabled' = $Newuser.Enabled
		'Creation Date' = (Convert-Date $Newuser.WhenCreated.ToFileTime())
	}
	
	$NewCreatedUsersTable.Add($obj)
}
if (($NewCreatedUsersTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No new users have been recently created'
	}
	$NewCreatedUsersTable.Add($obj)
}



#Get Domain Admins
$DomainAdminMembers = Get-ADGroupMember "Domain Admins"

$TotalAdmins = $DomainAdminMembers.Count
$CurrentAdminCount = 0

foreach ($DomainAdminMember in $DomainAdminMembers)
{
	$Title = "Processing $($CurrentAdminCount++) of $($TotalAdmins) Domain Admins..."
	$Percent = [math]::Round($CurrentAdminCount / $TotalAdmins * 100, 2)
	Update-Progress $Title $Percent
	#Write-Progress -Activity "Processing $($CurrentAdminCount++) of $($TotalAdmins) Domain Admins..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalAdmins - $CurrentAdminCount) / $TotalAdmins) * 100) + "%") -PercentComplete ((($TotalAdmins - $CurrentAdminCount) / $TotalAdmins) * 100) -ErrorAction SilentlyContinue	
	
	$Name = $DomainAdminMember.Name
	$Type = $DomainAdminMember.ObjectClass
	$Enabled = ($AllUsers | Where-Object { $_.Name -eq $Name }).Enabled
	
	$obj = [PSCustomObject]@{
		
		'Name'    = $Name
		'Enabled' = $Enabled
		'Type'    = $Type
	}
	
	$DomainAdminTable.Add($obj)
}

if (($DomainAdminTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No Domain Admin Members were found'
	}
	$DomainAdminTable.Add($obj)
}

#Get Enterprise Admins
$EnterpriseAdminsMembers = Get-ADGroupMember "Enterprise Admins" -Server $SchemaMaster

$TotalEnterpriseAdmins = $EnterpriseAdminsMembers.Count
$CurrentEnterpriseAdmin = 0

foreach ($EnterpriseAdminsMember in $EnterpriseAdminsMembers)
{
	$Title = "Processing $($CurrentEnterpriseAdmin++) of $($TotalEnterpriseAdmins) Enterprise Admins..."
	$Percent = [math]::Round($CurrentEnterpriseAdmin / $TotalEnterpriseAdmins * 100, 2)
	Update-Progress $Title $Percent	
#	Write-Progress -Activity "Processing $($CurrentEnterpriseAdmin++) of $($TotalEnterpriseAdmins) Enterprise Admins..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalEnterpriseAdmins - $CurrentEnterpriseAdmin) / $TotalEnterpriseAdmins) * 100) + "%") -PercentComplete ((($TotalEnterpriseAdmins - $CurrentEnterpriseAdmin) / $TotalEnterpriseAdmins) * 100) -ErrorAction SilentlyContinue

	$Name = $EnterpriseAdminsMember.Name
	$Type = $EnterpriseAdminsMember.ObjectClass
	$Enabled = ($AllUsers | Where-Object { $_.Name -eq $Name }).Enabled
	
	$obj = [PSCustomObject]@{
		
		'Name'    = $Name
		'Enabled' = $Enabled
		'Type'    = $Type
	}
	
	$EnterpriseAdminTable.Add($obj)
}

if (($EnterpriseAdminTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: Enterprise Admin members were found'
	}
	$EnterpriseAdminTable.Add($obj)
}

$DefaultComputersOU = (Get-ADDomain).ComputersContainer
$DefaultComputers = $Computers | Where-Object { $_.DistinguishedName -like "*$($DefaultComputersOU)"}

$TotalComputers = $DefaultComputers.Count
$CurrentComputerCount = 0

foreach ($DefaultComputer in $DefaultComputers)
{
	$Title = "Processing $($CurrentComputerCount++) of $($TotalComputers) Default Computers..."
	$Percent = [math]::Round($CurrentComputerCount / $TotalComputers * 100, 2)
	Update-Progress $Title $Percent
	#Write-Progress -Activity "Processing $($CurrentComputerCount++) of $($TotalComputers) Default Computers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalComputers - $CurrentComputerCount) / $TotalComputers) * 100) + "%") -PercentComplete ((($TotalComputers - $CurrentComputerCount) / $TotalComputers) * 100) -ErrorAction SilentlyContinue

	$obj = [PSCustomObject]@{
		
		'Name' = $DefaultComputer.Name
		'Enabled' = $DefaultComputer.Enabled
		'Operating System' = $DefaultComputer.OperatingSystem
		'Modified Date' = (Convert-Date $DefaultComputer.Modified.ToFileTime())
		'Password Last Set' = Convert-Date $DefaultComputer.PasswordLastSet.ToFileTime()
		'Protect from Deletion' = $DefaultComputer.ProtectedFromAccidentalDeletion
	}
	
	$DefaultComputersinDefaultOUTable.Add($obj)
}

if (($DefaultComputersinDefaultOUTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No computers were found in the Default OU (' + $DefaultComputersOU + ')'
	}
	$DefaultComputersinDefaultOUTable.Add($obj)
}

$DefaultUsersOU = (Get-ADDomain).UsersContainer
$DefaultUsers = $Allusers | Where-Object { $_.DistinguishedName -like "*$($DefaultUsersOU)" } | Select-Object Name, UserPrincipalName, Enabled, ProtectedFromAccidentalDeletion, EmailAddress, @{ Name = 'LastLogon'; Expression = { Convert-Date $_.LastLogon } }, DistinguishedName

$TotalDefaultUsers = $DefaultUsers.Count
$CurrentDefaultUserCount = 0

foreach ($DefaultUser in $DefaultUsers)
{
	
	$Title = "Processing $($CurrentDefaultUserCount++) of $($TotalDefaultUsers) Default Users..."
	$Percent = [math]::Round($CurrentDefaultUserCount / $TotalDefaultUsers * 100, 2)
	Update-Progress $Title $Percent

#	Write-Progress -Activity "Processing $($CurrentDefaultUserCount++) of $($TotalDefaultUsers) Default Users..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalDefaultUsers - $CurrentDefaultUserCount) / $TotalDefaultUsers) * 100) + "%") -PercentComplete ((($TotalDefaultUsers - $CurrentDefaultUserCount) / $TotalDefaultUsers) * 100) -ErrorAction SilentlyContinue

	$obj = [PSCustomObject]@{
		
		'Name' = $DefaultUser.Name
		'UserPrincipalName' = $DefaultUser.UserPrincipalName
		'Enabled' = $DefaultUser.Enabled
		'Protected from Deletion' = $DefaultUser.ProtectedFromAccidentalDeletion
		'Last Logon' = Convert-Date $DefaultUser.LastLogon
		'Email Address' = $DefaultUser.EmailAddress
	}
	
	$DefaultUsersinDefaultOUTable.Add($obj)
}
if (($DefaultUsersinDefaultOUTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No Users were found in the default OU (' + $DefaultUsersOU + ')'
	}
	$DefaultUsersinDefaultOUTable.Add($obj)
}


#Expiring Accounts
$LooseUsers = Search-ADAccount -AccountExpiring -UsersOnly

$TotalLooseUsers = $LooseUsers.Count
$CurrentLooseUserCount = 0

foreach ($LooseUser in $LooseUsers)
{
	$Title = "Processing $($CurrentLooseUserCount++) of $($TotalLooseUsers) Loose Users..."
	$Percent = [math]::Round($CurrentLooseUserCount / $TotalLooseUsers * 100, 2)
	Update-Progress $Title $Percent

	#Write-Progress -Activity "Processing $($CurrentLooseUserCount++) of $($TotalLooseUsers) Loose Users..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalLooseUsers - $CurrentLooseUserCount) / $TotalLooseUsers) * 100) + "%") -PercentComplete ((($TotalLooseUsers - $CurrentLooseUserCount) / $TotalLooseUsers) * 100) -ErrorAction SilentlyContinue
	
	$NameLoose = $LooseUser.Name
	$UPNLoose = $LooseUser.UserPrincipalName
	$ExpirationDate = $LooseUser.AccountExpirationDate
	$enabled = $LooseUser.Enabled
	
	$obj = [PSCustomObject]@{
		
		'Name'			    = $NameLoose
		'UserPrincipalName' = $UPNLoose
		'Expiration Date'   = $ExpirationDate
		'Enabled'		    = $enabled
	}
	
	$ExpiringAccountsTable.Add($obj)
}

if (($ExpiringAccountsTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No Users were found to expire soon'
	}
	$ExpiringAccountsTable.Add($obj)
}

#Security Logs
$SecurityLogs = Get-EventLog -Newest 7 -LogName "Security" | Where-Object { $_.Message -like "*An account*" }

foreach ($SecurityLog in $SecurityLogs)
{
	
	$TimeGenerated = $SecurityLog.TimeGenerated
	$EntryType = $SecurityLog.EntryType
	$Recipient = $SecurityLog.Message
	
	$obj = [PSCustomObject]@{
		
		'Time'    = $TimeGenerated
		'Type'    = $EntryType
		'Message' = $Recipient
	}
	
	$SecurityEventTable.Add($obj)
}

if (($SecurityEventTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No logon security events were found'
	}
	$SecurityEventTable.Add($obj)
}

#Tenant Domain
$Domains = Get-ADForest | Select-Object -ExpandProperty upnsuffixes | ForEach-Object{
	
	$obj = [PSCustomObject]@{
		
		'UPN Suffixes' = $_
		Valid		   = "True"
	}
	
	$DomainTable.Add($obj)
}
if (($DomainTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No UPN Suffixes were found'
	}
	$DomainTable.Add($obj)
}

($Domains)

Write-Host "Done!" -ForegroundColor White

<###########################

		   Groups

############################>

Write-Host "Working on Groups Report..." -ForegroundColor Green

#Get groups and sort in alphabetical order
$Groups = Get-ADGroup -Filter * -Properties *
$SecurityCount = 0
$MailSecurityCount = 0
$CustomGroup = 0
$DefaultGroup = 0
$Groupswithmemebrship = 0
$Groupswithnomembership = 0
$GroupsProtected = 0
$GroupsNotProtected = 0

$TotalGroups = $Groups.Count
$CurrentGroupCount = 0

foreach ($Group in $Groups)
{
	
	$Title = "Processing $($CurrentGroupCount++) of $($TotalGroups) Total Groups..."
	$Percent = [math]::Round($CurrentGroupCount / $TotalGroups * 100, 2)
	Update-Progress $Title $Percent

#	Write-Progress -Activity "Processing $($CurrentGroupCount++) of $($TotalGroups) Security Groups..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalGroups - $CurrentGroupCount) / $TotalGroups) * 100) + "%") -PercentComplete ((($TotalGroups - $CurrentGroupCount) / $TotalGroups) * 100) -ErrorAction SilentlyContinue

	$DefaultADGroup = 'False'
	$Type = New-Object 'System.Collections.Generic.List[System.Object]'
	$Gemail = (Get-ADGroup $Group -Properties mail).mail
	
	if (($group.GroupCategory -eq "Security") -and ($null -ne $Gemail))
	{
		
		$MailSecurityCount++
	}
	
	if (($group.GroupCategory -eq "Security") -and ($Null -eq ($Gemail)))
	{
		
		$SecurityCount++
	}
	
	if ($Group.ProtectedFromAccidentalDeletion -eq $True)
	{
		
		$GroupsProtected++
	}
	
	else
	{
		
		$GroupsNotProtected++
	}
	
	if ($DefaultSGs -contains $Group.Name)
	{
		
		$DefaultADGroup = "True"
		$DefaultGroup++
	}
	
	else
	{
		
		$CustomGroup++
	}
	
	if ($group.GroupCategory -eq "Distribution")
	{
		
		$Type = "Distribution Group"
	}
	
	if (($group.GroupCategory -eq "Security") -and ($Null -eq ($Gemail)))
	{
		
		$Type = "Security Group"
	}
	
	if (($group.GroupCategory -eq "Security") -and ($Null -ne ($Gemail)))
	{
		
		$Type = "Mail-Enabled Security Group"
	}
	
	if ($Group.Name -ne "Domain Users")
	{
		
		$Users = (Get-ADGroupMember -Identity $Group | Sort-Object DisplayName | Select-Object -ExpandProperty Name) -join ", "
		
		if (!($Users))
		{
			
			$Groupswithnomembership++
		}
		
		else
		{
			
			$Groupswithmemebrship++
			
		}
	}
	
	else
	{
		
		$Users = "Skipped Domain Users Membership"
	}
	
	# $OwnerDN = Get-ADGroup -Filter { name -eq $Group.Name } -Properties managedBy | Select-Object -ExpandProperty ManagedBy
	# Try
	# {
	# 	$Manager = Get-ADUser -Filter { distinguishedname -like $OwnerDN } | Select-Object -ExpandProperty Name
	# }
	# Catch
	# {
	# 	write-host -ForegroundColor Yellow "Cannot resolve the manager, " $Manager " on the group " $group.name
	# }
	
	#$Manager = $AllUsers | Where-Object { $_.distinguishedname -eq $OwnerDN } | Select-Object -ExpandProperty Name

	$Manager = (Get-ADGroup -Filter { name -eq $Group.Name } -Properties managedBy | Select-Object -ExpandProperty ManagedBy) -replace '^CN=|,.*$'
	
	$obj = [PSCustomObject]@{
		
		'Name' = $Group.name
		'Type' = $Type
		'Members' = $users
		'Managed By' = $Manager
		'E-mail Address' = $GEmail
		'Protected from Deletion' = $Group.ProtectedFromAccidentalDeletion
		'Default AD Group' = $DefaultADGroup
	}
	
	$table.Add($obj)
}

if (($table).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No Groups were found'
	}
	$table.Add($obj)
}
#TOP groups table
$obj1 = [PSCustomObject]@{
	
	'Total Groups' = $Groups.Count
	'Mail-Enabled Security Groups' = $MailSecurityCount
	'Security Groups' = $SecurityCount
	'Distribution Groups' = $DistroCount
}

$TOPGroupsTable.Add($obj1)

$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Mail-Enabled Security Groups'
	'Count' = $MailSecurityCount
}

$GroupTypetable.Add($obj1)

$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Security Groups'
	'Count' = $SecurityCount
}

$GroupTypetable.Add($obj1)
$DistroCount = ($Groups | Where-Object { $_.GroupCategory -eq "Distribution" }).Count

$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Distribution Groups'
	'Count' = $DistroCount
}

$GroupTypetable.Add($obj1)

#Default Group Pie Chart
$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Default Groups'
	'Count' = $DefaultGroup
}

$DefaultGrouptable.Add($obj1)

$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Custom Groups'
	'Count' = $CustomGroup
}

$DefaultGrouptable.Add($obj1)

#Group Protection Pie Chart
$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Protected'
	'Count' = $GroupsProtected
}

$GroupProtectionTable.Add($obj1)

$obj1 = [PSCustomObject]@{
	
	'Name'  = 'Not Protected'
	'Count' = $GroupsNotProtected
}

$GroupProtectionTable.Add($obj1)

#Groups with membership vs no membership pie chart
$objmem = [PSCustomObject]@{
	
	'Name'  = 'With Members'
	'Count' = $Groupswithmemebrship
}

$GroupMembershipTable.Add($objmem)

$objmem = [PSCustomObject]@{
	
	'Name'  = 'No Members'
	'Count' = $Groupswithnomembership
}

$GroupMembershipTable.Add($objmem)

Write-Host "Done!" -ForegroundColor White

<###########################

    Organizational Units

############################>

Write-Host "Working on Organizational Units Report..." -ForegroundColor Green

#Get all OUs'
$OUs = Get-ADOrganizationalUnit -Filter * -Properties *
$OUwithLinked = 0
$OUwithnoLink = 0
$OUProtected = 0
$OUNotProtected = 0

$TotalOUs = $OUs.Count
$CurrentOUCount = 0 

foreach ($OU in $OUs)
{

	$Title = "Processing $($CurrentOUCount++) of $($TotalOUs) Total OUs..."
	$Percent = [math]::Round($CurrentOUCount / $TotalOUs * 100, 2)
	Update-Progress $Title $Percent
	
	#Write-Progress -Activity "Processing $($CurrentOUCount++) of $($TotalOUs) Users..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalOUs - $CurrentOUCount) / $TotalOUs) * 100) + "%") -PercentComplete ((($TotalOUs - $CurrentOUCount) / $TotalOUs) * 100) -ErrorAction SilentlyContinue

	$LinkedGPOs = New-Object 'System.Collections.Generic.List[System.Object]'
	
	if (($OU.linkedgrouppolicyobjects).length -lt 1)
	{
		
		$LinkedGPOs = "None"
		$OUwithnoLink++
	}
	
	else
	{
		
		$OUwithLinked++
		$GPOslinks = $OU.linkedgrouppolicyobjects
		
		foreach ($GPOlink in $GPOslinks)
		{
			
			$Split1 = $GPOlink -split "{" | Select-Object -Last 1
			$Split2 = $Split1 -split "}" | Select-Object -First 1
			$LinkedGPOs.Add((Get-GPO -Guid $Split2 -ErrorAction SilentlyContinue).DisplayName)
		}
	}
	
	if ($OU.ProtectedFromAccidentalDeletion -eq $True)
	{
		
		$OUProtected++
	}
	
	else
	{
		
		$OUNotProtected++
	}
	
	$LinkedGPOs = $LinkedGPOs -join ", "
	$obj = [PSCustomObject]@{
		
		'Name' = $OU.Name
		'Linked GPOs' = $LinkedGPOs
		'Modified Date' = (Convert-Date $OU.WhenChanged.ToFileTime())
		'Protected from Deletion' = $OU.ProtectedFromAccidentalDeletion
	}
	
	$OUTable.Add($obj)
}

if (($OUTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No OUs were found'
	}
	$OUTable.Add($obj)
}

#OUs with no GPO Linked
$obj1 = [PSCustomObject]@{
	
	'Name'  = "OUs with no GPOs linked"
	'Count' = $OUwithnoLink
}

$OUGPOTable.Add($obj1)

$obj2 = [PSCustomObject]@{
	
	'Name'  = "OUs with GPOs linked"
	'Count' = $OUwithLinked
}

$OUGPOTable.Add($obj2)

#OUs Protected Pie Chart
$obj1 = [PSCustomObject]@{
	
	'Name'  = "Protected"
	'Count' = $OUProtected
}

$OUProtectionTable.Add($obj1)

$obj2 = [PSCustomObject]@{
	
	'Name'  = "Not Protected"
	'Count' = $OUNotProtected
}

$OUProtectionTable.Add($obj2)

Write-Host "Done!" -ForegroundColor White

<###########################

           USERS

############################>

Write-Host "Working on Users Report..." -ForegroundColor Green

$UserEnabled = 0
$UserDisabled = 0
$UserPasswordExpires = 0
$UserPasswordNeverExpires = 0
$ProtectedUsers = 0
$NonProtectedUsers = 0

# $UsersWIthPasswordsExpiringInUnderAWeek = 0
# $UsersNotLoggedInOver30Days = 0
# $AccountsExpiringSoon = 0


#Get users that haven't logged on in X amount of days, var is set at start of script
$Userphaventloggedonrecentlytable = New-Object 'System.Collections.Generic.List[System.Object]'
foreach ($User in $AllUsers)
{
	
	$AttVar = $User | Select-Object Enabled, PasswordExpired, @{ Name = 'PasswordLastSet'; Expression = { Convert-Date $_.PasswordLastSet.ToFileTime() }}, PasswordNeverExpires, PasswordNotRequired, Name, SamAccountName, EmailAddress, @{ Name = 'AccountExpirationDate'; Expression = { Convert-Date $_.AccountExpirationDate } }, @{ Name = 'LastLogon'; Expression = { Convert-Date $_.LastLogon } }, DistinguishedName
	$maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
	
	if ((($AttVar.PasswordNeverExpires) -eq $False) -and (($AttVar.Enabled) -ne $false))
	{
		
		#Get Password last set date
		$passwordSetDate = ($User | ForEach-Object { $_.PasswordLastSet })
		
		if ($null -eq $passwordSetDate)
		{
			
			$daystoexpire = "User has never logged on"
		}
		
		else
		{
			
			#Check for Fine Grained Passwords
			$PasswordPol = (Get-ADUserResultantPasswordPolicy $user)
			
			if ($Null -ne ($PasswordPol))
			{
				
				$maxPasswordAge = ($PasswordPol).MaxPasswordAge
			}
			
			$expireson = $passwordsetdate.AddDays($maxPasswordAge)
			$today = (Get-Date)
			
			#Gets the count on how many days until the password expires and stores it in the $daystoexpire var
			$daystoexpire = (New-TimeSpan -Start $today -End $Expireson).Days
		}
	}
	
	else
	{
		
		$daystoexpire = "N/A"
	}
	
	if (($User.Enabled -eq $True) -and ($AttVar.LastLogon -lt ((Get-Date).AddDays(- $Days))) -and ($Null -ne $User.LastLogon))
	{
		
		$obj = [PSCustomObject]@{
			
			'Name' = $User.Name
			'UserPrincipalName' = $User.UserPrincipalName
			'Enabled' = $AttVar.Enabled
			'Protected from Deletion' = $User.ProtectedFromAccidentalDeletion
			'Last Logon' = $AttVar.LastLogon
			'Password Never Expires' = $AttVar.PasswordNeverExpires
			'Days Until Password Expires' = $daystoexpire
		}
		
		$userphaventloggedonrecentlytable.Add($obj)
	}
	
	#Items for protected vs non protected users
	if ($User.ProtectedFromAccidentalDeletion -eq $False)
	{
		
		$NonProtectedUsers++
	}
	
	else
	{
		
		$ProtectedUsers++
	}
	
	#Items for the enabled vs disabled users pie chart
	if (($AttVar.PasswordNeverExpires) -ne $false)
	{
		
		$UserPasswordNeverExpires++
	}
	
	else
	{
		
		$UserPasswordExpires++
	}
	
	#Items for password expiration pie chart
	if (($AttVar.Enabled) -ne $false)
	{
		
		$UserEnabled++
	}
	
	else
	{
		
		$UserDisabled++
	}
	
	$Name = $User.Name
	$UPN = $User.UserPrincipalName
	$Enabled = $AttVar.Enabled
	$EmailAddress = $AttVar.EmailAddress
	$AccountExpiration = $AttVar.AccountExpirationDate
	$PasswordExpired = $AttVar.PasswordExpired
	$PasswordLastSet = $AttVar.PasswordLastSet
	$PasswordNeverExpires = $AttVar.PasswordNeverExpires
	$LastLogon = $AttVar.LastLogon
#	$daysUntilPWExpire = $daystoexpire #Commented out because not in use
	
	$obj = [PSCustomObject]@{
		
		'Name'				      = $Name
		'UserPrincipalName'	      = $UPN
		'Enabled'				  = $Enabled
		'Protected from Deletion' = $User.ProtectedFromAccidentalDeletion
		'Last Logon'			  = $LastLogon
		'Email Address'		      = $EmailAddress
		'Account Expiration'	  = $AccountExpiration
		'Change Password Next Logon' = $PasswordExpired
		'Password Last Set'	      = $PasswordLastSet
		'Password Never Expires'  = $PasswordNeverExpires
		'Days Until Password Expires' = $DaysToExpire
	}
	
	$usertable.Add($obj)
	
	if ($daystoexpire -lt $DaysUntilPWExpireINT)
	{
		
		$obj = [PSCustomObject]@{
			
			'Name'					      = $Name
			'Days Until Password Expires' = $daystoexpire
		}
		
		$PasswordExpireSoonTable.Add($obj)
	}
}
if (($userphaventloggedonrecentlytable).Count -eq 0)
{
	$userphaventloggedonrecentlytable = [PSCustomObject]@{
		
		Information = "Information: No Users were found to have not logged on in $Days days or more"
	}
}
if (($PasswordExpireSoonTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No users were found to have passwords expiring soon'
	}
	$PasswordExpireSoonTable.Add($obj)
}


if (($usertable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No users were found'
	}
	$usertable.Add($obj)
}

#Data for users enabled vs disabled pie graph
$objULic = [PSCustomObject]@{
	
	'Name'  = 'Enabled'
	'Count' = $UserEnabled
}

$EnabledDisabledUsersTable.Add($objULic)

$objULic = [PSCustomObject]@{
	
	'Name'  = 'Disabled'
	'Count' = $UserDisabled
}

$EnabledDisabledUsersTable.Add($objULic)

#Data for users password expires pie graph
$objULic = [PSCustomObject]@{
	
	'Name'  = 'Password Expires'
	'Count' = $UserPasswordExpires
}

$PasswordExpirationTable.Add($objULic)

$objULic = [PSCustomObject]@{
	
	'Name'  = 'Password Never Expires'
	'Count' = $UserPasswordNeverExpires
}

$PasswordExpirationTable.Add($objULic)

#Data for protected users pie graph
$objULic = [PSCustomObject]@{
	
	'Name'  = 'Protected'
	'Count' = $ProtectedUsers
}

$ProtectedUsersTable.Add($objULic)

$objULic = [PSCustomObject]@{
	
	'Name'  = 'Not Protected'
	'Count' = $NonProtectedUsers
}

$ProtectedUsersTable.Add($objULic)
if ($null -ne (($userphaventloggedonrecentlytable).Information))
{
	$UHLONXD = "0"
	
}
Else
{
	$UHLONXD = $userphaventloggedonrecentlytable.Count
	
}
#TOP User table
If ($null -eq (($ExpiringAccountsTable).Information))
{
	
	$objULic = [PSCustomObject]@{
		'Total Users' = $AllUsers.Count
		"Users with Passwords Expiring in less than $DaysUntilPWExpireINT days" = $PasswordExpireSoonTable.Count
		'Expiring Accounts' = $ExpiringAccountsTable.Count
		"Users Haven't Logged on in $Days Days or more" = $UHLONXD
	}
	
	$TOPUserTable.Add($objULic)
	
	
}
Else
{
	
	$objULic = [PSCustomObject]@{
		'Total Users' = $AllUsers.Count
		"Users with Passwords Expiring in less than $DaysUntilPWExpireINT days" = $PasswordExpireSoonTable.Count
		'Expiring Accounts' = "0"
		"Users Haven't Logged on in $Days Days or more" = $UHLONXD
	}
	$TOPUserTable.Add($objULic)
}

Write-Host "Done!" -ForegroundColor White
<###########################

	   Group Policy

############################>
Write-Host "Working on Group Policy Report..." -ForegroundColor Green

$GPOTable = New-Object 'System.Collections.Generic.List[System.Object]'
$TotalGPOs = $GPOs.Count
$CurrentGPOCount = 0

foreach ($GPO in $GPOs)
{
	
	$Title = "Processing $($CurrentGPOCount++) of $($TotalGPOs) Total GPOs..."
	$Percent = [math]::Round($CurrentGPOCount / $TotalGPOs * 100, 2)
	Update-Progress $Title $Percent

#	Write-Progress -Activity "Processing $($CurrentGPOCount++) of $($TotalGPOs) Group Policies..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalGPOs - $CurrentGPOCount) / $TotalGPOs) * 100) + "%") -PercentComplete ((($TotalGPOs - $CurrentGPOCount) / $TotalGPOs) * 100) -ErrorAction SilentlyContinue

	$obj = [PSCustomObject]@{
		
		'Name' = $GPO.DisplayName
		'Status' = $GPO.GpoStatus
		'Modified Date' = Convert-Date $GPO.ModificationTime.ToFileTime()
		'User Version' = $GPO.UserVersion
		'Computer Version' = $GPO.ComputerVersion
	}
	
	$GPOTable.Add($obj)
}
if (($GPOTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No Group Policy Objects were found'
	}
	$GPOTable.Add($obj)
}
Write-Host "Done!" -ForegroundColor White

<###########################

	   AD Health

############################>
Write-Host "Working on DC Diag Report..." -ForegroundColor Green

$DCDiagTable = New-Object 'System.Collections.Generic.List[System.Object]'
# $TotalDCs = $DCs.Count
# $CurrentDCCount = 0

$DCDiag = Invoke-DcDiag

foreach ($Log in $DCDiag)
{
	# $Title = "Processing $($CurrentDCCount++) of $($TotalDCs) Total DCs..."
	# $Percent = [math]::Round($CurrentDCCount / $TotalDCs * 100, 2)
	# Update-Progress $Title $Percent

	$Obj = [PSCustomObject]@{
		
		'DC Name' = $Log.DomainController
		'Test Name' = $Log.TestName
		'Test Result' = $Log.TestResult
		'Entity' = $Log.Entity
	}

	$DCDiagTable.Add($Obj)

}

$OutputDCDiagPath = $ReportSavePath + '\dcdiag.html'
$FileLine = @()

Foreach ($Line in $DCDiag.FullLog -Split "`n") {
	$Obj = New-Object -TypeName PSObject
	$Value = $Line 
	Add-Member -InputObject $Obj -Type NoteProperty -Name HealthCheck -Value $Value
	$FileLine += $Obj
}

$FileLine | ConvertTo-Html -Property HealthCheck | Out-File $OutputDCDiagPath


if (($DCDiagTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No DC Diag information was found'
	}
	$DCDiagTable.Add($obj)
}
Write-Host "Done!" -ForegroundColor White

<###########################

	   Computers

############################>
Write-Host "Working on Computers Report..." -ForegroundColor Green

$ComputersProtected = 0
$ComputersNotProtected = 0
$ComputerEnabled = 0
$ComputerDisabled = 0
#Only search for versions of windows that exist in the Environment
$WindowsRegex = "(Windows (Server )?(\d+|XP)?( R2)?).*"
$OsVersions = $Computers | Select-Object OperatingSystem -unique | ForEach-Object {
	if ($_.OperatingSystem -match $WindowsRegex ){ 
		return $matches[1]
	} elseif ($_.OperatingSystem -ne $null) {
		return $_.OperatingSystem
	}
} | Select-Object -unique | Sort-Object

$OsObj = [PSCustomObject]@{}

$OsVersions | ForEach-Object {

	$OsObj | Add-Member -Name $_ -Value 0 -Type NoteProperty

}

$TotalComputers = $Computers.Count
$CurrentComputerCount = 0

foreach ($Computer in $Computers)
{
	$Title = "Processing $($CurrentComputerCount++) of $($TotalComputers) Total Computers..."
	$Percent = [math]::Round($CurrentComputerCount / $TotalComputers * 100, 2)
	Update-Progress $Title $Percent

	#Write-Progress -Activity "Processing $($CurrentComputerCount++) of $($TotalComputers) Computers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($TotalComputers - $CurrentComputerCount) / $TotalComputers) * 100) + "%") -PercentComplete ((($TotalComputers - $CurrentComputerCount) / $TotalComputers) * 100) -ErrorAction SilentlyContinue

	if ($Computer.ProtectedFromAccidentalDeletion -eq $True)
	{
		
		$ComputersProtected++
	}
	
	else
	{
		
		$ComputersNotProtected++
	}
	
	if ($Computer.Enabled -eq $True)
	{
		
		$ComputerEnabled++
	}
	
	else
	{
		
		$ComputerDisabled++
	}
	
	$obj = [PSCustomObject]@{
		
		'Name' = $Computer.Name
		'Enabled' = $Computer.Enabled
		'Operating System' = $Computer.OperatingSystem
		'Modified Date' = (Convert-Date $Computer.Modified.ToFileTime())
		'Last Logon' = [datetime]::FromFileTime((Get-ADComputer -Identity $Computer -Properties * | ForEach-Object { $_.LastLogonTimeStamp } | Out-String)).ToString('yyyy-MM-dd hh:mm:ss tt') 
		'Password Last Set' = Convert-Date $Computer.PasswordLastSet.ToFileTime()
		'Protect from Deletion' = $Computer.ProtectedFromAccidentalDeletion
		
	}
	
	$ComputersTable.Add($obj)
	
	if ($Computer.OperatingSystem -match $WindowsRegex)
	{
		$OsObj."$($matches[1])"++
	}

}

if (($ComputersTable).Count -eq 0)
{
	
	$Obj = [PSCustomObject]@{
		
		Information = 'Information: No computers were found'
	}
	$ComputersTable.Add($obj)
}

#Pie chart breaking down OS for computer obj
$OsObj.PSObject.Properties  | ForEach-Object {
	$GraphComputerOS.Add([PSCustomObject]@{'Name'  = $_.Name;"Count" =$_.Value})
}

#Data for TOP Computers data table
$OsObj | Add-Member -Name 'Total Computers' -Value $Computers.Count -Type NoteProperty

$TOPComputersTable.Add($OsObj)


#Data for protected Computers pie graph
$objULic = [PSCustomObject]@{
	
	'Name'  = 'Protected'
	'Count' = $ComputerProtected
}

$ComputerProtectedTable.Add($objULic)

$objULic = [PSCustomObject]@{
	
	'Name'  = 'Not Protected'
	'Count' = $ComputersNotProtected
}

$ComputerProtectedTable.Add($objULic)

#Data for enabled/vs Computers pie graph
$objULic = [PSCustomObject]@{
	
	'Name'  = 'Enabled'
	'Count' = $ComputerEnabled
}

$ComputersEnabledTable.Add($objULic)

$objULic = [PSCustomObject]@{
	
	'Name'  = 'Disabled'
	'Count' = $ComputerDisabled
}

$ComputersEnabledTable.Add($objULic)

Write-Host "Done!" -ForegroundColor White

$TabArray = @('Dashboard', 'Groups', 'Organizational Units', 'Users', 'Group Policy', 'Computers','AD Health')

Write-Host "Compiling Report..." -ForegroundColor Green

##--OU Protection PIE CHART--##
#Basic Properties 
$PO12 = Get-HTMLPieChartObject
$PO12.Title = "Organizational Units Protected from Deletion"
$PO12.Size.Height = 250
$PO12.Size.width = 250
$PO12.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PO12.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PO12.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PO12.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PO12.DataDefinition.DataNameColumnName = 'Name'
$PO12.DataDefinition.DataValueColumnName = 'Count'

##--Computer OS Breakdown PIE CHART--##
$PieObjectComputerObjOS = Get-HTMLPieChartObject
$PieObjectComputerObjOS.Title = "Computer Operating Systems"

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectComputerObjOS.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectComputerObjOS.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectComputerObjOS.ChartStyle.ColorSchemeName = 'Random'

##--Computers Protection PIE CHART--##
#Basic Properties 
$PieObjectComputersProtected = Get-HTMLPieChartObject
$PieObjectComputersProtected.Title = "Computers Protected from Deletion"
$PieObjectComputersProtected.Size.Height = 250
$PieObjectComputersProtected.Size.width = 250
$PieObjectComputersProtected.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectComputersProtected.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectComputersProtected.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectComputersProtected.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectComputersProtected.DataDefinition.DataNameColumnName = 'Name'
$PieObjectComputersProtected.DataDefinition.DataValueColumnName = 'Count'

##--Computers Enabled PIE CHART--##
#Basic Properties 
$PieObjectComputersEnabled = Get-HTMLPieChartObject
$PieObjectComputersEnabled.Title = "Computers Enabled vs Disabled"
$PieObjectComputersEnabled.Size.Height = 250
$PieObjectComputersEnabled.Size.width = 250
$PieObjectComputersEnabled.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectComputersEnabled.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectComputersEnabled.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectComputersEnabled.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectComputersEnabled.DataDefinition.DataNameColumnName = 'Name'
$PieObjectComputersEnabled.DataDefinition.DataValueColumnName = 'Count'

##--USERS Protection PIE CHART--##
#Basic Properties 
$PieObjectProtectedUsers = Get-HTMLPieChartObject
$PieObjectProtectedUsers.Title = "Users Protected from Deletion"
$PieObjectProtectedUsers.Size.Height = 250
$PieObjectProtectedUsers.Size.width = 250
$PieObjectProtectedUsers.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectProtectedUsers.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectProtectedUsers.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectProtectedUsers.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectProtectedUsers.DataDefinition.DataNameColumnName = 'Name'
$PieObjectProtectedUsers.DataDefinition.DataValueColumnName = 'Count'

#Basic Properties 
$PieObjectOUGPOLinks = Get-HTMLPieChartObject
$PieObjectOUGPOLinks.Title = "OU GPO Links"
$PieObjectOUGPOLinks.Size.Height = 250
$PieObjectOUGPOLinks.Size.width = 250
$PieObjectOUGPOLinks.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectOUGPOLinks.ChartStyle.ColorSchemeName = "ColorScheme4"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectOUGPOLinks.ChartStyle.ColorSchemeName = "Generated5"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectOUGPOLinks.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectOUGPOLinks.DataDefinition.DataNameColumnName = 'Name'
$PieObjectOUGPOLinks.DataDefinition.DataValueColumnName = 'Count'

#Basic Properties 
$PieObject4 = Get-HTMLPieChartObject
$PieObject4.Title = "Office 365 Unassigned Licenses"
$PieObject4.Size.Height = 250
$PieObject4.Size.width = 250
$PieObject4.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObject4.ChartStyle.ColorSchemeName = "ColorScheme4"

#There are 8 generated schemes, randomly generated at runtime 
$PieObject4.ChartStyle.ColorSchemeName = "Generated4"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObject4.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObject4.DataDefinition.DataNameColumnName = 'Name'
$PieObject4.DataDefinition.DataValueColumnName = 'Unassigned Licenses'

#Basic Properties 
$PieObjectGroupType = Get-HTMLPieChartObject
$PieObjectGroupType.Title = "Group Types"
$PieObjectGroupType.Size.Height = 250
$PieObjectGroupType.Size.width = 250
$PieObjectGroupType.ChartStyle.ChartType = 'doughnut'

#Pie Chart Groups with members vs no members
$PieObjectGroupMembersType = Get-HTMLPieChartObject
$PieObjectGroupMembersType.Title = "Group Membership"
$PieObjectGroupMembersType.Size.Height = 250
$PieObjectGroupMembersType.Size.width = 250
$PieObjectGroupMembersType.ChartStyle.ChartType = 'doughnut'
$PieObjectGroupMembersType.ChartStyle.ColorSchemeName = "ColorScheme4"
$PieObjectGroupMembersType.ChartStyle.ColorSchemeName = "Generated8"
$PieObjectGroupMembersType.ChartStyle.ColorSchemeName = 'Random'
$PieObjectGroupMembersType.DataDefinition.DataNameColumnName = 'Name'
$PieObjectGroupMembersType.DataDefinition.DataValueColumnName = 'Count'

#Basic Properties 
$PieObjectGroupType2 = Get-HTMLPieChartObject
$PieObjectGroupType2.Title = "Custom vs Default Groups"
$PieObjectGroupType2.Size.Height = 250
$PieObjectGroupType2.Size.width = 250
$PieObjectGroupType2.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectGroupType.ChartStyle.ColorSchemeName = "ColorScheme4"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectGroupType.ChartStyle.ColorSchemeName = "Generated8"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectGroupType.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectGroupType.DataDefinition.DataNameColumnName = 'Name'
$PieObjectGroupType.DataDefinition.DataValueColumnName = 'Count'

##--Enabled users vs Disabled Users PIE CHART--##
#Basic Properties 
$EnabledDisabledUsersPieObject = Get-HTMLPieChartObject
$EnabledDisabledUsersPieObject.Title = "Enabled vs Disabled Users"
$EnabledDisabledUsersPieObject.Size.Height = 250
$EnabledDisabledUsersPieObject.Size.width = 250
$EnabledDisabledUsersPieObject.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$EnabledDisabledUsersPieObject.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$EnabledDisabledUsersPieObject.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$EnabledDisabledUsersPieObject.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$EnabledDisabledUsersPieObject.DataDefinition.DataNameColumnName = 'Name'
$EnabledDisabledUsersPieObject.DataDefinition.DataValueColumnName = 'Count'

##--PasswordNeverExpires PIE CHART--##
#Basic Properties 
$PWExpiresUsersTable = Get-HTMLPieChartObject
$PWExpiresUsersTable.Title = "Password Expiration"
$PWExpiresUsersTable.Size.Height = 250
$PWExpiresUsersTable.Size.Width = 250
$PWExpiresUsersTable.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PWExpiresUsersTable.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PWExpiresUsersTable.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PWExpiresUsersTable.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PWExpiresUsersTable.DataDefinition.DataNameColumnName = 'Name'
$PWExpiresUsersTable.DataDefinition.DataValueColumnName = 'Count'

##--Group Protection PIE CHART--##
#Basic Properties 
$PieObjectGroupProtection = Get-HTMLPieChartObject
$PieObjectGroupProtection.Title = "Groups Protected from Deletion"
$PieObjectGroupProtection.Size.Height = 250
$PieObjectGroupProtection.Size.width = 250
$PieObjectGroupProtection.ChartStyle.ChartType = 'doughnut'

#These file exist in the module directoy, There are 4 schemes by default
$PieObjectGroupProtection.ChartStyle.ColorSchemeName = "ColorScheme3"

#There are 8 generated schemes, randomly generated at runtime 
$PieObjectGroupProtection.ChartStyle.ColorSchemeName = "Generated3"

#you can also ask for a random scheme.  Which also happens ifyou have too many records for the scheme
$PieObjectGroupProtection.ChartStyle.ColorSchemeName = 'Random'

#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectGroupProtection.DataDefinition.DataNameColumnName = 'Name'
$PieObjectGroupProtection.DataDefinition.DataValueColumnName = 'Count'

#Dashboard Report
$FinalReport = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalReport.Add($(Get-HTMLOpenPage -TitleText $ReportTitle -LeftLogoString $CompanyLogo -RightLogoString $RightLogo))
$FinalReport.Add($(Get-HTMLTabHeader -TabNames $TabArray))
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[0] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Company Information"))
$FinalReport.Add($(Get-HTMLContentTable $CompanyInfoTable))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Groups"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Domain Administrators'))
$FinalReport.Add($(Get-HTMLContentDataTable $DomainAdminTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Enterprise Administrators'))
$FinalReport.Add($(Get-HTMLContentDataTable $EnterpriseAdminTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Objects in Default OUs"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Computers'))
$FinalReport.Add($(Get-HTMLContentDataTable $DefaultComputersinDefaultOUTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Users'))
$FinalReport.Add($(Get-HTMLContentDataTable $DefaultUsersinDefaultOUTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "AD Objects Modified in Last $ADModNumber Days"))
$FinalReport.Add($(Get-HTMLContentDataTable $ADObjectTable))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Expiring Items"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Users with Passwords Expiring in less than $DaysUntilPWExpireINT days"))
$FinalReport.Add($(Get-HTMLContentDataTable $PasswordExpireSoonTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Accounts Expiring Soon'))
$FinalReport.Add($(Get-HTMLContentDataTable $ExpiringAccountsTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Accounts"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Users Haven't Logged on in $Days Days or more"))
$FinalReport.Add($(Get-HTMLContentDataTable $userphaventloggedonrecentlytable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Accounts Created in $UserCreatedDays Days or Less"))
$FinalReport.Add($(Get-HTMLContentDataTable $NewCreatedUsersTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Security Logs"))
$FinalReport.Add($(Get-HTMLContentDataTable $securityeventtable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "UPN Suffixes"))
$FinalReport.Add($(Get-HTMLContentTable $DomainTable))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLTabContentClose))

#Groups Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[1] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Groups Overivew"))
$FinalReport.Add($(Get-HTMLContentTable $TOPGroupsTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Active Directory Groups"))
$FinalReport.Add($(Get-HTMLContentDataTable $Table -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumn1of2))

$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Domain Administrators'))
$FinalReport.Add($(Get-HTMLContentDataTable $DomainAdminTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Enterprise Administrators'))
$FinalReport.Add($(Get-HTMLContentDataTable $EnterpriseAdminTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Active Directory Groups Chart"))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 4))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectGroupType -DataSet $GroupTypetable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 4))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectGroupType2 -DataSet $DefaultGrouptable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 3 -ColumnCount 4))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectGroupMembersType -DataSet $GroupMembershipTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 4 -ColumnCount 4))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectGroupProtection -DataSet $GroupProtectionTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLTabContentClose))

#Organizational Unit Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[2] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Organizational Units"))
$FinalReport.Add($(Get-HTMLContentDataTable $OUTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Organizational Units Charts"))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 2))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectOUGPOLinks -DataSet $OUGPOTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 2))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PO12 -DataSet $OUProtectionTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentclose))
$FinalReport.Add($(Get-HTMLTabContentClose))

#Users Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[3] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Users Overivew"))
$FinalReport.Add($(Get-HTMLContentTable $TOPUserTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Active Directory Users"))
$FinalReport.Add($(Get-HTMLContentDataTable $UserTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Expiring Items"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Users with Passwords Expiring in less than $DaysUntilPWExpireINT days"))
$FinalReport.Add($(Get-HTMLContentDataTable $PasswordExpireSoonTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Accounts Expiring Soon'))
$FinalReport.Add($(Get-HTMLContentDataTable $ExpiringAccountsTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Accounts"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Users Haven't Logged on in $Days Days or more"))
$FinalReport.Add($(Get-HTMLContentDataTable $userphaventloggedonrecentlytable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))

$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText "Accounts Created in $UserCreatedDays Days or Less"))
$FinalReport.Add($(Get-HTMLContentDataTable $NewCreatedUsersTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Users Charts"))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 3))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $EnabledDisabledUsersPieObject -DataSet $EnabledDisabledUsersTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 3))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PWExpiresUsersTable -DataSet $PasswordExpirationTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 3 -ColumnCount 3))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectProtectedUsers -DataSet $ProtectedUsersTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLTabContentClose))

#GPO Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[4] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Group Policies"))
$FinalReport.Add($(Get-HTMLContentDataTable $GPOTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLTabContentClose))

#Computers Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[5] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Computers Overivew"))
$FinalReport.Add($(Get-HTMLContentTable $TOPComputersTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Computers"))
$FinalReport.Add($(Get-HTMLContentDataTable $ComputersTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Computers Charts"))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 2))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectComputersProtected -DataSet $ComputerProtectedTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 2))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectComputersEnabled -DataSet $ComputersEnabledTable))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentclose))

$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "Computers Operating System Breakdown"))
$FinalReport.Add($(Get-HTMLPieChart -ChartObject $PieObjectComputerObjOS -DataSet $GraphComputerOS))
$FinalReport.Add($(Get-HTMLContentclose))

$FinalReport.Add($(Get-HTMLTabContentClose))

#DC Diag Report
$FinalReport.Add($(Get-HTMLTabContentopen -TabName $TabArray[6] -TabHeading ("Report: " + (Get-Date -Format MM-dd-yyyy))))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "DC Diag"))
$FinalReport.Add($(Get-HTMLContentDataTable $DCDiagTable -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))

$FinalReport.Add($(Get-HTMLTabContentClose))

$FinalReport.Add($(Get-HTMLClosePage))

$ReportName = ($ReportTitle)

Save-HTMLReport -ReportContent $FinalReport -ReportName $ReportName -ReportPath $ReportSavePath
