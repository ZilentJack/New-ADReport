<#
  .SYNOPSIS
    Basic AD Report with some statistics.
    - Writes a basic report as a text file by default.
    - Can be excuted with regular 'Domain Users' permissions.

    Requires PS Module "ActiveDirectory" to be present on executing host.
    - Found in Remote Server Administration Tools (RSAT), if executed from a Windows client OS (enable feature).
	
  .DESCRIPTION
    Basic extraction & analysis of Active Directory accounts and groups.

  .PARAMETER DumpFile_ComputerInfo
    Create a dump file with relevant information of all AD computer accounts. Default = $false.
	
  .PARAMETER DumpFile_PrivilegedUserInfo
    Create a dump file with relevant information of all AD privileged user accounts. Default = $false.
	
  .PARAMETER DumpFile_UserInfo
    Create a dump file with relevant information of all AD user accounts. Default = $false.
	
  .PARAMETER WriteHost_FinalReport
    Output the final report and statistics to console. Default = $false.
	
  .PARAMETER UserInactiveLogonDays
    How many days without a logon before we consider the user inactive? Default = 120 days.
	
  .PARAMETER UserInactivePasswordDays
    How many days without a password change before we consider the user inactive? Default = 120 days.

  .PARAMETER ComputerInactiveLogonDays
    How many days without a logon before we consider the computer inactive? Default = 90 days.

  .PARAMETER ComputerInactivePasswordDays
    How many days without a password change before we consider the computer inactive? Default = 90 days.
	
  .EXAMPLE
    PS C:\> New-ADReport -DumpFile_ComputerInfo -DumpFile_PrivilegedUserInfo -DumpFile_UserInfo -WriteHost_FinalReport -Verbose

    1. Writes a report to a text file (randomized name)
    2. Dumps 3 files with:
         a) Computer information
         b) Privileged user information
         c) User information (randomized names)
    3. Writes the report (same as in text file) to the console (write-host)
    4. Writes status messages to the console (verbose)

  .EXAMPLE
    PS C:\> New-ADReport -ComputerInactiveLogonDays 42 -ComputerInactivePasswordDays 42 -UserInactiveLogonDays 80 -UserInactivePasswordDays 80
    
    1. Writes a report to a text file (randomized name)
    2. Sets custom values (integers) to the 4 different optional parameters

  .LINK
    Get latest version here: http://1drv.ms/1GAe0Eo

  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg
    Fixes by       : Slavi Parpulev
    Date created   : 01/10-2014
    Last modified  : 29/09-2018

    Version history:
    - 1.14: Initial version for PS 3.0
    - 1.15: Check for members of SID: S-1-5-32-546 (Guests)
    - 1.16: Broader testing and minor feature upgrade
    - 1.17: Converted to true function by Claus Nielsen / @claustn
    - 1.18: Minor changes
    - 1.19: Added a few more groups
    - 1.20: First public release [21/3-2015]
    - 1.21: Minor fixes (priv-user CSV format, pwd min length, comp container)
    - 1.22: Fixed SIDhistory count for users & computers (missed SIDHistory property for $obj_ADUsers & $obj_ADComputers)
    - 1.23: Fixed "A referral was returned from the server" on Get-ADUser without Global Catalog server defined (port 3268) if multiple domains
    - 1.24: Fixed Computers Container (CN=Computers) queries
    - 1.25: Basic searches for AD trusts + forest info + FSMO roles
    - 1.26: CR-0006 implemented
    - 1.27: $cnt_ADComputersWindowsClients_enabled calculation fixed
    - 1.28: $strGlobalCatalogServer detection changed and $PSScriptRoot implemented for PSdrive support (incl. directory for output files)
    - 1.29: LDAPs checks + PSScriptRoot path
    - 1.30 Added check for Server 2003 and support for specifying domain to run against

    Tested on:
     - WS 2016
     - WS 2012 R2 (Set-StrictMode -Version 1.0)
     - WS 2012 R2 (Set-StrictMode -Version 2.0)
     - WS 2012 R2 (Set-StrictMode -Version 3.0)
     - WS 2012 R2 (Native PS 4.0)
     - WS 2008 R2 (Native PS 2.0)
     - WS 2008 R2 (Native PS 3.0)
     - Windows 7 SP1 w/RSAT (PS 2.0)
     - Winodws 8.1 w/RSAT
     - Windows 10 w/RSAT
     - WS 2012 (Native PS 4.0)

    Known Issues & possible solutions:
     KI-0001: Code is not pretty and can be optimized in several ways.
       Solution: Feel free to share your ideas & fixes with me. I'll include in vNext and give credit.
     KI-0002: "Get-ADUser : Not a valid Win32 FileTime." > This is probably due to one or more users having an unexpected pwdlastset value of "-1".
       Solution: Find those users and (re)set passwords: Get-ADUser -filter * -Properties samAccountName,pwdlastset | Where {$_.pwdlastset -lt 0}
     KI-0003: "Get-ADUser : The server has returned the following error: invalid enumeration context."
       Solution: Might be due to large number of AD objects with non-indexed properties. No solution at this point.

    Change Requests (not prioritized):
     CR-0001: AccountExpirationDates could be set to something far into the future, making it meaningless. Check for sanity.
     CR-0002: Dump group membership to files. Switch option.
     CR-0003: Check group "DHCP Administrators" perhaps.
     CR-0004: Stats should reflect Privileged and Highly Privileges non-user accounts too. Perhaps separate file dump.
     CR-0005: Include check for SID-History attack: http://www.version2.dk/blog/historien-om-den-skjulte-domain-admin-68832.
     CR-0006: Dump SIDHistory values in user dumps > implemented v1.26.
     CR-0007: Computer OS stats/table/matrix (Build, Name, SP level, #Enabled, #Disabled, #Stale, %stats).
     CR-0008: Detect other out of support Windows OSs, not just Windows XP.
     CR-0009: Multi-domain support & stats.
     CR-0010: Explicitly show (High) Privileged Accounts with old passwords/long time since last login.
     CR-0011: Get # 'Account is sensitive and cannot be delegated'.
     CR-0012: Check connection between SCRIL bit set and Password Never Expires. Take into account.
     CR-0013: Computers that are "trusted for delegation" can be regular DCs. Take into account.
     CR-0014: Consider including trust info from https://gallery.technet.microsoft.com/scriptcenter/Enumerate-Domain-Trusts-25ecb802 or maybe https://technet.microsoft.com/en-us/library/hh852315(v=wps.630).aspx

    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

Function New-ADReport
{
  [CmdletBinding()]
  param
  (
    [Parameter(HelpMessage = 'Domain to enumerate')]
    [ValidateNotNullOrEmpty()]
    [String]
    $Server = $env:USERDNSDOMAIN,
    [Parameter(HelpMessage = 'Create dump file with computer info')]
    [switch]
    $DumpFile_ComputerInfo,
    [Parameter(HelpMessage = 'Create dump file with privileged user info')]
    [switch]
    $DumpFile_PrivilegedUserInfo,
    [Parameter(HelpMessage = 'Create dump file with user info')]
    [Switch]
    $DumpFile_UserInfo,
    [Parameter(HelpMessage = 'Write report to console')]
    [switch]
    $WriteHost_FinalReport,
    [ValidateNotNull()]
    [int]
    $ComputerInactiveLogonDays = 90,
    [ValidateNotNull()]
    [Int]
    $ComputerInactivePasswordDays = 90,
    [ValidateNotNull()]
    [int]
    $UserInactiveLogonDays = 120,
    [ValidateNotNull()]
    [int]
    $UserInactivePasswordDays = 120
  )
	
  $str_ScriptVersion = '1.30'

  
  # Import AD module
  Import-Module ActiveDirectory -Verbose:$False -ErrorAction SilentlyContinue
  
  $CheckADModule = Get-Module -List ActiveDirectory
  If (!$CheckADModule) { Write-Verbose "Error: No ActiveDirectory module loaded. Will Break!"; Break } #Quit?

   # Get date/time stamp
  $time = Get-Date
  $str_FileTimeStamp = Get-Date -format 'yyyyMMddHHmmss'

  # Get current script execution directory (for output files)
  If(!$PSScriptRoot){$PSScriptRoot = (Get-Item -Path ".\").FullName}
  If(!$PSScriptRoot){$PSScriptRoot = (Get-Location).Path}

  
  Write-Verbose "Scan AD version               : $str_ScriptVersion" 
  Write-Verbose "- File Time Stamp             : $str_FileTimeStamp" 
  Write-Verbose "- Start Time                  : $time"

  # Basic AD info
  Write-Verbose 'Progress: Getting forest info...' 
  $obj_ADForest = Get-ADForest
  $str_ADForest_Name = $obj_ADForest.Name
  $str_ADForest_RootDomain = $obj_ADForest.RootDomain
  $str_ADForest_ForestMode = $obj_ADForest.ForestMode
  $str_ADForest_DomainNamingMaster = $obj_ADForest.DomainNamingMaster
  $str_ADForest_SchemaMaster = $obj_ADForest.SchemaMaster
  $obj_ADForestDCs = ($obj_ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }

  Write-Verbose 'Progress: Getting domain info...' 
  $obj_ADDomain = Get-ADDomain -Server $Server
  $str_ADDomain_DNSRoot = $obj_ADDomain.DNSRoot
  $str_ADDomain_NetBIOSName = $obj_ADDomain.NetBIOSName
  $str_ADDomain_Forest = $obj_ADDomain.Forest
  $str_ADDomain_DomainMode = $obj_ADDomain.DomainMode
  $str_ADDomain_DistinguishedName = $obj_ADDomain.DistinguishedName
  $str_ADDomainSID = $obj_ADDomain.DomainSID.Value
  $str_ADDomainComputersContainer = $obj_ADDomain.ComputersContainer
  $str_ADDomainExpectedDefaultComputersContainer = "CN=Computers,$str_ADDomain_DistinguishedName"
  $str_ADDomain_InfrastructureMaster = $obj_ADDomain.InfrastructureMaster
  $str_ADDomain_PDCEmulator = $obj_ADDomain.PDCEmulator
  $str_ADDomain_RIDMaster = $obj_ADDomain.RIDMaster

  # Are we in the Forest Root Domain?
  If ($str_ADDomain_DNSRoot -eq $str_ADDomain_Forest){ $bol_ForestRootDomain = $True } Else { $bol_ForestRootDomain = $False }

  # Do we have the default Computers container (CN=Computers) in use or not?
  If ($str_ADDomainComputersContainer -eq $str_ADDomainExpectedDefaultComputersContainer){ $bol_ExpectedDefaultComputersContainer = $True } Else { $bol_ExpectedDefaultComputersContainer = $False }

  # AD Password Policy info
  Write-Verbose 'Progress: Getting default domain password policy...' 
  $obj_ADDomainPwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Server
  $str_ADDomainPwdPolicy_ComplexityEnabled = $obj_ADDomainPwdPolicy.ComplexityEnabled
  $str_ADDomainPwdPolicy_LockoutDuration = $obj_ADDomainPwdPolicy.LockoutDuration
  $str_ADDomainPwdPolicy_LockoutObservationWindow = $obj_ADDomainPwdPolicy.LockoutObservationWindow
  $str_ADDomainPwdPolicy_LockoutThreshold = $obj_ADDomainPwdPolicy.LockoutThreshold
  $str_ADDomainPwdPolicy_MaxPasswordAge = $obj_ADDomainPwdPolicy.MaxPasswordAge
  $str_ADDomainPwdPolicy_MinPasswordAge = $obj_ADDomainPwdPolicy.MinPasswordAge
  $str_ADDomainPwdPolicy_MinPasswordLength = $obj_ADDomainPwdPolicy.MinPasswordLength
  $str_ADDomainPwdPolicy_PasswordHistoryCount = $obj_ADDomainPwdPolicy.PasswordHistoryCount
  $str_ADDomainPwdPolicy_ReversibleEncryptionEnabled = $obj_ADDomainPwdPolicy.ReversibleEncryptionEnabled

  # AD Fine Grained Password Policy info
  Write-Verbose 'Progress: Checking for fine grained password policies...'
  $cnt_ADFineGrainedPwdPolicies = @(Get-ADFineGrainedPasswordPolicy -Server $Server -Filter *).Count

  # Basic AD trust info
  Write-Verbose 'Progress: Getting AD trust info...' 
  $obj_ADDomainTrusts = Get-ADObject -Server $Server -Filter {ObjectClass -eq "trustedDomain"} -Properties *
  If ($obj_ADDomainTrusts) { $cnt_ADDomainTrusts = $obj_ADDomainTrusts.Count } Else { $cnt_ADDomainTrusts = 0 }

  # Find Administrator account (500)
  Write-Verbose 'Progress: Finding special accounts...' 
  $obj_AdministratorSID = New-Object System.Security.Principal.SecurityIdentifier ("$str_ADDomainSID-500")
  $str_AdministratorUserName = $obj_AdministratorSID.Translate([System.Security.Principal.NTAccount]).Value

   # Find Guest account (501)
  $obj_GuestSID = New-Object System.Security.Principal.SecurityIdentifier ("$str_ADDomainSID-501")
  $str_GuestUserName = $obj_GuestSID.Translate([System.Security.Principal.NTAccount]).Value

  # Basic krbtgt info
  $str_ADUser_krbtgt_PasswordLastSet = (Get-ADUser -Server $Server krbtgt -Properties PasswordLastSet).PasswordLastSet


  # Initialize user counters (set to zero for report to look nice)
  $cnt_ADUsers                            = 0
  $cnt_ADUsers_enabled                    = 0
  $cnt_ADUsers_disabled                   = 0
  $cnt_ADUsersPrivileged_all              = 0
  $cnt_ADUsersPrivileged_all_enabled      = 0
  $cnt_ADUsersHighlyPrivileged            = 0
  $cnt_ADUsersHighlyPrivileged_enabled    = 0
  $cnt_ADUsers_enabled_noexpiration       = 0
  $cnt_ADUsersReversibleEncryption        = 0
  $cnt_ADUsersDoesNotRequirePreAuth       = 0
  $cnt_ADUsersSmartcardLogonNotRequired   = 0
  $cnt_ADUsersCannotChangePassword        = 0
  $cnt_ADUsersPasswordNeverExpires        = 0
  $cnt_ADUsersPasswordNotRequired         = 0
  $cnt_ADUsersAdminCount                  = 0
  $cnt_ADUsersWithSIDHistory              = 0
  $cnt_ADUsersTrustedForDelegation        = 0
  $cnt_ADUsersServicePrincipalName        = 0
  $cnt_ADUsersNoLastLogonDate             = 0
  $cnt_ADUsersOldLastLogonDate            = 0
  $cnt_ADUsersPasswordExpired             = 0
  $cnt_ADUsersNoPasswordLastSet           = 0
  $cnt_ADUsersOldPasswordLastSet          = 0
  $cnt_ADUsersLockedOut                   = 0
  $cnt_ADUsersExpired_all                 = 0

  # Initialize group counters (set to zero for report to look nice)
  $cnt_ADGroupAdministrators              = 0
  $cnt_ADGroupDomainAdmins                = 0
  $cnt_ADGroupEnterpriseAdmins            = 0
  $cnt_ADGroupSchemaAdmins                = 0
  $cnt_ADGroupAccountOperators            = 0
  $cnt_ADGroupServerOperators             = 0
  $cnt_ADGroupBackupOperators             = 0
  $cnt_ADGroupPrintOperators              = 0
  $cnt_ADGroupGuests                      = 0
  $cnt_ADGroupCertPublishers              = 0
  $cnt_ADGroupGPCreatorOwners             = 0
  $cnt_ADGroupDnsAdmins                   = 0
  $cnt_ADGroupAdministrators_enabled      = 0
  $cnt_ADGroupDomainAdmins_enabled        = 0
  $cnt_ADGroupEnterpriseAdmins_enabled    = 0
  $cnt_ADGroupSchemaAdmins_enabled        = 0
  $cnt_ADGroupAccountOperators_enabled    = 0
  $cnt_ADGroupServerOperators_enabled     = 0
  $cnt_ADGroupBackupOperators_enabled     = 0
  $cnt_ADGroupPrintOperators_enabled      = 0
  $cnt_ADGroupGuests_enabled              = 0
  $cnt_ADGroupCertPublishers_enabled      = 0
  $cnt_ADGroupGPCreatorOwners_enabled     = 0
  $cnt_ADGroupDnsAdmins_enabled           = 0

  # Initialize computer counters (set to zero for report to look nice)
  $cnt_ADComputers                        = 0
  $cnt_ADComputers_enabled                = 0
  $cnt_ADComputers_disabled               = 0
  $cnt_ADComputersReversibleEncryption    = 0
  $cnt_ADComputersDoesNotRequirePreAuth   = 0
  $cnt_ADComputersCannotChangePassword    = 0
  $cnt_ADComputersPasswordNeverExpires    = 0
  $cnt_ADComputersPasswordNotRequired     = 0
  $cnt_ADComputersWithSIDHistory          = 0
  $cnt_ADComputersTrustedForDelegation    = 0
  $cnt_ADComputersNoLastLogonDate         = 0
  $cnt_ADComputersOldLastLogonDate        = 0
  $cnt_ADComputersPasswordExpired         = 0
  $cnt_ADComputersNoPasswordLastSet       = 0
  $cnt_ADComputersOldPasswordLastSet      = 0
  $cnt_ADComputersLockedOut               = 0
  $cnt_ADComputersExpired_all             = 0
  $cnt_ADDomainControllers                = 0
  $cnt_ADGlobalCatalogSrv                 = 0
  $cnt_ADComputersContainer_enabled       = 0
  $cnt_ADComputersContainerCN_enabled     = 0
  $cnt_ADComputersUnknownOS_enabled       = 0
  $cnt_ADComputersWindowsServers_enabled  = 0
  $cnt_ADComputersWindowsClients_enabled  = 0
  $cnt_ADComputersWinXP_enabled           = 0
  $cnt_ADComputersServer2003_enabled      = 0
  $cnt_ADComputersWindows_enabled         = 0
  $cnt_ADComputersNonWindows_enabled      = 0
  $cnt_ADComputersContainer_disabled      = 0
  $cnt_ADComputersContainerCN_disabled    = 0
  $cnt_ADComputersUnknownOS_disabled      = 0
  $cnt_ADComputersWindowsServers_disabled = 0
  $cnt_ADComputersWindowsClients_disabled = 0
  $cnt_ADComputersWinXP_disabled          = 0
  $cnt_ADComputersServer2003_disabled     = 0
  $cnt_ADComputersWindows_disabled        = 0
  $cnt_ADComputersNonWindows_disabled     = 0


  # ================= #
  # Gather AD objects #
  # ================= #

  # Get AD users + count
  Write-Verbose 'Progress: Getting AD users...' 
  $obj_ADUsers = @(Get-ADUser -Server $Server -Filter * -Properties SamAccountName, SID, SIDHistory, GivenName, Surname, UserPrincipalName, Description, Enabled, Created, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, SmartcardLogonRequired, CannotChangePassword, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, PasswordLastSet, PasswordExpired, LastLogonDate, BadLogonCount, LastBadPasswordAttempt, LockedOut, AccountLockoutTime, adminCount, TrustedForDelegation)
  $cnt_ADUsers = @($obj_ADUsers).Count

  # Get AD computers + count
  Write-Verbose 'Progress: Getting AD computers...' 
  $obj_ADComputers = @(Get-ADComputer -Server $Server -Filter * -Properties Name, SID, SIDHistory, DNSHostName, IPv4Address, IPv6Address, Description, Enabled, Created, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, CannotChangePassword, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, PasswordLastSet, PasswordExpired, LastLogonDate, BadLogonCount, LastBadPasswordAttempt, LockedOut, AccountLockoutTime, OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, TrustedForDelegation)
  $cnt_ADComputers = @($obj_ADComputers).Count

  Write-Verbose 'Progress: Getting DC information...' 
  $cnt_ADDomainControllers = @(Get-ADDomainController -Server $Server -Filter *).Count
  $cnt_ADGlobalCatalogSrv = @(Get-ADDomainController -Server $Server -Filter { IsGlobalCatalog -eq $True }).Count

  # Get enabled AD objects + count
  Write-Verbose 'Progress: Getting enabled AD accounts...' 
  $obj_ADUsers_enabled = $obj_ADUsers | Where-Object { $_.Enabled -eq $True }
  $cnt_ADUsers_enabled = @($obj_ADUsers_enabled).Count
  $obj_ADComputers_enabled = $obj_ADComputers | Where-Object { $_.Enabled -eq $True }
  $cnt_ADComputers_enabled = @($obj_ADComputers_enabled).Count

  # Get disabled AD objects + count
  Write-Verbose 'Progress: Getting disabled AD accounts...' 
  $obj_ADUsers_disabled = $obj_ADUsers | Where-Object { $_.Enabled -eq $False }
  If ($obj_ADUsers_disabled) { $cnt_ADUsers_disabled = @($obj_ADUsers_disabled).Count }
	
  $obj_ADComputers_disabled = $obj_ADComputers | Where-Object { $_.Enabled -eq $False }
  If ($obj_ADComputers_disabled) { $cnt_ADComputers_disabled = @($obj_ADComputers_disabled).Count }

   # ================= #
  # AD group analysis #
  # ================= #

  # Reference:
  # - Privileged Accounts and Groups in Active Directory: https://technet.microsoft.com/en-us/library/dn487460.aspx
  # - Well-known security identifiers in Windows operating systems: https://support.microsoft.com/en-us/kb/243330

  Write-Verbose 'Progress: Getting members of interesting groups...' 

  # We need a Global Catalog in case we deal with multiple domains
  # https://technet.microsoft.com/en-us/library/ee617217.aspx
  $strGlobalCatalogServer = (Get-ADDomainController -Discover -Service "GlobalCatalog" -DomainName $str_ADDomain_Forest).Hostname
  $intGlobalCatalogServerPort = 3268

  Write-Verbose "GlobalCatalog used: $($strGlobalCatalogServer):$intGlobalCatalogServerPort"


  # Get members of interesting Forest Root Domain groups (only users)
  If ($bol_ForestRootDomain)
  {
    # Look for users only
    $obj_ADGroupEnterpriseAdmins = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-519 -Recursive | Where-Object { $_.objectClass -eq 'user' })        # Enterprise Admins
    $obj_ADGroupSchemaAdmins = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-518 -Recursive | Where-Object { $_.objectClass -eq 'user' })            # Schema Admins

    # Look for non-users
    $obj_ADGroupEnterpriseAdminsNonUser = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-519 -Recursive | Where-Object { $_.objectClass -ne 'user' }) # Enterprise Admins
    $obj_ADGroupSchemaAdminsNonUser = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-518 -Recursive | Where-Object { $_.objectClass -ne 'user' })     # Schema Admins
  }

  # Get members of interesting groups (only users)
  $obj_ADGroupAdministrators = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-544 -Recursive | Where-Object { $_.objectClass -eq 'user' })                  # Administrators
  $obj_ADGroupDomainAdmins = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-512 -Recursive | Where-Object { $_.objectClass -eq 'user' })            # Domain Admins
  $obj_ADGroupAccountOperators = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-548 -Recursive | Where-Object { $_.objectClass -eq 'user' })                # Account Operators
  $obj_ADGroupServerOperators = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-549 -Recursive | Where-Object { $_.objectClass -eq 'user' })                 # Server Operators
  $obj_ADGroupBackupOperators = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-551 -Recursive | Where-Object { $_.objectClass -eq 'user' })                 # Backup Operators
  $obj_ADGroupPrintOperators = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-550 -Recursive | Where-Object { $_.objectClass -eq 'user' })                  # Print Operators
  $obj_ADGroupGuests = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-546 -Recursive | Where-Object { $_.objectClass -eq 'user' })                          # Guests
  $obj_ADGroupCertPublishers = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-517 -Recursive | Where-Object { $_.objectClass -eq 'user' })          # Cert Publishers (OK to have non-user members)
  $obj_ADGroupGPCreatorOwners = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-520 -Recursive | Where-Object { $_.objectClass -eq 'user' })         # Group Policy Creator Owners
  $obj_ADGroupDnsAdmins = @(Get-ADGroupMember -Server $Server -Identity "DnsAdmins" -Recursive | Where-Object { $_.objectClass -eq 'user' })                        # DnsAdmins
  

  # Get members of interesting groups (non-users)
  $obj_ADGroupAdministratorsNonUser = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-544 -Recursive | Where-Object { $_.objectClass -ne 'user' })           # Administrators
  $obj_ADGroupDomainAdminsNonUser = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-512 -Recursive | Where-Object { $_.objectClass -ne 'user' })     # Domain Admins
  $obj_ADGroupAccountOperatorsNonUser = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-548 -Recursive | Where-Object { $_.objectClass -ne 'user' })         # Account Operators
  $obj_ADGroupServerOperatorsNonUser = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-549 -Recursive | Where-Object { $_.objectClass -ne 'user' })          # Server Operators
  $obj_ADGroupBackupOperatorsNonUser = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-551 -Recursive | Where-Object { $_.objectClass -ne 'user' })          # Backup Operators
  $obj_ADGroupPrintOperatorsNonUser = @(Get-ADGroupMember -Server $Server -Identity S-1-5-32-550 -Recursive | Where-Object { $_.objectClass -ne 'user' })           # Print Operators
  $obj_ADGroupGPCreatorOwnersNonUser = @(Get-ADGroupMember -Server $Server -Identity $str_ADDomainSID-520 -Recursive | Where-Object { $_.objectClass -ne 'user' })  # Group Policy Creator Owners
  $obj_ADGroupDnsAdminsNonUser = @(Get-ADGroupMember -Server $Server -Identity "DnsAdmins" -Recursive | Where-Object { $_.objectClass -ne 'user' })                 # DnsAdmins

  $WeHavePrivilegedNonUserAccounts = $False
	
  If ($obj_ADGroupAdministratorsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupDomainAdminsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupEnterpriseAdminsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupSchemaAdminsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupAccountOperatorsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupServerOperatorsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupBackupOperatorsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupPrintOperatorsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupGPCreatorOwnersNonUser) { $WeHavePrivilegedNonUserAccounts = $True }
  If ($obj_ADGroupDnsAdminsNonUser) { $WeHavePrivilegedNonUserAccounts = $True }

  # Aggregate All Privileged Accounts (users only)
  $obj_ADUsersPrivileged_all = @()
  If ($obj_ADGroupAdministrators) { $obj_ADUsersPrivileged_all += $obj_ADGroupAdministrators }
  If ($obj_ADGroupDomainAdmins) { $obj_ADUsersPrivileged_all += $obj_ADGroupDomainAdmins }
  If ($obj_ADGroupEnterpriseAdmins) { $obj_ADUsersPrivileged_all += $obj_ADGroupEnterpriseAdmins }
  If ($obj_ADGroupSchemaAdmins) { $obj_ADUsersPrivileged_all += $obj_ADGroupSchemaAdmins }
  If ($obj_ADGroupAccountOperators) { $obj_ADUsersPrivileged_all += $obj_ADGroupAccountOperators }
  If ($obj_ADGroupServerOperators) { $obj_ADUsersPrivileged_all += $obj_ADGroupServerOperators }
  If ($obj_ADGroupBackupOperators) { $obj_ADUsersPrivileged_all += $obj_ADGroupBackupOperators }
  If ($obj_ADGroupPrintOperators) { $obj_ADUsersPrivileged_all += $obj_ADGroupPrintOperators }
  If ($obj_ADGroupCertPublishers) { $obj_ADUsersPrivileged_all += $obj_ADGroupCertPublishers }
  If ($obj_ADGroupGPCreatorOwners) { $obj_ADUsersPrivileged_all += $obj_ADGroupGPCreatorOwners }
  If ($obj_ADGroupDnsAdmins) { $obj_ADUsersPrivileged_all += $obj_ADGroupDnsAdmins }

  # Get only unique Privileged Accounts (users only) + get enabled users in separate counter
  $obj_ADUsersPrivileged_all = $obj_ADUsersPrivileged_all | Sort-Object -Unique
  If ($obj_ADUsersPrivileged_all) {
      $cnt_ADUsersPrivileged_all = @($obj_ADUsersPrivileged_all).Count
      $cnt_ADUsersPrivileged_all_enabled = @($obj_ADUsersPrivileged_all | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }).Count
     }

  # Aggregate Highly Privileged Accounts (users only)
  $obj_ADUsersHighlyPrivileged = @()
  If ($obj_ADGroupAdministrators) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupAdministrators }
  If ($obj_ADGroupDomainAdmins) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupDomainAdmins }
  If ($obj_ADGroupEnterpriseAdmins) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupEnterpriseAdmins }
  If ($obj_ADGroupSchemaAdmins) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupSchemaAdmins }
  If ($obj_ADGroupGPCreatorOwners) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupGPCreatorOwners }
  If ($obj_ADGroupDnsAdmins) { $obj_ADUsersHighlyPrivileged += $obj_ADGroupDnsAdmins }

  # Get only unique Highly Privileged Accounts (users only) + get enabled users in separate counter
  $obj_ADUsersHighlyPrivileged = $obj_ADUsersHighlyPrivileged | Sort-Object -Unique
  If ($obj_ADUsersHighlyPrivileged) {
      $cnt_ADUsersHighlyPrivileged = @($obj_ADUsersHighlyPrivileged).Count
      $cnt_ADUsersHighlyPrivileged_enabled = @($obj_ADUsersHighlyPrivileged | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }).Count
     }
	
  # Count members of interesting groups (users only)
  If ($obj_ADGroupAdministrators) { $cnt_ADGroupAdministrators = @($obj_ADGroupAdministrators).Count }
  If ($obj_ADGroupDomainAdmins) { $cnt_ADGroupDomainAdmins = @($obj_ADGroupDomainAdmins).Count }
  If ($obj_ADGroupEnterpriseAdmins) { $cnt_ADGroupEnterpriseAdmins = @($obj_ADGroupEnterpriseAdmins).Count }
  If ($obj_ADGroupSchemaAdmins) { $cnt_ADGroupSchemaAdmins = @($obj_ADGroupSchemaAdmins).Count }
  If ($obj_ADGroupAccountOperators) { $cnt_ADGroupAccountOperators = @($obj_ADGroupAccountOperators).Count }
  If ($obj_ADGroupServerOperators) { $cnt_ADGroupServerOperators = @($obj_ADGroupServerOperators).Count }
  If ($obj_ADGroupBackupOperators) { $cnt_ADGroupBackupOperators = @($obj_ADGroupBackupOperators).Count }
  If ($obj_ADGroupPrintOperators) { $cnt_ADGroupPrintOperators = @($obj_ADGroupPrintOperators).Count }
  If ($obj_ADGroupCertPublishers) { $cnt_ADGroupCertPublishers = @($obj_ADGroupCertPublishers).Count }
  If ($obj_ADGroupGPCreatorOwners) { $cnt_ADGroupGPCreatorOwners = @($obj_ADGroupGPCreatorOwners).Count }
  If ($obj_ADGroupDnsAdmins) { $cnt_ADGroupDnsAdmins = @($obj_ADGroupDnsAdmins).Count }
	
  # Limit to enabled/active group members
  $obj_ADGroupAdministrators_enabled = @()
  $obj_ADGroupDomainAdmins_enabled = @()
  $obj_ADGroupEnterpriseAdmins_enabled = @()
  $obj_ADGroupSchemaAdmins_enabled = @()
  $obj_ADGroupAccountOperators_enabled = @()
  $obj_ADGroupServerOperators_enabled = @()
  $obj_ADGroupBackupOperators_enabled = @()
  $obj_ADGroupPrintOperators_enabled = @()
  $obj_ADGroupGuests_enabled = @()
  $obj_ADGroupCertPublishers_enabled = @()
  $obj_ADGroupGPCreatorOwners_enabled = @()
  $obj_ADGroupDnsAdmins_enabled = @()
  
  If ($obj_ADGroupAdministrators) { $obj_ADGroupAdministrators_enabled = @($obj_ADGroupAdministrators | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupDomainAdmins) { $obj_ADGroupDomainAdmins_enabled = @($obj_ADGroupDomainAdmins | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupEnterpriseAdmins) { $obj_ADGroupEnterpriseAdmins_enabled = @($obj_ADGroupEnterpriseAdmins | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupSchemaAdmins) { $obj_ADGroupSchemaAdmins_enabled = @($obj_ADGroupSchemaAdmins | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupAccountOperators) { $obj_ADGroupAccountOperators_enabled = @($obj_ADGroupAccountOperators | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupServerOperators) { $obj_ADGroupServerOperators_enabled = @($obj_ADGroupServerOperators | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupBackupOperators) { $obj_ADGroupBackupOperators_enabled = @($obj_ADGroupBackupOperators | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupPrintOperators) { $obj_ADGroupPrintOperators_enabled = @($obj_ADGroupPrintOperators | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupGuests) { $obj_ADGroupGuests_enabled = @($obj_ADGroupGuests | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupCertPublishers) { $obj_ADGroupCertPublishers_enabled = @($obj_ADGroupCertPublishers | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupGPCreatorOwners) { $obj_ADGroupGPCreatorOwners_enabled = @($obj_ADGroupGPCreatorOwners | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }
  If ($obj_ADGroupDnsAdmins) { $obj_ADGroupDnsAdmins_enabled = @($obj_ADGroupDnsAdmins | Get-ADUser -Server "$($strGlobalCatalogServer):$intGlobalCatalogServerPort" | Where-Object { $_.Enabled -eq $True }) }

  # Count enabled/active group members
  If ($obj_ADGroupAdministrators_enabled) { $cnt_ADGroupAdministrators_enabled = @($obj_ADGroupAdministrators_enabled).Count }
  If ($obj_ADGroupDomainAdmins_enabled) { $cnt_ADGroupDomainAdmins_enabled = @($obj_ADGroupDomainAdmins_enabled).Count }
  If ($obj_ADGroupEnterpriseAdmins_enabled) { $cnt_ADGroupEnterpriseAdmins_enabled = @($obj_ADGroupEnterpriseAdmins_enabled).Count }
  If ($obj_ADGroupSchemaAdmins_enabled) { $cnt_ADGroupSchemaAdmins_enabled = @($obj_ADGroupSchemaAdmins_enabled).Count }
  If ($obj_ADGroupAccountOperators_enabled) { $cnt_ADGroupAccountOperators_enabled = @($obj_ADGroupAccountOperators_enabled).Count }
  If ($obj_ADGroupServerOperators_enabled) { $cnt_ADGroupServerOperators_enabled = @($obj_ADGroupServerOperators_enabled).Count }
  If ($obj_ADGroupBackupOperators_enabled) { $cnt_ADGroupBackupOperators_enabled = @($obj_ADGroupBackupOperators_enabled).Count }
  If ($obj_ADGroupPrintOperators_enabled) { $cnt_ADGroupPrintOperators_enabled = @($obj_ADGroupPrintOperators_enabled).Count }
  If ($obj_ADGroupGuests_enabled) { $cnt_ADGroupGuests_enabled = @($obj_ADGroupGuests_enabled).Count }
  If ($obj_ADGroupCertPublishers_enabled) { $cnt_ADGroupCertPublishers_enabled = @($obj_ADGroupCertPublishers_enabled).Count }
  If ($obj_ADGroupGPCreatorOwners_enabled) { $cnt_ADGroupGPCreatorOwners_enabled = @($obj_ADGroupGPCreatorOwners_enabled).Count }
  If ($obj_ADGroupDnsAdmins_enabled) { $cnt_ADGroupDnsAdmins_enabled = @($obj_ADGroupDnsAdmins_enabled).Count }

  # ================ #
  # AD user analysis #
  # ================ #

  Write-Verbose 'Progress: Getting interesting user accounts...' 

  # Get interesting users
  $obj_ADUsersReversibleEncryption = @($obj_ADUsers_enabled | Where-Object { $_.AllowReversiblePasswordEncryption -eq $True })
  $obj_ADUsersDoesNotRequirePreAuth = @($obj_ADUsers_enabled | Where-Object { $_.DoesNotRequirePreAuth -eq $True })
  $obj_ADUsersSmartcardLogonNotRequired = @($obj_ADUsers_enabled | Where-Object { $_.SmartcardLogonRequired -eq $False })
  $obj_ADUsersCannotChangePassword = @($obj_ADUsers_enabled | Where-Object { $_.CannotChangePassword -eq $True })
  $obj_ADUsersPasswordNeverExpires = @($obj_ADUsers_enabled | Where-Object { $_.PasswordNeverExpires -eq $True })
  $obj_ADUsersPasswordNotRequired = @($obj_ADUsers_enabled | Where-Object { $_.PasswordNotRequired -eq $True })
  $obj_ADUsersAdminCount = @($obj_ADUsers_enabled | Where-Object { $_.adminCount -gt 0 })
	
  # Get users with SPN/Delegation set
  $obj_ADUsersTrustedForDelegation = @($obj_ADUsers_enabled | Where-Object { $_.TrustedForDelegation -eq $True })
  $obj_ADUsersServicePrincipalName = @($obj_ADUsers_enabled | Where-Object { $_.ServicePrincipalName -eq $True })
	
  # Get users with SIDHistory defined
  $obj_ADUsersWithSIDHistory = @($obj_ADUsers_enabled | Where-Object { $_.SIDHistory })
	
  # Count interesting users
  If ($obj_ADUsersReversibleEncryption) { $cnt_ADUsersReversibleEncryption = @($obj_ADUsersReversibleEncryption).Count }
  If ($obj_ADUsersDoesNotRequirePreAuth) { $cnt_ADUsersDoesNotRequirePreAuth = @($obj_ADUsersDoesNotRequirePreAuth).Count }
  If ($obj_ADUsersSmartcardLogonNotRequired) { $cnt_ADUsersSmartcardLogonNotRequired = @($obj_ADUsersSmartcardLogonNotRequired).Count }
  If ($obj_ADUsersCannotChangePassword) { $cnt_ADUsersCannotChangePassword = @($obj_ADUsersCannotChangePassword).Count }
  If ($obj_ADUsersPasswordNeverExpires) { $cnt_ADUsersPasswordNeverExpires = @($obj_ADUsersPasswordNeverExpires).Count }
  If ($obj_ADUsersPasswordNotRequired) { $cnt_ADUsersPasswordNotRequired = @($obj_ADUsersPasswordNotRequired).Count }
  If ($obj_ADUsersAdminCount) { $cnt_ADUsersAdminCount = @($obj_ADUsersAdminCount).Count }
  If ($obj_ADUsersTrustedForDelegation) { $cnt_ADUsersTrustedForDelegation = @($obj_ADUsersTrustedForDelegation).Count }
  If ($obj_ADUsersServicePrincipalName) { $cnt_ADUsersServicePrincipalName = @($obj_ADUsersServicePrincipalName).Count }
  If ($obj_ADUsersWithSIDHistory) { $cnt_ADUsersWithSIDHistory = @($obj_ADUsersWithSIDHistory).Count }
	
  # Get users without an expiration date set
  $obj_ADUsers_enabled_noexpiration = @($obj_ADUsers_enabled | Where-Object { $_.AccountExpirationDate -eq $null })
  If ($obj_ADUsers_enabled_noexpiration) { $cnt_ADUsers_enabled_noexpiration = @($obj_ADUsers_enabled_noexpiration).Count }
	
  # Find inactive users
  $oldUserLogonTime = $time.AddDays(- ($UserInactiveLogonDays))
  $oldUserPasswordtime = $time.AddDays(- ($UserInactivePasswordDays))
	
  $obj_ADUsersNoLastLogonDate = @($obj_ADUsers_enabled | Where-Object { $_.LastLogonDate -eq $null })
  $obj_ADUsersOldLastLogonDate = @($obj_ADUsers_enabled | Where-Object { $_.LastLogonDate -lt $oldUserLogonTime -and $_.LastLogonDate -ne $null })
  $obj_ADUsersNoPasswordLastSet = @($obj_ADUsers_enabled | Where-Object { $_.PasswordLastSet -eq $null })
  $obj_ADUsersOldPasswordLastSet = @($obj_ADUsers_enabled | Where-Object { $_.PasswordLastSet -lt $oldUserPasswordtime -and $_.PasswordLastSet -ne $null })
  $obj_ADUsersPasswordExpired = @($obj_ADUsers_enabled | Where-Object { $_.PasswordExpired -eq $True })
  $obj_ADUsersLockedOut = @($obj_ADUsers_enabled | Where-Object { $_.LockedOut -eq $True }) # AccountLockoutTime -ne $null
	
  # Count inactive users
  If ($obj_ADUsersNoLastLogonDate) { $cnt_ADUsersNoLastLogonDate = @($obj_ADUsersNoLastLogonDate).Count }
  If ($obj_ADUsersOldLastLogonDate) { $cnt_ADUsersOldLastLogonDate = @($obj_ADUsersOldLastLogonDate).Count }
  If ($obj_ADUsersNoPasswordLastSet) { $cnt_ADUsersNoPasswordLastSet = @($obj_ADUsersNoPasswordLastSet).Count }
  If ($obj_ADUsersOldPasswordLastSet) { $cnt_ADUsersOldPasswordLastSet = @($obj_ADUsersOldPasswordLastSet).Count }
  If ($obj_ADUsersPasswordExpired) { $cnt_ADUsersPasswordExpired = @($obj_ADUsersPasswordExpired).Count }
  If ($obj_ADUsersLockedOut) { $cnt_ADUsersLockedOut = @($obj_ADUsersLockedOut).Count }
	
  # Get unique inactive users
  If ($obj_ADUsersNoLastLogonDate) { $obj_ADUsersExpired_all += $obj_ADUsersNoLastLogonDate }
  If ($obj_ADUsersOldLastLogonDate) { $obj_ADUsersExpired_all += $obj_ADUsersOldLastLogonDate }
  If ($obj_ADUsersNoPasswordLastSet) { $obj_ADUsersExpired_all += $obj_ADUsersNoPasswordLastSet }
  If ($obj_ADUsersOldPasswordLastSet) { $obj_ADUsersExpired_all += $obj_ADUsersOldPasswordLastSet }
  If ($obj_ADUsersPasswordExpired) { $obj_ADUsersExpired_all += $obj_ADUsersPasswordExpired }
  If ($obj_ADUsersLockedOut) { $obj_ADUsersExpired_all += $obj_ADUsersLockedOut }
  $obj_ADUsersExpired_all = $obj_ADUsersExpired_all | Sort-Object -Unique
  If ($obj_ADUsersExpired_all) { $cnt_ADUsersExpired_all = @($obj_ADUsersExpired_all).Count }

  # ==================== #
  # AD computer analysis #
  # ==================== #
  Write-Verbose 'Progress: Getting interesting computer accounts...'

  # Get interesting computers
  $obj_ADComputersReversibleEncryption = @($obj_ADComputers_enabled | Where-Object { $_.AllowReversiblePasswordEncryption -eq $True })
  $obj_ADComputersDoesNotRequirePreAuth = @($obj_ADComputers_enabled | Where-Object { $_.DoesNotRequirePreAuth -eq $True })
  $obj_ADComputersCannotChangePassword = @($obj_ADComputers_enabled | Where-Object { $_.CannotChangePassword -eq $True })
  $obj_ADComputersPasswordNeverExpires = @($obj_ADComputers_enabled | Where-Object { $_.PasswordNeverExpires -eq $True })
  $obj_ADComputersPasswordNotRequired = @($obj_ADComputers_enabled | Where-Object { $_.PasswordNotRequired -eq $True })
  $obj_ADComputersTrustedForDelegation = @($obj_ADComputers_enabled | Where-Object { $_.TrustedForDelegation })
  $obj_ADComputersWithSIDHistory = @($obj_ADComputers_enabled | Where-Object { $_.SIDHistory })
	
  # Count interesting computers
  If ($obj_ADComputersReversibleEncryption) { $cnt_ADComputersReversibleEncryption = @($obj_ADComputersReversibleEncryption).Count }
  If ($obj_ADComputersDoesNotRequirePreAuth) { $cnt_ADComputersDoesNotRequirePreAuth = @($obj_ADComputersDoesNotRequirePreAuth).Count }
  If ($obj_ADComputersCannotChangePassword) { $cnt_ADComputersCannotChangePassword = @($obj_ADComputersCannotChangePassword).Count }
  If ($obj_ADComputersPasswordNeverExpires) { $cnt_ADComputersPasswordNeverExpires = @($obj_ADComputersPasswordNeverExpires).Count }
  If ($obj_ADComputersPasswordNotRequired) { $cnt_ADComputersPasswordNotRequired = @($obj_ADComputersPasswordNotRequired).Count }
  If ($obj_ADComputersTrustedForDelegation) { $cnt_ADComputersTrustedForDelegation = @($obj_ADComputersTrustedForDelegation).Count }
  If ($obj_ADComputersWithSIDHistory) { $cnt_ADComputersWithSIDHistory = @($obj_ADComputersWithSIDHistory).Count }
	
  # Find inactive computers
  $oldComputerLogonTime = $time.AddDays(- ($ComputerInactiveLogonDays))
  $oldComputerPasswordtime = $time.AddDays(- ($ComputerInactivePasswordDays))
	
  $obj_ADComputersNoLastLogonDate = @($obj_ADComputers_enabled | Where-Object { $_.LastLogonDate -eq $null })
  $obj_ADComputersOldLastLogonDate = @($obj_ADComputers_enabled | Where-Object { $_.LastLogonDate -lt $oldComputerLogonTime -and $_.LastLogonDate -ne $null })
  $obj_ADComputersNoPasswordLastSet = @($obj_ADComputers_enabled | Where-Object { $_.PasswordLastSet -eq $null })
  $obj_ADComputersOldPasswordLastSet = @($obj_ADComputers_enabled | Where-Object { $_.PasswordLastSet -lt $oldComputerPasswordtime -and $_.PasswordLastSet -ne $null })
  $obj_ADComputersPasswordExpired = @($obj_ADComputers_enabled | Where-Object { $_.PasswordExpired -eq $True })
  $obj_ADComputersLockedOut = @($obj_ADComputers_enabled | Where-Object { $_.LockedOut -eq $True }) # AccountLockoutTime -ne $null
	
  # Count inactive computers
  If ($obj_ADComputersNoLastLogonDate) { $cnt_ADComputersNoLastLogonDate = @($obj_ADComputersNoLastLogonDate).Count }
  If ($obj_ADComputersOldLastLogonDate) { $cnt_ADComputersOldLastLogonDate = @($obj_ADComputersOldLastLogonDate).Count }
  If ($obj_ADComputersNoPasswordLastSet) { $cnt_ADComputersNoPasswordLastSet = @($obj_ADComputersNoPasswordLastSet).Count }
  If ($obj_ADComputersOldPasswordLastSet) { $cnt_ADComputersOldPasswordLastSet = @($obj_ADComputersOldPasswordLastSet).Count }
  If ($obj_ADComputersPasswordExpired) { $cnt_ADComputersPasswordExpired = @($obj_ADComputersPasswordExpired).Count }
  If ($obj_ADComputersLockedOut) { $cnt_ADComputersLockedOut = @($obj_ADComputersLockedOut).Count }
	
  # Get unique inactive computers
  If ($obj_ADComputersNoLastLogonDate) { $obj_ADComputersExpired_all += $obj_ADComputersNoLastLogonDate }
  If ($obj_ADComputersOldLastLogonDate) { $obj_ADComputersExpired_all += $obj_ADComputersOldLastLogonDate }
  If ($obj_ADComputersNoPasswordLastSet) { $obj_ADComputersExpired_all += $obj_ADComputersNoPasswordLastSet }
  If ($obj_ADComputersOldPasswordLastSet) { $obj_ADComputersExpired_all += $obj_ADComputersOldPasswordLastSet }
  If ($obj_ADComputersPasswordExpired) { $obj_ADComputersExpired_all += $obj_ADComputersPasswordExpired }
  If ($obj_ADComputersLockedOut) { $obj_ADComputersExpired_all += $obj_ADComputersLockedOut }
  $obj_ADComputersExpired_all = $obj_ADComputersExpired_all | Sort-Object -Unique
  If ($obj_ADComputersExpired_all) { $cnt_ADComputersExpired_all = @($obj_ADComputersExpired_all).Count }

  # Operating Systems - enabled and have an IP Address assigned -> used 'recently'
  $obj_ADComputersUnknownOS_enabled = @($obj_ADComputers_enabled | Where-Object { $_.OperatingSystem -eq $null })
  $obj_ADComputersServers_enabled = @($obj_ADComputers_enabled | Where-Object { $_.OperatingSystem -like '*server*'  -and $_.IPv4Address -like "*.*"})
  $obj_ADComputersWinXP_enabled = @($obj_ADComputers_enabled | Where-Object { $_.OperatingSystem -like '*xp*' -and $_.IPv4Address -like "*.*"})
  $obj_ADComputersServer2003_enabled = @($obj_ADComputers_enabled | Where-Object { $_.OperatingSystem -like '*server 2003*' -and $_.IPv4Address -like "*.*"})

  If ($obj_ADComputersUnknownOS_enabled) { $cnt_ADComputersUnknownOS_enabled = @($obj_ADComputersUnknownOS_enabled).Count }
  If ($obj_ADComputersServers_enabled) { $cnt_ADComputersWindowsServers_enabled = @($obj_ADComputersServers_enabled).Count }
  If ($obj_ADComputersWinXP_enabled) { $cnt_ADComputersWinXP_enabled = @($obj_ADComputersWinXP_enabled).Count }
  If ($obj_ADComputersServer2003_enabled) { $cnt_ADComputersServer2003_enabled = @($obj_ADComputersServer2003_enabled).Count }

  # Windows vs Non-Windows - enabled
  $obj_ADComputersWindows_enabled = @($obj_ADComputers_enabled | Where-Object { $_.OperatingSystem -like '*Windows*' })
  If ($obj_ADComputersWindows_enabled) { $cnt_ADComputersWindows_enabled = @($obj_ADComputersWindows_enabled).Count }
  $cnt_ADComputersNonWindows_enabled = $cnt_ADComputers_enabled - $cnt_ADComputersWindows_enabled

  $cnt_ADComputersWindowsClients_enabled = $cnt_ADComputers_enabled - $cnt_ADComputersWindowsServers_enabled - $cnt_ADComputersNonWindows_enabled

  # Operating Systems - disabled
  $obj_ADComputersUnknownOS_disabled = @($obj_ADComputers_disabled | Where-Object { $_.OperatingSystem -eq $null })
  $obj_ADComputersServers_disabled = @($obj_ADComputers_disabled | Where-Object { $_.OperatingSystem -like '*server*' })
  $obj_ADComputersWinXP_disabled = @($obj_ADComputers_disabled | Where-Object { $_.OperatingSystem -like '*xp*' })
  $obj_ADComputersServer2003_disabled = @($obj_ADComputers_disabled | Where-Object { $_.OperatingSystem -like '*server 2003*' })

  If ($obj_ADComputersUnknownOS_disabled) { $cnt_ADComputersUnknownOS_disabled = @($obj_ADComputersUnknownOS_disabled).Count }
  If ($obj_ADComputersServers_disabled) { $cnt_ADComputersWindowsServers_disabled = @($obj_ADComputersServers_disabled).Count }
  If ($obj_ADComputersWinXP_disabled) { $cnt_ADComputersWinXP_disabled = @($obj_ADComputersWinXP_disabled).Count }
  If ($obj_ADComputersServer2003_disabled) { $cnt_ADComputersServer2003_disabled = @($obj_ADComputersServer2003_disabled).Count }

   # Windows vs Non-Windows - disabled
  $obj_ADComputersWindows_disabled = @($obj_ADComputers_disabled | Where-Object { $_.OperatingSystem -like '*Windows*' })
  If ($obj_ADComputersWindows_disabled) { $cnt_ADComputersWindows_disabled = @($obj_ADComputersWindows_disabled).Count }
  $cnt_ADComputersNonWindows_disabled = $cnt_ADComputers_disabled - $cnt_ADComputersWindows_disabled

  $cnt_ADComputersWindowsClients_disabled = $cnt_ADComputers_disabled - $cnt_ADComputersUnknownOS_disabled - $cnt_ADComputersWindowsServers_disabled - $cnt_ADComputersNonWindows_disabled
	
  # How many computer objects are placed under the Get-ADDomain.ComputersContainer?
  $obj_ADComputersContainer_enabled = @($obj_ADComputers_enabled | Where-Object { $_.DistinguishedName -match $str_ADDomainComputersContainer })
  $obj_ADComputersContainer_disabled = @($obj_ADComputers_disabled | Where-Object { $_.DistinguishedName -match $str_ADDomainComputersContainer })

  If ($obj_ADComputersContainer_enabled) { $cnt_ADComputersContainer_enabled = @($obj_ADComputersContainer_enabled).Count }
  If ($obj_ADComputersContainer_disabled) { $cnt_ADComputersContainer_disabled = @($obj_ADComputersContainer_disabled).Count }

  # Get-ADDomain.ComputersContainer might not be the same as the Computers Container (CN=Computers), let's also find out if the built-in CN is also populated with computers (might be redundant work)
  $obj_ADComputersContainerCN_enabled = @($obj_ADComputers_enabled | Where-Object { $_.DistinguishedName -match $str_ADDomainExpectedDefaultComputersContainer })
  $obj_ADComputersContainerCN_disabled = @($obj_ADComputers_disabled | Where-Object { $_.DistinguishedName -match $str_ADDomainExpectedDefaultComputersContainer })

  If ($obj_ADComputersContainerCN_enabled) { $cnt_ADComputersContainerCN_enabled = @($obj_ADComputersContainerCN_enabled).Count }
  If ($obj_ADComputersContainerCN_disabled) { $cnt_ADComputersContainerCN_disabled = @($obj_ADComputersContainerCN_disabled).Count }

  # Check LDAP+LDAPS for all DCs in the forest
  Write-Verbose 'Progress: Check LDAP+LDAPS for all DCs in the forest...'
  $int_ADForestDCs = $obj_ADForestDCs.Count
  
  $int_ADForestDCsWithLDAP     = 0
  $int_ADForestDCsWithoutLDAP  = 0
  $int_ADForestDCsWithLDAPS    = 0
  $int_ADForestDCsWithoutLDAPS = 0

  $str_ADForestDCsWithLDAP     = ""
  $str_ADForestDCsWithoutLDAP  = ""
  $str_ADForestDCsWithLDAPS    = ""
  $str_ADForestDCsWithoutLDAPS = ""

  ForEach ($obj_ADForestDC in $obj_ADForestDCs)
    {
        $strDCHostName = $obj_ADForestDC.HostName
        Write-Verbose "- Test LDAP: '$strDCHostName'"
 
        $LDAP = [ADSI]"LDAP://$($strDCHostName):389"
        $LDAPS = [ADSI]"LDAP://$($strDCHostName):636"
 
        # First we check regular LDAP
        try
        {
            $LDAPConnection = [adsi]($LDAP)
        }
        Catch
        {
        }  
        If ($LDAPConnection.Path)
        {
            Write-Verbose "- LDAP connection to $($LDAP.Path) completed with success."
            $int_ADForestDCsWithLDAP++
            $str_ADForestDCsWithLDAP += "$strDCHostName`r`n                                "
        }
        Else
        {
            Write-Verbose "- LDAP connection (TCP 389) to LDAP://$strDCHostName did not work."
            $int_ADForestDCsWithoutLDAP++
            $str_ADForestDCsWithoutLDAP += "$strDCHostName`r`n                                "
        }
 
        # Next we check LDAPS
        try
        {
            $LDAPSConnection = [adsi]($LDAPS)
        }
        Catch
        {
        }
        If ($LDAPSConnection.Path)
        {
            Write-Verbose "- LDAPS connection to $($LDAPS.Path) completed with success."
            $int_ADForestDCsWithLDAPS++
            $str_ADForestDCsWithLDAPS += "$strDCHostName`r`n                                "
        }
        Else
        {
            Write-Verbose "- LDAPS connection (TCP 636) to LDAP://$dcname did not work."
            $int_ADForestDCsWithoutLDAPS++
            $str_ADForestDCsWithoutLDAPS += "$strDCHostName`r`n                                "
        }
    }

  $str_ADForestDCsWithoutLDAP  = $str_ADForestDCsWithoutLDAP -replace ".$"
  $str_ADForestDCsWithoutLDAPS = $str_ADForestDCsWithoutLDAPS -replace ".$"

  # Create report content
  Write-Verbose 'Progress: Creating report content...'

   # Write output / stats
  $Str_ReportText = @"

"New-ADReport version         : [$str_ScriptVersion]
 - File Time Stamp            : [$str_FileTimeStamp]
 - Start Time                 : [$time]

[ACTIVE DIRECTORY]
Basic info:
 - DNSRoot                    : $str_ADDomain_DNSRoot
 - NetBIOS Name               : $str_ADDomain_NetBIOSName
 - Domain SID                 : $str_ADDomainSID
 - Forest                     : $str_ADDomain_Forest
 - Forest Root Domain         : $bol_ForestRootDomain
 - Domain Functional Level    : $str_ADDomain_DomainMode
 - Forest Functional Level    : $str_ADForest_ForestMode
 - Number of trusts           : $cnt_ADDomainTrusts
 - Last krbtgt reset          : $str_ADUser_krbtgt_PasswordLastSet
 - Administrator name (500)   : $str_AdministratorUserName
 - Guest name (501)           : $str_GuestUserName

FSMO roles:
 - DomainNamingMaster (forest): $str_ADForest_DomainNamingMaster
 - SchemaMaster (forest)      : $str_ADForest_SchemaMaster
 - InfrastructureMaster       : $str_ADDomain_InfrastructureMaster
 - PDCEmulator                : $str_ADDomain_PDCEmulator
 - RIDMaster                  : $str_ADDomain_RIDMaster

LDAP test:                     [with/without/total]
 - Domain Controllers w/LDAP  : $int_ADForestDCsWithLDAP/$int_ADForestDCsWithoutLDAP/$int_ADForestDCs
   - List of DCs w/LDAP       : $str_ADForestDCsWithLDAP
   - List of DCs wo/LDAP      : $str_ADForestDCsWithoutLDAP

LDAPS test:                    [with/without/total]
 - Domain Controllers w/LDAPS : $int_ADForestDCsWithLDAPS/$int_ADForestDCsWithoutLDAPS/$int_ADForestDCs
   - List of DCs w/LDAPS      : $str_ADForestDCsWithLDAPS
   - List of DCs wo/LDAPS     : $str_ADForestDCsWithoutLDAPS

Default Domain password policy:
 - ComplexityEnabled          : $str_ADDomainPwdPolicy_ComplexityEnabled
 - Minimum Password Length    : $str_ADDomainPwdPolicy_MinPasswordLength
 - LockoutDuration            : $str_ADDomainPwdPolicy_LockoutDuration
 - Lockout Observation Window : $str_ADDomainPwdPolicy_LockoutObservationWindow
 - Lockout Threshold          : $str_ADDomainPwdPolicy_LockoutThreshold
 - Maximum Password Age       : $str_ADDomainPwdPolicy_MaxPasswordAge
 - Minimum Password Age       : $str_ADDomainPwdPolicy_MinPasswordAge
 - Password History Count     : $str_ADDomainPwdPolicy_PasswordHistoryCount
 - Reversible Encryption      : $str_ADDomainPwdPolicy_ReversibleEncryptionEnabled
Fine Grained Password Policies: $cnt_ADFineGrainedPwdPolicies

[USERS]
Domain users                  : $cnt_ADUsers
 - Disabled user accounts     : $cnt_ADUsers_disabled ($([Math]::round((($cnt_ADUsers_disabled/$cnt_ADUsers) * 100)))%)
 - Enabled user accounts      : $cnt_ADUsers_enabled ($([Math]::round((($cnt_ADUsers_enabled/$cnt_ADUsers) * 100)))%)
  - No expiration date set    : $cnt_ADUsers_enabled_noexpiration ($([Math]::round((($cnt_ADUsers_enabled_noexpiration/$cnt_ADUsers_enabled) * 100)))%)
  - Reversible pwd allowed    : $cnt_ADUsersReversibleEncryption ($([Math]::round((($cnt_ADUsersReversibleEncryption/$cnt_ADUsers_enabled) * 100)))%)
  - No pre-authentication     : $cnt_ADUsersDoesNotRequirePreAuth ($([Math]::round((($cnt_ADUsersDoesNotRequirePreAuth/$cnt_ADUsers_enabled) * 100)))%)
  - SmartCard not required    : $cnt_ADUsersSmartcardLogonNotRequired ($([Math]::round((($cnt_ADUsersSmartcardLogonNotRequired/$cnt_ADUsers_enabled) * 100)))%)
  - User cannot change pwd    : $cnt_ADUsersCannotChangePassword ($([Math]::round((($cnt_ADUsersCannotChangePassword/$cnt_ADUsers_enabled) * 100)))%)
  - Password never expires    : $cnt_ADUsersPasswordNeverExpires ($([Math]::round((($cnt_ADUsersPasswordNeverExpires/$cnt_ADUsers_enabled) * 100)))%)
  - Password not required     : $cnt_ADUsersPasswordNotRequired ($([Math]::round((($cnt_ADUsersPasswordNotRequired/$cnt_ADUsers_enabled) * 100)))%)
  - AdminCount bit is set     : $cnt_ADUsersAdminCount ($([Math]::round((($cnt_ADUsersAdminCount/$cnt_ADUsers_enabled) * 100)))%)
  - Trusted for delegation    : $cnt_ADUsersTrustedForDelegation ($([Math]::round((($cnt_ADUsersTrustedForDelegation/$cnt_ADUsers_enabled) * 100)))%)
  - ServicePrincipalName set  : $cnt_ADUsersServicePrincipalName ($([Math]::round((($cnt_ADUsersServicePrincipalName/$cnt_ADUsers_enabled) * 100)))%)
  - SIDHistory defined        : $cnt_ADUsersWithSIDHistory ($([Math]::round((($cnt_ADUsersWithSIDHistory/$cnt_ADUsers_enabled) * 100)))%)

Possible inactive users:
  - No LastLogonDate value    : $cnt_ADUsersNoLastLogonDate ($([Math]::round((($cnt_ADUsersNoLastLogonDate/$cnt_ADUsers_enabled) * 100)))%)
  - Old LastLogonDate value   : $cnt_ADUsersOldLastLogonDate ($UserInactiveLogonDays or more days) ($([Math]::round((($cnt_ADUsersOldLastLogonDate/$cnt_ADUsers_enabled) * 100)))%)
  - Password has expired      : $cnt_ADUsersPasswordExpired ($([Math]::round((($cnt_ADUsersPasswordExpired/$cnt_ADUsers_enabled) * 100)))%)
  - Must Change Password Next : $cnt_ADUsersNoPasswordLastSet ($([Math]::round((($cnt_ADUsersNoPasswordLastSet/$cnt_ADUsers_enabled) * 100)))%)
  - Old PasswordLastSet value : $cnt_ADUsersOldPasswordLastSet ($UserInactivePasswordDays or more days) ($([Math]::round((($cnt_ADUsersOldPasswordLastSet/$cnt_ADUsers_enabled) * 100)))%)
  - Locked Out                : $cnt_ADUsersLockedOut ($([Math]::round((($cnt_ADUsersLockedOut/$cnt_ADUsers_enabled) * 100)))%)
               = TOTAL UNIQUE : $cnt_ADUsersExpired_all ($([Math]::round((($cnt_ADUsersExpired_all/$cnt_ADUsers_enabled) * 100)))%)

[GROUPS]                       [enabled-users/all-users] (does not account for non-users)
Highly privileged users:
 - Builtin\Administrators     : $cnt_ADGroupAdministrators_enabled/$cnt_ADGroupAdministrators ($([Math]::round((($cnt_ADGroupAdministrators_enabled/$cnt_ADUsers_enabled) * 100)))%)
    - Note: Builtin\Administrators also includes members of Domain Admins
 - Domain Admins              : $cnt_ADGroupDomainAdmins_enabled/$cnt_ADGroupDomainAdmins ($([Math]::round((($cnt_ADGroupDomainAdmins_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Enterprise Admins          : $cnt_ADGroupEnterpriseAdmins_enabled/$cnt_ADGroupEnterpriseAdmins ($([Math]::round((($cnt_ADGroupEnterpriseAdmins_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Schema Admins              : $cnt_ADGroupSchemaAdmins_enabled/$cnt_ADGroupSchemaAdmins ($([Math]::round((($cnt_ADGroupSchemaAdmins_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Group Policy Creator Owners: $cnt_ADGroupGPCreatorOwners_enabled/$cnt_ADGroupGPCreatorOwners ($([Math]::round((($cnt_ADGroupGPCreatorOwners_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - DNS Admins                 : $cnt_ADGroupDnsAdmins_enabled/$cnt_ADGroupDnsAdmins ($([Math]::round((($cnt_ADGroupDnsAdmins_enabled/$cnt_ADUsers_enabled) * 100)))%)
               = TOTAL UNIQUE : $cnt_ADUsersHighlyPrivileged_enabled/$cnt_ADUsersHighlyPrivileged
Privileged users:
 - Builtin\Account Operators  : $cnt_ADGroupAccountOperators_enabled/$cnt_ADGroupAccountOperators ($([Math]::round((($cnt_ADGroupAccountOperators_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Builtin\Server Operators   : $cnt_ADGroupServerOperators_enabled/$cnt_ADGroupServerOperators ($([Math]::round((($cnt_ADGroupServerOperators_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Builtin\Backup Operators   : $cnt_ADGroupBackupOperators_enabled/$cnt_ADGroupBackupOperators ($([Math]::round((($cnt_ADGroupBackupOperators_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Builtin\Print Operators    : $cnt_ADGroupPrintOperators_enabled/$cnt_ADGroupPrintOperators ($([Math]::round((($cnt_ADGroupPrintOperators_enabled/$cnt_ADUsers_enabled) * 100)))%)
 - Cert Publishers            : $cnt_ADGroupCertPublishers_enabled/$cnt_ADGroupCertPublishers ($([Math]::round((($cnt_ADGroupCertPublishers_enabled/$cnt_ADUsers_enabled) * 100)))%)
               = TOTAL UNIQUE : $($cnt_ADUsersPrivileged_all_enabled-$cnt_ADUsersHighlyPrivileged_enabled)/$($cnt_ADUsersPrivileged_all-$cnt_ADUsersHighlyPrivileged)
Admin stats (enabled users):
 - Privileged users PCT       : $([Math]::round((($cnt_ADUsersPrivileged_all_enabled/$cnt_ADUsers_enabled) * 100)))%
 - Highly privileged PCT      : $([Math]::round((($cnt_ADUsersHighlyPrivileged_enabled/$cnt_ADUsers_enabled) * 100)))%
Other notes:
 - Privileged NonUser Accounts: $WeHavePrivilegedNonUserAccounts
 - Enabled Guest group members: $cnt_ADGroupGuests_enabled

[COMPUTERS]
Domain computers              : $cnt_ADComputers
 - Disabled computer accounts : $cnt_ADComputers_disabled ($([Math]::round((($cnt_ADComputers_disabled/$cnt_ADComputers) * 100)))%)
 - Enabled computer accounts  : $cnt_ADComputers_enabled ($([Math]::round((($cnt_ADComputers_enabled/$cnt_ADComputers) * 100)))%)
  - Reversible pwd allowed    : $cnt_ADComputersReversibleEncryption ($([Math]::round((($cnt_ADComputersReversibleEncryption/$cnt_ADComputers_enabled) * 100)))%)
  - No pre-authentication     : $cnt_ADComputersDoesNotRequirePreAuth ($([Math]::round((($cnt_ADComputersDoesNotRequirePreAuth/$cnt_ADComputers_enabled) * 100)))%)
  - Account cannot change pwd : $cnt_ADComputersCannotChangePassword ($([Math]::round((($cnt_ADComputersCannotChangePassword/$cnt_ADComputers_enabled) * 100)))%)
  - Password never expires    : $cnt_ADComputersPasswordNeverExpires ($([Math]::round((($cnt_ADComputersPasswordNeverExpires/$cnt_ADComputers_enabled) * 100)))%)
  - Password not required     : $cnt_ADComputersPasswordNotRequired ($([Math]::round((($cnt_ADComputersPasswordNotRequired/$cnt_ADComputers_enabled) * 100)))%)
  - Trusted for delegation    : $cnt_ADComputersTrustedForDelegation ($([Math]::round((($cnt_ADComputersTrustedForDelegation/$cnt_ADComputers_enabled) * 100)))%)
  - SIDHistory defined        : $cnt_ADComputersWithSIDHistory ($([Math]::round((($cnt_ADComputersWithSIDHistory/$cnt_ADComputers_enabled) * 100)))%)

Possible inactive computers:
  - No LastLogonDate value    : $cnt_ADComputersNoLastLogonDate ($([Math]::round((($cnt_ADComputersNoLastLogonDate/$cnt_ADComputers_enabled) * 100)))%)
  - Old LastLogonDate value   : $cnt_ADComputersOldLastLogonDate ($ComputerInactiveLogonDays or more days) ($([Math]::round((($cnt_ADComputersOldLastLogonDate/$cnt_ADComputers_enabled) * 100)))%)
  - Password has expired      : $cnt_ADComputersPasswordExpired ($([Math]::round((($cnt_ADComputersPasswordExpired/$cnt_ADComputers_enabled) * 100)))%)
  - No PasswordLastSet value  : $cnt_ADComputersNoPasswordLastSet ($([Math]::round((($cnt_ADComputersNoPasswordLastSet/$cnt_ADComputers_enabled) * 100)))%)
  - Old PasswordLastSet value : $cnt_ADComputersOldPasswordLastSet ($ComputerInactivePasswordDays or more days) ($([Math]::round((($cnt_ADComputersOldPasswordLastSet/$cnt_ADComputers_enabled) * 100)))%)
  - Locked Out                : $cnt_ADComputersLockedOut ($([Math]::round((($cnt_ADComputersLockedOut/$cnt_ADComputers_enabled) * 100)))%)
               = TOTAL UNIQUE : $cnt_ADComputersExpired_all ($([Math]::round((($cnt_ADComputersExpired_all/$cnt_ADComputers_enabled) * 100)))%)

AD Computers and DC roles:
 - # of Domain Controllers    : $cnt_ADDomainControllers
 - # of Global Catalog Srvs   : $cnt_ADGlobalCatalogSrv
 - Global Catalog server used : $($strGlobalCatalogServer):$intGlobalCatalogServerPort

Clients and Operating systems : [enabled/disabled]
 - Default CompContainer used : $bol_ExpectedDefaultComputersContainer ($str_ADDomainComputersContainer)
   - Below that Container/OU  : $cnt_ADComputersContainer_enabled/$cnt_ADComputersContainer_disabled
 - Below CN=Computers Contain.: $cnt_ADComputersContainerCN_enabled/$cnt_ADComputersContainerCN_disabled
 - # of Unknown OS (null)     : $cnt_ADComputersUnknownOS_enabled/$cnt_ADComputersUnknownOS_disabled
 - # of Windows Server family : $cnt_ADComputersWindowsServers_enabled/$cnt_ADComputersWindowsServers_disabled
   - Server 2003 (unsupported): $cnt_ADComputersServer2003_enabled/$cnt_ADComputersServer2003_disabled
 - # of Windows Client family : $cnt_ADComputersWindowsClients_enabled/$cnt_ADComputersWindowsClients_disabled
   - Windows XP (unsupported) : $cnt_ADComputersWinXP_enabled/$cnt_ADComputersWinXP_disabled
 - # of Windows OS (any type) : $cnt_ADComputersWindows_enabled/$cnt_ADComputersWindows_disabled
 - # of Non-Windows OS        : $cnt_ADComputersNonWindows_enabled/$cnt_ADComputersNonWindows_disabled

"@

  # =============== #
  # Make dump files #
  # =============== #

  # Dump user information to CSV
  Write-Verbose 'Progress: Dumping user information to CSV...' 
  If ($DumpFile_UserInfo) { $obj_ADUsers | Select-Object SamAccountName, SID, @{name="SIDHistory";expression={$_.SIDHistory.Value -join ','}}, GivenName, Surname, UserPrincipalName, Description, Enabled, Created, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, SmartcardLogonRequired, CannotChangePassword, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, PasswordLastSet, PasswordExpired, LastLogonDate, BadLogonCount, LastBadPasswordAttempt, LockedOut, AccountLockoutTime, adminCount, TrustedForDelegation | Export-CSV "$PSScriptRoot\ADReport-$str_ADDomain_DNSRoot-$str_FileTimeStamp-Users.csv" -Delimiter "`t" -NoTypeInformation -Encoding UTF8 }
	
  # Dump privileged user information to CSV
  Write-Verbose 'Progress: Dumping privileged user information to CSV...' 
  If ($DumpFile_PrivilegedUserInfo) { $obj_ADUsersPrivileged_all | Select-Object SamAccountName, SID, distinguishedName, objectClass | Export-CSV "$PSScriptRoot\ADReport-$str_ADDomain_DNSRoot-$str_FileTimeStamp-PrivilegedUsers.csv" -Delimiter "`t" -NoTypeInformation -Encoding UTF8 }
	
  # Dump computer information to CSV
  Write-Verbose 'Progress: Dumping computer information to CSV...' 
  If ($DumpFile_ComputerInfo) { $obj_ADComputers | Select-Object Name, SID, @{name="SIDHistory";expression={$_.SIDHistory.Value -join ','}}, DNSHostName, IPv4Address, IPv6Address, Description, Enabled, Created, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, CannotChangePassword, PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, PasswordLastSet, PasswordExpired, LastLogonDate, BadLogonCount, LastBadPasswordAttempt, LockedOut, AccountLockoutTime, OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, TrustedForDelegation | Export-CSV "$PSScriptRoot\ADReport-$str_ADDomain_DNSRoot-$str_FileTimeStamp-Computers.csv" -Delimiter "`t" -NoTypeInformation -Encoding UTF8 }

  # Dump Text Report
  $ElapsedTimeTotalSeconds = $($(Get-Date) - $time).TotalSeconds
  $str_ReportText += "[Elapsed Time: $ElapsedTimeTotalSeconds seconds]" 
  $str_ReportText | Out-File "$PSScriptRoot\ADReport-$str_ADDomain_DNSRoot-$str_FileTimeStamp-Report.txt"
	
  # Finalize
  If ($WriteHost_FinalReport) { Write-Host $str_ReportText }
  Else { Write-Verbose "Complete: $ElapsedTimeTotalSeconds seconds." }
}
