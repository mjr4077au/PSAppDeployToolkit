<#
.SYNOPSIS

PSAppDeployToolkit - This script contains the PSADT core runtime and functions using by a Deploy-Application.ps1 script.

.DESCRIPTION

The script can be called directly to dot-source the toolkit functions for testing, but it is usually called by the Deploy-Application.ps1 script.

The script can usually be updated to the latest version without impacting your per-application Deploy-Application scripts. Please check release notes before upgrading.

PSAppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2024 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham and Muhammad Mashwani).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.PARAMETER CleanupBlockedApps

Clean up the blocked applications.

This parameter is passed to the script when it is called externally, e.g. from a scheduled task or asynchronously.

.PARAMETER ShowBlockedAppDialog

Display a dialog box showing that the application execution is blocked.
This parameter is passed to the script when it is called externally, e.g. from a scheduled task or asynchronously.

.PARAMETER ReferredInstallName

Name of the referring application that invoked the script externally.
This parameter is passed to the script when it is called externally, e.g. from a scheduled task or asynchronously.

.PARAMETER ReferredInstallTitle

Title of the referring application that invoked the script externally.
This parameter is passed to the script when it is called externally, e.g. from a scheduled task or asynchronously.

.PARAMETER ReferredLogname

Logfile name of the referring application that invoked the script externally.
This parameter is passed to the script when it is called externally, e.g. from a scheduled task or asynchronously.

.PARAMETER AsyncToolkitLaunch

This parameter is passed to the script when it is being called externally, e.g. from a scheduled task or asynchronously.

.INPUTS

None

You cannot pipe objects to this script.

.OUTPUTS

None

This script does not generate any output.

.NOTES

The other parameters specified for this script that are not documented in this help section are for use only by functions in this script that call themselves by running this script again asynchronously.

.LINK

https://psappdeploytoolkit.com
#>


[CmdletBinding()]
Param (
    ## Script Parameters: These parameters are passed to the script when it is called externally from a scheduled task or because of an Image File Execution Options registry setting
    [Switch]$ShowInstallationPrompt = $false,
    [Switch]$ShowInstallationRestartPrompt = $false,
    [Switch]$CleanupBlockedApps = $false,
    [Switch]$ShowBlockedAppDialog = $false,
    [Switch]$DisableLogging = $false,
    [String]$ReferredInstallName = '',
    [String]$ReferredInstallTitle = '',
    [String]$ReferredLogName = '',
    [String]$Title = '',
    [String]$Message = '',
    [String]$MessageAlignment = '',
    [String]$ButtonRightText = '',
    [String]$ButtonLeftText = '',
    [String]$ButtonMiddleText = '',
    [String]$Icon = '',
    [String]$Timeout = '',
    [Switch]$ExitOnTimeout = $false,
    [Boolean]$MinimizeWindows = $false,
    [Switch]$PersistPrompt = $false,
    [Int32]$CountdownSeconds = 60,
    [Int32]$CountdownNoHideSeconds = 30,
    [Switch]$NoCountdown = $false,
    [Switch]$AsyncToolkitLaunch = $false,
    [Boolean]$TopMost = $true
)

##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

## Add the custom types required for the toolkit
Add-Type -LiteralPath ($appDeployCustomTypesSourceCode = "$PSScriptRoot\AppDeployToolkitMain.cs") -ErrorAction Stop -ReferencedAssemblies $(
    'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    if ($PSVersionTable.PSEdition.Equals('Core'))
    {
        'System.Collections', 'System.Text.RegularExpressions', 'System.Security.Principal.Windows', 'System.ComponentModel.Primitives', 'Microsoft.Win32.Primitives'
    }
)

. "$PSScriptRoot\PSAppDeployToolkit\Private\AppDeployToolkitPrivate.ps1"
. "$PSScriptRoot\PSAppDeployToolkit\Public\AppDeployToolkitPublic.ps1"

New-Variable -Name StateMgmt -Option Constant -Value ([ordered]@{
    DotSourced = $MyInvocation.InvocationName.Equals('.') -or [System.String]::IsNullOrWhiteSpace($MyInvocation.Line)
    Variables = $null
    Sessions = $null
    Config = $null
    UI = $null
    Progress = [ordered]@{
        Runspace = [runspacefactory]::CreateRunspace()
        SyncHash = [hashtable]::Synchronized(@{})
    }
})

function Get-SidTypeAccountName
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Security.Principal.WellKnownSidType]$WellKnownSidType
    )

    # Translate the SidType into its user-readable name.
    return [System.Security.Principal.SecurityIdentifier]::new($WellKnownSidType, $null).Translate([System.Security.Principal.NTAccount]).Value
}

function Initialize-PsadtVariableDatabase
{
    param (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force
    )

    # Return early if we've already initialised and we're not re-initing.
    if (!$Script:DotSourced -and $Script:StateMgmt.Variables -and $Script:StateMgmt.Variables.Count -and $Script:StateMgmt.Sessions -and $Script:StateMgmt.Sessions.Count -and !$Force)
    {
        return
    }

    # Open new dictionary for storage.
    $variables = [ordered]@{}

    ## Variables: Toolkit Name
    $variables.Add('appDeployToolkitName', [string]'PSAppDeployToolkit')
    $variables.Add('appDeployMainScriptFriendlyName', [string]'App Deploy Toolkit Main')

    ## Variables: Script Info
    $variables.Add('appDeployMainScriptVersion', [version]'3.10.0')
    $variables.Add('appDeployMainScriptMinimumConfigVersion', [version]'3.10.0')
    $variables.Add('appDeployMainScriptDate', [string]'03/27/2024')

    ## Variables: Culture
    $variables.Add('culture', [cultureinfo]$Host.CurrentCulture)
    $variables.Add('currentLanguage', [string]$variables.culture.TwoLetterISOLanguageName.ToUpper())
    $variables.Add('currentUILanguage', [string]$Host.CurrentUICulture.TwoLetterISOLanguageName.ToUpper())

    ## Variables: Environment Variables
    $variables.Add('envHost', $Host)
    $variables.Add('envShellFolders', [psobject](Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Ignore))
    $variables.Add('envAllUsersProfile', [string]$env:ALLUSERSPROFILE)
    $variables.Add('envAppData', [string][System.Environment]::GetFolderPath('ApplicationData'))
    $variables.Add('envArchitecture', [string]$env:PROCESSOR_ARCHITECTURE)
    $variables.Add('envCommonDesktop', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Desktop' -ErrorAction Ignore))
    $variables.Add('envCommonDocuments', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Documents' -ErrorAction Ignore))
    $variables.Add('envCommonStartMenuPrograms', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Programs' -ErrorAction Ignore))
    $variables.Add('envCommonStartMenu', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Start Menu' -ErrorAction Ignore))
    $variables.Add('envCommonStartUp', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Startup' -ErrorAction Ignore))
    $variables.Add('envCommonTemplates', [string]($variables.envShellFolders | Select-Object -ExpandProperty 'Common Templates' -ErrorAction Ignore))
    $variables.Add('envComputerName', [string][System.Environment]::MachineName.ToUpper())
    $variables.Add('envHomeDrive', [string]$env:HOMEDRIVE)
    $variables.Add('envHomePath', [string]$env:HOMEPATH)
    $variables.Add('envHomeShare', [string]$env:HOMESHARE)
    $variables.Add('envLocalAppData', [string][System.Environment]::GetFolderPath('LocalApplicationData'))
    $variables.Add('envLogicalDrives', [string[]][System.Environment]::GetLogicalDrives())
    $variables.Add('envProgramData', [string][System.Environment]::GetFolderPath('CommonApplicationData'))
    $variables.Add('envPublic', [string]$env:PUBLIC)
    $variables.Add('envSystemDrive', [string]$env:SYSTEMDRIVE)
    $variables.Add('envSystemRoot', [string]$env:SYSTEMROOT)
    $variables.Add('envTemp', [string][System.IO.Path]::GetTempPath())
    $variables.Add('envUserCookies', [string][System.Environment]::GetFolderPath('Cookies'))
    $variables.Add('envUserDesktop', [string][System.Environment]::GetFolderPath('DesktopDirectory'))
    $variables.Add('envUserFavorites', [string][System.Environment]::GetFolderPath('Favorites'))
    $variables.Add('envUserInternetCache', [string][System.Environment]::GetFolderPath('InternetCache'))
    $variables.Add('envUserInternetHistory', [string][System.Environment]::GetFolderPath('History'))
    $variables.Add('envUserMyDocuments', [string][System.Environment]::GetFolderPath('MyDocuments'))
    $variables.Add('envUserName', [string][System.Environment]::UserName)
    $variables.Add('envUserPictures', [string][System.Environment]::GetFolderPath('MyPictures'))
    $variables.Add('envUserProfile', [string]$env:USERPROFILE)
    $variables.Add('envUserSendTo', [string][System.Environment]::GetFolderPath('SendTo'))
    $variables.Add('envUserStartMenu', [string][System.Environment]::GetFolderPath('StartMenu'))
    $variables.Add('envUserStartMenuPrograms', [string][System.Environment]::GetFolderPath('Programs'))
    $variables.Add('envUserStartUp', [string][System.Environment]::GetFolderPath('StartUp'))
    $variables.Add('envUserTemplates', [string][System.Environment]::GetFolderPath('Templates'))
    $variables.Add('envSystem32Directory', [string][System.Environment]::SystemDirectory)
    $variables.Add('envWinDir', [string]$env:WINDIR)

    ## Variables: Domain Membership
    $w32cs = Get-CimInstance -ClassName Win32_ComputerSystem
    [string]$w32csd = $w32cs.Domain | Where-Object {$_}
    $variables.Add('IsMachinePartOfDomain', [string]$w32cs.PartOfDomain)
    $variables.Add('envMachineWorkgroup', [System.String]::Empty)
    $variables.Add('envMachineADDomain', [System.String]::Empty)
    $variables.Add('envLogonServer', [System.String]::Empty)
    $variables.Add('MachineDomainController', [System.String]::Empty)
    $variables.Add('envMachineDNSDomain', [string]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object {$_} | ForEach-Object {$_.ToLower()}))
    $variables.Add('envUserDNSDomain', [string]($env:USERDNSDOMAIN | Where-Object {$_} | ForEach-Object {$_.ToLower()}))
    $variables.Add('envUserDomain', [string]$(try {[System.Environment]::UserDomainName.ToUpper()} catch {$null}))
    $variables.Add('envComputerNameFQDN', [string]$variables.envComputerName)
    if ($variables.IsMachinePartOfDomain.Equals($true))
    {
        $variables.envMachineADDomain = $w32csd.ToLower()
        $variables.envComputerNameFQDN = try
        {
            [System.Net.Dns]::GetHostEntry('localhost').HostName
        }
        catch
        {
            # Function GetHostEntry failed, but we can construct the FQDN in another way
            $variables.envComputerNameFQDN + '.' + $variables.envMachineADDomain
        }

        # Set the logon server and remove backslashes at the beginning.
        $variables.envLogonServer = [string]$(try
        {
            $env:LOGONSERVER | Where-Object {$_ -and !$_.Contains('\\MicrosoftAccount')} | ForEach-Object {[System.Net.Dns]::GetHostEntry($_.TrimStart('\')).HostName}
        }
        catch
        {
            # If running in system context or if GetHostEntry fails, fall back on the logonserver value stored in the registry
            Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction Ignore | Select-Object -ExpandProperty DCName -ErrorAction Ignore
        })
        while ($variables.envLogonServer.StartsWith('\'))
        {
            $variables.envLogonServer = $variables.envLogonServer.Substring(1)
        }

        try
        {
            $variables.MachineDomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
        }
        catch
        {
            [System.Void]$null
        }
    }
    else
    {
        $variables.envMachineWorkgroup = $w32csd.ToUpper()
    }

    ## Variables: Operating System
    $regVer = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $variables.Add('envOS', [ciminstance](Get-CimInstance -ClassName Win32_OperatingSystem))
    $variables.Add('envOSName', [string]$variables.envOS.Caption.Trim())
    $variables.Add('envOSServicePack', [string]$variables.envOS.CSDVersion)
    $variables.Add('envOSVersion', [version]$variables.envOS.Version)
    $variables.Add('envOSVersionMajor', [string]$variables.envOSVersion.Major)
    $variables.Add('envOSVersionMinor', [string]$variables.envOSVersion.Minor)
    $variables.Add('envOSVersionBuild', [string]$variables.envOSVersion.Build)
    $variables.Add('envOSVersionRevision', [string]$(if ($regVer | Get-Member -Name UBR) {$regVer.UBR} elseif ($regVer | Get-Member -Name BuildLabEx) {$regVer.BuildLabEx.Split('.')[1]}))
    $variables.envOSVersion = if ($variables.envOSVersionRevision) {"$($variables.envOSVersion.ToString()).$($variables.envOSVersionRevision)"} else {$variables.envOSVersion.ToString()}

    # Get the operating system type.
    $variables.Add('envOSProductType', [int32]$variables.envOS.ProductType)
    $variables.Add('IsServerOS', [boolean]($variables.envOSProductType -eq 3))
    $variables.Add('IsDomainControllerOS', [boolean]($variables.envOSProductType -eq 2))
    $variables.Add('IsWorkStationOS', [boolean]($variables.envOSProductType -eq 1))
    $variables.Add('IsMultiSessionOS', [boolean]($variables.envOSName -match '^Microsoft Windows \d+ Enterprise (for Virtual Desktops|Enterprise Multi-Session)$'))
    $variables.Add('envOSProductTypeName', [string]$(switch ($variables.envOSProductType) {
        3 { 'Server' }
        2 { 'Domain Controller' }
        1 { 'Workstation' }
        default { 'Unknown' }
    }))

    # Get the OS Architecture.
    $variables.Add('Is64Bit', [boolean]((Get-CimInstance -Class Win32_Processor | Where-Object {$_.DeviceID -eq 'CPU0'}).AddressWidth -eq 64))
    $variables.Add('envOSArchitecture', [string]$(if ($variables.Is64Bit) {'64-bit'} else {'32-bit'}))

    ## Variables: Current Process Architecture
    $variables.Add('Is64BitProcess', [boolean]([System.IntPtr]::Size -eq 8))
    $variables.Add('psArchitecture', [string]$(if ($variables.Is64BitProcess) {'x64'} else {'x86'}))

    ## Variables: Get Normalized ProgramFiles and CommonProgramFiles Paths
    if ($variables.Is64Bit)
    {
        if ($variables.Is64BitProcess)
        {
            $variables.Add('envProgramFiles', [string][System.Environment]::GetFolderPath('ProgramFiles'))
            $variables.Add('envCommonProgramFiles', [string][System.Environment]::GetFolderPath('CommonProgramFiles'))
        }
        else
        {
            $variables.Add('envProgramFiles', [string][System.Environment]::GetEnvironmentVariable('ProgramW6432'))
            $variables.Add('envCommonProgramFiles', [string][System.Environment]::GetEnvironmentVariable('CommonProgramW6432'))
        }

        ## Powershell 2 doesn't support X86 folders so need to use variables instead
        try
        {
            $variables.Add('envProgramFilesX86', [string][System.Environment]::GetFolderPath('ProgramFilesX86'))
            $variables.Add('envCommonProgramFilesX86', [string][System.Environment]::GetFolderPath('CommonProgramFilesX86'))
        }
        catch
        {
            $variables.Add('envProgramFilesX86', [string][System.Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))
            $variables.Add('envCommonProgramFilesX86', [string][System.Environment]::GetEnvironmentVariable('CommonProgramFiles(x86)'))
        }
    }
    else
    {
        $variables.Add('envProgramFiles', [string][Environment]::GetFolderPath('ProgramFiles'))
        $variables.Add('envProgramFilesX86', [System.String]::Empty)
        $variables.Add('envCommonProgramFiles', [string][Environment]::GetFolderPath('CommonProgramFiles'))
        $variables.Add('envCommonProgramFilesX86', [System.String]::Empty)
    }

    ## Variables: Office C2R version, bitness and channel
    $variables.Add('envOfficeVars', [psobject](Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Ignore))
    $variables.Add('envOfficeVersion', [string]$(if ($variables.envOfficeVars | Select-Object -ExpandProperty VersionToReport -ErrorAction Ignore) {$variables.envOfficeVars.VersionToReport}))
    $variables.Add('envOfficeBitness', [string]$(if ($variables.envOfficeVars | Select-Object -ExpandProperty Platform -ErrorAction Ignore) {$variables.envOfficeVars.Platform}))

    # Channel needs special handling for group policy values.
    $officeChannelProperty = if ($variables.envOfficeVars | Select-Object -ExpandProperty UpdateChannel -ErrorAction Ignore)
    {
        $variables.envOfficeVars.UpdateChannel
    }
    elseif ($variables.envOfficeVars | Select-Object -ExpandProperty CDNBaseURL -ErrorAction SilentlyContinue)
    {
        $variables.envOfficeVars.CDNBaseURL
    }
    $variables.Add('envOfficeChannel', [string]$(switch -regex ($officeChannelProperty)
    {
        "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" {"monthly"}
        "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" {"semi-annual"}
        "64256afe-f5d9-4f86-8936-8840a6a4f5be" {"monthly targeted"}
        "b8f9b850-328d-4355-9145-c59439a0c4cf" {"semi-annual targeted"}
        "55336b82-a18d-4dd6-b5f6-9e5095c314a6" {"monthly enterprise"}
    }))

    ## Variables: Hardware
    $variables.Add('envSystemRAM', [int32](Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {[System.Math]::Round(($_.Sum / 1GB), 2)}))

    ## Variables: PowerShell And CLR (.NET) Versions
    $variables.Add('envPSVersionTable', [hashtable]$PSVersionTable)

    # PowerShell Version
    $variables.Add('envPSVersion', [string]$variables.envPSVersionTable.PSVersion.ToString())
    $variables.Add('envPSVersionMajor', [string]$variables.envPSVersionTable.PSVersion.Major)
    $variables.Add('envPSVersionMinor', [string]$variables.envPSVersionTable.PSVersion.Minor)
    $variables.Add('envPSVersionBuild', [string]$variables.envPSVersionTable.PSVersion.Build)
    $variables.Add('envPSVersionRevision', [string]$variables.envPSVersionTable.PSVersion.Revision)

    # CLR (.NET) Version used by Windows PowerShell
    if ($variables.envPSVersionTable.ContainsKey('CLRVersion'))
    {
        $variables.Add('envCLRVersion', [string]$variables.envPSVersionTable.CLRVersion.ToString())
        $variables.Add('envCLRVersionMajor', [string]$variables.envPSVersionTable.CLRVersion.Major)
        $variables.Add('envCLRVersionMinor', [string]$variables.envPSVersionTable.CLRVersion.Minor)
        $variables.Add('envCLRVersionBuild', [string]$variables.envPSVersionTable.CLRVersion.Build)
        $variables.Add('envCLRVersionRevision', [string]$variables.envPSVersionTable.CLRVersion.Revision)
    }
    else
    {
        $variables.Add('envCLRVersion', [System.String]::Empty)
        $variables.Add('envCLRVersionMajor', [System.String]::Empty)
        $variables.Add('envCLRVersionMinor', [System.String]::Empty)
        $variables.Add('envCLRVersionBuild', [System.String]::Empty)
        $variables.Add('envCLRVersionRevision', [System.String]::Empty)
    }

    ## Variables: Permissions/Accounts
    $variables.Add('CurrentProcessToken', [System.Security.Principal.WindowsIdentity]::GetCurrent())
    $variables.Add('CurrentProcessSID', [System.Security.Principal.SecurityIdentifier]$variables.CurrentProcessToken.User)
    $variables.Add('ProcessNTAccount', [string]$variables.CurrentProcessToken.Name)
    $variables.Add('ProcessNTAccountSID', [string]$variables.CurrentProcessSID.Value)
    $variables.Add('IsAdmin', [boolean]($variables.CurrentProcessToken.Groups -contains [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'))
    $variables.Add('IsLocalSystemAccount', [boolean]$variables.CurrentProcessSID.IsWellKnown([System.Security.Principal.WellKnownSidType]'LocalSystemSid'))
    $variables.Add('IsLocalServiceAccount', [boolean]$variables.CurrentProcessSID.IsWellKnown([System.Security.Principal.WellKnownSidType]'LocalServiceSid'))
    $variables.Add('IsNetworkServiceAccount', [boolean]$variables.CurrentProcessSID.IsWellKnown([System.Security.Principal.WellKnownSidType]'NetworkServiceSid'))
    $variables.Add('IsServiceAccount', [boolean]($variables.CurrentProcessToken.Groups -contains [System.Security.Principal.SecurityIdentifier]'S-1-5-6'))
    $variables.Add('IsProcessUserInteractive', [boolean][System.Environment]::UserInteractive)
    $variables.Add('LocalSystemNTAccount', [string](Get-SidTypeAccountName -WellKnownSidType LocalSystemSid))
    $variables.Add('LocalUsersGroup', [string](Get-SidTypeAccountName -WellKnownSidType BuiltinUsersSid))
    $variables.Add('LocalPowerUsersGroup', [string](Get-SidTypeAccountName -WellKnownSidType BuiltinPowerUsersSid -ErrorAction Ignore))
    $variables.Add('LocalAdministratorsGroup', [string](Get-SidTypeAccountName -WellKnownSidType BuiltinAdministratorsSid))
    $variables.Add('SessionZero', [boolean]($variables.IsLocalSystemAccount -or $variables.IsLocalServiceAccount -or $variables.IsNetworkServiceAccount -or $variables.IsServiceAccount))

    ## Variables: Logged on user information
    $variables.Add('LoggedOnUserSessions', [PSADT.QueryUser]::GetUserSessionInfo($env:ComputerName))
    $variables.Add('usersLoggedOn', [string[]]($variables.LoggedOnUserSessions | ForEach-Object {$_.NTAccount}))
    $variables.Add('CurrentLoggedOnUserSession', [psobject]($variables.LoggedOnUserSessions | Where-Object {$_.IsCurrentSession}))
    $variables.Add('CurrentConsoleUserSession', [psobject]($variables.LoggedOnUserSessions | Where-Object {$_.IsConsoleSession}))
    $variables.Add('RunAsActiveUser', [psobject]$(if ($variables.usersLoggedOn)
    {
        # Determine the account that will be used to execute commands in the user session when toolkit is running under the SYSTEM account
        # If a console user exists, then that will be the active user session.
        # If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user.
        if ($IsMultiSessionOS)
        {
            $variables.LoggedOnUserSessions | Where-Object {$_.IsCurrentSession}
        }
        else
        {
            $variables.LoggedOnUserSessions | Where-Object {$_.IsActiveUserSession}
        }
    }))

    ## Variables: Priary user language
    $variables.Add('HKUPrimaryLanguageShort', [string]$(if ($RunAsActiveUser)
    {
        # Read language defined by Group Policy
        if (!([string[]]$HKULanguages = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MUI\Settings' -ErrorAction Ignore | Select-Object -ExpandProperty PreferredUILanguages -ErrorAction Ignore))
        {
            [string[]]$HKULanguages = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser.SID)\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction Ignore | Select-Object -ExpandProperty PreferredUILanguages -ErrorAction Ignore
        }

        # Read language for Win Vista & higher machines
        if (!$HKULanguages)
        {
            [string[]]$HKULanguages = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser.SID)\Control Panel\Desktop" -ErrorAction Ignore | Select-Object -ExpandProperty PreferredUILanguages -ErrorAction Ignore
        }
        if (!$HKULanguages)
        {
            [string[]]$HKULanguages = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser.SID)\Control Panel\Desktop\MuiCached" -ErrorAction Ignore | Select-Object -ExpandProperty MachinePreferredUILanguages -ErrorAction Ignore
        }
        if (!$HKULanguages)
        {
            [string[]]$HKULanguages = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser.SID)\Control Panel\International" -ErrorAction Ignore | Select-Object -ExpandProperty LocaleName -ErrorAction Ignore
        }

        # Read language for Win XP machines
        if (!$HKULanguages -and ($HKULocale = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser.SID)\Control Panel\International" -ErrorAction Ignore | Select-Object -ExpandProperty Locale -ErrorAction Ignore))
        {
            [string[]]$HKULanguages = ([Globalization.CultureInfo]([System.Convert]::ToInt32('0x' + $HKULocale, 16))).Name
        }

        # Determine the language if we found anything of use.
        if ($HKULanguages)
        {
            [cultureinfo]$PrimaryWindowsUILanguage = $HKULanguages[0]
            [string]$HKUPrimaryLanguageShort = $PrimaryWindowsUILanguage.TwoLetterISOLanguageName.ToUpper()

            #  If the detected language is Chinese, determine if it is simplified or traditional Chinese
            if ($HKUPrimaryLanguageShort -eq 'ZH')
            {
                if ($PrimaryWindowsUILanguage.EnglishName -match 'Simplified')
                {
                    [string]$HKUPrimaryLanguageShort = 'ZH-Hans'
                }
                if ($PrimaryWindowsUILanguage.EnglishName -match 'Traditional')
                {
                    [string]$HKUPrimaryLanguageShort = 'ZH-Hant'
                }
            }

            #  If the detected language is Portuguese, determine if it is Brazilian Portuguese
            if ($HKUPrimaryLanguageShort -eq 'PT')
            {
                if ($PrimaryWindowsUILanguage.ThreeLetterWindowsLanguageName -eq 'PTB')
                {
                    [string]$HKUPrimaryLanguageShort = 'PT-BR'
                }
            }

            if (![System.String]::IsNullOrWhiteSpace($HKUPrimaryLanguageShort))
            {
                $HKUPrimaryLanguageShort
            }
        }
    }))

    ## Variables: Executables
    $variables.Add('exeWusa', [string]"$($variables.envWinDir)\System32\wusa.exe") # Installs Standalone Windows Updates
    $variables.Add('exeMsiexec', [string]"$($variables.envWinDir)\System32\msiexec.exe") # Installs MSI Installers
    $variables.Add('exeSchTasks', [string]"$($variables.envWinDir)\System32\schtasks.exe") # Manages Scheduled Tasks

    ## Variables: RegEx Patterns
    $variables.Add('MSIProductCodeRegExPattern', [string]'^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$')

    ## Variables: Invalid FileName Characters
    $variables.Add('invalidFileNameChars', [char[]][System.IO.Path]::GetInvalidFileNameChars())

    ## Variables: Registry Keys
    # Registry keys for native and WOW64 applications
    $variables.Add('regKeyApplications', [string[]]('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'))
    $variables.Add('regKeyLotusNotes', [string]"Registry::HKEY_LOCAL_MACHINE\SOFTWARE\$(if ($variables.Is64Bit) {'Wow6432Node\'})Lotus\Notes")
    $variables.Add('regKeyAppExecution', [string]'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')

    ## Variables: User Temp Path. When running in system context we can derive the native "C:\Users" base path from the Public environment variable.
    $variables.Add('loggedOnUserTempPath', [string]$(if (($null -ne $variables.RunAsActiveUser.NTAccount) -and [System.IO.Directory]::Exists(($runasUserProfile = "$(Split-Path -LiteralPath $variables.envPublic)\$($variables.RunAsActiveUser.UserName)")))
    {
        [System.IO.Directory]::CreateDirectory($runasUserProfile).FullName
    }
    else
    {
        "$dirAppDeployTemp\ExecuteAsUser"
    }))

    ## Variables: System DPI Scale Factor (Requires PSADT.UiAutomation loaded)
    [System.Drawing.Graphics]$GraphicsObject = $null
    [System.IntPtr]$DeviceContextHandle = [IntPtr]::Zero
    $variables.Add('UserDisplayScaleFactor', [boolean]$false)
    $variables.Add('dpiScale', [int32]0)
    $variables.Add('dpiPixels', [int32]0)

    # If a user is logged on, then get display scale factor for logged on user (even if running in session 0).
    try
    {
        # Get Graphics Object from the current Window Handle.
        [System.Drawing.Graphics]$GraphicsObject = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)

        # Get Device Context Handle.
        [IntPtr]$DeviceContextHandle = $GraphicsObject.GetHdc()

        # Get Logical and Physical screen height.
        [int32]$LogicalScreenHeight = [PSADT.UiAutomation]::GetDeviceCaps($DeviceContextHandle, [int32][PSADT.UiAutomation+DeviceCap]::VERTRES)
        [int32]$PhysicalScreenHeight = [PSADT.UiAutomation]::GetDeviceCaps($DeviceContextHandle, [int32][PSADT.UiAutomation+DeviceCap]::DESKTOPVERTRES)

        # Calculate DPI scale and pixels.
        $variables.dpiScale = [System.Math]::Round([double]$PhysicalScreenHeight / [double]$LogicalScreenHeight, 2) * 100
        $variables.dpiPixels = [System.Math]::Round(($variables.dpiScale / 100) * 96, 0)
    }
    catch
    {
        $variables.dpiScale = 0
        $variables.dpiPixels = 0
    }
    finally
    {
        # Release the device context handle and dispose of the graphics object.
        if ($null -ne $GraphicsObject)
        {
            if ($DeviceContextHandle -ne [IntPtr]::Zero)
            {
                $GraphicsObject.ReleaseHdc($DeviceContextHandle)
            }
            $GraphicsObject.Dispose()
        }
    }

    # Failed to get dpi, try to read them from registry - Might not be accurate.
    if ($variables.RunAsActiveUser)
    {
        if ($variables.dpiPixels -lt 1)
        {
            $variables.dpiPixels = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser)\Control Panel\Desktop\WindowMetrics" -ErrorAction Ignore | Select-Object -ExpandProperty AppliedDPI -ErrorAction Ignore
        }
        if ($variables.dpiPixels -lt 1)
        {
            $variables.dpiPixels = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$($variables.RunAsActiveUser)\Control Panel\Desktop" -ErrorAction Ignore | Select-Object -ExpandProperty LogPixels -ErrorAction Ignore
        }
        $variables.UserDisplayScaleFactor = $true
    }

    # Failed to get dpi from first two registry entries, try to read FontDPI - Usually inaccurate.
    if ($variables.dpiPixels -lt 1)
    {
        #  This registry setting only exists if system scale factor has been changed at least once.
        $variables.dpiPixels = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI' -ErrorAction Ignore | Select-Object -ExpandProperty LogPixels -ErrorAction Ignore
        $variables.UserDisplayScaleFactor = $false
    }

    # Calculate DPI scale if its empty and we have DPI pixels.
    if (($variables.dpiScale -lt 1) -and ($variables.dpiPixels -gt 0))
    {
        $variables.dpiScale = [System.Math]::Round(($variables.dpiPixels * 100) / 96)
    }

    # Store variables within the module's scope.
    $Script:StateMgmt.Variables = $variables
}

function Import-PsadtVariables
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCmdlet]$Cmdlet,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force
    )

    # Initialise variables.
    Initialize-PsadtVariableDatabase -Force:$Force

    # Create variables within the provided session.
    if (!$Script:StateMgmt.DotSourced)
    {
        $ExecutionContext.InvokeCommand.InvokeScript(
            $Cmdlet.SessionState,
            {$args[0].GetEnumerator().ForEach({New-Variable -Name $_.Name -Value $_.Value -Force})}.Ast.GetScriptBlock(),
            $Script:StateMgmt.Variables
        )
    }
    else
    {
        # When dot-sourcing during the v4.0 transition, just pump variables into the scope above.
        $Script:StateMgmt.Variables.GetEnumerator().ForEach({New-Variable -Name $_.Name -Value $_.Value -Scope 1 -Force})
    }
}

filter Convert-PsadtConfigToObjects
{
    if ($null -eq $_)
    {
        # Just return for null objects.
        return
    }
    elseif ($_ -is [System.String])
    {
        # Because XML sucks and everything's a string, we need to process the value.
        # Before doing so, expand any variables. We don't know what the caller's doing here.
        if ([System.String]::IsNullOrWhiteSpace(($str = $ExecutionContext.InvokeCommand.ExpandString($_.Trim()))))
        {
            # String was empty, just return.
            return
        }
        elseif ([System.UInt32]::TryParse($str, [ref]$null))
        {
            # String is an unsigned int, convert it.
            return [System.UInt32]::Parse($str)
        }
        elseif ([System.Int32]::TryParse($str, [ref]$null))
        {
            # String is an signed int, convert it.
            return [System.Int32]::Parse($str)
        }
        elseif ([System.Boolean]::TryParse($str, [ref]$null))
        {
            # String is a bool, convert it.
            return [System.Boolean]::Parse($str)
        }
        else
        {
            # String is just a string. Split, trim, join, then return it.
            return [System.String]::Join("`n", $str.Split("`n").Trim())
        }
    }
    else
    {
        # We've got an XML element to process.
        # Open up a hashtable for returning at the end.
        $obj = [ordered]@{}

        # Recursively process each property.
        foreach ($property in ($_ | Get-Member -MemberType Property).Name.Where({!$_.Equals('#comment')}))
        {
            if ($null -ne ($_.$property))
            {
                $obj.Add($property, ($_.$property | Convert-PsadtConfigToObjects))
            }
        }

        # Return the object if it's not empty.
        if ($obj.Count)
        {
            return [pscustomobject]$obj
        }
    }
}

function Get-PsadtUiLanguage
{
    # If an override has been configured, return it immediately.
    if ($Script:StateMgmt.Config.UI_Options.InstallationUI_LanguageOverride)
    {
        return "UI_Messages_$($Script:StateMgmt.Config.UI_Options.InstallationUI_LanguageOverride)"
    }

    # Get the logged on user's language value, otherwise fall back to PowerShell's
    $langId = if ($Script:StateMgmt.Variables.HKUPrimaryLanguageShort)
    {
        $HKUPrimaryLanguageShort
    }
    else
    {
        $currentLanguage
    }

    # Default to English if the detected UI language is not available in the XML config file
    if (!$Script:StateMgmt.Config.PSObject.Properties.Name.Contains("UI_Messages_$langId"))
    {
        return 'EN'
    }
    return $langId
}

function Import-PsadtConfig
{
    param (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force
    )

    # We need the PSADT variables within this function's scope
    # so we can expand variables when we convert the XML data.
    if (!$Script:DotSourced)
    {
        # Return early if we've already initialised and we're not re-initing.
        if ($Script:StateMgmt.Config -and $Script:StateMgmt.UI -and $Script:StateMgmt.Sessions -and $Script:StateMgmt.Sessions.Count -and !$Force)
        {
            return
        }
        Import-PsadtVariables -Cmdlet $PSCmdlet -Force:$Force
    }

    # Load in the XML file, doing it correctly and not with a simple cast.
    $xml = [System.Xml.XmlDocument]::new()
    $xml.Load([System.Xml.XmlReader]::Create($appDeployConfigFile))
    
    # Store config and UI within the module's scope.
    $Script:StateMgmt.Config = ($xml | Convert-PsadtConfigToObjects).AppDeployToolkit_Config
    $Script:StateMgmt.UI = $Script:StateMgmt.Config."UI_Messages_$(Get-PsadtUiLanguage)"

    # Process logo files.
    $Script:StateMgmt.Config.BannerIcon_Options.Icon_Filename = (Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $Script:StateMgmt.Config.BannerIcon_Options.Icon_Filename)).FullName
    $Script:StateMgmt.Config.BannerIcon_Options.LogoImage_Filename = (Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $Script:StateMgmt.Config.BannerIcon_Options.LogoImage_Filename)).FullName
    $Script:StateMgmt.Config.BannerIcon_Options.Banner_Filename = (Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $Script:StateMgmt.Config.BannerIcon_Options.Banner_Filename)).FullName

    #  Check that dependency files are present
    if (![System.IO.File]::Exists($Script:StateMgmt.Config.BannerIcon_Options.Icon_Filename))
    {
        throw 'App Deploy logo icon file not found.'
    }
    if (![System.IO.File]::Exists($Script:StateMgmt.Config.BannerIcon_Options.Banner_Filename))
    {
        throw 'App Deploy logo banner file not found.'
    }

    # Change paths to user accessible ones if user isn't an admin.
    if (!$Script:StateMgmt.Variables.IsAdmin)
    {
        if ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_TempPathNoAdminRights)
        {
            $Script:StateMgmt.Config.Toolkit_Options.Toolkit_TempPath = $Script:StateMgmt.Config.Toolkit_Options.Toolkit_TempPathNoAdminRights
        }
        if ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_RegPathNoAdminRights)
        {
            $Script:StateMgmt.Config.Toolkit_Options.Toolkit_RegPath = $Script:StateMgmt.Config.Toolkit_Options.Toolkit_RegPathNoAdminRights
        }
        if ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_LogPathNoAdminRights)
        {
            $Script:StateMgmt.Config.Toolkit_Options.Toolkit_LogPath = $Script:StateMgmt.Config.Toolkit_Options.Toolkit_LogPathNoAdminRights
        }
        if ($Script:StateMgmt.Config.MSI_Options.MSI_LogPathNoAdminRights)
        {
            $Script:StateMgmt.Config.MSI_Options.MSI_LogPath = $Script:StateMgmt.Config.MSI_Options.MSI_LogPathNoAdminRights
        }
    }
}

Import-PsadtVariables -Cmdlet $PSCmdlet
Import-PsadtConfig

## Variables: Script Info
[Hashtable]$appDeployMainScriptParameters = $PSBoundParameters

## Variables: Datetime
[DateTime]$currentDateTime = Get-Date
[String]$currentTime = Get-Date -Date $currentDateTime -UFormat '%T'
[String]$currentDate = Get-Date -Date $currentDateTime -UFormat '%d-%m-%Y'
[Timespan]$currentTimeZoneBias = [TimeZone]::CurrentTimeZone.GetUtcOffset($currentDateTime)

## Variables: Script Name and Script Paths
[String]$scriptPath = $MyInvocation.MyCommand.Definition
[String]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[String]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[String]$scriptRoot = Split-Path -Path $scriptPath -Parent
[String]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($invokingScript) {
    #  If this script was invoked by another script
    [String]$scriptParentPath = Split-Path -Path $invokingScript -Parent
}
Else {
    #  If this script was not invoked by another script, fall back to the directory one level above this script
    [String]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
}

## Variables: App Deploy Script Dependency Files
[String]$appDeployRunHiddenVbsFile = Join-Path -Path $scriptRoot -ChildPath 'RunHidden.vbs'

#  App Deploy Optional Extensions File
[String]$appDeployToolkitDotSourceExtensions = 'AppDeployToolkitExtensions.ps1'

## Variables: Script Directories
[String]$dirFiles = Join-Path -Path $scriptParentPath -ChildPath 'Files'
[String]$dirSupportFiles = Join-Path -Path $scriptParentPath -ChildPath 'SupportFiles'
[String]$dirAppDeployTemp = Join-Path -Path $Script:StateMgmt.Config.Toolkit_Options.Toolkit_TempPath -ChildPath $appDeployToolkitName

If (-not (Test-Path -LiteralPath $dirAppDeployTemp -PathType 'Container' -ErrorAction 'SilentlyContinue')) {
    $null = New-Item -Path $dirAppDeployTemp -ItemType 'Directory' -Force -ErrorAction 'SilentlyContinue'
}

## Set the deploy mode to "Interactive" if it has not been specified
If (!(Test-Path -LiteralPath 'variable:deployMode')) {
    [String]$deployMode = 'Interactive'
}

## Set the deployment type to "Install" if it has not been specified
If (!(Test-Path -LiteralPath 'variable:deploymentType')) {
    [String]$deploymentType = 'Install'
}

## Ensure the deployment type is always title-case for log aesthetics.
$deploymentType = $culture.TextInfo.ToTitleCase($deploymentType)

## COM Objects: Initialize
[__ComObject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'SilentlyContinue'
[__ComObject]$ShellApp = New-Object -ComObject 'Shell.Application' -ErrorAction 'SilentlyContinue'

## Variables: Reset/Remove Variables
[String]$installPhase = 'Initialization'
[String]$logName = [System.String]::Empty
[String]$defaultMsiExecutablesList = [System.String]::Empty
[String]$oldPSWindowTitle = $Host.UI.RawUI.WindowTitle
[Boolean]$instProgressRunning = $false
[Boolean]$useDefaultMsi = $false
[Boolean]$msiRebootDetected = $false
[Boolean]$BlockExecution = $false
[Boolean]$installationStarted = $false
[Boolean]$runningTaskSequence = $false
[Boolean]$LogFileInitialized = $false
If (Test-Path -LiteralPath 'variable:welcomeTimer') {
    Remove-Variable -Name 'welcomeTimer' -Scope 'Script'
}
#  Reset the deferral history
If (Test-Path -LiteralPath 'variable:deferHistory') {
    Remove-Variable -Name 'deferHistory'
}
If (Test-Path -LiteralPath 'variable:deferTimes') {
    Remove-Variable -Name 'deferTimes'
}
If (Test-Path -LiteralPath 'variable:deferDays') {
    Remove-Variable -Name 'deferDays'
}

## Variables: Resolve Parameters. For use in a pipeline
filter Resolve-Parameters {
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]$Parameter
    )

    Switch ($Parameter) {
        {$_.Value -is [System.Management.Automation.SwitchParameter]} {
            "-$($_.Key):`$$($_.Value.ToString().ToLower())"
            break
        }
        {$_.Value -is [System.Boolean]} {
            "-$($_.Key):`$$($_.Value.ToString().ToLower())"
            break
        }
        {$_.Value -is [System.Int16]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Int32]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Int64]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.UInt16]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.UInt32]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.UInt64]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Single]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Double]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Decimal]} {
            "-$($_.Key):$($_.Value)"
            break
        }
        {$_.Value -is [System.Collections.IDictionary]} {
            "-$($_.Key):'$(($_.Value.GetEnumerator() | Resolve-Parameters).Replace("'",'"') -join "', '")'"
            break
        }
        {$_.Value -is [System.Collections.IEnumerable]} {
            "-$($_.Key):'$($_.Value -join "', '")'"
            break
        }
        default {
            "-$($_.Key):'$($_.Value)'"
            break
        }
    }
}
#endregion
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================
#region ScriptBody

## If the script was invoked by the Help Console, exit the script now
If ($invokingScript) {
    If ((Split-Path -Path $invokingScript -Leaf) -eq 'AppDeployToolkitHelp.ps1') {
        Return
    }
}

## Set process as DPI-aware for better dialog rendering.
[System.Void][PSADT.UiAutomation]::SetProcessDPIAware()

## Define ScriptBlocks to disable/revert script logging
[ScriptBlock]$DisableScriptLogging = { $OldDisableLoggingValue = $DisableLogging ; $DisableLogging = $true }
[ScriptBlock]$RevertScriptLogging = { $DisableLogging = $OldDisableLoggingValue }

## Disable logging until log file details are available
. $DisableScriptLogging

## Assemblies: Load
Try {
    Add-Type -AssemblyName ('System.Drawing', 'System.Windows.Forms', 'PresentationFramework', 'Microsoft.VisualBasic', 'PresentationCore', 'WindowsBase') -ErrorAction 'Stop'
}
Catch {
    Write-Log -Message "Failed to load assembly. `r`n$(Resolve-Error)" -Severity 3 -Source $appDeployToolkitName
    If ($deployMode -eq 'Silent') {
        Write-Log -Message "Continue despite assembly load error since deployment mode is [$deployMode]." -Source $appDeployToolkitName
    }
    Else {
        Exit-Script -ExitCode 60004
    }
}

## Dot Source script extensions
If (Test-Path -LiteralPath "$scriptRoot\$appDeployToolkitDotSourceExtensions" -PathType 'Leaf') {
    . "$scriptRoot\$appDeployToolkitDotSourceExtensions"
}

## If the default Deploy-Application.ps1 hasn't been modified, and the main script was not called by a referring script, check for MSI / MST and modify the install accordingly
If ((-not $ReferredInstallName) -and (!(Test-Path -LiteralPath 'variable:appName') -or [System.String]::IsNullOrWhiteSpace($appName))) {
    # Build properly formatted Architecture String
    Switch ($Is64Bit) {
        $false {
            $formattedOSArch = 'x86'
        }
        $true {
            $formattedOSArch = 'x64'
        }
    }
    #  Find the first MSI file in the Files folder and use that as our install
    If ([String]$defaultMsiFile = (Get-ChildItem -LiteralPath $dirFiles -ErrorAction 'SilentlyContinue' | Where-Object { (-not $_.PsIsContainer) -and ([IO.Path]::GetExtension($_.Name) -eq '.msi') -and ($_.Name.EndsWith(".$formattedOSArch.msi")) } | Select-Object -ExpandProperty 'FullName' -First 1)) {
        Write-Log -Message "Discovered $formattedOSArch Zero-Config MSI under $defaultMSIFile" -Source $appDeployToolkitName
    }
    ElseIf ([String]$defaultMsiFile = (Get-ChildItem -LiteralPath $dirFiles -ErrorAction 'SilentlyContinue' | Where-Object { (-not $_.PsIsContainer) -and ([IO.Path]::GetExtension($_.Name) -eq '.msi') } | Select-Object -ExpandProperty 'FullName' -First 1)) {
        Write-Log -Message "Discovered Arch-Independent Zero-Config MSI under $defaultMSIFile" -Source $appDeployToolkitName
    }
    If ($defaultMsiFile) {
        Try {
            [Boolean]$useDefaultMsi = $true
            Write-Log -Message "Discovered Zero-Config MSI installation file [$defaultMsiFile]." -Source $appDeployToolkitName
            #  Discover if there is a zero-config MST file
            If ([System.String]::IsNullOrWhiteSpace($DefaultMstFile)) {$defaultMstFile = [IO.Path]::ChangeExtension($defaultMsiFile, 'mst')}
            If (Test-Path -LiteralPath $defaultMstFile -PathType 'Leaf') {
                Write-Log -Message "Discovered Zero-Config MST installation file [$defaultMstFile]." -Source $appDeployToolkitName
            }
            Else {
                [String]$defaultMstFile = ''
            }
            #  Discover if there are zero-config MSP files. Name multiple MSP files in alphabetical order to control order in which they are installed.
            If (!$defaultMspFiles -and ($mspFiles = Get-ChildItem -LiteralPath $dirFiles -ErrorAction 'SilentlyContinue' | Where-Object { (-not $_.PsIsContainer) -and ([IO.Path]::GetExtension($_.Name) -eq '.msp') } | Select-Object -ExpandProperty 'FullName')) {$defaultMspFiles = $mspFiles}
            If ($defaultMspFiles) {
                Write-Log -Message "Discovered Zero-Config MSP installation file(s) [$($defaultMspFiles -join ',')]." -Source $appDeployToolkitName
            }

            ## Read the MSI and get the installation details
            [Hashtable]$GetDefaultMsiTablePropertySplat = @{ Path = $defaultMsiFile; Table = 'Property'; ContinueOnError = $false; ErrorAction = 'Stop' }
            If ($defaultMstFile) {
                $GetDefaultMsiTablePropertySplat.Add('TransformPath', $defaultMstFile)
            }
            [PSObject]$defaultMsiPropertyList = Get-MsiTableProperty @GetDefaultMsiTablePropertySplat
            [String]$appVendor = $defaultMsiPropertyList.Manufacturer
            [String]$appName = $defaultMsiPropertyList.ProductName
            [String]$appVersion = $defaultMsiPropertyList.ProductVersion
            $GetDefaultMsiTablePropertySplat.Set_Item('Table', 'File')
            [PSObject]$defaultMsiFileList = Get-MsiTableProperty @GetDefaultMsiTablePropertySplat
            [String[]]$defaultMsiExecutables = Get-Member -InputObject $defaultMsiFileList -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Name' -ErrorAction 'Stop' | Where-Object { [IO.Path]::GetExtension($_) -eq '.exe' } | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) }
            [String]$defaultMsiExecutablesList = $defaultMsiExecutables -join ','
            Write-Log -Message "App Vendor [$appVendor]." -Source $appDeployToolkitName
            Write-Log -Message "App Name [$appName]." -Source $appDeployToolkitName
            Write-Log -Message "App Version [$appVersion]." -Source $appDeployToolkitName
            If ($defaultMsiExecutablesList) {Write-Log -Message "MSI Executable List [$defaultMsiExecutablesList]." -Source $appDeployToolkitName}
        }
        Catch {
            Write-Log -Message "Failed to process Zero-Config MSI Deployment. `r`n$(Resolve-Error)" -Source $appDeployToolkitName
            $useDefaultMsi = $false ; $appVendor = '' ; $appName = '' ; $appVersion = ''
        }
    }
}

## Set up sample variables if Dot Sourcing the script, app details have not been specified
If (!(Test-Path -LiteralPath 'variable:appName') -or [System.String]::IsNullOrWhiteSpace($appName)) {
    [String]$appName = $appDeployMainScriptFriendlyName
    If (!(Test-Path -LiteralPath 'variable:appVendor') -or [System.String]::IsNullOrWhiteSpace($appVendor)) {
        [String]$appVendor = 'PS'
    }
    If (!(Test-Path -LiteralPath 'variable:appVersion') -or [System.String]::IsNullOrWhiteSpace($appVersion)) {
        [String]$appVersion = $appDeployMainScriptVersion
    }
    If (!(Test-Path -LiteralPath 'variable:appLang') -or [System.String]::IsNullOrWhiteSpace($appLang)) {
        [String]$appLang = $currentLanguage
    }
    If (!(Test-Path -LiteralPath 'variable:appRevision') -or [System.String]::IsNullOrWhiteSpace($appRevision)) {
        [String]$appRevision = '01'
    }
    If (!(Test-Path -LiteralPath 'variable:appArch') -or [System.String]::IsNullOrWhiteSpace($appArch)) {
        [String]$appArch = ''
    }
}
Else {
    If (!(Test-Path -LiteralPath 'variable:appVendor') -or [System.String]::IsNullOrWhiteSpace($appVendor)) {
        [String]$appVendor = ''
    }
    If (!(Test-Path -LiteralPath 'variable:appVersion') -or [System.String]::IsNullOrWhiteSpace($appVersion)) {
        [String]$appVersion = ''
    }
    If (!(Test-Path -LiteralPath 'variable:appLang') -or [System.String]::IsNullOrWhiteSpace($appLang)) {
        [String]$appLang = ''
    }
    If (!(Test-Path -LiteralPath 'variable:appRevision') -or [System.String]::IsNullOrWhiteSpace($appRevision)) {
        [String]$appRevision = ''
    }
    If (!(Test-Path -LiteralPath 'variable:appArch') -or [System.String]::IsNullOrWhiteSpace($appArch)) {
        [String]$appArch = ''
    }
}

## Sanitize the application details, as they can cause issues in the script
[String]$appVendor = (Remove-InvalidFileNameChars -Name ($appVendor.Trim()))
[String]$appName = (Remove-InvalidFileNameChars -Name ($appName.Trim()))
[String]$appVersion = (Remove-InvalidFileNameChars -Name ($appVersion.Trim()))
[String]$appArch = (Remove-InvalidFileNameChars -Name ($appArch.Trim()))
[String]$appLang = (Remove-InvalidFileNameChars -Name ($appLang.Trim()))
[String]$appRevision = (Remove-InvalidFileNameChars -Name ($appRevision.Trim()))

## Build the Installation Title
If ($ReferredInstallTitle) {
    [String]$installTitle = (Remove-InvalidFileNameChars -Name ($ReferredInstallTitle.Trim()))
}
If (-not $installTitle) {
    [String]$installTitle = "$appVendor $appName $appVersion".Trim()
}

## Set Powershell window title, in case the window is visible
$Host.UI.RawUI.WindowTitle = "$installTitle - $DeploymentType" -replace '\s{2,}',' '

## Build the Installation Name
If ($ReferredInstallName) {
    [String]$installName = (Remove-InvalidFileNameChars -Name $ReferredInstallName)
}
If (-not $installName) {
    If ($appArch) {
        [String]$installName = $appVendor + '_' + $appName + '_' + $appVersion + '_' + $appArch + '_' + $appLang + '_' + $appRevision
    }
    Else {
        [String]$installName = $appVendor + '_' + $appName + '_' + $appVersion + '_' + $appLang + '_' + $appRevision
    }
}
[String]$installName = (($installName -replace ' ', '').Trim('_') -replace '[_]+', '_')

## Set the Defer History registry path
[String]$regKeyDeferHistory = "$Script:StateMgmt.Config.Toolkit_Options.Toolkit_RegPath\$appDeployToolkitName\DeferHistory\$installName"

## Variables: Log Files
If ($ReferredLogName) {
    [String]$logName = $ReferredLogName
}
If (-not $logName) {
    [String]$logName = $installName + '_' + $appDeployToolkitName + '_' + $deploymentType + '.log'
}
#  If option to compress logs is selected, then log will be created in temp log folder ($logTempFolder) and then copied to actual log folder ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_LogPath) after being zipped.
[String]$logTempFolder = Join-Path -Path $envTemp -ChildPath "${installName}_$deploymentType"
If ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_CompressLogs) {
    #  If the temp log folder already exists from a previous ZIP operation, then delete all files in it to avoid issues
    If (Test-Path -LiteralPath $logTempFolder -PathType 'Container' -ErrorAction 'SilentlyContinue') {
        $null = Remove-Item -LiteralPath $logTempFolder -Recurse -Force -ErrorAction 'SilentlyContinue'
    }
}

## Revert script logging to original setting
. $RevertScriptLogging

## Initialize Logging
$scriptSeparator = '*' * 79
Write-Log -Message ($scriptSeparator, $scriptSeparator) -Source $appDeployToolkitName
Write-Log -Message "[$installName] setup started." -Source $appDeployToolkitName

# Calculate banner height
[Int32]$appDeployLogoBannerHeight = 0
Try {
    [System.Drawing.Bitmap]$appDeployLogoBannerObject = New-Object -TypeName 'System.Drawing.Bitmap' -ArgumentList ($appDeployLogoBanner)
    [Int32]$appDeployLogoBannerHeight = [System.Math]::Ceiling(450 * ($appDeployLogoBannerObject.Height/$appDeployLogoBannerObject.Width))
    If ($appDeployLogoBannerHeight -gt $Script:StateMgmt.Config.BannerIcon_Options.Banner_MaxHeight) {
        $appDeployLogoBannerHeight = $Script:StateMgmt.Config.BannerIcon_Options.Banner_MaxHeight
    }
    $appDeployLogoBannerObject.Dispose() # Must dispose() when installing from local cache or else AppDeployToolkitBanner.png is locked and cannot be removed
}
Catch {
}

## Get the default font to use in the user interface
[System.Drawing.Font]$defaultFont = [System.Drawing.SystemFonts]::MessageBoxFont

## Check how the script was invoked
If ($invokingScript) {
    Write-Log -Message "Script [$scriptPath] dot-source invoked by [$invokingScript]" -Source $appDeployToolkitName
}
Else {
    Write-Log -Message "Script [$scriptPath] invoked directly" -Source $appDeployToolkitName
}

## Evaluate non-default parameters passed to the scripts
If (Test-Path -LiteralPath 'variable:deployAppScriptParameters') {
    [String]$deployAppScriptParameters = ($deployAppScriptParameters.GetEnumerator() | Resolve-Parameters) -join ' '
}
#  Save main script parameters hashtable for async execution of the toolkit
[Hashtable]$appDeployMainScriptAsyncParameters = $appDeployMainScriptParameters
If ($appDeployMainScriptParameters) {
    [String]$appDeployMainScriptParameters = ($appDeployMainScriptParameters.GetEnumerator() | Resolve-Parameters) -join ' '
}
If ($appDeployExtScriptParameters) {
    [String]$appDeployExtScriptParameters = ($appDeployExtScriptParameters.GetEnumerator() | Resolve-Parameters) -join ' '
}

## Check the XML config file version
If ($Script:StateMgmt.Config.Config_File.Config_Version -lt $appDeployMainScriptMinimumConfigVersion) {
    [String]$XMLConfigVersionErr = "The XML configuration file version [$($Script:StateMgmt.Config.Config_File.Config_Version)] is lower than the supported version required by the Toolkit [$appDeployMainScriptMinimumConfigVersion]. Please upgrade the configuration file."
    Write-Log -Message $XMLConfigVersionErr -Severity 3 -Source $appDeployToolkitName
    Throw $XMLConfigVersionErr
}

## Log system/script information
If ((Test-Path -LiteralPath 'variable:appScriptVersion') -and $appScriptVersion) {
    Write-Log -Message "[$installName] script version is [$appScriptVersion]" -Source $appDeployToolkitName
}
If ((Test-Path -LiteralPath 'variable:appScriptDate') -and $appScriptDate) {
    Write-Log -Message "[$installName] script date is [$appScriptDate]" -Source $appDeployToolkitName
}
If ((Test-Path -LiteralPath 'variable:appScriptAuthor') -and $appScriptAuthor) {
    Write-Log -Message "[$installName] script author is [$appScriptAuthor]" -Source $appDeployToolkitName
}
If (Test-Path -LiteralPath 'variable:deployAppScriptFriendlyName') {
    Write-Log -Message "[$deployAppScriptFriendlyName] script version is [$deployAppScriptVersion]" -Source $appDeployToolkitName
}
If (Test-Path -LiteralPath 'variable:deployAppScriptParameters') {
    Write-Log -Message "The following non-default parameters were passed to [$deployAppScriptFriendlyName]: [$deployAppScriptParameters]" -Source $appDeployToolkitName
}
If ($appDeployMainScriptFriendlyName) {
    Write-Log -Message "[$appDeployMainScriptFriendlyName] script version is [$appDeployMainScriptVersion]" -Source $appDeployToolkitName
}
If ($appDeployMainScriptParameters) {
    Write-Log -Message "The following non-default parameters were passed to [$appDeployMainScriptFriendlyName]: [$appDeployMainScriptParameters]" -Source $appDeployToolkitName
}
If ($appDeployExtScriptFriendlyName) {
    Write-Log -Message "[$appDeployExtScriptFriendlyName] version is [$appDeployExtScriptVersion]" -Source $appDeployToolkitName
}
If ($appDeployExtScriptParameters) {
    Write-Log -Message "The following non-default parameters were passed to [$appDeployExtScriptFriendlyName]: [$appDeployExtScriptParameters]" -Source $appDeployToolkitName
}
Write-Log -Message "Computer Name is [$envComputerNameFQDN]" -Source $appDeployToolkitName
Write-Log -Message "Current User is [$ProcessNTAccount]" -Source $appDeployToolkitName
If ($envOSServicePack) {
    Write-Log -Message "OS Version is [$envOSName $envOSServicePack $envOSArchitecture $envOSVersion]" -Source $appDeployToolkitName
}
Else {
    Write-Log -Message "OS Version is [$envOSName $envOSArchitecture $envOSVersion]" -Source $appDeployToolkitName
}
Write-Log -Message "OS Type is [$envOSProductTypeName]" -Source $appDeployToolkitName
Write-Log -Message "Current Culture is [$($culture.Name)], language is [$currentLanguage] and UI language is [$currentUILanguage]" -Source $appDeployToolkitName
Write-Log -Message "Hardware Platform is [$(. $DisableScriptLogging; Get-HardwarePlatform; . $RevertScriptLogging)]" -Source $appDeployToolkitName
Write-Log -Message "PowerShell Host is [$($envHost.Name)] with version [$($envHost.Version)]" -Source $appDeployToolkitName
Write-Log -Message "PowerShell Version is [$envPSVersion $psArchitecture]" -Source $appDeployToolkitName
If ($envPSVersionTable.ContainsKey('CLRVersion')) {
    Write-Log -Message "PowerShell CLR (.NET) version is [$envCLRVersion]" -Source $appDeployToolkitName
}
Write-Log -Message $scriptSeparator -Source $appDeployToolkitName

## Install required assemblies for toast notifications if conditions are right.
If (!$Script:StateMgmt.Config.Toast_Options.Toast_Disable -and $PSVersionTable.PSEdition.Equals('Core') -and !(Get-Package -Name Microsoft.Windows.SDK.NET.Ref -ErrorAction Ignore)) {
    try {
        Write-Log -Message "Installing WinRT assemblies for PowerShell 7 toast notification support. This will take at least 5 minutes, please wait..." -Source $appDeployToolkitName
        Install-Package -Name Microsoft.Windows.SDK.NET.Ref -ProviderName NuGet -Force -Confirm:$false | Out-Null
    }
    catch {
        Write-Log -Message "An error occurred while preparing WinRT assemblies for usage. Toast notifications will not be available for this execution." -Severity 2 -Source $appDeployToolkitName
    }
}

## Set the install phase to asynchronous if the script was not dot sourced, i.e. called with parameters
If ($AsyncToolkitLaunch) {
    $installPhase = 'Asynchronous'
}

## If the ShowInstallationPrompt Parameter is specified, only call that function.
If ($showInstallationPrompt) {
    Write-Log -Message "[$appDeployMainScriptFriendlyName] called with switch [-ShowInstallationPrompt]." -Source $appDeployToolkitName
    $appDeployMainScriptAsyncParameters.Remove('ShowInstallationPrompt')
    $appDeployMainScriptAsyncParameters.Remove('AsyncToolkitLaunch')
    $appDeployMainScriptAsyncParameters.Remove('ReferredInstallName')
    $appDeployMainScriptAsyncParameters.Remove('ReferredInstallTitle')
    $appDeployMainScriptAsyncParameters.Remove('ReferredLogName')
    Show-InstallationPrompt @appDeployMainScriptAsyncParameters
    Exit 0
}

## If the ShowInstallationRestartPrompt Parameter is specified, only call that function.
If ($showInstallationRestartPrompt) {
    Write-Log -Message "[$appDeployMainScriptFriendlyName] called with switch [-ShowInstallationRestartPrompt]." -Source $appDeployToolkitName
    $appDeployMainScriptAsyncParameters.Remove('ShowInstallationRestartPrompt')
    $appDeployMainScriptAsyncParameters.Remove('AsyncToolkitLaunch')
    $appDeployMainScriptAsyncParameters.Remove('ReferredInstallName')
    $appDeployMainScriptAsyncParameters.Remove('ReferredInstallTitle')
    $appDeployMainScriptAsyncParameters.Remove('ReferredLogName')
    Show-InstallationRestartPrompt @appDeployMainScriptAsyncParameters
    Exit 0
}

## If the CleanupBlockedApps Parameter is specified, only call that function.
If ($cleanupBlockedApps) {
    $deployModeSilent = $true
    Write-Log -Message "[$appDeployMainScriptFriendlyName] called with switch [-CleanupBlockedApps]." -Source $appDeployToolkitName
    Unblock-AppExecution
    Exit 0
}

## If the ShowBlockedAppDialog Parameter is specified, only call that function.
If ($showBlockedAppDialog) {
    Try {
        . $DisableScriptLogging
        Write-Log -Message "[$appDeployMainScriptFriendlyName] called with switch [-ShowBlockedAppDialog]." -Source $appDeployToolkitName
        #  Create a mutex and specify a name without acquiring a lock on the mutex
        [Boolean]$showBlockedAppDialogMutexLocked = $false
        [String]$showBlockedAppDialogMutexName = 'Global\PSADT_ShowBlockedAppDialog_Message'
        [Threading.Mutex]$showBlockedAppDialogMutex = New-Object -TypeName 'System.Threading.Mutex' -ArgumentList ($false, $showBlockedAppDialogMutexName)
        #  Attempt to acquire an exclusive lock on the mutex, attempt will fail after 1 millisecond if unable to acquire exclusive lock
        If ((Test-IsMutexAvailable -MutexName $showBlockedAppDialogMutexName -MutexWaitTimeInMilliseconds 1) -and ($showBlockedAppDialogMutex.WaitOne(1))) {
            [Boolean]$showBlockedAppDialogMutexLocked = $true
            Show-InstallationPrompt -Title $installTitle -Message $Script:UI.BlockExecution_Message -Icon 'Warning' -ButtonRightText 'OK'
            Exit 0
        }
        Else {
            #  If attempt to acquire an exclusive lock on the mutex failed, then exit script as another blocked app dialog window is already open
            Write-Log -Message "Unable to acquire an exclusive lock on mutex [$showBlockedAppDialogMutexName] because another blocked application dialog window is already open. Exiting script..." -Severity 2 -Source $appDeployToolkitName
            Exit 0
        }
    }
    Catch {
        Write-Log -Message "There was an error in displaying the Installation Prompt. `r`n$(Resolve-Error)" -Severity 3 -Source $appDeployToolkitName
        Exit 60005
    }
    Finally {
        If ($showBlockedAppDialogMutexLocked) {
            $null = $showBlockedAppDialogMutex.ReleaseMutex()
        }
        If ($showBlockedAppDialogMutex) {
            $showBlockedAppDialogMutex.Close()
        }
    }
}

## Log details for all currently logged in users
Write-Log -Message "Display session information for all logged on users: `r`n$($LoggedOnUserSessions | Format-List | Out-String)" -Source $appDeployToolkitName
If ($usersLoggedOn) {
    Write-Log -Message "The following users are logged on to the system: [$($usersLoggedOn -join ', ')]." -Source $appDeployToolkitName

    #  Check if the current process is running in the context of one of the logged in users
    If ($CurrentLoggedOnUserSession) {
        Write-Log -Message "Current process is running with user account [$ProcessNTAccount] under logged in user session for [$($CurrentLoggedOnUserSession.NTAccount)]." -Source $appDeployToolkitName
    }
    Else {
        Write-Log -Message "Current process is running under a system account [$ProcessNTAccount]." -Source $appDeployToolkitName
    }

    # Guard Intune detection code behind a variable.
    If ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_OobeDetection) {
        # Check if OOBE / ESP is running [credit Michael Niehaus]
        If (![PSADT.Utilities]::OobeCompleted()) {
            Write-Log -Message "Detected OOBE in progress, changing deployment mode to silent." -Source $appDeployToolkitExtName
            $deployMode = 'Silent'
        }

        [Int]$defenderHideSysTray = Get-RegistryKey -Key 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' -Value 'HideSystray'
        If ($defenderHideSysTray -ne "1" -and ($null -eq (Get-Process -Name SecurityHealthSystray -ErrorAction SilentlyContinue))) {
            $deployMode = 'Silent'
        }
    }

    #  Display account and session details for the account running as the console user (user with control of the physical monitor, keyboard, and mouse)
    If ($CurrentConsoleUserSession) {
        Write-Log -Message "The following user is the console user [$($CurrentConsoleUserSession.NTAccount)] (user with control of physical monitor, keyboard, and mouse)." -Source $appDeployToolkitName
    }
    Else {
        Write-Log -Message 'There is no console user logged in (user with control of physical monitor, keyboard, and mouse).' -Source $appDeployToolkitName
    }

    #  Display the account that will be used to execute commands in the user session when toolkit is running under the SYSTEM account
    If ($RunAsActiveUser) {
        Write-Log -Message "The active logged on user is [$($RunAsActiveUser.NTAccount)]." -Source $appDeployToolkitName
    }
}
Else {
    Write-Log -Message 'No users are logged on to the system.' -Source $appDeployToolkitName
}

## Log which language's UI messages are loaded from the config XML file
If ($HKUPrimaryLanguageShort) {
    Write-Log -Message "The active logged on user [$($RunAsActiveUser.NTAccount)] has a primary UI language of [$HKUPrimaryLanguageShort]." -Source $appDeployToolkitName
}
Else {
    Write-Log -Message "The current system account [$ProcessNTAccount] has a primary UI language of [$currentLanguage]." -Source $appDeployToolkitName
}
If ($Script:StateMgmt.Config.UI_Options.InstallationUI_LanguageOverride) {
    Write-Log -Message "The config XML file was configured to override the detected primary UI language with the following UI language: [$($Script:StateMgmt.Config.UI_Options.InstallationUI_LanguageOverride)]." -Source $appDeployToolkitName
}
Write-Log -Message "The following UI messages were imported from the config XML file: [$xmlUIMessageLanguage]." -Source $appDeployToolkitName

## Log system DPI scale factor of active logged on user
If ($UserDisplayScaleFactor) {
    Write-Log -Message "The active logged on user [$($RunAsActiveUser.NTAccount)] has a DPI scale factor of [$dpiScale] with DPI pixels [$dpiPixels]." -Source $appDeployToolkitName
}
Else {
    Write-Log -Message "The system has a DPI scale factor of [$dpiScale] with DPI pixels [$dpiPixels]." -Source $appDeployToolkitName
}

## Check if script is running from a SCCM Task Sequence
Try {
    [__ComObject]$SMSTSEnvironment = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction 'Stop'
    Write-Log -Message 'Successfully loaded COM Object [Microsoft.SMS.TSEnvironment]. Therefore, script is currently running from a SCCM Task Sequence.' -Source $appDeployToolkitName
    $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($SMSTSEnvironment)
    $runningTaskSequence = $true
}
Catch {
    Write-Log -Message 'Unable to load COM Object [Microsoft.SMS.TSEnvironment]. Therefore, script is not currently running from a SCCM Task Sequence.' -Source $appDeployToolkitName
    $runningTaskSequence = $false
}

## Check to see if the Task Scheduler service is in a healthy state by checking its services to see if they exist, are currently running, and have a start mode of 'Automatic'.
## The task scheduler service and the services it is dependent on can/should only be started/stopped/modified when running in the SYSTEM context.
[Boolean]$IsTaskSchedulerHealthy = $true
If ($IsLocalSystemAccount) {
    #  Check the health of the 'Task Scheduler' service
    Try {
        If (Test-ServiceExists -Name 'Schedule' -ContinueOnError $false) {
            If ((Get-ServiceStartMode -Name 'Schedule' -ContinueOnError $false) -ne 'Automatic') {
                Set-ServiceStartMode -Name 'Schedule' -StartMode 'Automatic' -ContinueOnError $false
            }
            Start-ServiceAndDependencies -Name 'Schedule' -SkipServiceExistsTest -ContinueOnError $false
        }
        Else {
            [Boolean]$IsTaskSchedulerHealthy = $false
        }
    }
    Catch {
        [Boolean]$IsTaskSchedulerHealthy = $false
    }
    #  Log the health of the 'Task Scheduler' service
    Write-Log -Message "The task scheduler service is in a healthy state: $IsTaskSchedulerHealthy." -Source $appDeployToolkitName
}
Else {
    Write-Log -Message "Skipping attempt to check for and make the task scheduler services healthy, because the App Deployment Toolkit is not running under the [$LocalSystemNTAccount] account." -Source $appDeployToolkitName
}

## If script is running in session zero
If ($SessionZero) {
    ##  If the script was launched with deployment mode set to NonInteractive, then continue
    If ($deployMode -eq 'NonInteractive') {
        Write-Log -Message "Session 0 detected but deployment mode was manually set to [$deployMode]." -Source $appDeployToolkitName
    }
    ElseIf ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_SessionDetection) {
        ##  If the process is not able to display a UI, enable NonInteractive mode
        If (-not $IsProcessUserInteractive) {
            $deployMode = 'NonInteractive'
            Write-Log -Message "Session 0 detected, process not running in user interactive mode; deployment mode set to [$deployMode]." -Source $appDeployToolkitName
        }
        Else {
            If (-not $usersLoggedOn) {
                $deployMode = 'NonInteractive'
                Write-Log -Message "Session 0 detected, process running in user interactive mode, no users logged in; deployment mode set to [$deployMode]." -Source $appDeployToolkitName
            }
            Else {
                Write-Log -Message 'Session 0 detected, process running in user interactive mode, user(s) logged in.' -Source $appDeployToolkitName
            }
        }
    }
    Else {
        Write-Log -Message "Session 0 detected but toolkit configured to not adjust deployment mode." -Source $appDeployToolkitName
    }
}
Else {
    Write-Log -Message 'Session 0 not detected.' -Source $appDeployToolkitName
}

## Set Deploy Mode switches
If ($deployMode) {
    Write-Log -Message "Installation is running in [$deployMode] mode." -Source $appDeployToolkitName
}
Switch ($deployMode) {
    'Silent' {
        $deployModeNonInteractive = $true; $deployModeSilent = $true
    }
    'NonInteractive' {
        $deployModeNonInteractive = $true; $deployModeSilent = $true
    }
    Default {
        $deployModeNonInteractive = $false; $deployModeSilent = $false
    }
}

## Check deployment type (install/uninstall)
Switch ($deploymentType) {
    'Install' {
        $deploymentTypeName = $Script:UI.DeploymentType_Install
    }
    'Uninstall' {
        $deploymentTypeName = $Script:UI.DeploymentType_UnInstall
    }
    'Repair' {
        $deploymentTypeName = $Script:UI.DeploymentType_Repair
    }
    Default {
        $deploymentTypeName = $Script:UI.DeploymentType_Install
    }
}
If ($deploymentTypeName) {
    Write-Log -Message "Deployment type is [$deploymentTypeName]." -Source $appDeployToolkitName
}

If ($useDefaultMsi) {
    Write-Log -Message "Discovered Zero-Config MSI installation file [$defaultMsiFile]." -Source $appDeployToolkitName
}

## Check current permissions and exit if not running with Administrator rights
If ($Script:StateMgmt.Config.Toolkit_Options.Toolkit_RequireAdmin) {
    #  Check if the current process is running with elevated administrator permissions
    If ((-not $IsAdmin) -and (-not $ShowBlockedAppDialog)) {
        [String]$AdminPermissionErr = "[$appDeployToolkitName] has an XML config file option [Toolkit_RequireAdmin] set to [True] so as to require Administrator rights for the toolkit to function. Please re-run the deployment script as an Administrator or change the option in the XML config file to not require Administrator rights."
        Write-Log -Message $AdminPermissionErr -Severity 3 -Source $appDeployToolkitName
        Show-DialogBox -Text $AdminPermissionErr -Icon 'Stop'
        Throw $AdminPermissionErr
    }
}

## If terminal server mode was specified, change the installation mode to support it
If ($terminalServerMode) {
    Enable-TerminalServerInstallMode
}

## If not in install phase Asynchronous, change the install phase so we dont have Initialization phase when we are done initializing
## This should get overwritten shortly, unless this is not dot sourced by Deploy-Application.ps1
If (-not $AsyncToolkitLaunch) {
    $installPhase = 'Execution'
}

#endregion
##*=============================================
##* END SCRIPT BODY
##*=============================================
