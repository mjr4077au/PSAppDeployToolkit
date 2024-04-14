#---------------------------------------------------------------------------
#
# Module setup to ensure expected functionality.
#
#---------------------------------------------------------------------------

# Set required variables to ensure module functionality.
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-PSDebug -Strict
Set-StrictMode -Version Latest

# Add the custom types required for the toolkit.
Add-Type -LiteralPath "$PSScriptRoot\PSAppDeployToolkit.cs" -ReferencedAssemblies $(
    'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    if ($PSVersionTable.PSEdition.Equals('Core'))
    {
        'System.Collections', 'System.Text.RegularExpressions', 'System.Security.Principal.Windows', 'System.ComponentModel.Primitives', 'Microsoft.Win32.Primitives'
    }
)

# Add system types required for the toolkit.,
Add-Type -AssemblyName ('System.Drawing', 'System.Windows.Forms', 'PresentationFramework', 'Microsoft.VisualBasic', 'PresentationCore', 'WindowsBase')

# Dot-source our imports.
(Get-ChildItem -Path $PSScriptRoot\*\*.ps1).FullName.ForEach({. $_})

# Define aliases for certain module functions. These need to disappear.
Set-Alias -Name 'Register-DLL' -Value 'Invoke-RegisterOrUnregisterDLL'
Set-Alias -Name 'Unregister-DLL' -Value 'Invoke-RegisterOrUnregisterDLL'
Set-Alias -Name 'Refresh-Desktop' -Value 'Update-Desktop'
Set-Alias -Name 'Refresh-SessionEnvironmentVariables' -Value 'Update-SessionEnvironmentVariables'
if (!(Get-Command -Name 'Get-ScheduledTask')) {New-Alias -Name 'Get-ScheduledTask' -Value 'Get-SchedulerTask'}

# Set process as DPI-aware for better dialog rendering.
[System.Void][PSADT.UiAutomation]::SetProcessDPIAware()

# Define array for holding all sessions in play.
New-Variable -Name ADTSessions -Option Constant -Value ([System.Collections.Generic.List[ADTSession]]::new())


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function New-ADTSession
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCmdlet]$Cmdlet,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Install', 'Uninstall', 'Repair')]
        [System.String]$DeploymentType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Interactive', 'NonInteractive', 'Silent')]
        [System.String]$DeployMode,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppArch,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppLang,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppRevision,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppScriptVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppScriptDate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$AppScriptAuthor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$InstallName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$InstallTitle,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$DeployAppScriptFriendlyName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version]$DeployAppScriptVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.String]$DeployAppScriptDate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.Hashtable]$DeployAppScriptParameters,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$AllowRebootPassThru,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$TerminalServerMode,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$DisableLogging
    )

    # Clamp the session count at one, for now.
    if ($Script:ADTSessions.Count)
    {
        throw [System.InvalidOperationException]::new("Only one $($Script:MyInvocation.MyCommand.ScriptBlock.Module.Name) session is permitted at this time.")
    }

    # Instantiate a new ADT session and initialise it.
    $Script:ADTSessions.Add(($session = [ADTSession]::new($PSBoundParameters)))
    try
    {
        $session.Open()
    }
    catch
    {
        [System.Void]$Script:ADTSessions.Remove($session)
        throw
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Get-ADTSession
{
    # Return the most recent session in the database.
    try
    {
        return $Script:ADTSessions[-1]
    }
    catch
    {
        throw [System.InvalidOperationException]::new("Please ensure that [New-ADTSession] is called before using any $($Script:MyInvocation.MyCommand.ScriptBlock.Module.Name) functions.")
    }
}
