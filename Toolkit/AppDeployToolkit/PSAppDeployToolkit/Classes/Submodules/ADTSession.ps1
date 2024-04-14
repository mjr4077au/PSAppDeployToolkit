#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

class ADTSession
{
    # Private variables.
    hidden [System.Collections.Specialized.OrderedDictionary]$Session = [ordered]@{
        Shell = New-Object -ComObject 'WScript.Shell'
        ShellApp = New-Object -ComObject 'Shell.Application'
        DefaultFont = [System.Drawing.SystemFonts]::MessageBoxFont
        LegacyMode = $null
        Cmdlet = $null
        Config = $null
        UiMessages = $null
        Environment = $null
        RegKeyDeferHistory = $null
        BannerHeight = 0
        Initialised = $false
        State = @{
            OldPSWindowTitle = $Host.UI.RawUI.WindowTitle
            MessageLanguage = $null
            WelcomeTimer = $null
            LogTempFolder = $null
            LogFileInitialized = $false
            BlockExecution = $false
            MsiRebootDetected = $false
            IsTaskSchedulerHealthy = $true
            DefaultMsiExecutablesList = [System.String]::Empty
            DeploymentTypeName = [System.String]::Empty
            DeployModeNonInteractive = $false
            DeployModeSilent = $false
        }
    }

    # Variables we export publically for compatibility.
    hidden [System.Collections.Specialized.OrderedDictionary]$Properties = [ordered]@{
        # Deploy-Application.ps1 variables.
        DeploymentType = 'Install'
        DeployMode = 'Interactive'
        AppVendor = [System.String]::Empty
        AppName = [System.String]::Empty
        AppVersion = [System.String]::Empty
        AppArch = [System.String]::Empty
        AppLang = [System.String]::Empty
        AppRevision = [System.String]::Empty
        AppScriptVersion = [System.String]::Empty
        AppScriptDate = [System.String]::Empty
        AppScriptAuthor = [System.String]::Empty
        InstallName = [System.String]::Empty
        InstallTitle = [System.String]::Empty
        DeployAppScriptFriendlyName = [System.String]::Empty
        DeployAppScriptVersion = [System.String]::Empty
        DeployAppScriptDate = [System.String]::Empty
        DeployAppScriptParameters = @{}
        InstallPhase = 'Initialization'

        # Deploy-Application.ps1 parameters.
        AllowRebootPassThru = $false
        TerminalServerMode = $false
        DisableLogging = $false

        # Calculated variables we publicise.
        CurrentDateTime = $null
        CurrentTime = [System.String]::Empty
        CurrentDate = [System.String]::Empty
        CurrentTimeZoneBias = $null
        DefaultMsiFile = [System.String]::Empty
        DefaultMstFile = [System.String]::Empty
        DefaultMspFiles = [System.String]::Empty
        UseDefaultMsi = $false
        LogName = [System.String]::Empty
        ScriptParentPath = [System.String]::Empty
        DirFiles = [System.String]::Empty
        DirSupportFiles = [System.String]::Empty
        DirAppDeployTemp = [System.String]::Empty
    }

    # Constructors.
    ADTSession([System.Management.Automation.PSCmdlet]$Cmdlet)
    {
        $this.Init(@{Cmdlet = $Cmdlet})
    }
    ADTSession([System.Collections.Hashtable]$Parameters)
    {
        $this.Init($Parameters)
    }

    # Private methods.
    hidden [System.Void] Init([System.Collections.Hashtable]$Parameters)
    {
        # Establish start date/time first so we can accurately mark the start of execution.
        $this.Properties.CurrentDateTime = [System.DateTime]::Now
        $this.Properties.CurrentTime = Get-Date -Date $this.Properties.CurrentDateTime -UFormat '%T'
        $this.Properties.CurrentDate = Get-Date -Date $this.Properties.CurrentDateTime -UFormat '%d-%m-%Y'
        $this.Properties.CurrentTimeZoneBias = [System.TimeZone]::CurrentTimeZone.GetUtcOffset($this.Properties.CurrentDateTime)

        # Set whether this session is to be invoked in legacy mode.
        $this.Session.LegacyMode = (Get-PSCallStack).Command.Contains('AppDeployToolkitMain.ps1')

        # Generate userland environment variables for exportation.
        $this.Session.Environment = New-ADTVariableDatabase

        # Import config file.
        $this.ImportConfig()
        $this.ImportUIStrings()

        # Process provided parameters.
        $this.Session.Cmdlet = $Parameters.Cmdlet
        $Parameters.GetEnumerator().Where({!$_.Name.Equals('Cmdlet')}).ForEach({$this.Properties[$_.Name] = $_.Value})

        # Ensure the deployment type is always title-cased for log aesthetics.
        $this.Properties.DeploymentType = $this.Session.Cmdlet.Host.CurrentCulture.TextInfo.ToTitleCase($this.Properties.DeploymentType)

        # Establish script directories.
        $this.Properties.ScriptParentPath = [System.IO.Path]::GetDirectoryName($this.Session.Cmdlet.MyInvocation.MyCommand.Path)
        $this.Properties.DirFiles = "$($this.Properties.ScriptParentPath)\Files"
        $this.Properties.DirSupportFiles = "$($this.Properties.ScriptParentPath)\SupportFiles"
        $this.Properties.DirAppDeployTemp = [System.IO.Directory]::CreateDirectory("$($this.Session.Config.Toolkit_Options.Toolkit_TempPath)\$($this.Session.Environment.appDeployToolkitName)").FullName
    }

    hidden [System.Void] ImportConfig()
    {
        # Create variables within this scope from the database, it's needed during the config import.
        $this.Session.Environment.GetEnumerator().ForEach({New-Variable -Name $_.Name -Value $_.Value -Option Constant})

        # Read XML file and confirm the version meets our minimum requirements.
        $xml = [System.Xml.XmlDocument]::new(); $xml.Load([System.Xml.XmlReader]::Create("$($Script:PSScriptRoot)\AppDeployToolkitConfig.xml"))
        if (([System.Version]$xml.AppDeployToolkit_Config.Config_File.Config_Version) -lt $this.Session.Environment.appDeployMainScriptMinimumConfigVersion)
        {
            throw [System.InvalidOperationException]::new("The XML configuration file version [$($xml.AppDeployToolkit_Config.Config_File.Config_Version)] is lower than the supported version required by the Toolkit [$($this.Session.Environment.appDeployMainScriptMinimumConfigVersion)]. Please upgrade the configuration file.")
        }

        # Process the XML file into something sane for PowerShell.
        $this.Session.Config = ($xml | Convert-ADTConfigToObjects).AppDeployToolkit_Config

        # Process logo files.
        $this.Session.Config.BannerIcon_Options.Icon_Filename = (Resolve-Path -LiteralPath "$($Script:PSScriptRoot)\$($this.Session.Config.BannerIcon_Options.Icon_Filename)").Path
        $this.Session.Config.BannerIcon_Options.LogoImage_Filename = (Resolve-Path -LiteralPath "$($Script:PSScriptRoot)\$($this.Session.Config.BannerIcon_Options.LogoImage_Filename)").Path
        $this.Session.Config.BannerIcon_Options.Banner_Filename = (Resolve-Path -LiteralPath "$($Script:PSScriptRoot)\$($this.Session.Config.BannerIcon_Options.Banner_Filename)").Path

        #  Check that dependency files are present
        if (![System.IO.File]::Exists($this.Session.Config.BannerIcon_Options.Icon_Filename))
        {
            throw 'App Deploy logo icon file not found.'
        }
        if (![System.IO.File]::Exists($this.Session.Config.BannerIcon_Options.Banner_Filename))
        {
            throw 'App Deploy logo banner file not found.'
        }

        # Change paths to user accessible ones if user isn't an admin.
        if (!$this.Session.Environment.IsAdmin)
        {
            if ($this.Session.Config.Toolkit_Options.Toolkit_TempPathNoAdminRights)
            {
                $this.Session.Config.Toolkit_Options.Toolkit_TempPath = $this.Session.Config.Toolkit_Options.Toolkit_TempPathNoAdminRights
            }
            if ($this.Session.Config.Toolkit_Options.Toolkit_RegPathNoAdminRights)
            {
                $this.Session.Config.Toolkit_Options.Toolkit_RegPath = $this.Session.Config.Toolkit_Options.Toolkit_RegPathNoAdminRights
            }
            if ($this.Session.Config.Toolkit_Options.Toolkit_LogPathNoAdminRights)
            {
                $this.Session.Config.Toolkit_Options.Toolkit_LogPath = $this.Session.Config.Toolkit_Options.Toolkit_LogPathNoAdminRights
            }
            if ($this.Session.Config.MSI_Options.MSI_LogPathNoAdminRights)
            {
                $this.Session.Config.MSI_Options.MSI_LogPath = $this.Session.Config.MSI_Options.MSI_LogPathNoAdminRights
            }
        }
    }

    hidden [System.Void] ImportUIStrings()
    {
        # Get the best language identifier.
        $this.Session.State.MessageLanguage = if ($this.Session.Config.UI_Options.InstallationUI_LanguageOverride)
        {
            # The caller has specified a specific language.
            $this.Session.Config.UI_Options.InstallationUI_LanguageOverride
        }
        elseif ($this.Session.Environment.HKUPrimaryLanguageShort)
        {
            # Get the logged on user's language value.
            $this.Session.Environment.HKUPrimaryLanguageShort
        }
        else
        {
            # Fall back to PowerShell's.
            $this.Session.Environment.currentLanguage
        }

        # Default to English if the detected UI language is not available in the XML config file.
        if (!$this.Session.Config.PSObject.Properties.Name.Contains("UI_Messages_$($this.Session.State.MessageLanguage)"))
        {
            $this.Session.State.MessageLanguage = "EN"
        }
        
        # Store the chosen language within this session.
        $this.Session.UiMessages = $this.Session.Config."UI_Messages_$($this.Session.State.MessageLanguage)"
    }

    hidden [System.String] GetLogSource()
    {
        # Get the first command in the callstack and consider it the log source.
        return (Get-PSCallStack).Command.Where({![System.String]::IsNullOrWhiteSpace($_)})[0]
    }

    hidden [System.Void] DetectDefaultMsi()
    {
        # If the default Deploy-Application.ps1 hasn't been modified, and the main script was not called by a referring script, check for MSI / MST and modify the install accordingly.
        if (![System.String]::IsNullOrWhiteSpace($this.Properties.AppName))
        {
            return
        }

        # Find the first MSI file in the Files folder and use that as our install.
        $logSrc = $this.GetLogSource()
        if (!$this.Properties.DefaultMsiFile)
        {
            # Get all MSI files.
            $msiFiles = Get-ChildItem -Path "$($this.Properties.DirFiles)\*.msi" -ErrorAction Ignore

            if ($this.Properties.DefaultMsiFile = $msiFiles | Where-Object {$_.Name.EndsWith(".$($this.Session.Environment.envOSArchitecture).msi")} | Select-Object -ExpandProperty FullName -First 1)
            {
                Write-Log -Message "Discovered $($this.Session.Environment.envOSArchitecture) Zero-Config MSI under $($this.Properties.DefaultMsiFile)" -Source $logSrc
            }
            elseif ($this.Properties.DefaultMsiFile = $msiFiles | Select-Object -ExpandProperty FullName -First 1)
            {
                Write-Log -Message "Discovered Arch-Independent Zero-Config MSI under $($this.Properties.DefaultMsiFile)" -Source $logSrc
            }
            else
            {
                # Return early if we haven't found anything.
                return
            }
        }
        else
        {
            Write-Log -Message "Discovered Zero-Config MSI installation file [$($this.Properties.DefaultMsiFile)]." -Source $logSrc
        }

        try
        {
            # Discover if there is a zero-config MST file
            if ([System.String]::IsNullOrWhiteSpace($this.Properties.DefaultMstFile))
            {
                $this.Properties.DefaultMstFile = [System.IO.Path]::ChangeExtension($this.Properties.DefaultMsiFile, 'mst')
            }
            if ([System.IO.File]::Exists($this.Properties.DefaultMstFile))
            {
                Write-Log -Message "Discovered Zero-Config MST installation file [$($this.Properties.DefaultMstFile)]." -Source $logSrc
            }
            else
            {
                $this.Properties.DefaultMstFile = [System.String]::Empty
            }

            #  Discover if there are zero-config MSP files. Name multiple MSP files in alphabetical order to control order in which they are installed.
            if (!$this.Properties.DefaultMspFiles)
            {
                $defaultMspFiles = Get-ChildItem -Path "$($this.Properties.DirFiles)\*.msi" | Select-Object -ExpandProperty FullName
            }
            if ($this.Properties.DefaultMspFiles)
            {
                Write-Log -Message "Discovered Zero-Config MSP installation file(s) [$($this.Properties.DefaultMspFiles -join ',')]." -Source $logSrc
            }

            # Read the MSI and get the installation details.
            $gmtpParams = @{Path = $this.Properties.DefaultMsiFile; Table = 'File'; ContinueOnError = $false}
            if ($this.Properties.DefaultMstFile) {$gmtpParams.Add('TransformPath', $this.Properties.DefaultMstFile)}
            $msiProps = Get-MsiTableProperty @gmtpParams

            # Generate list of MSI executables for testing later on.
            if (($this.Session.State.DefaultMsiExecutablesList = (Get-Member -InputObject $msiProps | Where-Object {[System.IO.Path]::GetExtension($_.Name) -eq '.exe'} | ForEach-Object {[System.IO.Path]::GetFileNameWithoutExtension($_.Name)}) -join ','))
            {
                Write-Log -Message "MSI Executable List [$($this.Session.State.DefaultMsiExecutablesList)]." -Source $logSrc
            }
            
            # Change table and get properties from it.
            $gmtpParams.Set_Item('Table', 'Property')
            $msiProps = Get-MsiTableProperty @gmtpParams

            # Update our app variables with new values.
            Write-Log -Message "App Vendor [$(($this.Properties.AppVendor = $msiProps.Manufacturer))]." -Source $logSrc
            Write-Log -Message "App Name [$(($this.Properties.AppName = $msiProps.ProductName))]." -Source $logSrc
            Write-Log -Message "App Version [$(($this.Properties.AppVersion = $msiProps.ProductVersion))]." -Source $logSrc
            $this.Properties.UseDefaultMsi = $true
        }
        catch
        {
            Write-Log -Message "Failed to process Zero-Config MSI Deployment.`n$(Resolve-Error)" -Source $logSrc
        }
    }

    hidden [System.Void] SetAppProperties()
    {
        # Set up sample variables if Dot Sourcing the script, app details have not been specified
        if ([System.String]::IsNullOrWhiteSpace($this.Properties.AppName))
        {
            $this.Properties.AppName = $this.Session.Environment.appDeployToolkitName

            if (![System.String]::IsNullOrWhiteSpace($this.Properties.AppVendor))
            {
                $this.Properties.AppVendor = [System.String]::Empty
            }
            if ([System.String]::IsNullOrWhiteSpace($this.Properties.AppVersion))
            {
                $this.Properties.AppVersion = $this.Session.Environment.appDeployMainScriptVersion.ToString()
            }
            if ([System.String]::IsNullOrWhiteSpace($this.Properties.AppLang))
            {
                $this.Properties.AppLang = $this.Session.Environment.currentLanguage
            }
            if ([System.String]::IsNullOrWhiteSpace($this.Properties.AppRevision))
            {
                $this.Properties.AppRevision = '01'
            }
        }

        ## Sanitize the application details, as they can cause issues in the script.
        $this.Properties.AppVendor = Remove-InvalidFileNameChars -Name $this.Properties.AppVendor.Trim()
        $this.Properties.AppName = Remove-InvalidFileNameChars -Name $this.Properties.AppName.Trim()
        $this.Properties.AppVersion = Remove-InvalidFileNameChars -Name $this.Properties.AppVersion.Trim()
        $this.Properties.AppArch = Remove-InvalidFileNameChars -Name $this.Properties.AppArch.Trim()
        $this.Properties.AppLang = Remove-InvalidFileNameChars -Name $this.Properties.AppLang.Trim()
        $this.Properties.AppRevision = Remove-InvalidFileNameChars -Name $this.Properties.AppRevision.Trim()
    }

    hidden [System.Void] SetInstallProperties()
    {
        # Build the Installation Title.
        if ([System.String]::IsNullOrWhiteSpace($this.Properties.InstallTitle))
        {
            $this.Properties.InstallTitle = "$($this.Properties.AppVendor) $($this.Properties.AppName) $($this.Properties.AppVersion)".Trim() -replace '\s{2,}',' '
        }

        # Build the Installation Name.
        If ([System.String]::IsNullOrWhiteSpace($this.Properties.InstallName))
        {
            $this.Properties.InstallName = "$($this.Properties.AppVendor)_$($this.Properties.AppName)_$($this.Properties.AppVersion)_$($this.Properties.AppArch)_$($this.Properties.AppLang)_$($this.Properties.AppRevision)"
        }
        $this.Properties.InstallName = ($this.Properties.InstallName -replace '\s').Trim('_') -replace '[_]+', '_'

        # Set Powershell window title, in case the window is visible.
        $this.Session.Cmdlet.Host.UI.RawUI.WindowTitle = "$($this.Properties.InstallTitle) - $($this.Properties.DeploymentType)" -replace '\s{2,}',' '

        # Set the Defer History registry path.
        $this.Session.RegKeyDeferHistory = "$($this.Session.Config.Toolkit_Options.Toolkit_RegPath)\$($this.Session.Environment.appDeployToolkitName)\DeferHistory\$($this.Properties.InstallName)"
    }

    hidden [System.Void] SetLogName()
    {
        # Generate a log name from our installation properties.
        $this.Session.LogName = "$($this.Properties.InstallName)_$($this.Session.Environment.appDeployToolkitName)_$($this.Properties.DeploymentType).log"

        # If option to compress logs is selected, then log will be created in temp log folder ($logTempFolder) and then copied to actual log folder ($this.Session.Config.Toolkit_Options.Toolkit_LogPath) after being zipped.
        if ($this.Session.Config.Toolkit_Options.Toolkit_CompressLogs)
        {
            # If the temp log folder already exists from a previous ZIP operation, then delete all files in it to avoid issues.
            if ([System.IO.Directory]::Exists(($this.Session.State.LogTempFolder = "$([System.IO.Path]::GetTempPath())$($this.Properties.InstallName)_$($this.Properties.DeploymentType)")))
            {
                [System.IO.Directory]::Remove($this.Session.State.LogTempFolder, $true)
            }
        }
    }

    hidden [System.Void] CalcBannerHeight()
    {
        try
        {
            # Calculate banner height.
            $banner = [System.Drawing.Bitmap]::new($this.Session.Config.BannerIcon_Options.Banner_Filename)
            $this.Session.BannerHeight = [System.Math]::Min([System.Math]::Ceiling(450 * ($banner.Height / $banner.Width)), $this.Session.Config.BannerIcon_Options.Banner_MaxHeight)
            $banner.Dispose()
        }
        catch
        {
            # Catch blocks will warn in PSScriptAnalyzer if they're empty.
            [System.Void]$null
        }
    }

    hidden [System.Void] WriteLogDivider()
    {
        # Write divider as requested.
        Write-Log -Message ('*' * 79) -Source $this.GetLogSource()
    }

    hidden [System.Void] OpenLogFile()
    {
        # Initialize logging.
        $this.WriteLogDivider()
        $this.WriteLogDivider()
        Write-Log -Message "[$($this.Properties.InstallName)] setup started." -Source $this.GetLogSource()
    }

    hidden [System.Void] LogScriptInfo()
    {
        $logSrc = $this.GetLogSource()
        if ($this.Properties.AppScriptVersion)
        {
            Write-Log -Message "[$($this.Properties.InstallName)] script version is [$($this.Properties.AppScriptVersion)]" -Source $logSrc
        }
        if ($this.Properties.AppScriptDate)
        {
            Write-Log -Message "[$($this.Properties.InstallName)] script date is [$($this.Properties.AppScriptDate)]" -Source $logSrc
        }
        if ($this.Properties.AppScriptAuthor)
        {
            Write-Log -Message "[$($this.Properties.InstallName)] script author is [$($this.Properties.AppScriptAuthor)]" -Source $logSrc
        }
        if ($this.Properties.DeployAppScriptFriendlyName)
        {
            Write-Log -Message "[$($this.Properties.DeployAppScriptFriendlyName)] script version is [$($this.Properties.DeployAppScriptVersion)]" -Source $logSrc
        }
        if ($this.Properties.DeployAppScriptParameters -and $this.Properties.DeployAppScriptParameters.Count)
        {
            Write-Log -Message "The following parameters were passed to [$($this.Properties.DeployAppScriptFriendlyName)]: [$($this.Properties.deployAppScriptParameters | Resolve-Parameters)]" -Source $logSrc
        }
        Write-Log -Message "[$($this.Session.Environment.appDeployToolkitName)] module version is [$($Script:MyInvocation.MyCommand.ScriptBlock.Module.Version)]" -Source $logSrc
        Write-Log -Message "[$($this.Session.Environment.appDeployToolkitName)] session in compatibility mode is [$($this.Session.LegacyMode)]" -Source $logSrc
    }

    hidden [System.Void] LogSystemInfo()
    {
        Write-Log -Message "Computer Name is [$($this.Session.Environment.envComputerNameFQDN)]" -Source ($logSrc = $this.GetLogSource())
        Write-Log -Message "Current User is [$($this.Session.Environment.ProcessNTAccount)]" -Source $logSrc
        if ($this.Session.Environment.envOSServicePack)
        {
            Write-Log -Message "OS Version is [$($this.Session.Environment.envOSName) $($this.Session.Environment.envOSServicePack) $($this.Session.Environment.envOSArchitecture) $($this.Session.Environment.envOSVersion)]" -Source $logSrc
        }
        else
        {
            Write-Log -Message "OS Version is [$($this.Session.Environment.envOSName) $($this.Session.Environment.envOSArchitecture) $($this.Session.Environment.envOSVersion)]" -Source $logSrc
        }
        Write-Log -Message "OS Type is [$($this.Session.Environment.envOSProductTypeName)]" -Source $logSrc
        Write-Log -Message "Current Culture is [$($($this.Session.Environment.culture).Name)], language is [$($this.Session.Environment.currentLanguage)] and UI language is [$($this.Session.Environment.currentUILanguage)]" -Source $logSrc
        Write-Log -Message "Hardware Platform is [$(Get-HardwarePlatform)]" -Source $logSrc
        Write-Log -Message "PowerShell Host is [$($($this.Session.Environment.envHost).Name)] with version [$($this.Session.Environment.envHost.Version)]" -Source $logSrc
        Write-Log -Message "PowerShell Version is [$($this.Session.Environment.envPSVersion) $($this.Session.Environment.psArchitecture)]" -Source $logSrc
        if ($this.Session.Environment.envPSVersionTable.ContainsKey('CLRVersion'))
        {
            Write-Log -Message "PowerShell CLR (.NET) version is [$($this.Session.Environment.envCLRVersion)]" -Source $logSrc
        }
    }

    hidden [System.Void] InstallToastDependencies()
    {
        # Install required assemblies for toast notifications if conditions are right.
        if (!$this.Session.Config.Toast_Options.Toast_Disable -and $Script:PSVersionTable.PSEdition.Equals('Core') -and !(Get-Package -Name Microsoft.Windows.SDK.NET.Ref -ErrorAction Ignore))
        {
            try
            {
                Write-Log -Message "Installing WinRT assemblies for PowerShell 7 toast notification support. This will take at least 5 minutes, please wait..." -Source $this.GetLogSource()
                Install-Package -Name Microsoft.Windows.SDK.NET.Ref -ProviderName NuGet -Force -Confirm:$false | Out-Null
            }
            catch
            {
                Write-Log -Message "An error occurred while preparing WinRT assemblies for usage. Toast notifications will not be available for this execution." -Severity 2 -Source $this.GetLogSource()
            }
        }
    }

    hidden [System.Void] LogUserInfo()
    {
        # Log details for all currently logged in users.
        Write-Log -Message "Display session information for all logged on users:`n$($this.Session.Environment.LoggedOnUserSessions | Format-List | Out-String)" -Source ($logSrc = $this.GetLogSource()) -DebugMessage
        if ($this.Session.Environment.usersLoggedOn)
        {
            Write-Log -Message "The following users are logged on to the system: [$($this.Session.Environment.usersLoggedOn -join ', ')]." -Source $logSrc

            # Check if the current process is running in the context of one of the logged in users
            if ($this.Session.Environment.CurrentLoggedOnUserSession)
            {
                Write-Log -Message "Current process is running with user account [$($this.Session.Environment.ProcessNTAccount)] under logged in user session for [$($this.Session.Environment.CurrentLoggedOnUserSession.NTAccount)]." -Source $logSrc
            }
            else
            {
                Write-Log -Message "Current process is running under a system account [$($this.Session.Environment.ProcessNTAccount)]." -Source $logSrc
            }

            # Guard Intune detection code behind a variable.
            if ($this.Session.Config.Toolkit_Options.Toolkit_OobeDetection -and ![PSADT.Utilities]::OobeCompleted())
            {
                Write-Log -Message "Detected OOBE in progress, changing deployment mode to silent." -Source $logSrc
                $deployMode = 'Silent'
            }

            # Display account and session details for the account running as the console user (user with control of the physical monitor, keyboard, and mouse)
            if ($this.Session.Environment.CurrentConsoleUserSession)
            {
                Write-Log -Message "The following user is the console user [$($this.Session.Environment.CurrentConsoleUserSession.NTAccount)] (user with control of physical monitor, keyboard, and mouse)." -Source $logSrc
            }
            else
            {
                Write-Log -Message 'There is no console user logged in (user with control of physical monitor, keyboard, and mouse).' -Source $logSrc
            }

            # Display the account that will be used to execute commands in the user session when toolkit is running under the SYSTEM account
            if ($this.Session.Environment.RunAsActiveUser)
            {
                Write-Log -Message "The active logged on user is [$($this.Session.Environment.RunAsActiveUser.NTAccount)]." -Source $logSrc
            }
        }
        else
        {
            Write-Log -Message 'No users are logged on to the system.' -Source $logSrc
        }

        # Log which language's UI messages are loaded from the config XML file
        if ($this.Session.Environment.HKUPrimaryLanguageShort)
        {
            Write-Log -Message "The active logged on user [$($this.Session.Environment.RunAsActiveUser.NTAccount)] has a primary UI language of [$($this.Session.Environment.HKUPrimaryLanguageShort)]." -Source $logSrc
        }
        else
        {
            Write-Log -Message "The current system account [$($this.Session.Environment.ProcessNTAccount)] has a primary UI language of [$($this.Session.Environment.currentLanguage)]." -Source $logSrc
        }

        # Advise whether the UI language was overridden.
        If ($this.Session.Config.UI_Options.InstallationUI_LanguageOverride)
        {
            Write-Log -Message "The config XML file was configured to override the detected primary UI language with the following UI language: [$((Get-ADTSession).GetConfig().UI_Options.InstallationUI_LanguageOverride)]." -Source $logSrc
        }
        Write-Log -Message "The following UI messages were imported from the config XML file: [$($this.Session.State.MessageLanguage)]." -Source $logSrc

        # Log system DPI scale factor of active logged on user
        if ($this.Session.Environment.UserDisplayScaleFactor)
        {
            Write-Log -Message "The active logged on user [$($this.Session.Environment.RunAsActiveUser.NTAccount)] has a DPI scale factor of [$($this.Session.Environment.dpiScale)] with DPI pixels [$($this.Session.Environment.dpiPixels)]." -Source $logSrc
        }
        else
        {
            Write-Log -Message "The system has a DPI scale factor of [$($this.Session.Environment.dpiScale)] with DPI pixels [$($this.Session.Environment.dpiPixels)]." -Source $logSrc
        }
    }

    hidden [System.Void] PerformSCCMTests()
    {
        # Check if script is running from a SCCM Task Sequence.
        if ($this.Session.Environment.RunningTaskSequence)
        {
            Write-Log -Message 'Successfully found COM object [Microsoft.SMS.TSEnvironment]. Therefore, script is currently running from a SCCM Task Sequence.' -Source $this.GetLogSource()
        }
        else
        {
            Write-Log -Message 'Unable to find COM object [Microsoft.SMS.TSEnvironment]. Therefore, script is not currently running from a SCCM Task Sequence.' -Source $this.GetLogSource()
        }
    }

    hidden [System.Void] PerformSystemAccountTests()
    {
        # Check to see if the Task Scheduler service is in a healthy state by checking its services to see if they exist, are currently running, and have a start mode of 'Automatic'.
        # The task scheduler service and the services it is dependent on can/should only be started/stopped/modified when running in the SYSTEM context.
        $logSrc = $this.GetLogSource()
        if ($this.Session.Environment.IsLocalSystemAccount)
        {
            # Check the health of the 'Task Scheduler' service
            try
            {
                if (Test-ServiceExists -Name 'Schedule' -ContinueOnError $false)
                {
                    if ((Get-ServiceStartMode -Name 'Schedule' -ContinueOnError $false) -ne 'Automatic')
                    {
                        Set-ServiceStartMode -Name 'Schedule' -StartMode 'Automatic' -ContinueOnError $false
                    }
                    Start-ServiceAndDependencies -Name 'Schedule' -SkipServiceExistsTest -ContinueOnError $false
                }
                else
                {
                    $this.Session.State.IsTaskSchedulerHealthy = $false
                }
            }
            catch
            {
                $this.Session.State.IsTaskSchedulerHealthy = $false
            }

            # Log the health of the 'Task Scheduler' service.
            Write-Log -Message "The task scheduler service is in a healthy state: $($this.Session.State.IsTaskSchedulerHealthy)." -Source $logSrc
        }
        else
        {
            Write-Log -Message "Skipping attempt to check for and make the task scheduler services healthy, because $($this.Session.Environment.appDeployToolkitName) is not running under the [$($this.Session.Environment.LocalSystemNTAccount)] account." -Source $logSrc
        }

        # If script is running in session zero.
        if ($this.Session.Environment.SessionZero)
        {
            # If the script was launched with deployment mode set to NonInteractive, then continue
            if ($this.Properties.DeployMode -eq 'NonInteractive')
            {
                Write-Log -Message "Session 0 detected but deployment mode was manually set to [$($this.Session.Environment.DeployMode)]." -Source $logSrc
            }
            elseif ($this.Session.Config.Toolkit_Options.Toolkit_SessionDetection)
            {
                # If the process is not able to display a UI, enable NonInteractive mode
                if (!$this.Session.Environment.IsProcessUserInteractive)
                {
                    $this.Properties.DeployMode = 'NonInteractive'
                    Write-Log -Message "Session 0 detected, process not running in user interactive mode; deployment mode set to [$($this.Session.Environment.DeployMode)]." -Source $logSrc
                }
                elseif (!$this.Session.Environment.usersLoggedOn)
                {
                    $this.Properties.DeployMode = 'NonInteractive'
                    Write-Log -Message "Session 0 detected, process running in user interactive mode, no users logged in; deployment mode set to [$($this.Session.Environment.deployMode)]." -Source $logSrc
                }
                else
                {
                    Write-Log -Message 'Session 0 detected, process running in user interactive mode, user(s) logged in.' -Source $logSrc
                }
            }
            else
            {
                Write-Log -Message "Session 0 detected but toolkit configured to not adjust deployment mode." -Source $logSrc
            }
        }
        else
        {
            Write-Log -Message 'Session 0 not detected.' -Source $logSrc
        }
    }

    hidden [System.Void] SetDeploymentProperties()
    {
        # Set Deploy Mode switches.
        Write-Log -Message "Installation is running in [$($this.Properties.DeployMode)] mode." -Source ($logSrc = $this.GetLogSource())
        switch ($this.Properties.DeployMode)
        {
            'Silent' {
                $this.Session.State.DeployModeNonInteractive = $true; $this.Session.State.DeployModeSilent = $true
            }
            'NonInteractive' {
                $this.Session.State.DeployModeNonInteractive = $true; $this.Session.State.DeployModeSilent = $false
            }
        }

        # Check deployment type (install/uninstall).
        $this.Session.State.DeploymentTypeName = switch ($this.Properties.DeploymentType)
        {
            'Install' {
                $this.GetUiMessages().DeploymentType_Install
            }
            'Uninstall' {
                $this.GetUiMessages().DeploymentType_UnInstall
            }
            'Repair' {
                $this.GetUiMessages().DeploymentType_Repair
            }
            default {
                $this.GetUiMessages().DeploymentType_Install
            }
        }
        Write-Log -Message "Deployment type is [$($this.Session.State.DeploymentTypeName)]." -Source $logSrc
    }

    hidden [System.Void] TestDefaultMsi()
    {
        # Advise the caller if a zero-config MSI was found.
        if ($this.Properties.UseDefaultMsi)
        {
            Write-Log -Message "Discovered Zero-Config MSI installation file [$($this.Properties.DefaultMsiFile)]." -Source $this.GetLogSource()
        }
    }

    hidden [System.Void] TestAdminRequired()
    {
        # Check current permissions and exit if not running with Administrator rights
        if ($this.Session.Config.Toolkit_Options.Toolkit_RequireAdmin -and !$this.Session.Environment.IsAdmin)# -and !$ShowBlockedAppDialog)
        {
            $adminErr = "[$($this.Session.Environment.appDeployToolkitName)] has an XML config file option [Toolkit_RequireAdmin] set to [True] so as to require Administrator rights for the toolkit to function. Please re-run the deployment script as an Administrator or change the option in the XML config file to not require Administrator rights."
            Write-Log -Message $adminErr -Severity 3 -Source $this.GetLogSource()
            Show-DialogBox -Text $adminErr -Icon Stop
            throw $adminErr
        }
    }

    hidden [System.Void] PerformTerminalServerTests()
    {
        # If terminal server mode was specified, change the installation mode to support it
        if ($this.Properties.TerminalServerMode)
        {
            Enable-TerminalServerInstallMode
        }
    }

    # Public methods.
    [System.Object] GetPropertyValue([System.String]$Name)
    {
        # This getter exists as once the script is initialised, we need to read the variable from the caller's scope.
        # We must get the variable every time as syntax like `$var = 'val'` always constructs a new PSVariable...
        if ($this.Session.LegacyMode -and $this.Session.Initialised)
        {
            return Invoke-ScriptBlockInSessionState -SessionState $this.Session.Cmdlet.SessionState -Arguments $Name -ScriptBlock {
                Get-Variable -Name $args[0] -ValueOnly
            }
        }
        else
        {
            return $this.Properties.$Name
        }
    }

    [System.Void] SetPropertyValue([System.String]$Name, [System.Object]$Value)
    {
        # This getter exists as once the script is initialised, we need to read the variable from the caller's scope.
        # We must get the variable every time as syntax like `$var = 'val'` always constructs a new PSVariable...
        if ($this.Session.LegacyMode -and $this.Session.Initialised)
        {
            Invoke-ScriptBlockInSessionState -SessionState $this.Session.Cmdlet.SessionState -Arguments $Name, $Value -ScriptBlock {
                Set-Variable -Name $args[0] -Value $args[1]
            }
        }
        else
        {
            $this.Properties[$Name] = $Value
        }
    }

    [System.Object] GetConfig()
    {
        return $this.Session.Config
    }

    [System.Object] GetUiMessages()
    {
        return $this.Session.UiMessages
    }

    [System.Void] Open()
    {
        # Ensure this session isn't being opened twice.
        if ($this.Session.Initialised)
        {
            throw [System.InvalidOperationException]::new("The current $($this.Session.Environment.appDeployToolkitName) session has already been opened.")
        }

        # Dot-source script extensions if they exist.
        if ([System.IO.File]::Exists(($appDeployToolkitDotSourceExtensions = "$($this.Properties.ScriptParentPath)\AppDeployToolkitExtensions.ps1")))
        {
            . $appDeployToolkitDotSourceExtensions
        }

        # Initialise PSADT session.
        $this.DetectDefaultMsi()
        $this.SetAppProperties()
        $this.SetInstallProperties()
        $this.SetLogName()
        $this.CalcBannerHeight()
        $this.OpenLogFile()
        $this.LogScriptInfo()
        $this.LogSystemInfo()
        $this.WriteLogDivider()
        $this.InstallToastDependencies()
        $this.LogUserInfo()
        $this.PerformSCCMTests()
        $this.PerformSystemAccountTests()
        $this.SetDeploymentProperties()
        $this.TestDefaultMsi()
        $this.TestAdminRequired()
        $this.PerformTerminalServerTests()

        ## Change the install phase since we've finished initialising. This should get overwritten shortly.
        $this.Properties.InstallPhase = 'Execution'

        # Export environment variables to the user's scope.
        Invoke-ScriptBlockInSessionState -SessionState $this.Session.Cmdlet.SessionState -Arguments $this.Session.Environment -ScriptBlock {
            $args[0].GetEnumerator().ForEach({Set-Variable -Name $_.Name -Value $_.Value -Option Constant -Force})
        }

        # Export session's public variables to the user's scope. For these, we can't capture the Set-Variable
        # PassThru data as syntax like `$var = 'val'` constructs a new PSVariable every time.
        if ($this.Session.LegacyMode)
        {
            Invoke-ScriptBlockInSessionState -SessionState $this.Session.Cmdlet.SessionState -Arguments $this.Properties -ScriptBlock {
                $args[0].GetEnumerator().ForEach({Set-Variable -Name $_.Name -Value $_.Value -Force})
            }
        }

        # Reflect that we've completed initialisation. This is important for variable retrieval.
        $this.Session.Initialised = $true
    }

    [System.Void] Close()
    {
        # Migrate `Exit-Script` into here.
    }
}
