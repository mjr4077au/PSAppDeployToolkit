#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-InstallationPrompt
{
    <#

    .SYNOPSIS
    Displays a custom installation prompt with the toolkit branding and optional buttons.

    .DESCRIPTION
    Any combination of Left, Middle or Right buttons can be displayed. The return value of the button clicked by the user is the button text specified.

    .PARAMETER Title
    Title of the prompt. Default: the application installation name.

    .PARAMETER Message
    Message text to be included in the prompt

    .PARAMETER MessageAlignment
    Alignment of the message text. Options: Left, Center, Right. Default: Center.

    .PARAMETER ButtonLeftText
    Show a button on the left of the prompt with the specified text

    .PARAMETER ButtonRightText
    Show a button on the right of the prompt with the specified text

    .PARAMETER ButtonMiddleText
    Show a button in the middle of the prompt with the specified text

    .PARAMETER Icon
    Show a system icon in the prompt. Options: Application, Asterisk, Error, Exclamation, Hand, Information, None, Question, Shield, Warning, WinLogo. Default: None

    .PARAMETER NoWait
    Specifies whether to show the prompt asynchronously (i.e. allow the script to continue without waiting for a response). Default: $false.

    .PARAMETER PersistPrompt
    Specify whether to make the prompt persist in the center of the screen every couple of seconds, specified in the AppDeployToolkitConfig.xml. The user will have no option but to respond to the prompt - resistance is futile!

    .PARAMETER MinimizeWindows
    Specifies whether to minimize other windows when displaying prompt. Default: $false.

    .PARAMETER Timeout
    Specifies the time period in seconds after which the prompt should timeout. Default: UI timeout value set in the config XML file.

    .PARAMETER ExitOnTimeout
    Specifies whether to exit the script if the UI times out. Default: $true.

    .PARAMETER TopMost
    Specifies whether the progress window should be topmost. Default: $true.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    None. This function does not generate any output.

    .EXAMPLE
    Show-InstallationPrompt -Message 'Do you want to proceed with the installation?' -ButtonRightText 'Yes' -ButtonLeftText 'No'

    .EXAMPLE
    Show-InstallationPrompt -Title 'Funny Prompt' -Message 'How are you feeling today?' -ButtonRightText 'Good' -ButtonLeftText 'Bad' -ButtonMiddleText 'Indifferent'

    .EXAMPLE
    Show-InstallationPrompt -Message 'You can customize text to appear at the end of an install, or remove it completely for unattended installations.' -Icon Information -NoWait

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$Title = (Get-ADTSession).GetPropertyValue('InstallTitle'),
        [Parameter(Mandatory = $false)]
        [String]$Message = '',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Left', 'Center', 'Right')]
        [String]$MessageAlignment = 'Center',
        [Parameter(Mandatory = $false)]
        [String]$ButtonRightText = '',
        [Parameter(Mandatory = $false)]
        [String]$ButtonLeftText = '',
        [Parameter(Mandatory = $false)]
        [String]$ButtonMiddleText = '',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Application', 'Asterisk', 'Error', 'Exclamation', 'Hand', 'Information', 'None', 'Question', 'Shield', 'Warning', 'WinLogo')]
        [String]$Icon = 'None',
        [Parameter(Mandatory = $false)]
        [Switch]$NoWait = $false,
        [Parameter(Mandatory = $false)]
        [Switch]$PersistPrompt = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$MinimizeWindows = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$Timeout = (Get-ADTSession).GetConfig().UI_Options.InstallationUI_Timeout,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$ExitOnTimeout = $true,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$TopMost = $true
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        ## Bypass if in non-interactive mode
        If ((Test-Path -LiteralPath 'variable:deployModeSilent') -and $deployModeSilent) {
            Write-Log -Message "Bypassing Show-InstallationPrompt [Mode: $deployMode]. Message:$Message" -Source ${CmdletName}
            Return
        }

        ## Get parameters for calling function asynchronously
        [Hashtable]$installPromptParameters = $PSBoundParameters

        ## Check if the countdown was specified
        If ($timeout -gt (Get-ADTSession).GetConfig().UI_Options.InstallationUI_Timeout) {
            [String]$CountdownTimeoutErr = 'The installation UI dialog timeout cannot be longer than the timeout specified in the XML configuration file.'
            Write-Log -Message $CountdownTimeoutErr -Severity 3 -Source ${CmdletName}
            Throw $CountdownTimeoutErr
        }

        ## If the NoWait parameter is specified, launch a new PowerShell session to show the prompt asynchronously
        If ($NoWait) {
            # Remove the NoWait parameter so that the script is run synchronously in the new PowerShell session. This also prevents the function to loop indefinitely.
            $installPromptParameters.Remove('NoWait')
            # Format the parameters as a string
            [String]$installPromptParameters = ($installPromptParameters.GetEnumerator() | Resolve-Parameters) -join ' '


            Start-Process -FilePath ([System.Diagnostics.Process]::GetCurrentProcess().Path) -ArgumentList "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & {& `'$scriptPath`' -ReferredInstallTitle `'$Title`' -ReferredInstallName `'$installName`' -ReferredLogName `'$logName`' -ShowInstallationPrompt $installPromptParameters -AsyncToolkitLaunch}" -WindowStyle 'Hidden' -ErrorAction 'SilentlyContinue'
            Return
        }

        [Windows.Forms.Application]::EnableVisualStyles()
        $formInstallationPrompt = New-Object -TypeName 'System.Windows.Forms.Form'
        $formInstallationPrompt.SuspendLayout()
        $pictureBanner = New-Object -TypeName 'System.Windows.Forms.PictureBox'
        If ($Icon -ne 'None') {
            $pictureIcon = New-Object -TypeName 'System.Windows.Forms.PictureBox'
        }
        $labelText = New-Object -TypeName 'System.Windows.Forms.Label'
        $buttonRight = New-Object -TypeName 'System.Windows.Forms.Button'
        $buttonMiddle = New-Object -TypeName 'System.Windows.Forms.Button'
        $buttonLeft = New-Object -TypeName 'System.Windows.Forms.Button'
        $buttonAbort = New-Object -TypeName 'System.Windows.Forms.Button'
        $flowLayoutPanel = New-Object -TypeName 'System.Windows.Forms.FlowLayoutPanel'
        $panelButtons = New-Object -TypeName 'System.Windows.Forms.Panel'

        [ScriptBlock]$Install_Prompt_Form_Cleanup_FormClosed = {
            ## Remove all event handlers from the controls
            Try {
                $installPromptTimer.Dispose()
                $installPromptTimer = $null
                $installPromptTimerPersist.remove_Tick($installPromptTimerPersist_Tick)
                $installPromptTimerPersist.Dispose()
                $installPromptTimerPersist = $null
                $formInstallationPrompt.remove_Load($Install_Prompt_Form_StateCorrection_Load)
                $formInstallationPrompt.remove_FormClosed($Install_Prompt_Form_Cleanup_FormClosed)
            }
            Catch {
            }
        }

        [ScriptBlock]$Install_Prompt_Form_StateCorrection_Load = {
            # Disable the X button
            Try {
                $windowHandle = $formInstallationPrompt.Handle
                If ($windowHandle -and ($windowHandle -ne [IntPtr]::Zero)) {
                    $menuHandle = [PSADT.UiAutomation]::GetSystemMenu($windowHandle, $false)
                    If ($menuHandle -and ($menuHandle -ne [IntPtr]::Zero)) {
                        [PSADT.UiAutomation]::EnableMenuItem($menuHandle, 0xF060, 0x00000001)
                        [PSADT.UiAutomation]::DestroyMenu($menuHandle)
                    }
                }
            }
            Catch {
                # Not a terminating error if we can't disable the button. Just disable the Control Box instead
                Write-Log 'Failed to disable the Close button. Disabling the Control Box instead.' -Severity 2 -Source ${CmdletName}
                $formInstallationPrompt.ControlBox = $false
            }
            # Get the start position of the form so we can return the form to this position if PersistPrompt is enabled
            Set-Variable -Name 'formInstallationPromptStartPosition' -Value $formInstallationPrompt.Location -Scope 'Script'
        }

        ## Form

        ##----------------------------------------------
        ## Create padding object
        $paddingNone = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 0, 0, 0)

        ## Default control size
        $DefaultControlSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 0)

        ## Generic Button properties
        $buttonSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (130, 24)

        ## Picture Banner
        $pictureBanner.DataBindings.DefaultDataSourceUpdateMode = 0
        $pictureBanner.ImageLocation = (Get-ADTSession).GetConfig().BannerIcon_Options.Banner_Filename
        $pictureBanner.ClientSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, (Get-ADTSession).Session.BannerHeight)
        $pictureBanner.MinimumSize = $DefaultControlSize
        $pictureBanner.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
        $pictureBanner.Margin = $paddingNone
        $pictureBanner.TabStop = $false
        $pictureBanner.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, 0)

        ## Picture Icon
        If ($Icon -ne 'None') {
            $pictureIcon.DataBindings.DefaultDataSourceUpdateMode = 0
            $pictureIcon.Image = ([Drawing.SystemIcons]::$Icon).ToBitmap()
            $pictureIcon.Name = 'pictureIcon'
            $pictureIcon.MinimumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (64, 32)
            $pictureIcon.ClientSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (64, 32)
            $pictureIcon.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (24, 0, 8, 0)
            $pictureIcon.SizeMode = 'CenterImage'
            $pictureIcon.TabStop = $false
            $pictureIcon.Anchor = 'None'
            $pictureIcon.Margin = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 10, 0, 5)
        }

        ## Label Text
        $labelText.DataBindings.DefaultDataSourceUpdateMode = 0
        $labelText.Font = $defaultFont
        $labelText.Name = 'labelText'
        $System_Drawing_Size = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (386, 0)
        $labelText.ClientSize = $System_Drawing_Size
        If ($Icon -ne 'None') {
            $labelText.MinimumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (386, $pictureIcon.Height)
        }
        Else {
            $labelText.MinimumSize = $System_Drawing_Size
        }
        $labelText.MaximumSize = $System_Drawing_Size
        $labelText.Margin = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 10, 0, 5)
        $labelText.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (20, 0, 20, 0)
        $labelText.TabStop = $false
        $labelText.Text = $message
        $labelText.TextAlign = "Middle$($MessageAlignment)"
        $labelText.Anchor = 'None'
        $labelText.AutoSize = $true

        If ($Icon -ne 'None') {
            # Add margin for the icon based on labelText Height so its centered
            $pictureIcon.Height = $labelText.Height
        }
        ## Button Left
        $buttonLeft.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonLeft.Name = 'buttonLeft'
        $buttonLeft.Font = $defaultFont
        $buttonLeft.ClientSize = $buttonSize
        $buttonLeft.MinimumSize = $buttonSize
        $buttonLeft.MaximumSize = $buttonSize
        $buttonLeft.TabIndex = 0
        $buttonLeft.Text = $buttonLeftText
        $buttonLeft.DialogResult = 'No'
        $buttonLeft.AutoSize = $false
        $buttonLeft.Margin = $paddingNone
        $buttonLeft.Padding = $paddingNone
        $buttonLeft.UseVisualStyleBackColor = $true
        $buttonLeft.Location = '14,4'

        ## Button Middle
        $buttonMiddle.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonMiddle.Name = 'buttonMiddle'
        $buttonMiddle.Font = $defaultFont
        $buttonMiddle.ClientSize = $buttonSize
        $buttonMiddle.MinimumSize = $buttonSize
        $buttonMiddle.MaximumSize = $buttonSize
        $buttonMiddle.TabIndex = 1
        $buttonMiddle.Text = $buttonMiddleText
        $buttonMiddle.DialogResult = 'Ignore'
        $buttonMiddle.AutoSize = $true
        $buttonMiddle.Margin = $paddingNone
        $buttonMiddle.Padding = $paddingNone
        $buttonMiddle.UseVisualStyleBackColor = $true
        $buttonMiddle.Location = '160,4'

        ## Button Right
        $buttonRight.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonRight.Name = 'buttonRight'
        $buttonRight.Font = $defaultFont
        $buttonRight.ClientSize = $buttonSize
        $buttonRight.MinimumSize = $buttonSize
        $buttonRight.MaximumSize = $buttonSize
        $buttonRight.TabIndex = 2
        $buttonRight.Text = $ButtonRightText
        $buttonRight.DialogResult = 'Yes'
        $buttonRight.AutoSize = $true
        $buttonRight.Margin = $paddingNone
        $buttonRight.Padding = $paddingNone
        $buttonRight.UseVisualStyleBackColor = $true
        $buttonRight.Location = '306,4'

        ## Button Abort (Hidden)
        $buttonAbort.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonAbort.Name = 'buttonAbort'
        $buttonAbort.Font = $defaultFont
        $buttonAbort.ClientSize = '0,0'
        $buttonAbort.MinimumSize = '0,0'
        $buttonAbort.MaximumSize = '0,0'
        $buttonAbort.BackColor = [System.Drawing.Color]::Transparent
        $buttonAbort.ForeColor = [System.Drawing.Color]::Transparent
        $buttonAbort.FlatAppearance.BorderSize = 0
        $buttonAbort.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::Transparent
        $buttonAbort.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::Transparent
        $buttonAbort.FlatStyle = [System.Windows.Forms.FlatStyle]::System
        $buttonAbort.DialogResult = 'Abort'
        $buttonAbort.TabStop = $false
        $buttonAbort.Visible = $true # Has to be set visible so we can call Click on it
        $buttonAbort.Margin = $paddingNone
        $buttonAbort.Padding = $paddingNone
        $buttonAbort.UseVisualStyleBackColor = $true

        ## FlowLayoutPanel
        $flowLayoutPanel.MinimumSize = $DefaultControlSize
        $flowLayoutPanel.MaximumSize = $DefaultControlSize
        $flowLayoutPanel.ClientSize = $DefaultControlSize
        $flowLayoutPanel.AutoSize = $true
        $flowLayoutPanel.AutoSizeMode = 'GrowAndShrink'
        $flowLayoutPanel.Anchor = 'Top,Left'
        $flowLayoutPanel.FlowDirection = 'LeftToRight'
        $flowLayoutPanel.WrapContents = $true
        $flowLayoutPanel.Margin = $paddingNone
        $flowLayoutPanel.Padding = $paddingNone
        ## Make sure label text is positioned correctly
        If ($Icon -ne 'None') {
            $labelText.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 0, 10, 0)
            $pictureIcon.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, 0)
            $labelText.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (64, 0)
        }
        Else {
            $labelText.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (10, 0, 10, 0)
            $labelText.MinimumSize = $DefaultControlSize
            $labelText.MaximumSize = $DefaultControlSize
            $labelText.ClientSize = $DefaultControlSize
            $labelText.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, 0)
        }
        If ($Icon -ne 'None') {
            $flowLayoutPanel.Controls.Add($pictureIcon)
        }
        $flowLayoutPanel.Controls.Add($labelText)
        $flowLayoutPanel.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, $appDeployLogoBannerHeight)

        ## ButtonsPanel
        $panelButtons.MinimumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        $panelButtons.ClientSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        If ($Icon -ne 'None') {
            $panelButtons.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (64, 0)
        }
        Else {
            $panelButtons.Padding = $paddingNone
        }
        $panelButtons.Margin = $paddingNone
        $panelButtons.MaximumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        $panelButtons.AutoSize = $true
        If ($buttonLeftText) {
            $panelButtons.Controls.Add($buttonLeft)
        }
        If ($buttonMiddleText) {
            $panelButtons.Controls.Add($buttonMiddle)
        }
        If ($buttonRightText) {
            $panelButtons.Controls.Add($buttonRight)
        }
        ## Add the ButtonsPanel to the flowLayoutPanel if any buttons are present
        If ($buttonLeftText -or $buttonMiddleText -or $buttonRightText) {
            $flowLayoutPanel.Controls.Add($panelButtons)
        }

        ## Form Installation Prompt
        $formInstallationPrompt.ClientSize = $DefaultControlSize
        $formInstallationPrompt.Padding = $paddingNone
        $formInstallationPrompt.Margin = $paddingNone
        $formInstallationPrompt.DataBindings.DefaultDataSourceUpdateMode = 0
        $formInstallationPrompt.Name = 'InstallPromptForm'
        $formInstallationPrompt.Text = $title
        $formInstallationPrompt.StartPosition = 'CenterScreen'
        $formInstallationPrompt.FormBorderStyle = 'Fixed3D'
        $formInstallationPrompt.MaximizeBox = $false
        $formInstallationPrompt.MinimizeBox = $false
        $formInstallationPrompt.TopMost = $TopMost
        $formInstallationPrompt.TopLevel = $true
        $formInstallationPrompt.AutoSize = $true
        $formInstallationPrompt.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
        $formInstallationPrompt.AutoScaleDimensions = New-Object System.Drawing.SizeF(96,96)
        $formInstallationPrompt.Icon = New-Object -TypeName 'System.Drawing.Icon' -ArgumentList (Get-ADTSession).GetConfig().BannerIcon_Options.Icon_Filename
        $formInstallationPrompt.Controls.Add($pictureBanner)
        $formInstallationPrompt.Controls.Add($buttonAbort)
        $formInstallationPrompt.Controls.Add($flowLayoutPanel)
        ## Timer
        $installPromptTimer = New-Object -TypeName 'System.Windows.Forms.Timer'
        $installPromptTimer.Interval = ($timeout * 1000)
        $installPromptTimer.Add_Tick({
                Write-Log -Message 'Installation action not taken within a reasonable amount of time.' -Source ${CmdletName}
                $buttonAbort.PerformClick()
            })
        ## Init the OnLoad event to correct the initial state of the form
        $formInstallationPrompt.add_Load($Install_Prompt_Form_StateCorrection_Load)
        ## Clean up the control events
        $formInstallationPrompt.add_FormClosed($Install_Prompt_Form_Cleanup_FormClosed)

        ## Start the timer
        $installPromptTimer.Start()

        ## Persistence Timer
        If ($persistPrompt) {
            $installPromptTimerPersist = New-Object -TypeName 'System.Windows.Forms.Timer'
            $installPromptTimerPersist.Interval = ((Get-ADTSession).GetConfig().UI_Options.InstallationPrompt_PersistInterval * 1000)
            [ScriptBlock]$installPromptTimerPersist_Tick = {
                $formInstallationPrompt.WindowState = 'Normal'
                $formInstallationPrompt.TopMost = $TopMost
                $formInstallationPrompt.BringToFront()
                $formInstallationPrompt.Location = "$($formInstallationPromptStartPosition.X),$($formInstallationPromptStartPosition.Y)"
            }
            $installPromptTimerPersist.add_Tick($installPromptTimerPersist_Tick)
            $installPromptTimerPersist.Start()
        }

        If (-not $AsyncToolkitLaunch) {
            ## Close the Installation Progress Dialog if running
            Close-InstallationProgress
        }

        [String]$installPromptLoggedParameters = ($installPromptParameters.GetEnumerator() | Resolve-Parameters) -join ' '
        Write-Log -Message "Displaying custom installation prompt with the parameters: [$installPromptLoggedParameters]." -Source ${CmdletName}


        ## Show the prompt synchronously. If user cancels, then keep showing it until user responds using one of the buttons.
        $showDialog = $true
        While ($showDialog) {
            # Minimize all other windows
            If ($minimizeWindows) {
                $null = (Get-ADTSession).Session.ShellApp.MinimizeAll()
            }
            # Show the Form
            $formInstallationPrompt.ResumeLayout()
            $result = $formInstallationPrompt.ShowDialog()
            If (($result -eq 'Yes') -or ($result -eq 'No') -or ($result -eq 'Ignore') -or ($result -eq 'Abort')) {
                $showDialog = $false
            }
        }
        $formInstallationPrompt.Dispose()

        Switch ($result) {
            'Yes' {
                Write-Output -InputObject ($buttonRightText)
            }
            'No' {
                Write-Output -InputObject ($buttonLeftText)
            }
            'Ignore' {
                Write-Output -InputObject ($buttonMiddleText)
            }
            'Abort' {
                # Restore minimized windows
                $null = (Get-ADTSession).Session.ShellApp.UndoMinimizeAll()
                If ($ExitOnTimeout) {
                    Exit-Script -ExitCode (Get-ADTSession).GetConfig().UI_Options.InstallationUI_ExitCode
                }
                Else {
                    Write-Log -Message 'UI timed out but `$ExitOnTimeout set to `$false. Continue...' -Source ${CmdletName}
                }
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-DialogBox
{
    <#

    .SYNOPSIS
    Display a custom dialog box with optional title, buttons, icon and timeout.

    Show-InstallationPrompt is recommended over this function as it provides more customization and uses consistent branding with the other UI components.

    .DESCRIPTION
    Display a custom dialog box with optional title, buttons, icon and timeout. The default button is "OK", the default Icon is "None", and the default Timeout is None

    .PARAMETER Text
    Text in the message dialog box

    .PARAMETER Title
    Title of the message dialog box

    .PARAMETER Buttons
    Buttons to be included on the dialog box. Options: OK, OKCancel, AbortRetryIgnore, YesNoCancel, YesNo, RetryCancel, CancelTryAgainContinue. Default: OK.

    .PARAMETER DefaultButton
    The Default button that is selected. Options: First, Second, Third. Default: First.

    .PARAMETER Icon
    Icon to display on the dialog box. Options: None, Stop, Question, Exclamation, Information. Default: None

    .PARAMETER Timeout
    Timeout period in seconds before automatically closing the dialog box with the return message "Timeout". Default: UI timeout value set in the config XML file.

    .PARAMETER TopMost
    Specifies whether the message box is a system modal message box and appears in a topmost window. Default: $true.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    System.String. Returns the text of the button that was clicked.

    .EXAMPLE
    Show-DialogBox -Title 'Installed Complete' -Text 'Installation has completed. Please click OK and restart your computer.' -Icon 'Information'

    .EXAMPLE
    Show-DialogBox -Title 'Installation Notice' -Text 'Installation will take approximately 30 minutes. Do you wish to proceed?' -Buttons 'OKCancel' -DefaultButton 'Second' -Icon 'Exclamation' -Timeout 600 -Topmost $false

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Enter a message for the dialog box')]
        [ValidateNotNullorEmpty()]
        [String]$Text,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$Title = (Get-ADTSession).GetPropertyValue('InstallTitle'),
        [Parameter(Mandatory = $false)]
        [ValidateSet('OK', 'OKCancel', 'AbortRetryIgnore', 'YesNoCancel', 'YesNo', 'RetryCancel', 'CancelTryAgainContinue')]
        [String]$Buttons = 'OK',
        [Parameter(Mandatory = $false)]
        [ValidateSet('First', 'Second', 'Third')]
        [String]$DefaultButton = 'First',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Exclamation', 'Information', 'None', 'Stop', 'Question')]
        [String]$Icon = 'None',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$Timeout = (Get-ADTSession).GetConfig().UI_Options.InstallationUI_Timeout,
        [Parameter(Mandatory = $false)]
        [Boolean]$TopMost = $true
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        #  Bypass if in silent mode
        If ($deployModeSilent) {
            Write-Log -Message "Bypassing Show-DialogBox [Mode: $deployMode]. Text:$Text" -Source ${CmdletName}
            Return
        }

        Write-Log -Message "Displaying Dialog Box with message: $Text..." -Source ${CmdletName}

        [Hashtable]$dialogButtons = @{
            'OK'                     = 0
            'OKCancel'               = 1
            'AbortRetryIgnore'       = 2
            'YesNoCancel'            = 3
            'YesNo'                  = 4
            'RetryCancel'            = 5
            'CancelTryAgainContinue' = 6
        }

        [Hashtable]$dialogIcons = @{
            'None'        = 0
            'Stop'        = 16
            'Question'    = 32
            'Exclamation' = 48
            'Information' = 64
        }

        [Hashtable]$dialogDefaultButton = @{
            'First'  = 0
            'Second' = 256
            'Third'  = 512
        }

        Switch ($TopMost) {
            $true {
                $dialogTopMost = 4096
            }
            $false {
                $dialogTopMost = 0
            }
        }

        $response = $Shell.Popup($Text, $Timeout, $Title, ($dialogButtons[$Buttons] + $dialogIcons[$Icon] + $dialogDefaultButton[$DefaultButton] + $dialogTopMost))

        Switch ($response) {
            1 {
                Write-Log -Message 'Dialog Box Response: OK' -Source ${CmdletName}
                Write-Output -InputObject ('OK')
            }
            2 {
                Write-Log -Message 'Dialog Box Response: Cancel' -Source ${CmdletName}
                Write-Output -InputObject ('Cancel')
            }
            3 {
                Write-Log -Message 'Dialog Box Response: Abort' -Source ${CmdletName}
                Write-Output -InputObject ('Abort')
            }
            4 {
                Write-Log -Message 'Dialog Box Response: Retry' -Source ${CmdletName}
                Write-Output -InputObject ('Retry')
            }
            5 {
                Write-Log -Message 'Dialog Box Response: Ignore' -Source ${CmdletName}
                Write-Output -InputObject ('Ignore')
            }
            6 {
                Write-Log -Message 'Dialog Box Response: Yes' -Source ${CmdletName}
                Write-Output -InputObject ('Yes')
            }
            7 {
                Write-Log -Message 'Dialog Box Response: No' -Source ${CmdletName}
                Write-Output -InputObject ('No')
            }
            10 {
                Write-Log -Message 'Dialog Box Response: Try Again' -Source ${CmdletName}
                Write-Output -InputObject ('Try Again')
            }
            11 {
                Write-Log -Message 'Dialog Box Response: Continue' -Source ${CmdletName}
                Write-Output -InputObject ('Continue')
            }
            -1 {
                Write-Log -Message 'Dialog Box Timed Out...' -Source ${CmdletName}
                Write-Output -InputObject ('Timeout')
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-InstallationWelcome
{
    <#

    .SYNOPSIS
    Show a welcome dialog prompting the user with information about the installation and actions to be performed before the installation can begin.

    .DESCRIPTION
    The following prompts can be included in the welcome dialog:
        a) Close the specified running applications, or optionally close the applications without showing a prompt (using the -Silent switch).
        b) Defer the installation a certain number of times, for a certain number of days or until a deadline is reached.
        c) Countdown until applications are automatically closed.
        d) Prevent users from launching the specified applications while the installation is in progress.

    Notes:
        The process descriptions are retrieved from WMI, with a fall back on the process name if no description is available. Alternatively, you can specify the description yourself with a '=' symbol - see examples.
        The dialog box will timeout after the timeout specified in the XML configuration file (default 1 hour and 55 minutes) to prevent SCCM installations from timing out and returning a failure code to SCCM. When the dialog times out, the script will exit and return a 1618 code (SCCM fast retry code).

    .PARAMETER CloseApps
    Name of the process to stop (do not include the .exe). Specify multiple processes separated by a comma. Specify custom descriptions like this: "winword=Microsoft Office Word,excel=Microsoft Office Excel"

    .PARAMETER Silent
    Stop processes without prompting the user.

    .PARAMETER CloseAppsCountdown
    Option to provide a countdown in seconds until the specified applications are automatically closed. This only takes effect if deferral is not allowed or has expired.

    .PARAMETER ForceCloseAppsCountdown
    Option to provide a countdown in seconds until the specified applications are automatically closed regardless of whether deferral is allowed.

    .PARAMETER PromptToSave
    Specify whether to prompt to save working documents when the user chooses to close applications by selecting the "Close Programs" button. Option does not work in SYSTEM context unless toolkit launched with "psexec.exe -s -i" to run it as an interactive process under the SYSTEM account.

    .PARAMETER PersistPrompt
    Specify whether to make the Show-InstallationWelcome prompt persist in the center of the screen every couple of seconds, specified in the AppDeployToolkitConfig.xml. The user will have no option but to respond to the prompt. This only takes effect if deferral is not allowed or has expired.

    .PARAMETER BlockExecution
    Option to prevent the user from launching processes/applications, specified in -CloseApps, during the installation.

    .PARAMETER AllowDefer
    Enables an optional defer button to allow the user to defer the installation.

    .PARAMETER AllowDeferCloseApps
    Enables an optional defer button to allow the user to defer the installation only if there are running applications that need to be closed. This parameter automatically enables -AllowDefer

    .PARAMETER DeferTimes
    Specify the number of times the installation can be deferred.

    .PARAMETER DeferDays
    Specify the number of days since first run that the installation can be deferred. This is converted to a deadline.

    .PARAMETER DeferDeadline
    Specify the deadline date until which the installation can be deferred.

    Specify the date in the local culture if the script is intended for that same culture.

    If the script is intended to run on EN-US machines, specify the date in the format: "08/25/2013" or "08-25-2013" or "08-25-2013 18:00:00"

    If the script is intended for multiple cultures, specify the date in the universal sortable date/time format: "2013-08-22 11:51:52Z"

    The deadline date will be displayed to the user in the format of their culture.

    .PARAMETER CheckDiskSpace
    Specify whether to check if there is enough disk space for the installation to proceed.

    If this parameter is specified without the RequiredDiskSpace parameter, the required disk space is calculated automatically based on the size of the script source and associated files.

    .PARAMETER RequiredDiskSpace
    Specify required disk space in MB, used in combination with CheckDiskSpace.

    .PARAMETER MinimizeWindows
    Specifies whether to minimize other windows when displaying prompt. Default: $true.

    .PARAMETER TopMost
    Specifies whether the windows is the topmost window. Default: $true.

    .PARAMETER ForceCountdown
    Specify a countdown to display before automatically proceeding with the installation when a deferral is enabled.

    .PARAMETER CustomText
    Specify whether to display a custom message specified in the XML file. Custom message must be populated for each language section in the XML.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    None. This function does not return objects.

    .EXAMPLE
    # Prompt the user to close Internet Explorer, Word and Excel.
    Show-InstallationWelcome -CloseApps 'iexplore,winword,excel'

    .EXAMPLE
    # Close Word and Excel without prompting the user.
    Show-InstallationWelcome -CloseApps 'winword,excel' -Silent

    .EXAMPLE
    # Close Word and Excel and prevent the user from launching the applications while the installation is in progress.
    Show-InstallationWelcome -CloseApps 'winword,excel' -BlockExecution

    .EXAMPLE
    # Prompt the user to close Word and Excel, with customized descriptions for the applications and automatically close the applications after 10 minutes.
    Show-InstallationWelcome -CloseApps 'winword=Microsoft Office Word,excel=Microsoft Office Excel' -CloseAppsCountdown 600

    .EXAMPLE
    # Prompt the user to close Word, MSAccess and Excel.
    # By using the PersistPrompt switch, the dialog will return to the center of the screen every couple of seconds, specified in the AppDeployToolkitConfig.xml, so the user cannot ignore it by dragging it aside.
    Show-InstallationWelcome -CloseApps 'winword,msaccess,excel' -PersistPrompt

    .EXAMPLE
    # Allow the user to defer the installation until the deadline is reached.
    Show-InstallationWelcome -AllowDefer -DeferDeadline '25/08/2013'

    .EXAMPLE
    # Close Word and Excel and prevent the user from launching the applications while the installation is in progress.
    # Allow the user to defer the installation a maximum of 10 times or until the deadline is reached, whichever happens first.
    # When deferral expires, prompt the user to close the applications and automatically close them after 10 minutes.
    Show-InstallationWelcome -CloseApps 'winword,excel' -BlockExecution -AllowDefer -DeferTimes 10 -DeferDeadline '25/08/2013' -CloseAppsCountdown 600

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding(DefaultParametersetName = 'None')]
    Param (
        ## Specify process names separated by commas. Optionally specify a process description with an equals symbol, e.g. "winword=Microsoft Office Word"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$CloseApps,
        ## Specify whether to prompt user or force close the applications
        [Parameter(Mandatory = $false)]
        [Switch]$Silent = $false,
        ## Specify a countdown to display before automatically closing applications where deferral is not allowed or has expired
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$CloseAppsCountdown = 0,
        ## Specify a countdown to display before automatically closing applications whether or not deferral is allowed
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$ForceCloseAppsCountdown = 0,
        ## Specify whether to prompt to save working documents when the user chooses to close applications by selecting the "Close Programs" button
        [Parameter(Mandatory = $false)]
        [Switch]$PromptToSave = $false,
        ## Specify whether to make the prompt persist in the center of the screen every couple of seconds, specified in the AppDeployToolkitConfig.xml.
        [Parameter(Mandatory = $false)]
        [Switch]$PersistPrompt = $false,
        ## Specify whether to block execution of the processes during installation
        [Parameter(Mandatory = $false)]
        [Switch]$BlockExecution = $false,
        ## Specify whether to enable the optional defer button on the dialog box
        [Parameter(Mandatory = $false)]
        [Switch]$AllowDefer = $false,
        ## Specify whether to enable the optional defer button on the dialog box only if an app needs to be closed
        [Parameter(Mandatory = $false)]
        [Switch]$AllowDeferCloseApps = $false,
        ## Specify the number of times the deferral is allowed
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$DeferTimes = 0,
        ## Specify the number of days since first run that the deferral is allowed
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$DeferDays = 0,
        ## Specify the deadline (in format dd/mm/yyyy) for which deferral will expire as an option
        [Parameter(Mandatory = $false)]
        [String]$DeferDeadline = '',
        ## Specify whether to check if there is enough disk space for the installation to proceed. If this parameter is specified without the RequiredDiskSpace parameter, the required disk space is calculated automatically based on the size of the script source and associated files.
        [Parameter(ParameterSetName = 'CheckDiskSpaceParameterSet', Mandatory = $true)]
        [ValidateScript({ $_.IsPresent -eq ($true -or $false) })]
        [Switch]$CheckDiskSpace,
        ## Specify required disk space in MB, used in combination with $CheckDiskSpace.
        [Parameter(ParameterSetName = 'CheckDiskSpaceParameterSet', Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$RequiredDiskSpace = 0,
        ## Specify whether to minimize other windows when displaying prompt
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$MinimizeWindows = $true,
        ## Specifies whether the window is the topmost window
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$TopMost = $true,
        ## Specify a countdown to display before automatically proceeding with the installation when a deferral is enabled
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$ForceCountdown = 0,
        ## Specify whether to display a custom message specified in the XML file. Custom message must be populated for each language section in the XML.
        [Parameter(Mandatory = $false)]
        [Switch]$CustomText = $false
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        ## If running in NonInteractive mode, force the processes to close silently
        If ((Get-ADTSession).Session.State.DeployModeNonInteractive) {
            $Silent = $true
        }

        ## If using Zero-Config MSI Deployment, append any executables found in the MSI to the CloseApps list
        If ((Get-ADTSession).GetPropertyValue('UseDefaultMsi')) {
            $CloseApps = "$CloseApps,$defaultMsiExecutablesList"
        }

        ## Check disk space requirements if specified
        If ($CheckDiskSpace) {
            Write-Log -Message 'Evaluating disk space requirements.' -Source ${CmdletName}
            [Double]$freeDiskSpace = Get-FreeDiskSpace
            If ($RequiredDiskSpace -eq 0) {
                Try {
                    #  Determine the size of the Files folder
                    $fso = New-Object -ComObject 'Scripting.FileSystemObject' -ErrorAction 'Stop'
                    $RequiredDiskSpace = [Math]::Round((($fso.GetFolder((Get-ADTSession).GetPropertyValue('ScriptParentPath')).Size) / 1MB))
                }
                Catch {
                    Write-Log -Message "Failed to calculate disk space requirement from source files. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                }
                Finally {
                    Try {
                        $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($fso)
                    }
                    Catch {
                    }
                }
            }
            If ($freeDiskSpace -lt $RequiredDiskSpace) {
                Write-Log -Message "Failed to meet minimum disk space requirement. Space Required [$RequiredDiskSpace MB], Space Available [$freeDiskSpace MB]." -Severity 3 -Source ${CmdletName}
                If (-not $Silent) {
                    Show-InstallationPrompt -Message ((Get-ADTSession).GetUiMessages().DiskSpace_Message -f $installTitle, $RequiredDiskSpace, ($freeDiskSpace)) -ButtonRightText 'OK' -Icon 'Error'
                }
                Exit-Script -ExitCode (Get-ADTSession).GetConfig().UI_Options.InstallationUI_ExitCode
            }
            Else {
                Write-Log -Message 'Successfully passed minimum disk space requirement check.' -Source ${CmdletName}
            }
        }

        ## Create a Process object with custom descriptions where they are provided (split on an '=' sign)
        [PSObject[]]$processObjects = If ($CloseApps) {
            #  Split multiple processes on a comma, then split on equal sign, then create custom object with process name and description
            ForEach ($process in ($CloseApps -split ',' | Where-Object { $_ })) {
                If ($process.Contains('=')) {
                    [String[]]$ProcessSplit = $process -split '='
                    New-Object -TypeName 'PSObject' -Property @{
                        ProcessName        = $ProcessSplit[0]
                        ProcessDescription = $ProcessSplit[1]
                    }
                }
                Else {
                    [String]$ProcessInfo = $process
                    New-Object -TypeName 'PSObject' -Property @{
                        ProcessName        = $process
                        ProcessDescription = ''
                    }
                }
            }
        }

        ## Check Deferral history and calculate remaining deferrals
        [String]$deferDeadlineUniversal = $null
        If (($allowDefer) -or ($AllowDeferCloseApps)) {
            #  Set $allowDefer to true if $AllowDeferCloseApps is true
            $allowDefer = $true

            #  Get the deferral history from the registry
            $deferHistory = Get-DeferHistory
            $deferHistoryTimes = $deferHistory | Select-Object -ExpandProperty 'DeferTimesRemaining' -ErrorAction 'SilentlyContinue'
            $deferHistoryDeadline = $deferHistory | Select-Object -ExpandProperty 'DeferDeadline' -ErrorAction 'SilentlyContinue'

            #  Reset Switches
            $checkDeferDays = $false
            $checkDeferDeadline = $false
            If ($DeferDays -ne 0) {
                $checkDeferDays = $true
            }
            If ($DeferDeadline) {
                $checkDeferDeadline = $true
            }
            If ($DeferTimes -ne 0) {
                If ($deferHistoryTimes -ge 0) {
                    Write-Log -Message "Defer history shows [$($deferHistory.DeferTimesRemaining)] deferrals remaining." -Source ${CmdletName}
                    $DeferTimes = $deferHistory.DeferTimesRemaining - 1
                }
                Else {
                    $DeferTimes = $DeferTimes - 1
                }
                Write-Log -Message "The user has [$deferTimes] deferrals remaining." -Source ${CmdletName}
                If ($DeferTimes -lt 0) {
                    Write-Log -Message 'Deferral has expired.' -Source ${CmdletName}
                    $AllowDefer = $false
                }
            }
            Else {
                If (Test-Path -LiteralPath 'variable:deferTimes') {
                    Remove-Variable -Name 'deferTimes'
                }
                $DeferTimes = $null
            }
            If ($checkDeferDays -and $allowDefer) {
                If ($deferHistoryDeadline) {
                    Write-Log -Message "Defer history shows a deadline date of [$deferHistoryDeadline]." -Source ${CmdletName}
                    [String]$deferDeadlineUniversal = Get-UniversalDate -DateTime $deferHistoryDeadline
                }
                Else {
                    [String]$deferDeadlineUniversal = Get-UniversalDate -DateTime (Get-Date -Date ((Get-Date).AddDays($deferDays)) -Format ($culture).DateTimeFormat.UniversalDateTimePattern).ToString()
                }
                Write-Log -Message "The user has until [$deferDeadlineUniversal] before deferral expires." -Source ${CmdletName}
                If ((Get-UniversalDate) -gt $deferDeadlineUniversal) {
                    Write-Log -Message 'Deferral has expired.' -Source ${CmdletName}
                    $AllowDefer = $false
                }
            }
            If ($checkDeferDeadline -and $allowDefer) {
                #  Validate Date
                Try {
                    [String]$deferDeadlineUniversal = Get-UniversalDate -DateTime $deferDeadline -ErrorAction 'Stop'
                }
                Catch {
                    Write-Log -Message "Date is not in the correct format for the current culture. Type the date in the current locale format, such as 20/08/2014 (Europe) or 08/20/2014 (United States). If the script is intended for multiple cultures, specify the date in the universal sortable date/time format, e.g. '2013-08-22 11:51:52Z'. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                    Throw "Date is not in the correct format for the current culture. Type the date in the current locale format, such as 20/08/2014 (Europe) or 08/20/2014 (United States). If the script is intended for multiple cultures, specify the date in the universal sortable date/time format, e.g. '2013-08-22 11:51:52Z': $($_.Exception.Message)"
                }
                Write-Log -Message "The user has until [$deferDeadlineUniversal] remaining." -Source ${CmdletName}
                If ((Get-UniversalDate) -gt $deferDeadlineUniversal) {
                    Write-Log -Message 'Deferral has expired.' -Source ${CmdletName}
                    $AllowDefer = $false
                }
            }
        }
        If (($deferTimes -lt 0) -and (-not $deferDeadlineUniversal)) {
            $AllowDefer = $false
        }

        ## Prompt the user to close running applications and optionally defer if enabled
        If (!(Get-ADTSession).Session.State.DeployModeSilent -and !$Silent) {
            If ($forceCloseAppsCountdown -gt 0) {
                #  Keep the same variable for countdown to simplify the code:
                $closeAppsCountdown = $forceCloseAppsCountdown
                #  Change this variable to a boolean now to switch the countdown on even with deferral
                [Boolean]$forceCloseAppsCountdown = $true
            }
            ElseIf ($forceCountdown -gt 0) {
                #  Keep the same variable for countdown to simplify the code:
                $closeAppsCountdown = $forceCountdown
                #  Change this variable to a boolean now to switch the countdown on
                [Boolean]$forceCountdown = $true
            }
            Set-Variable -Name 'closeAppsCountdownGlobal' -Value $closeAppsCountdown -Scope 'Script'
            $promptResult = $null

            While ((Get-RunningProcesses -ProcessObjects $processObjects -OutVariable 'runningProcesses') -or (($promptResult -ne 'Defer') -and ($promptResult -ne 'Close'))) {
                [String]$runningProcessDescriptions = ($runningProcesses | Select-Object -ExpandProperty 'ProcessDescription' -ErrorAction SilentlyContinue | Sort-Object -Unique) -join ','
                #  Check if we need to prompt the user to defer, to defer and close apps, or not to prompt them at all
                If ($allowDefer) {
                    #  If there is deferral and closing apps is allowed but there are no apps to be closed, break the while loop
                    If ($AllowDeferCloseApps -and (-not $runningProcessDescriptions)) {
                        Break
                    }
                    #  Otherwise, as long as the user has not selected to close the apps or the processes are still running and the user has not selected to continue, prompt user to close running processes with deferral
                    ElseIf (($promptResult -ne 'Close') -or (($runningProcessDescriptions) -and ($promptResult -ne 'Continue'))) {
                        [String]$promptResult = Show-WelcomePrompt -ProcessDescriptions $runningProcessDescriptions -CloseAppsCountdown $closeAppsCountdownGlobal -ForceCloseAppsCountdown $forceCloseAppsCountdown -ForceCountdown $forceCountdown -PersistPrompt $PersistPrompt -AllowDefer -DeferTimes $deferTimes -DeferDeadline $deferDeadlineUniversal -MinimizeWindows $MinimizeWindows -CustomText:$CustomText -TopMost $TopMost
                    }
                }
                #  If there is no deferral and processes are running, prompt the user to close running processes with no deferral option
                ElseIf (($runningProcessDescriptions) -or ($forceCountdown)) {
                    [String]$promptResult = Show-WelcomePrompt -ProcessDescriptions $runningProcessDescriptions -CloseAppsCountdown $closeAppsCountdownGlobal -ForceCloseAppsCountdown $forceCloseAppsCountdown -ForceCountdown $forceCountdown -PersistPrompt $PersistPrompt -MinimizeWindows $minimizeWindows -CustomText:$CustomText -TopMost $TopMost
                }
                #  If there is no deferral and no processes running, break the while loop
                Else {
                    Break
                }

                #  If the user has clicked OK, wait a few seconds for the process to terminate before evaluating the running processes again
                If ($promptResult -eq 'Continue') {
                    Write-Log -Message 'The user selected to continue...' -Source ${CmdletName}
                    Start-Sleep -Seconds 2

                    #  Break the while loop if there are no processes to close and the user has clicked OK to continue
                    If (-not $runningProcesses) {
                        Break
                    }
                }
                #  Force the applications to close
                ElseIf ($promptResult -eq 'Close') {
                    Write-Log -Message 'The user selected to force the application(s) to close...' -Source ${CmdletName}
                    If (($PromptToSave) -and ($SessionZero -and (-not $IsProcessUserInteractive))) {
                        Write-Log -Message 'Specified [-PromptToSave] option will not be available, because current process is running in session zero and is not interactive.' -Severity 2 -Source ${CmdletName}
                    }
                    # Update the process list right before closing, in case it changed
                    $runningProcesses = Get-RunningProcesses -ProcessObjects $processObjects
                    # Close running processes
                    ForEach ($runningProcess in $runningProcesses) {
                        [PSObject[]]$AllOpenWindowsForRunningProcess = Get-WindowTitle -GetAllWindowTitles -DisableFunctionLogging | Where-Object { $_.ParentProcess -eq $runningProcess.ProcessName }
                        #  If the PromptToSave parameter was specified and the process has a window open, then prompt the user to save work if there is work to be saved when closing window
                        If (($PromptToSave) -and (-not ($SessionZero -and (-not $IsProcessUserInteractive))) -and ($AllOpenWindowsForRunningProcess) -and ($runningProcess.MainWindowHandle -ne [IntPtr]::Zero)) {
                            [Timespan]$PromptToSaveTimeout = New-TimeSpan -Seconds (Get-ADTSession).GetConfig().UI_Options.InstallationPromptToSave_Timeout
                            [Diagnostics.StopWatch]$PromptToSaveStopWatch = [Diagnostics.StopWatch]::StartNew()
                            $PromptToSaveStopWatch.Reset()
                            ForEach ($OpenWindow in $AllOpenWindowsForRunningProcess) {
                                Try {
                                    Write-Log -Message "Stopping process [$($runningProcess.ProcessName)] with window title [$($OpenWindow.WindowTitle)] and prompt to save if there is work to be saved (timeout in [$((Get-ADTSession).GetConfig().UI_Options.InstallationPromptToSave_Timeout)] seconds)..." -Source ${CmdletName}
                                    [Boolean]$IsBringWindowToFrontSuccess = [PSADT.UiAutomation]::BringWindowToFront($OpenWindow.WindowHandle)
                                    [Boolean]$IsCloseWindowCallSuccess = $runningProcess.CloseMainWindow()
                                    If (-not $IsCloseWindowCallSuccess) {
                                        Write-Log -Message "Failed to call the CloseMainWindow() method on process [$($runningProcess.ProcessName)] with window title [$($OpenWindow.WindowTitle)] because the main window may be disabled due to a modal dialog being shown." -Severity 3 -Source ${CmdletName}
                                    }
                                    Else {
                                        $PromptToSaveStopWatch.Start()
                                        Do {
                                            [Boolean]$IsWindowOpen = [Boolean](Get-WindowTitle -GetAllWindowTitles -DisableFunctionLogging | Where-Object { $_.WindowHandle -eq $OpenWindow.WindowHandle })
                                            If (-not $IsWindowOpen) {
                                                Break
                                            }
                                            Start-Sleep -Seconds 3
                                        } While (($IsWindowOpen) -and ($PromptToSaveStopWatch.Elapsed -lt $PromptToSaveTimeout))
                                        $PromptToSaveStopWatch.Reset()
                                        If ($IsWindowOpen) {
                                            Write-Log -Message "Exceeded the [$((Get-ADTSession).GetConfig().UI_Options.InstallationPromptToSave_Timeout)] seconds timeout value for the user to save work associated with process [$($runningProcess.ProcessName)] with window title [$($OpenWindow.WindowTitle)]." -Severity 2 -Source ${CmdletName}
                                        }
                                        Else {
                                            Write-Log -Message "Window [$($OpenWindow.WindowTitle)] for process [$($runningProcess.ProcessName)] was successfully closed." -Source ${CmdletName}
                                        }
                                    }
                                }
                                Catch {
                                    Write-Log -Message "Failed to close window [$($OpenWindow.WindowTitle)] for process [$($runningProcess.ProcessName)]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                                    Continue
                                }
                                Finally {
                                    $runningProcess.Refresh()
                                }
                            }
                        }
                        Else {
                            Write-Log -Message "Stopping process $($runningProcess.ProcessName)..." -Source ${CmdletName}
                            Stop-Process -Name $runningProcess.ProcessName -Force -ErrorAction 'SilentlyContinue'
                        }
                    }

                    If ($runningProcesses = Get-RunningProcesses -ProcessObjects $processObjects -DisableLogging) {
                        # Apps are still running, give them 2s to close. If they are still running, the Welcome Window will be displayed again
                        Write-Log -Message 'Sleeping for 2 seconds because the processes are still not closed...' -Source ${CmdletName}
                        Start-Sleep -Seconds 2
                    }
                }
                #  Stop the script (if not actioned before the timeout value)
                ElseIf ($promptResult -eq 'Timeout') {
                    Write-Log -Message 'Installation not actioned before the timeout value.' -Source ${CmdletName}
                    $BlockExecution = $false

                    If (($deferTimes -ge 0) -or ($deferDeadlineUniversal)) {
                        Set-DeferHistory -DeferTimesRemaining $DeferTimes -DeferDeadline $deferDeadlineUniversal
                    }
                    ## Dispose the welcome prompt timer here because if we dispose it within the Show-WelcomePrompt function we risk resetting the timer and missing the specified timeout period
                    If ($script:welcomeTimer) {
                        Try {
                            $script:welcomeTimer.Dispose()
                            $script:welcomeTimer = $null
                        }
                        Catch {
                        }
                    }

                    #  Restore minimized windows
                    $null = (Get-ADTSession).Session.ShellApp.UndoMinimizeAll()

                    Exit-Script -ExitCode (Get-ADTSession).GetConfig().UI_Options.InstallationUI_ExitCode
                }
                #  Stop the script (user chose to defer)
                ElseIf ($promptResult -eq 'Defer') {
                    Write-Log -Message 'Installation deferred by the user.' -Source ${CmdletName}
                    $BlockExecution = $false

                    Set-DeferHistory -DeferTimesRemaining $DeferTimes -DeferDeadline $deferDeadlineUniversal

                    #  Restore minimized windows
                    $null = (Get-ADTSession).Session.ShellApp.UndoMinimizeAll()

                    Exit-Script -ExitCode (Get-ADTSession).GetConfig().UI_Options.InstallationDefer_ExitCode
                }
            }
        }

        ## Force the processes to close silently, without prompting the user
        If (($Silent -or (Get-ADTSession).Session.State.DeployModeSilent) -and $CloseApps) {
            [Array]$runningProcesses = $null
            [Array]$runningProcesses = Get-RunningProcesses $processObjects
            If ($runningProcesses) {
                [String]$runningProcessDescriptions = ($runningProcesses | Where-Object { $_.ProcessDescription } | Select-Object -ExpandProperty 'ProcessDescription' | Sort-Object -Unique) -join ','
                Write-Log -Message "Force closing application(s) [$($runningProcessDescriptions)] without prompting user." -Source ${CmdletName}
                $runningProcesses.ProcessName | ForEach-Object -Process { Stop-Process -Name $_ -Force -ErrorAction 'SilentlyContinue' }
                Start-Sleep -Seconds 2
            }
        }

        ## Force nsd.exe to stop if Notes is one of the required applications to close
        If (($processObjects | Select-Object -ExpandProperty 'ProcessName') -contains 'notes') {
            ## Get the path where Notes is installed
            [String]$notesPath = Get-Item -LiteralPath $regKeyLotusNotes -ErrorAction 'SilentlyContinue' | Get-ItemProperty | Select-Object -ExpandProperty 'Path'

            ## Ensure we aren't running as a Local System Account and Notes install directory was found
            If ((-not $IsLocalSystemAccount) -and ($notesPath)) {
                #  Get a list of all the executables in the Notes folder
                [string[]]$notesPathExes = Get-ChildItem -LiteralPath $notesPath -Filter '*.exe' -Recurse | Select-Object -ExpandProperty 'BaseName' | Sort-Object
                ## Check for running Notes executables and run NSD if any are found
                $notesPathExes | ForEach-Object {
                    If ((Get-Process | Select-Object -ExpandProperty 'Name') -contains $_) {
                        [String]$notesNSDExecutable = Join-Path -Path $notesPath -ChildPath 'NSD.exe'
                        Try {
                            If (Test-Path -LiteralPath $notesNSDExecutable -PathType 'Leaf' -ErrorAction 'Stop') {
                                Write-Log -Message "Executing [$notesNSDExecutable] with the -kill argument..." -Source ${CmdletName}
                                [Diagnostics.Process]$notesNSDProcess = Start-Process -FilePath $notesNSDExecutable -ArgumentList '-kill' -WindowStyle 'Hidden' -PassThru -ErrorAction 'SilentlyContinue'

                                If (-not $notesNSDProcess.WaitForExit(10000)) {
                                    Write-Log -Message "[$notesNSDExecutable] did not end in a timely manner. Force terminate process." -Source ${CmdletName}
                                    Stop-Process -Name 'NSD' -Force -ErrorAction 'SilentlyContinue'
                                }
                            }
                        }
                        Catch {
                            Write-Log -Message "Failed to launch [$notesNSDExecutable]. `r`n$(Resolve-Error)" -Source ${CmdletName}
                        }

                        Write-Log -Message "[$notesNSDExecutable] returned exit code [$($notesNSDProcess.ExitCode)]." -Source ${CmdletName}

                        #  Force NSD process to stop in case the previous command was not successful
                        Stop-Process -Name 'NSD' -Force -ErrorAction 'SilentlyContinue'
                    }
                }
            }

            #  Strip all Notes processes from the process list except notes.exe, because the other notes processes (e.g. notes2.exe) may be invoked by the Notes installation, so we don't want to block their execution.
            If ($notesPathExes) {
                [Array]$processesIgnoringNotesExceptions = Compare-Object -ReferenceObject ($processObjects | Select-Object -ExpandProperty 'ProcessName' | Sort-Object) -DifferenceObject $notesPathExes -IncludeEqual | Where-Object { ($_.SideIndicator -eq '<=') -or ($_.InputObject -eq 'notes') } | Select-Object -ExpandProperty 'InputObject'
                [Array]$processObjects = $processObjects | Where-Object { $processesIgnoringNotesExceptions -contains $_.ProcessName }
            }
        }

        ## If block execution switch is true, call the function to block execution of these processes
        If ($BlockExecution) {
            #  Make this variable globally available so we can check whether we need to call Unblock-AppExecution
            Set-Variable -Name 'BlockExecution' -Value $BlockExecution -Scope 'Script'
            Write-Log -Message '[-BlockExecution] parameter specified.' -Source ${CmdletName}
            Block-AppExecution -ProcessName ($processObjects | Select-Object -ExpandProperty 'ProcessName')
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-InstallationRestartPrompt
{
    <#

    .SYNOPSIS
    Displays a restart prompt with a countdown to a forced restart.

    .DESCRIPTION
    Displays a restart prompt with a countdown to a forced restart.

    .PARAMETER CountdownSeconds
    Specifies the number of seconds to countdown before the system restart. Default: 60

    .PARAMETER CountdownNoHideSeconds
    Specifies the number of seconds to display the restart prompt without allowing the window to be hidden. Default: 30

    .PARAMETER NoSilentRestart
    Specifies whether the restart should be triggered when Deploy mode is silent or very silent. Default: $true

    .PARAMETER NoCountdown
    Specifies not to show a countdown.

    The UI will restore/reposition itself persistently based on the interval value specified in the config file.

    .PARAMETER SilentCountdownSeconds
    Specifies number of seconds to countdown for the restart when the toolkit is running in silent mode and NoSilentRestart is $false. Default: 5

    .PARAMETER TopMost
    Specifies whether the windows is the topmost window. Default: $true.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    System.String. Returns the version of the specified file.

    .EXAMPLE
    Show-InstallationRestartPrompt -Countdownseconds 600 -CountdownNoHideSeconds 60

    .EXAMPLE
    Show-InstallationRestartPrompt -NoCountdown

    .EXAMPLE
    Show-InstallationRestartPrompt -Countdownseconds 300 -NoSilentRestart $false -SilentCountdownSeconds 10

    .NOTES
    Be mindful of the countdown you specify for the reboot as code directly after this function might NOT be able to execute - that includes logging.

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$CountdownSeconds = 60,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$CountdownNoHideSeconds = 30,
        [Parameter(Mandatory = $false)]
        [Boolean]$NoSilentRestart = $true,
        [Parameter(Mandatory = $false)]
        [Switch]$NoCountdown = $false,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Int32]$SilentCountdownSeconds = 5,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$TopMost = $true
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        ## If in non-interactive mode
        If ((Test-Path -LiteralPath 'variable:deployModeSilent') -and $deployModeSilent) {
            If ($NoSilentRestart -eq $false) {
                Write-Log -Message "Triggering restart silently, because the deploy mode is set to [$deployMode] and [NoSilentRestart] is disabled. Timeout is set to [$SilentCountdownSeconds] seconds." -Source ${CmdletName}
                Start-Process -FilePath ([System.Diagnostics.Process]::GetCurrentProcess().Path) -ArgumentList "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command `"& { Start-Sleep -Seconds $SilentCountdownSeconds; Restart-Computer -Force; }`"" -WindowStyle 'Hidden' -ErrorAction 'SilentlyContinue'
            }
            Else {
                Write-Log -Message "Skipping restart, because the deploy mode is set to [$deployMode] and [NoSilentRestart] is enabled." -Source ${CmdletName}
            }
            Return
        }
        ## Get the parameters passed to the function for invoking the function asynchronously
        [Hashtable]$installRestartPromptParameters = $PSBoundParameters

        ## Check if we are already displaying a restart prompt
        If (Get-Process | Where-Object { $_.MainWindowTitle -match (Get-ADTSession).GetUiMessages().RestartPrompt_Title }) {
            Write-Log -Message "${CmdletName} was invoked, but an existing restart prompt was detected. Cancelling restart prompt." -Severity 2 -Source ${CmdletName}
            Return
        }

        ## If the script has been dot-source invoked by the deploy app script, display the restart prompt asynchronously
        If ($deployAppScriptFriendlyName) {
            If ($NoCountdown) {
                Write-Log -Message "Invoking ${CmdletName} asynchronously with no countdown..." -Source ${CmdletName}
            }
            Else {
                Write-Log -Message "Invoking ${CmdletName} asynchronously with a [$countDownSeconds] second countdown..." -Source ${CmdletName}
            }
            ## Remove Silent reboot parameters from the list that is being forwarded to the main script for asynchronous function execution. This is only for Interactive mode so we dont need silent mode reboot parameters.
            $installRestartPromptParameters.Remove('NoSilentRestart')
            $installRestartPromptParameters.Remove('SilentCountdownSeconds')
            ## Prepare a list of parameters of this function as a string
            [String]$installRestartPromptParameters = ($installRestartPromptParameters.GetEnumerator() | Resolve-Parameters) -join ' '
            ## Start another powershell instance silently with function parameters from this function
            Start-Process -FilePath ([System.Diagnostics.Process]::GetCurrentProcess().Path) -ArgumentList "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & {& `'$scriptPath`' -ReferredInstallTitle `'$installTitle`' -ReferredInstallName `'$installName`' -ReferredLogName `'$logName`' -ShowInstallationRestartPrompt $installRestartPromptParameters -AsyncToolkitLaunch}" -WindowStyle 'Hidden' -ErrorAction 'SilentlyContinue'
            Return
        }

        [DateTime]$startTime = Get-Date
        [DateTime]$countdownTime = $startTime

        [Windows.Forms.Application]::EnableVisualStyles()
        $formRestart = New-Object -TypeName 'System.Windows.Forms.Form'
        $formRestart.SuspendLayout()
        $labelCountdown = New-Object -TypeName 'System.Windows.Forms.Label'
        $labelTimeRemaining = New-Object -TypeName 'System.Windows.Forms.Label'
        $labelMessage = New-Object -TypeName 'System.Windows.Forms.Label'
        $buttonRestartLater = New-Object -TypeName 'System.Windows.Forms.Button'
        $pictureBanner = New-Object -TypeName 'System.Windows.Forms.PictureBox'
        $buttonRestartNow = New-Object -TypeName 'System.Windows.Forms.Button'
        $timerCountdown = New-Object -TypeName 'System.Windows.Forms.Timer'
        $flowLayoutPanel = New-Object -TypeName 'System.Windows.Forms.FlowLayoutPanel'
        $panelButtons = New-Object -TypeName 'System.Windows.Forms.Panel'

        [ScriptBlock]$RestartComputer = {
            Write-Log -Message 'Forcefully restarting the computer...' -Source ${CmdletName}
            Restart-Computer -Force
        }

        [ScriptBlock]$Restart_Form_StateCorrection_Load = {
            # Disable the X button
            Try {
                $windowHandle = $formRestart.Handle
                If ($windowHandle -and ($windowHandle -ne [IntPtr]::Zero)) {
                    $menuHandle = [PSADT.UiAutomation]::GetSystemMenu($windowHandle, $false)
                    If ($menuHandle -and ($menuHandle -ne [IntPtr]::Zero)) {
                        [PSADT.UiAutomation]::EnableMenuItem($menuHandle, 0xF060, 0x00000001)
                        [PSADT.UiAutomation]::DestroyMenu($menuHandle)
                    }
                }
            }
            Catch {
                # Not a terminating error if we can't disable the button. Just disable the Control Box instead
                Write-Log 'Failed to disable the Close button. Disabling the Control Box instead.' -Severity 2 -Source ${CmdletName}
                $formRestart.ControlBox = $false
            }
            ## Initialize the countdown timer
            [DateTime]$currentTime = Get-Date
            [DateTime]$countdownTime = $startTime.AddSeconds($countdownSeconds)
            $timerCountdown.Start()
            ## Set up the form
            [Timespan]$remainingTime = $countdownTime.Subtract($currentTime)
            $labelCountdown.Text = [String]::Format('{0}:{1:d2}:{2:d2}', $remainingTime.Days * 24 + $remainingTime.Hours, $remainingTime.Minutes, $remainingTime.Seconds)
            If ($remainingTime.TotalSeconds -le $countdownNoHideSeconds) {
                $buttonRestartLater.Enabled = $false
            }
            ## Get the start position of the form so we can return the form to this position if PersistPrompt is enabled
            Set-Variable -Name 'formInstallationRestartPromptStartPosition' -Value $formRestart.Location -Scope 'Script'
        }

        ## Persistence Timer
        If ($NoCountdown) {
            $restartTimerPersist = New-Object -TypeName 'System.Windows.Forms.Timer'
            $restartTimerPersist.Interval = ((Get-ADTSession).GetConfig().UI_Options.InstallationRestartPrompt_PersistInterval * 1000)
            [ScriptBlock]$restartTimerPersist_Tick = {
                #  Show the Restart Popup
                $formRestart.WindowState = 'Normal'
                $formRestart.TopMost = $TopMost
                $formRestart.BringToFront()
                $formRestart.Location = "$($formInstallationRestartPromptStartPosition.X),$($formInstallationRestartPromptStartPosition.Y)"
            }
            $restartTimerPersist.add_Tick($restartTimerPersist_Tick)
            $restartTimerPersist.Start()
        }

        [ScriptBlock]$buttonRestartLater_Click = {
            ## Minimize the form
            $formRestart.WindowState = 'Minimized'
            If ($NoCountdown) {
                ## Reset the persistence timer
                $restartTimerPersist.Stop()
                $restartTimerPersist.Start()
            }
        }

        ## Restart the computer
        [ScriptBlock]$buttonRestartNow_Click = { & $RestartComputer }

        ## Hide the form if minimized
        [ScriptBlock]$formRestart_Resize = { If ($formRestart.WindowState -eq 'Minimized') {
                $formRestart.WindowState = 'Minimized'
            } }

        [ScriptBlock]$timerCountdown_Tick = {
            ## Get the time information
            [DateTime]$currentTime = Get-Date
            [DateTime]$countdownTime = $startTime.AddSeconds($countdownSeconds)
            [Timespan]$remainingTime = $countdownTime.Subtract($currentTime)
            ## If the countdown is complete, restart the machine
            If ($countdownTime -le $currentTime) {
                $buttonRestartNow.PerformClick()
            }
            Else {
                ## Update the form
                $labelCountdown.Text = [String]::Format('{0}:{1:d2}:{2:d2}', $remainingTime.Days * 24 + $remainingTime.Hours, $remainingTime.Minutes, $remainingTime.Seconds)
                If ($remainingTime.TotalSeconds -le $countdownNoHideSeconds) {
                    $buttonRestartLater.Enabled = $false
                    #  If the form is hidden when we hit the "No Hide", bring it back up
                    If ($formRestart.WindowState -eq 'Minimized') {
                        #  Show Popup
                        $formRestart.WindowState = 'Normal'
                        $formRestart.TopMost = $TopMost
                        $formRestart.BringToFront()
                        $formRestart.Location = "$($formInstallationRestartPromptStartPosition.X),$($formInstallationRestartPromptStartPosition.Y)"
                    }
                }
            }
        }

        ## Remove all event handlers from the controls
        [ScriptBlock]$Restart_Form_Cleanup_FormClosed = {
            Try {
                $buttonRestartLater.remove_Click($buttonRestartLater_Click)
                $buttonRestartNow.remove_Click($buttonRestartNow_Click)
                $formRestart.remove_Load($Restart_Form_StateCorrection_Load)
                $formRestart.remove_Resize($formRestart_Resize)
                $timerCountdown.remove_Tick($timerCountdown_Tick)
                $restartTimerPersist.remove_Tick($restartTimerPersist_Tick)
                $formRestart.remove_FormClosed($Restart_Form_Cleanup_FormClosed)
            }
            Catch {
            }
        }

        ## Form
        ##----------------------------------------------
        ## Create zero px padding object
        $paddingNone = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 0, 0, 0)
        ## Create basic control size
        $defaultControlSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 0)

        ## Generic Button properties
        $buttonSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (195, 24)

        ## Picture Banner
        $pictureBanner.DataBindings.DefaultDataSourceUpdateMode = 0
        $pictureBanner.ImageLocation = (Get-ADTSession).GetConfig().BannerIcon_Options.Banner_Filename
        $System_Drawing_Point = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, 0)
        $pictureBanner.Location = $System_Drawing_Point
        $pictureBanner.Name = 'pictureBanner'
        $System_Drawing_Size = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, (Get-ADTSession).Session.BannerHeight)
        $pictureBanner.ClientSize = $System_Drawing_Size
        $pictureBanner.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
        $pictureBanner.Margin = $paddingNone
        $pictureBanner.TabStop = $false

        ## Label Message
        $labelMessage.DataBindings.DefaultDataSourceUpdateMode = 0
        $labelMessage.Font = $defaultFont
        $labelMessage.Name = 'labelMessage'
        $labelMessage.ClientSize = $defaultControlSize
        $labelMessage.MinimumSize = $defaultControlSize
        $labelMessage.MaximumSize = $defaultControlSize
        $labelMessage.Margin = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (0, 10, 0, 5)
        $labelMessage.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (10, 0, 10, 0)
        $labelMessage.Text = "$((Get-ADTSession).GetUiMessages().RestartPrompt_Message) $((Get-ADTSession).GetUiMessages().RestartPrompt_MessageTime)`n`n$((Get-ADTSession).GetUiMessages().RestartPrompt_MessageRestart)"
        If ($NoCountdown) {
            $labelMessage.Text = (Get-ADTSession).GetUiMessages().RestartPrompt_Message
        }
        $labelMessage.TextAlign = 'MiddleCenter'
        $labelMessage.Anchor = 'Top'
        $labelMessage.TabStop = $false
        $labelMessage.AutoSize = $true

        ## Label Time remaining message
        $labelTimeRemaining.DataBindings.DefaultDataSourceUpdateMode = 0
        $labelTimeRemaining.Font = "$($defaultFont.Name), $($defaultFont.Size + 2), style=Regular"
        $labelTimeRemaining.Name = 'labelTimeRemaining'
        $labelTimeRemaining.ClientSize = $defaultControlSize
        $labelTimeRemaining.MinimumSize = $defaultControlSize
        $labelTimeRemaining.MaximumSize = $defaultControlSize
        $labelTimeRemaining.Margin = $paddingNone
        $labelTimeRemaining.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (10, 0, 10, 0)
        $labelTimeRemaining.TabStop = $false
        $labelTimeRemaining.Text = (Get-ADTSession).GetUiMessages().RestartPrompt_TimeRemaining
        $labelTimeRemaining.TextAlign = 'MiddleCenter'
        $labelTimeRemaining.Anchor = 'Top'
        $labelTimeRemaining.AutoSize = $true

        ## Label Countdown
        $labelCountdown.DataBindings.DefaultDataSourceUpdateMode = 0
        $labelCountdown.Font = "$($defaultFont.Name), $($defaultFont.Size + 9), style=Bold"
        $labelCountdown.Name = 'labelCountdown'
        $labelCountdown.ClientSize = $defaultControlSize
        $labelCountdown.MinimumSize = $defaultControlSize
        $labelCountdown.MaximumSize = $defaultControlSize
        $labelCountdown.Margin = $paddingNone
        $labelCountdown.Padding = New-Object -TypeName 'System.Windows.Forms.Padding' -ArgumentList (10, 0, 10, 0)
        $labelCountdown.TabStop = $false
        $labelCountdown.Text = '00:00:00'
        $labelCountdown.TextAlign = 'MiddleCenter'
        $labelCountdown.AutoSize = $true

        ## Panel Flow Layout
        $System_Drawing_Point = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (0, $appDeployLogoBannerHeight)
        $flowLayoutPanel.Location = $System_Drawing_Point
        $flowLayoutPanel.MinimumSize = $DefaultControlSize
        $flowLayoutPanel.MaximumSize = $DefaultControlSize
        $flowLayoutPanel.ClientSize = $DefaultControlSize
        $flowLayoutPanel.Margin = $paddingNone
        $flowLayoutPanel.Padding = $paddingNone
        $flowLayoutPanel.AutoSizeMode = 'GrowAndShrink'
        $flowLayoutPanel.AutoSize = $true
        $flowLayoutPanel.Anchor = 'Top'
        $flowLayoutPanel.FlowDirection = 'TopDown'
        $flowLayoutPanel.WrapContents = $true
        $flowLayoutPanel.Controls.Add($labelMessage)
        If (-not $NoCountdown) {
            $flowLayoutPanel.Controls.Add($labelTimeRemaining)
            $flowLayoutPanel.Controls.Add($labelCountdown)
        }

        ## Button Minimize
        $buttonRestartLater.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonRestartLater.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (240, 4)
        $buttonRestartLater.Name = 'buttonRestartLater'
        $buttonRestartLater.Font = $defaultFont
        $buttonRestartLater.ClientSize = $buttonSize
        $buttonRestartLater.MinimumSize = $buttonSize
        $buttonRestartLater.MaximumSize = $buttonSize
        $buttonRestartLater.TabIndex = 0
        $buttonRestartLater.Text = (Get-ADTSession).GetUiMessages().RestartPrompt_ButtonRestartLater
        $buttonRestartLater.AutoSize = $true
        $buttonRestartLater.Margin = $paddingNone
        $buttonRestartLater.Padding = $paddingNone
        $buttonRestartLater.UseVisualStyleBackColor = $true
        $buttonRestartLater.add_Click($buttonRestartLater_Click)

        ## Button Restart Now
        $buttonRestartNow.DataBindings.DefaultDataSourceUpdateMode = 0
        $buttonRestartNow.Location = New-Object -TypeName 'System.Drawing.Point' -ArgumentList (14, 4)
        $buttonRestartNow.Name = 'buttonRestartNow'
        $buttonRestartNow.Font = $defaultFont
        $buttonRestartNow.ClientSize = $buttonSize
        $buttonRestartNow.MinimumSize = $buttonSize
        $buttonRestartNow.MaximumSize = $buttonSize
        $buttonRestartNow.TabIndex = 1
        $buttonRestartNow.Text = (Get-ADTSession).GetUiMessages().RestartPrompt_ButtonRestartNow
        $buttonRestartNow.Margin = $paddingNone
        $buttonRestartNow.Padding = $paddingNone
        $buttonRestartNow.UseVisualStyleBackColor = $true
        $buttonRestartNow.add_Click($buttonRestartNow_Click)

        ## Form Restart
        $formRestart.ClientSize = $defaultControlSize
        $formRestart.Padding = $paddingNone
        $formRestart.Margin = $paddingNone
        $formRestart.DataBindings.DefaultDataSourceUpdateMode = 0
        $formRestart.Name = 'formRestart'
        $formRestart.Text = $installTitle
        $formRestart.StartPosition = 'CenterScreen'
        $formRestart.FormBorderStyle = 'Fixed3D'
        $formRestart.MaximizeBox = $false
        $formRestart.MinimizeBox = $false
        $formRestart.TopMost = $TopMost
        $formRestart.TopLevel = $true
        $formRestart.Icon = New-Object -TypeName 'System.Drawing.Icon' -ArgumentList (Get-ADTSession).GetConfig().BannerIcon_Options.Icon_Filename
        $formRestart.AutoSize = $true
        $formRestart.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
        $formRestart.AutoScaleDimensions = New-Object System.Drawing.SizeF(96,96)
        $formRestart.ControlBox = $true
        $formRestart.Controls.Add($pictureBanner)

        ## Button Panel
        $panelButtons.MinimumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        $panelButtons.ClientSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        $panelButtons.MaximumSize = New-Object -TypeName 'System.Drawing.Size' -ArgumentList (450, 39)
        $panelButtons.AutoSize = $true
        $panelButtons.Padding = $paddingNone
        $panelButtons.Margin = $paddingNone
        $panelButtons.Controls.Add($buttonRestartNow)
        $panelButtons.Controls.Add($buttonRestartLater)
        ## Add the Buttons Panel to the flowPanel
        $flowLayoutPanel.Controls.Add($panelButtons)
        ## Add FlowPanel to the form
        $formRestart.Controls.Add($flowLayoutPanel)
        $formRestart.add_Resize($formRestart_Resize)
        ## Timer Countdown
        If (-not $NoCountdown) {
            $timerCountdown.add_Tick($timerCountdown_Tick)
        }
        ##----------------------------------------------
        # Init the OnLoad event to correct the initial state of the form
        $formRestart.add_Load($Restart_Form_StateCorrection_Load)
        # Clean up the control events
        $formRestart.add_FormClosed($Restart_Form_Cleanup_FormClosed)
        $formRestartClosing = [Windows.Forms.FormClosingEventHandler] { If ($_.CloseReason -eq 'UserClosing') {
                $_.Cancel = $true
            } }
        $formRestart.add_FormClosing($formRestartClosing)

        If ($NoCountdown) {
            Write-Log -Message 'Displaying restart prompt with no countdown.' -Source ${CmdletName}
        }
        Else {
            Write-Log -Message "Displaying restart prompt with a [$countDownSeconds] second countdown." -Source ${CmdletName}
        }

        #  Show the Form
        $formRestart.ResumeLayout()
        Write-Output -InputObject ($formRestart.ShowDialog())
        $formRestart.Dispose()
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-BalloonTip
{
    <#

    .SYNOPSIS
    Displays a balloon tip notification in the system tray.

    .DESCRIPTION
    Displays a balloon tip notification in the system tray.

    .PARAMETER BalloonTipText
    Text of the balloon tip.

    .PARAMETER BalloonTipTitle
    Title of the balloon tip.

    .PARAMETER BalloonTipIcon
    Icon to be used. Options: 'Error', 'Info', 'None', 'Warning'. Default is: Info.

    .PARAMETER BalloonTipTime
    Time in milliseconds to display the balloon tip. Default: 10000.

    .PARAMETER NoWait
    Create the balloontip asynchronously. Default: $false

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    System.String. Returns the version of the specified file.

    .EXAMPLE
    Show-BalloonTip -BalloonTipText 'Installation Started' -BalloonTipTitle 'Application Name'

    .EXAMPLE
    Show-BalloonTip -BalloonTipIcon 'Info' -BalloonTipText 'Installation Started' -BalloonTipTitle 'Application Name' -BalloonTipTime 1000

    .NOTES
    For Windows 10 OS and above a Toast notification is displayed in place of a balloon tip if toast notifications are enabled in the XML config file.

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$BalloonTipText,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [String]$BalloonTipTitle = (Get-ADTSession).GetPropertyValue('InstallTitle'),
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet('Error', 'Info', 'None', 'Warning')]
        [Windows.Forms.ToolTipIcon]$BalloonTipIcon = 'Info',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullorEmpty()]
        [Int32]$BalloonTipTime = 10000,
        [Parameter(Mandatory = $false, Position = 4)]
        [Switch]$NoWait = $false
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        ## Skip balloon if in silent mode, disabled in the config or presentation is detected
        If (($deployModeSilent) -or (-not (Get-ADTSession).GetConfig().UI_Options.ShowBalloonNotifications)) {
            Write-Log -Message "Bypassing Show-BalloonTip [Mode:$deployMode, Config Show Balloon Notifications:(Get-ADTSession).GetConfig().UI_Options.ShowBalloonNotifications]. BalloonTipText:$BalloonTipText" -Source ${CmdletName}
            Return
        }
        If (Test-PowerPoint) {
            Write-Log -Message "Bypassing Show-BalloonTip [Mode:$deployMode, Presentation Detected:$true]. BalloonTipText:$BalloonTipText" -Source ${CmdletName}
            Return
        }
        ## Dispose of previous balloon
        If (Test-Path -LiteralPath 'variable:notifyIcon') {
            Try {
                $script:notifyIcon.Dispose()
            }
            Catch {
            }
        }

        If (($envOSVersionMajor -lt 10) -or ((Get-ADTSession).GetConfig().Toast_Options.Toast_Disable -eq $true)) {
            ## NoWait - Create the balloontip icon asynchronously
            If ($NoWait) {
                Write-Log -Message "Displaying balloon tip notification asynchronously with message [$BalloonTipText]." -Source ${CmdletName}
                ## Create a script block to display the balloon notification in a new PowerShell process so that we can wait to cleanly dispose of the balloon tip without having to make the deployment script wait
                ## Scriptblock text has to be as short as possible because it is passed as a parameter to powershell
                ## Don't strongly type parameter BalloonTipIcon as System.Drawing assembly not loaded yet in asynchronous scriptblock so will throw error
                [ScriptBlock]$notifyIconScriptBlock = {
                    Param(
                        [Parameter(Mandatory = $true, Position = 0)]
                        [ValidateNotNullOrEmpty()]
                        [String]$BalloonTipText,
                        [Parameter(Mandatory = $false, Position = 1)]
                        [ValidateNotNullorEmpty()]
                        [String]$BalloonTipTitle,
                        [Parameter(Mandatory = $false, Position = 2)]
                        [ValidateSet('Error', 'Info', 'None', 'Warning')]
                        $BalloonTipIcon = 'Info',
                        [Parameter(Mandatory = $false, Position = 3)]
                        [ValidateNotNullorEmpty()]
                        [Int32]$BalloonTipTime,
                        [Parameter(Mandatory = $false, Position = 4)]
                        [ValidateNotNullorEmpty()]
                        [String]$AppDeployLogoIcon
                    )
                    Add-Type -AssemblyName 'System.Windows.Forms', 'System.Drawing' -ErrorAction 'Stop'
                    $BalloonTipIconText = [String]::Concat($BalloonTipTitle, ' - ', $BalloonTipText)
                    If ($BalloonTipIconText.Length -gt 63) {
                        $BalloonTipIconText = [String]::Concat($BalloonTipIconText.Substring(0, 60), '...')
                    }
                    [Windows.Forms.ToolTipIcon]$BalloonTipIcon = $BalloonTipIcon
                    $script:notifyIcon = New-Object -TypeName 'System.Windows.Forms.NotifyIcon' -Property @{
                        BalloonTipIcon  = $BalloonTipIcon
                        BalloonTipText  = $BalloonTipText
                        BalloonTipTitle = $BalloonTipTitle
                        Icon            = New-Object -TypeName 'System.Drawing.Icon' -ArgumentList (Get-ADTSession).GetConfig().BannerIcon_Options.Icon_Filename
                        Text            = $BalloonTipIconText
                        Visible         = $true
                    }

                    $script:notifyIcon.ShowBalloonTip($BalloonTipTime)
                    Start-Sleep -Milliseconds ($BalloonTipTime)
                    $script:notifyIcon.Dispose() }

                ## Invoke a separate PowerShell process passing the script block as a command and associated parameters to display the balloon tip notification asynchronously
                Try {
                    Execute-Process -Path ([System.Diagnostics.Process]::GetCurrentProcess().Path) -Parameters "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & {$notifyIconScriptBlock} `'$BalloonTipText`' `'$BalloonTipTitle`' `'$BalloonTipIcon`' `'$BalloonTipTime`' `'$AppDeployLogoIcon`'" -NoWait -WindowStyle 'Hidden' -CreateNoWindow
                }
                Catch {
                }
            }
            ## Otherwise create the balloontip icon synchronously
            Else {
                Write-Log -Message "Displaying balloon tip notification with message [$BalloonTipText]." -Source ${CmdletName}
                ## Prepare Text - Cut it if longer than 63 chars
                $BalloonTipIconText = [String]::Concat($BalloonTipTitle, ' - ', $BalloonTipText)
                If ($BalloonTipIconText.Length -gt 63) {
                    $BalloonTipIconText = [String]::Concat($BalloonTipIconText.Substring(0, 60), '...')
                }
                ## Create the BalloonTip
                [Windows.Forms.ToolTipIcon]$BalloonTipIcon = $BalloonTipIcon
                $script:notifyIcon = New-Object -TypeName 'System.Windows.Forms.NotifyIcon' -Property @{
                    BalloonTipIcon  = $BalloonTipIcon
                    BalloonTipText  = $BalloonTipText
                    BalloonTipTitle = $BalloonTipTitle
                    Icon            = New-Object -TypeName 'System.Drawing.Icon' -ArgumentList (Get-ADTSession).GetConfig().BannerIcon_Options.Icon_Filename
                    Text            = $BalloonTipIconText
                    Visible         = $true
                }
                ## Display the balloon tip notification
                $script:notifyIcon.ShowBalloonTip($BalloonTipTime)
            }
        }
        # Otherwise use toast notification
        Else {
            $toastAppID = $appDeployToolkitName
            $toastAppDisplayName = (Get-ADTSession).GetConfig().Toast_Options.Toast_AppName

            [scriptblock]$toastScriptBlock  = {
                Param(
                    [Parameter(Mandatory = $true, Position = 0)]
                    [ValidateNotNullOrEmpty()]
                    [String]$BalloonTipText,
                    [Parameter(Mandatory = $false, Position = 1)]
                    [ValidateNotNullorEmpty()]
                    [String]$BalloonTipTitle,
                    [Parameter(Mandatory = $false, Position = 2)]
                    [ValidateNotNullorEmpty()]
                    [String]$AppDeployLogoImage,
                    [Parameter(Mandatory = $false, Position = 3)]
                    [ValidateNotNullorEmpty()]
                    [String]$toastAppID,
                    [Parameter(Mandatory = $false, Position = 4)]
                    [ValidateNotNullorEmpty()]
                    [String]$toastAppDisplayName
                )

                # Check for required entries in registry for when using Powershell as application for the toast
                # Register the AppID in the registry for use with the Action Center, if required
                $regPathToastNotificationSettings = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings'
                $regPathToastApp = 'Registry::HKEY_CURRENT_USER\Software\Classes\AppUserModelId'

                # Create the registry entries
                $null = New-Item -Path "$regPathToastNotificationSettings\$toastAppId" -Force
                # Make sure the app used with the action center is enabled
                $null = New-ItemProperty -Path "$regPathToastNotificationSettings\$toastAppId" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD' -Force
                $null = New-ItemProperty -Path "$regPathToastNotificationSettings\$toastAppId" -Name 'Enabled' -Value 1 -PropertyType 'DWORD' -Force
                $null = New-ItemProperty -Path "$regPathToastNotificationSettings\$toastAppId" -Name 'SoundFile' -PropertyType 'STRING' -Force

                # Create the registry entries
                $null = New-Item -Path "$regPathToastApp\$toastAppId" -Force
                $null = New-ItemProperty -Path "$regPathToastApp\$toastAppId" -Name 'DisplayName' -Value "$($toastAppDisplayName)" -PropertyType 'STRING' -Force
                $null = New-ItemProperty -Path "$regPathToastApp\$toastAppId" -Name 'ShowInSettings' -Value 0 -PropertyType 'DWORD' -Force
                $null = New-ItemProperty -Path "$regPathToastApp\$toastAppId" -Name 'IconUri' -Value $appDeployLogoImage -PropertyType 'ExpandString' -Force
                $null = New-ItemProperty -Path "$regPathToastApp\$toastAppId" -Name 'IconBackgroundColor' -Value 0 -PropertyType 'ExpandString' -Force

                # Handle PowerShell 7-specific setup.
                If ($PSVersionTable.PSEdition.Equals('Core')) {
                    If ($pkg = Get-Package -Name Microsoft.Windows.SDK.NET.Ref -ErrorAction Ignore) {
                        Add-Type -AssemblyName (Get-ChildItem -Path "$([System.IO.Path]::GetDirectoryName($pkg.Source))\lib\*\*.dll").FullName
                    }
                    Else {
                        exit 60003
                    }
                }
                else {
                    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
                }

                ## Gets the Template XML so we can manipulate the values
                $Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01
                [xml] $ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())
                [xml] $ToastTemplate = @"
<toast launch="app-defined-string">
    <visual>
        <binding template="ToastImageAndText02">
            <text id="1">$BalloonTipTitle</text>
            <text id="2">$BalloonTipText</text>
            <image id="1" src="file://$appDeployLogoImage" />
        </binding>
    </visual>
</toast>
"@

                $ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
                $ToastXml.LoadXml($ToastTemplate.OuterXml)

                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($toastAppId)
                $notifier.Show($toastXml)

            }

            If ($ProcessNTAccount -eq $runAsActiveUser.NTAccount) {
                Write-Log -Message "Displaying toast notification with message [$BalloonTipText]." -Source ${CmdletName}
                Invoke-Command -ScriptBlock $toastScriptBlock -ArgumentList $BalloonTipText, $BalloonTipTitle, $AppDeployLogoImage, $toastAppID, $toastAppDisplayName
            }
            Else {
                ## Invoke a separate PowerShell process as the current user passing the script block as a command and associated parameters to display the toast notification in the user context
                Try {
                    Write-Log -Message "Displaying toast notification with message [$BalloonTipText] using Execute-ProcessAsUser." -Source ${CmdletName}
                    $executeToastAsUserScript = "$loggedOnUserTempPath" + "$($appDeployToolkitName)-ToastNotification.ps1"
                    Set-Content -Path $executeToastAsUserScript -Value $toastScriptBlock -Force
                    Execute-ProcessAsUser -Path ([System.Diagnostics.Process]::GetCurrentProcess().Path) -Parameters "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -File `"$executeToastAsUserScript`" `"$BalloonTipText`" `"$BalloonTipTitle`" `"$AppDeployLogoImage`" `"$toastAppID`" `"$toastAppDisplayName`"" -TempPath $loggedOnUserTempPath -Wait -RunLevel 'LeastPrivilege'
                }
                Catch {
                }
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}


#---------------------------------------------------------------------------
#
# 
#
#---------------------------------------------------------------------------

function Show-InstallationProgress
{
    <#

    .SYNOPSIS
    Displays a progress dialog in a separate thread with an updateable custom message.

    .DESCRIPTION
    Create a WPF window in a separate thread to display a marquee style progress ellipse with a custom message that can be updated.

    The status message supports line breaks.

    The first time this function is called in a script, it will display a balloon tip notification to indicate that the installation has started (provided balloon tips are enabled in the configuration).

    .PARAMETER StatusMessage
    The status message to be displayed. The default status message is taken from the XML configuration file.

    .PARAMETER WindowLocation
    The location of the progress window. Default: center of the screen.

    .PARAMETER TopMost
    Specifies whether the progress window should be topmost. Default: $true.

    .PARAMETER Quiet
    Specifies whether to not log the success of updating the progress message. Default: $false.

    .PARAMETER NoRelocation
    Specifies whether to not reposition the window upon updating the message. Default: $false.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    None. This function does not generate any output.

    .EXAMPLE
    # Uses the default status message from the XML configuration file.
    Show-InstallationProgress

    .EXAMPLE
    Show-InstallationProgress -StatusMessage 'Installation in Progress...'

    .EXAMPLE
    Show-InstallationProgress -StatusMessage "Installation in Progress...`r`nThe installation may take 20 minutes to complete."

    .EXAMPLE
    Show-InstallationProgress -StatusMessage 'Installation in Progress...' -WindowLocation 'BottomRight' -TopMost $false

    .LINK
    https://psappdeploytoolkit.com

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]$StatusMessage = (Get-ADTSession).GetUiMessages().Progress_MessageInstall,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Default', 'TopLeft', 'Top', 'TopRight', 'TopCenter', 'BottomLeft', 'Bottom', 'BottomRight')]
        [String]$WindowLocation = 'Default',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Boolean]$TopMost = $true,
        [Parameter(Mandatory = $false)]
        [Switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [Switch]$NoRelocation
    )

    Begin {
        ## Get the name of this function and write header
        [String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        If ((Test-Path -LiteralPath 'variable:deployModeSilent') -and $deployModeSilent) {
            If (!$Quiet) {
                Write-Log -Message "Bypassing Show-InstallationProgress [Mode: $deployMode]. Status message:$StatusMessage" -Source ${CmdletName}
            }
            Return
        }

        ## If the default progress message hasn't been overridden and the deployment type is uninstall, use the default uninstallation message
        If ($StatusMessage -eq (Get-ADTSession).GetUiMessages().Progress_MessageInstall) {
            If ((Get-ADTSession).GetPropertyValue('DeploymentType') -eq 'Uninstall') {
                $StatusMessage = (Get-ADTSession).GetUiMessages().Progress_MessageUninstall
            }
            ElseIf ((Get-ADTSession).GetPropertyValue('DeploymentType') -eq 'Repair') {
                $StatusMessage = (Get-ADTSession).GetUiMessages().Progress_MessageRepair
            }
        }

        If ($envHost.Name -match 'PowerGUI') {
            Write-Log -Message "$($envHost.Name) is not a supported host for WPF multi-threading. Progress dialog with message [$statusMessage] will not be displayed." -Severity 2 -Source ${CmdletName}
            Return
        }

        ## Check if the progress thread is running before invoking methods on it
        If (!$script:instProgressRunning) {
            #  Notify user that the software installation has started
            $balloonText = "$deploymentTypeName $((Get-ADTSession).GetUiMessages().BalloonText_Start)"
            Show-BalloonTip -BalloonTipIcon 'Info' -BalloonTipText $balloonText
            #  Create a synchronized hashtable to share objects between runspaces
            $script:ProgressSyncHash = [Hashtable]::Synchronized(@{ })
            #  Create a new runspace for the progress bar
            $script:ProgressRunspace = [runspacefactory]::CreateRunspace()
            $script:ProgressRunspace.ApartmentState = 'STA'
            $script:ProgressRunspace.ThreadOptions = 'ReuseThread'
            $script:ProgressRunspace.Open()
            #  Add the sync hash to the runspace
            $script:ProgressRunspace.SessionStateProxy.SetVariable('progressSyncHash', $script:ProgressSyncHash)
            #  Add other variables from the parent thread required in the progress runspace
            $script:ProgressRunspace.SessionStateProxy.SetVariable('installTitle', $installTitle)
            $script:ProgressRunspace.SessionStateProxy.SetVariable('windowLocation', $windowLocation)
            $script:ProgressRunspace.SessionStateProxy.SetVariable('topMost', $topMost.ToString())
            $script:ProgressRunspace.SessionStateProxy.SetVariable('appDeployLogoBanner', $appDeployLogoBanner)
            $script:ProgressRunspace.SessionStateProxy.SetVariable('ProgressStatusMessage', $statusMessage)
            $script:ProgressRunspace.SessionStateProxy.SetVariable('AppDeployLogoIcon', $AppDeployLogoIcon)

            #  Add the script block to be executed in the progress runspace
            $progressCmd = [PowerShell]::Create().AddScript({
                    [String]$xamlProgressString = @'
                <Window
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                x:Name="Window" Title="PSAppDeployToolkit"
                Padding="0,0,0,0" Margin="0,0,0,0"
                WindowStartupLocation = "Manual"
                Icon=""
                Top="0"
                Left="0"
                Topmost="True"
                ResizeMode="NoResize"
                ShowInTaskbar="True" VerticalContentAlignment="Center" HorizontalContentAlignment="Center" SizeToContent="WidthAndHeight">
                    <Window.Resources>
                    <Storyboard x:Key="Storyboard1" RepeatBehavior="Forever">
                    <DoubleAnimationUsingKeyFrames BeginTime="00:00:00" Storyboard.TargetName="ellipse" Storyboard.TargetProperty="(UIElement.RenderTransform).(TransformGroup.Children)[2].(RotateTransform.Angle)">
                        <SplineDoubleKeyFrame KeyTime="00:00:02" Value="360"/>
                    </DoubleAnimationUsingKeyFrames>
                    </Storyboard>
                    </Window.Resources>
                    <Window.Triggers>
                    <EventTrigger RoutedEvent="FrameworkElement.Loaded">
                    <BeginStoryboard Storyboard="{StaticResource Storyboard1}"/>
                    </EventTrigger>
                    </Window.Triggers>
                    <Grid Background="#F0F0F0" MinWidth="450" MaxWidth="450" Width="450">
                    <Grid.RowDefinitions>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition MinWidth="100" MaxWidth="100" Width="100"></ColumnDefinition>
                        <ColumnDefinition MinWidth="350" MaxWidth="350" Width="350"></ColumnDefinition>
                    </Grid.ColumnDefinitions>
                    <Image x:Name = "ProgressBanner" Grid.ColumnSpan="2" Margin="0,0,0,0" Source="" Grid.Row="0"/>
                    <TextBlock x:Name = "ProgressText" Grid.Row="1" Grid.Column="1" Margin="0,30,64,30" Text="Installation in progress" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center" TextAlignment="Center" Padding="10,0,10,0" TextWrapping="Wrap"></TextBlock>
                    <Ellipse x:Name = "ellipse" Grid.Row="1" Grid.Column="0" Margin="0,0,0,0" StrokeThickness="5" RenderTransformOrigin="0.5,0.5" Height="32" Width="32" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <Ellipse.RenderTransform>
                        <TransformGroup>
                            <ScaleTransform/>
                            <SkewTransform/>
                            <RotateTransform/>
                        </TransformGroup>
                    </Ellipse.RenderTransform>
                    <Ellipse.Stroke>
                        <LinearGradientBrush EndPoint="0.445,0.997" StartPoint="0.555,0.003">
                            <GradientStop Color="White" Offset="0"/>
                            <GradientStop Color="#0078d4" Offset="1"/>
                        </LinearGradientBrush>
                    </Ellipse.Stroke>
                    </Ellipse>
                    </Grid>
                </Window>
'@
                [Xml.XmlDocument]$xamlProgress = New-Object -TypeName 'System.Xml.XmlDocument'
                $xamlProgress.LoadXml($xamlProgressString)
                ## Set the configurable values using variables added to the runspace from the parent thread
                $xamlProgress.Window.TopMost = $topMost
                $xamlProgress.Window.Icon = $AppDeployLogoIcon
                $xamlProgress.Window.Grid.Image.Source = $appDeployLogoBanner
                $xamlProgress.Window.Grid.TextBlock.Text = $ProgressStatusMessage
                $xamlProgress.Window.Title = $installTitle
                #  Parse the XAML
                $progressReader = New-Object -TypeName 'System.Xml.XmlNodeReader' -ArgumentList ($xamlProgress)
                $script:ProgressSyncHash.Window = [Windows.Markup.XamlReader]::Load($progressReader)
                #  Grey out the X button
                $script:ProgressSyncHash.Window.add_Loaded({
                        #  Calculate the position on the screen where the progress dialog should be placed
                        [Int32]$screenWidth = [System.Windows.SystemParameters]::WorkArea.Width
                        [Int32]$screenHeight = [System.Windows.SystemParameters]::WorkArea.Height
                        [Int32]$script:screenCenterWidth = $screenWidth - $script:ProgressSyncHash.Window.ActualWidth
                        [Int32]$script:screenCenterHeight = $screenHeight - $script:ProgressSyncHash.Window.ActualHeight
                        #  Set the start position of the Window based on the screen size
                        If ($windowLocation -eq 'TopLeft') {
                            $script:ProgressSyncHash.Window.Left = [Double](0)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'Top') {
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth / 2)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'TopRight') {
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'TopCenter') {
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth / 2)
                            $script:ProgressSyncHash.Window.Top = [Double]($screenCenterHeight / 6)
                        }
                        ElseIf ($windowLocation -eq 'BottomLeft') {
                            $script:ProgressSyncHash.Window.Left = [Double](0)
                            $script:ProgressSyncHash.Window.Top = [Double]($screenCenterHeight)
                        }
                        ElseIf ($windowLocation -eq 'Bottom') {
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth / 2)
                            $script:ProgressSyncHash.Window.Top = [Double]($screenCenterHeight)
                        }
                        ElseIf ($windowLocation -eq 'BottomRight') {
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth)
                            $script:ProgressSyncHash.Window.Top = [Double]($screenCenterHeight - 100) #-100 Needed to not overlap system tray Toasts
                        }
                        Else {
                            #  Center the progress window by calculating the center of the workable screen based on the width of the screen minus half the width of the progress bar
                            $script:ProgressSyncHash.Window.Left = [Double]($screenCenterWidth / 2)
                            $script:ProgressSyncHash.Window.Top = [Double]($screenCenterHeight / 2)
                        }
                        #  Disable the X button
                        Try {
                            $windowHandle = (New-Object -TypeName System.Windows.Interop.WindowInteropHelper -ArgumentList ($this)).Handle
                            If ($windowHandle -and ($windowHandle -ne [IntPtr]::Zero)) {
                                $menuHandle = [PSADT.UiAutomation]::GetSystemMenu($windowHandle, $false)
                                If ($menuHandle -and ($menuHandle -ne [IntPtr]::Zero)) {
                                    [PSADT.UiAutomation]::EnableMenuItem($menuHandle, 0xF060, 0x00000001)
                                    [PSADT.UiAutomation]::DestroyMenu($menuHandle)
                                }
                            }
                        }
                        Catch {
                            # Not a terminating error if we can't disable the close button
                            Write-Log 'Failed to disable the Close button.' -Severity 2 -Source ${CmdletName}
                        }
                    })
                #  Prepare the ProgressText variable so we can use it to change the text in the text area
                $script:ProgressSyncHash.ProgressText = $script:ProgressSyncHash.Window.FindName('ProgressText')
                #  Add an action to the Window.Closing event handler to disable the close button
                $script:ProgressSyncHash.Window.Add_Closing({ $_.Cancel = $true })
                #  Allow the window to be dragged by clicking on it anywhere
                $script:ProgressSyncHash.Window.Add_MouseLeftButtonDown({ $script:ProgressSyncHash.Window.DragMove() })
                #  Add a tooltip
                $script:ProgressSyncHash.Window.ToolTip = $installTitle
                $null = $script:ProgressSyncHash.Window.ShowDialog()
                $script:ProgressSyncHash.Error = $Error
            })

            $progressCmd.Runspace = $script:ProgressRunspace
            Write-Log -Message "Creating the progress dialog in a separate thread with message: [$statusMessage]." -Source ${CmdletName}
            #  Invoke the progress runspace
            $null = $progressCmd.BeginInvoke()
            #  Allow the thread to be spun up safely before invoking actions against it.
            while (!($script:instProgressRunning = $script:ProgressSyncHash.ContainsKey('Window') -and ($script:ProgressSyncHash.Window.Dispatcher.Thread.ThreadState -eq 'Running')))
            {
                If ($script:ProgressSyncHash.ContainsKey('Error')) {
                    Write-Log -Message "Failure while displaying progress dialog. `r`n$(Resolve-Error -ErrorRecord $script:ProgressSyncHash.Error)" -Severity 3 -Source ${CmdletName}
                    break
                }
            }
        }
        ## Check if the progress thread is running before invoking methods on it
        Else {
            Try {
                #  Update the window title
                $script:ProgressSyncHash.Window.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Send, [Windows.Input.InputEventHandler] { $script:ProgressSyncHash.Window.Title = $installTitle }, $null, $null)
                #  Update the progress text
                $script:ProgressSyncHash.Window.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Send, [Windows.Input.InputEventHandler] { $script:ProgressSyncHash.ProgressText.Text = $statusMessage }, $null, $null)
                #  Calculate the position on the screen where the progress dialog should be placed
                if (!$NoRelocation) {
                    $script:ProgressSyncHash.Window.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Send, [Windows.Input.InputEventHandler] {
                        [Int32]$screenWidth = [System.Windows.SystemParameters]::WorkArea.Width
                        [Int32]$screenHeight = [System.Windows.SystemParameters]::WorkArea.Height
                        #  Set the start position of the Window based on the screen size
                        If ($windowLocation -eq 'TopLeft') {
                            $script:ProgressSyncHash.Window.Left = [Double](0)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'Top') {
                            $script:ProgressSyncHash.Window.Left = [Double](($screenWidth - $script:ProgressSyncHash.Window.ActualWidth) / 2)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'TopRight') {
                            $script:ProgressSyncHash.Window.Left = ($screenWidth - $script:ProgressSyncHash.Window.ActualWidth)
                            $script:ProgressSyncHash.Window.Top = [Double](0)
                        }
                        ElseIf ($windowLocation -eq 'TopCenter') {
                            $script:ProgressSyncHash.Window.Left = [Double](($screenWidth - $script:ProgressSyncHash.Window.ActualWidth) / 2)
                            $script:ProgressSyncHash.Window.Top = [Double](($screenHeight - $script:ProgressSyncHash.Window.ActualHeight) / 6)
                        }
                        ElseIf ($windowLocation -eq 'BottomLeft') {
                            $script:ProgressSyncHash.Window.Left = [Double](0)
                            $script:ProgressSyncHash.Window.Top = ($screenHeight - $script:ProgressSyncHash.Window.ActualHeight)
                        }
                        ElseIf ($windowLocation -eq 'Bottom') {
                            $script:ProgressSyncHash.Window.Left = [Double](($screenWidth - $script:ProgressSyncHash.Window.ActualWidth) / 2)
                            $script:ProgressSyncHash.Window.Top = ($screenHeight - $script:ProgressSyncHash.Window.ActualHeight)
                        }
                        ElseIf ($windowLocation -eq 'BottomRight') {
                            $script:ProgressSyncHash.Window.Left = ($screenWidth - $script:ProgressSyncHash.Window.ActualWidth)
                            $script:ProgressSyncHash.Window.Top = ($screenHeight - $script:ProgressSyncHash.Window.ActualHeight - 100) #-100 Needed to not overlap system tray Toasts
                        }
                        Else {
                            #  Center the progress window by calculating the center of the workable screen based on the width of the screen minus half the width of the progress bar
                            $script:ProgressSyncHash.Window.Left = [Double](($screenWidth - $script:ProgressSyncHash.Window.ActualWidth) / 2)
                            $script:ProgressSyncHash.Window.Top = [Double](($screenHeight - $script:ProgressSyncHash.Window.ActualHeight) / 2)
                        }
                    }, $null, $null)
                }

                If (!$Quiet) {
                    Write-Log -Message "Updated the progress message: [$statusMessage]." -Source ${CmdletName}
                }
            }
            Catch {
                Write-Log -Message "Unable to update the progress message. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
