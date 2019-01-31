function Update-Log {
    param(
        [string] $Message,

        [string] $Color = 'White',

        [switch] $NoNewLine
    )


    $LogTextBox.Foreground = $Color
    $LogTextBox.AppendText("$Message")
    if (-not $NoNewLine) { $LogTextBox.AppendText("`n") }
    ##$LogTextBox.Update()
    $LogTextBox.ScrollToEnd()
}

function Get-IPAddress {
    (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
}

function Get-UserProfileLastLogin {
    param(
        [string]$Domain,
        [string]$UserName
    )

    $CurrentUser = try { ([ADSI]"WinNT://$Domain/$UserName") } catch { }
    if ($CurrentUser.Properties.LastLogin) {
        try {
            [datetime](-join $CurrentUser.Properties.LastLogin)
        }
        catch {
            -join $CurrentUser.Properties.LastLogin
        }
    }
    elseif ($CurrentUser.Properties.Name) {
    }
    else {
        'N/A'
    }
}

function Get-UserProfiles {
    # Get all user profiles on this PC and let the user select which ones to migrate
    $RegKey = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    # Return each profile on this computer
    Get-ItemProperty -Path $RegKey | ForEach-Object {
        try {
            $SID = New-object System.Security.Principal.SecurityIdentifier($_.PSChildName)
            try {

                $User = $SID.Translate([System.Security.Principal.NTAccount]).Value

                # Don't show NT Authority accounts
                if ($User -notlike 'NT Authority\*') {
                    $Domain = $User.Split('\')[0]
                    $UserName = $User.Split('\')[1]
                    if ($Script:QueryLastLogon) {
                        $LastLogin = Get-UserProfileLastLogin -Domain $Domain -UserName $UserName
                    }
                    else {
                        $LastLogin = 'N/A'
                    }
                    $ProfilePath = Get-UserProfilePath -Domain $Domain -UserName $UserName

                    # Create and return a custom object for each user found
                    $UserObject = New-Object psobject
                    $UserObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain
                    $UserObject | Add-Member -MemberType NoteProperty -Name UserName -Value $UserName
                    $UserObject | Add-Member -MemberType NoteProperty -Name LastLogin -Value $LastLogin
                    $UserObject | Add-Member -MemberType NoteProperty -Name ProfilePath -Value $ProfilePath
                    $UserObject
                }
            }
            catch {
                Update-Log "Error while translating $SID to a user name." -Color 'Yellow'
            }
        }
        catch {
            Update-Log "Error while translating $($_.PSChildName) to SID." -Color 'Yellow'
        }
    }
}

function Get-UserProfilePath {
    param(
        [string]$Domain,
        [string]$UserName
    )

    $UserObject = New-Object System.Security.Principal.NTAccount($Domain, $UserName)
    $SID = $UserObject.Translate([System.Security.Principal.SecurityIdentifier])
    $User = Get-ItemProperty -Path "Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID.Value)"
    $User.ProfileImagePath
}

function Test-IsAdmin {
    $UserIdentity = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()

    if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Update-Log "You are not running this script as Administrator. " -Color 'Yellow' -NoNewLine
        Update-Log "Some tasks may fail if launched as Administrator.`n" -Color 'Yellow'
    }
}

function Set-SaveDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Destination', 'Source')]
        [string] $Type
    )

    # Bring up file explorer so user can select a directory to add
    $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
    $OpenDirectoryDialog.RootFolder = 'Desktop'
    $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
    if ($Type -eq 'Destination') {
        $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
    }
    else {
        $OpenDirectoryDialog.SelectedPath = $SaveSourceTextBox.Text
    }
    $OpenDirectoryDialog.ShowDialog() | Out-Null
    $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
    try {
        # If user hits cancel it could cause attempt to add null path, so check that there's something there
        if ($SelectedDirectory) {
            Update-Log "Changed save directory to [$SelectedDirectory]."
            if ($Type -eq 'Destination') {
                $SaveDestinationTextBox.Text = $SelectedDirectory
            }
            else {
                $SaveSourceTextBox.Text = $SelectedDirectory
            }
        }
    }
    catch {
        Update-Log "There was a problem with the directory you chose: $($_.Exception.Message)" -Color Red
    }
}

function Add-ExtraDirectory {
    # Bring up file explorer so user can select a directory to add
    $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
    $OpenDirectoryDialog.RootFolder = 'Desktop'
    $OpenDirectoryDialog.SelectedPath = 'C:\'
    $Result = $OpenDirectoryDialog.ShowDialog()
    $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
    try {
        # If user hits cancel don't add the path
        if ($Result -eq 'OK') {
            Update-Log "Adding to extra directories: $SelectedDirectory."
            $ExtraDirectoriesDataGridView.Rows.Add($SelectedDirectory)
        }
        else {
            Update-Log "Add directory action cancelled by user." -Color Yellow
        }
    }
    catch {
        Update-Log "There was a problem with the directory you chose: $($_.Exception.Message)" -Color Red
    }
}

function Remove-ExtraDirectory {
    # Remove selected cell from Extra Directories data grid view
    $CurrentCell = $ExtraDirectoriesDataGridView.CurrentCell
    Update-Log "Removed [$($CurrentCell.Value)] from extra directories."
    $CurrentRow = $ExtraDirectoriesDataGridView.Rows[$CurrentCell.RowIndex]
    $ExtraDirectoriesDataGridView.Rows.Remove($CurrentRow)
}

function Set-Config {
    $ExtraDirectoryCount = $ExtraDirectoriesDataGridView.RowCount

    if ($ExtraDirectoryCount) {
        Update-Log "Including $ExtraDirectoryCount extra directories."

        $ExtraDirectoryXML = @"
<!-- This component includes the additional directories selected by the user -->
<component type="Documents" context="System">
    <displayName>Additional Folders</displayName>
    <role role="Data">
        <rules>
            <include>
                <objectSet>

"@
        # Include each directory user has added to the Extra Directories data grid view
        $ExtraDirectoriesDataGridView.Rows | ForEach-Object {
            $CurrentRowIndex = $_.Index
            $Path = $ExtraDirectoriesDataGridView.Item(0, $CurrentRowIndex).Value

            $ExtraDirectoryXML += @"
                    <pattern type=`"File`">$Path\* [*]</pattern>"

"@
        }

        $ExtraDirectoryXML += @"
                </objectSet>
            </include>
        </rules>
    </role>
</component>
"@
    }
    else {
        Update-Log 'No extra directories will be included.'
    }

    Update-Log 'Data to be included:'
    foreach ($Control in $InclusionsGroupBox.Controls) { if ($Control.Checked) { Update-Log $Control.Text } }

    $ExcludedDataXML = @"
        $(
            if (-not $IncludePrintersCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_PRINTERS%\* [*]</pattern>`n" }
            if (-not $IncludeRecycleBinCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_BITBUCKET%\* [*]</pattern>`n" }
            if (-not $IncludeMyDocumentsCheckBox.Checked) {
                "<pattern type=`"File`">%CSIDL_MYDOCUMENTS%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_PERSONAL%\* [*]</pattern>`n"
            }
            if (-not $IncludeDesktopCheckBox.Checked) {
                "<pattern type=`"File`">%CSIDL_DESKTOP%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_DESKTOPDIRECTORY%\* [*]</pattern>`n"
            }
            if (-not $IncludeDownloadsCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_DOWNLOADS%\* [*]</pattern>`n" }
            if (-not $IncludeFavoritesCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_FAVORITES%\* [*]</pattern>`n" }
            if (-not $IncludeMyMusicCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYMUSIC%\* [*]</pattern>`n" }
            if (-not $IncludeMyPicturesCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYPICTURES%\* [*]</pattern>`n" }
            if (-not $IncludeMyVideoCheckBox.Checked) { "<pattern type=`"File`">%CSIDL_MYVIDEO%\* [*]</pattern>`n" }
        )
"@

    $AppDataXML = if ($IncludeAppDataCheckBox.Checked) {
        @"
        <!-- This component migrates all user app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>App Data</displayName>
            <paths>
                <path type="File">%CSIDL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $LocalAppDataXML = if ($IncludeLocalAppDataCheckBox.Checked) {
        @"
        <!-- This component migrates all user local app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>Local App Data</displayName>
            <paths>
                <path type="File">%CSIDL_LOCAL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_LOCAL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $WallpapersXML = if ($IncludeWallpapersCheckBox.Checked) {
        @"
        <!-- This component migrates wallpaper settings -->
        <component type="System" context="User">
            <displayName>Wallpapers</displayName>
            <role role="Settings">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [Pattern]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [PatternUpgrade]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallpaperStyle]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Windows\CurrentVersion\Themes [SetupVersion]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperLocalFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperStyle]</pattern>
                            <content filter="MigXmlHelper.ExtractSingleFile(NULL, NULL)">
                                <objectSet>
                                    <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                                </objectSet>
                            </content>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>

        <!-- This component migrates wallpaper files -->
        <component type="Documents" context="System">
            <displayName>Move JPG and BMP</displayName>
            <role role="Data">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="File"> %windir% [*.bmp]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.jpg]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.bmp]</pattern>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>
"@
    }

    $ConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<migration urlid="http://www.microsoft.com/migration/1.0/migxmlext/config">
<_locDefinition>
    <_locDefault _loc="locNone"/>
    <_locTag _loc="locData">displayName</_locTag>
</_locDefinition>

$ExtraDirectoryXML

<!-- This component migrates all user data except specified exclusions -->
<component type="Documents" context="User">
    <displayName>Documents</displayName>
    <role role="Data">
        <rules>
            <include filter="MigXmlHelper.IgnoreIrrelevantLinks()">
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","TRUE","FALSE")</script>
                </objectSet>
            </include>
            <exclude filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","FALSE","FALSE")</script>
                </objectSet>
            </exclude>
            <exclude>
                <objectSet>
$ExcludedDataXML
                </objectSet>
            </exclude>
            <contentModify script="MigXmlHelper.MergeShellLibraries('TRUE','TRUE')">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </contentModify>
            <merge script="MigXmlHelper.SourcePriority()">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </merge>
        </rules>
    </role>
</component>

$AppDataXML

$LocalAppDataXML

$WallpapersXML

</migration>
"@

    $Config = "$Destination\Config.xml"
    try {
        New-Item $Config -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Update-Log "Error creating config file [$Config]: $($_.Exception.Message)" -Color 'Red'
        return
    }
    try {
        Set-Content $Config $ConfigContent -ErrorAction Stop
    }
    catch {
        Update-Log "Error while setting config file content: $($_.Exception.Message)" -Color 'Red'
        return
    }

    # Return the path to the config
    $Config
}

function Get-USMT {
    # Test that USMT binaries are reachable
    if (Test-Path $USMTPath) {
        $Script:ScanState = "$USMTPath\scanstate.exe"
        $Script:LoadState = "$USMTPath\loadstate.exe"
        Update-Log "Using [$USMTPath] as path to USMT binaries."
    }
    else {
        Update-Log "Unable to reach USMT binaries. Verify [$USMTPath] exists and restart script.`n" -Color 'Red'
        $MigrateButton_OldPage.Enabled = $false
        $MigrateButton_NewPage.Enabled = $false
    }
}

function Get-USMTResults {
    param([string] $ActionType)

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        # Print back the entire log
        $Results = Get-Content "$Destination\$ActionType.log" | Out-String
    }
    else {
        # Get the last 4 lines from the log so we can see the results
        $Results = Get-Content "$Destination\$ActionType.log" -Tail 4 | ForEach-Object {
            ($_.Split(']', 2)[1]).TrimStart()
        } | Out-String
    }

    Update-Log $Results -Color 'Cyan'

    if ($ActionType -eq 'load') {
        Update-Log 'A reboot is recommended.' -Color 'Yellow'

        $EmailSubject = "Migration Load Results of $($OldComputerNameTextBox_NewPage.Text) to $($NewComputerNameTextBox_NewPage.Text)"
    }
    else {
        $EmailSubject = "Migration Save Results of $($OldComputerNameTextBox_OldPage.Text) to $($NewComputerNameTextBox_OldPage.Text)"
    }

    if ($EmailCheckBox.Checked) {
        if ($SMTPConnectionCheckBox.Checked -or (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
            $SMTPConnectionCheckBox.Checked = $true

            $EmailRecipients = @()

            $EmailRecipientsDataGridView.Rows | ForEach-Object {
                $CurrentRowIndex = $_.Index
                $EmailRecipients += $EmailRecipientsDataGridView.Item(0, $CurrentRowIndex).Value
            }

            Update-Log "Emailing migration results to: $EmailRecipients"

            try {
                $SendMailMessageParams = @{
                    From        = $EmailSenderTextBox.Text
                    To          = $EmailRecipients
                    Subject     = $EmailSubject
                    Body        = $LogTextBox.Text
                    SmtpServer  = $SMTPServerTextBox.Text
                    Attachments = "$Destination\$ActionType.log"
                }
                Send-MailMessage @SendMailMessageParams
            }
            catch {
                Update-Log "Error occurred sending email: $($_.Exception.Message)" -Color 'Red'
            }
        }
        else {
            Update-Log "Unable to send email of results because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
        }
    }
}

function Get-USMTProgress {
    param(
        [string] $Destination,

        [string] $ActionType
    )

    try {
        # Get the most recent entry in the progress log
        $LastLine = Get-Content "$Destination\$($ActionType)_progress.log" -Tail 1 -ErrorAction SilentlyContinue | Out-String
        Update-Log ($LastLine.Split(',', 4)[3]).TrimStart()
    }
    catch { Update-Log '.' -NoNewLine }
}

function Get-SaveState {
    # Use the migration folder name to get the old computer name
    if (Get-ChildItem $SaveSourceTextBox.Text -ErrorAction SilentlyContinue) {
        $SaveSource = Get-ChildItem $SaveSourceTextBox.Text | Where-Object { $_.PSIsContainer } |
            Sort-Object -Descending -Property { $_.CreationTime } | Select-Object -First 1
        if (Test-Path "$($SaveSource.FullName)\USMT\USMT.MIG") {
            $Script:UncompressedSource = $false
        }
        else {
            $Script:UncompressedSource = $true
            Update-Log -Message "Uncompressed save state detected."
        }
        $OldComputer = $SaveSource.BaseName
        Update-Log -Message "Old computer set to $OldComputer."
    }
    else {
        $OldComputer = 'N/A'
        Update-Log -Message "No saved state found at [$($SaveSourceTextBox.Text)]." -Color 'Yellow'
    }

    $OldComputer
}

function Show-DomainInfo {
    # Populate old user data if DomainMigration.txt file exists, otherwise disable group box
    if (Test-Path "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt") {
        $OldUser = Get-Content "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt"
        $OldDomainTextBox.Text = $OldUser.Split('\')[0]
        $OldUserNameTextBox.Text = $OldUser.Split('\')[1]
    }
    else {
        $CrossDomainMigrationGroupBox.Enabled = $false
        $CrossDomainMigrationGroupBox.Hide()
    }
}

function Save-UserState {
    param(
        [switch] $Debug
    )

    Update-Log "`nBeginning migration..."

    # Run scripts before doing actual data migration
    $OldComputerScriptsDataGridView.Rows | ForEach-Object {
        $ScriptName = $OldComputerScriptsDataGridView.Item(0, $_.Index).Value
        $ScriptPath = "$PSScriptRoot\USMT\Scripts\OldComputer\$ScriptName"
        Update-Log "Running $ScriptPath"
        if (-not $Debug) {
            $Result = if ($ScriptPath.EndsWith('ps1')) {
                . $ScriptPath
            }
            else {
                Start-Process $ScriptPath -Wait -PassThru
            }
            Update-Log ($Result | Out-String)
        }
    }

    # If we're saving locally, skip network stuff
    if ($SaveRemotelyCheckBox.Checked) {
        # If connection hasn't been verfied, test now
        if (-not $ConnectionCheckBox_OldPage.Checked) {
            $TestComputerConnectionParams = @{
                ComputerNameTextBox = $NewComputerNameTextBox_OldPage
                ComputerIPTextBox   = $NewComputerIPTextBox_OldPage
                ConnectionCheckBox  = $ConnectionCheckBox_OldPage
            }
            Test-ComputerConnection @TestComputerConnectionParams
        }

        # Try and use the IP if the user filled that out, otherwise use the name
        if ($NewComputerIPTextBox_OldPage.Text -ne '') {
            $NewComputer = $NewComputerIPTextBox_OldPage.Text
        }
        else {
            $NewComputer = $NewComputerNameTextBox_OldPage.Text
        }
    }

    $OldComputer = $OldComputerNameTextBox_OldPage.Text

    # After connection has been verified, continue with save state
    if ($ConnectionCheckBox_OldPage.Checked -or (-not $SaveRemotelyCheckBox.Checked)) {
        Update-Log 'Connection verified, proceeding with migration...'

        # Get the selected profiles
        if ($RecentProfilesCheckBox.Checked -eq $true) {
            Update-Log "All profiles logged into within the last $($RecentProfilesDaysTextBox.Text) days will be saved."
        }
        elseif ($Script:SelectedProfile) {
            Update-Log "Profile(s) selected for save state:"
            $Script:SelectedProfile | ForEach-Object { Update-Log $_.UserName }
        }
        else {
            Update-Log "You must select a user profile." -Color 'Red'
            return
        }

        if (-not $SaveRemotelyCheckBox.Checked) {
            $Script:Destination = "$($SaveDestinationTextBox.Text)\$OldComputer"
        }
        else {
            # Set destination folder on new computer
            try {
                $DriveLetter = $MigrationStorePath.Split(':', 2)[0]
                $MigrationStorePath = $MigrationStorePath.TrimStart('C:\')
                New-Item "\\$NewComputer\$DriveLetter$\$MigrationStorePath" -ItemType Directory -Force | Out-Null
                $Script:Destination = "\\$NewComputer\$DriveLetter$\$MigrationStorePath\$OldComputer"
            }
            catch {
                Update-Log "Error while creating migration store [$Destination]: $($_.Exception.Message)" -Color 'Yellow'
                return
            }
        }

        # Create destination folder
        if (!(Test-Path $Destination)) {
            try {
                New-Item $Destination -ItemType Directory -Force | Out-Null
            }
            catch {
                Update-Log "Error while creating migration store [$Destination]: $($_.Exception.Message)" -Color 'Yellow'
                return
            }
        }

        #Verify that the Destination folder is valid.
        if (Test-Path $Destination) {

            # If profile is a domain other than $DefaultDomain, save this info to text file
            if ($RecentProfilesCheckBox.Checked -eq $false) {
                $FullUserName = "$($Script:SelectedProfile.Domain)\$($Script:SelectedProfile.UserName)"
                if ($Script:SelectedProfile.Domain -ne $DefaultDomain) {
                    New-Item "$Destination\DomainMigration.txt" -ItemType File -Value $FullUserName -Force | Out-Null
                    Update-Log "Text file created with cross-domain information."
                }
            }

            # Clear encryption syntax in case it's already defined.
            $EncryptionSyntax = ""
            # Determine if Encryption has been requested
            if ($Script:EncryptionPasswordSet -eq $True) {
                #Disable Compression
                $Script:UncompressedSource = $false
                $Uncompressed = ''
                # Set the syntax for the encryption
                $EncryptionKey = """$Script:EncryptionPassword"""
                $EncryptionSyntax = "/encrypt /key:$EncryptionKey"
            }

            #Set the value to continue on error if it was specified above
            if ($ContinueOnError -eq $True) {
                $ContinueCommand = "/c"
            }
            if ($ContinueOnError -eq $False) {
                $ContinueCommand = ""
            }


            # Create config syntax for scanstate for custom XMLs.
            IF ($SelectedXMLS) {
                #Create the scanstate syntax line for the config files.
                foreach ($ConfigXML in $SelectedXMLS) {
                    $ConfigXMLPath = """$Script:USMTPath\$ConfigXML"""
                    $ScanstateConfig += "/i:$ConfigXMLPath "
                }
            }

            # Create config syntax for scanstate for generated XML.
            IF (!($SelectedXMLS)) {
                # Create the scan configuration
                Update-Log 'Generating configuration file...'
                $Config = Set-Config
                $GeneratedConfig = """$Config"""
                $ScanStateConfig = "/i:$GeneratedConfig"
            }

            # Generate parameter for logging
            $Logs = "`"/listfiles:$Destination\FilesMigrated.log`" `"/l:$Destination\scan.log`" `"/progress:$Destination\scan_progress.log`""

            # Set parameter for whether save state is compressed
            if ($UncompressedCheckBox.Checked -eq $true) {
                $Uncompressed = '/nocompress'
            }
            else {
                $Uncompressed = ''
            }

            # Create a string for all users to exclude by default
            foreach ($ExcludeProfile in $Script:DefaultExcludeProfile) {
                $ExcludeProfile = """$ExcludeProfile"""
                $UsersToExclude += "/ue:$ExcludeProfile "
            }

            # Set the EFS Syntax based on the config.
            if ($EFSHandling) {
                $EFSSyntax = "/efs:$EFSHandling"
            }


            # Overwrite existing save state, use volume shadow copy method, exclude all but the selected profile(s)
            # Get the selected profiles
            if ($RecentProfilesCheckBox.Checked -eq $true) {
                $Arguments = "`"$Destination`" $ScanStateConfig /o /vsc $UsersToExclude /uel:$($RecentProfilesDaysTextBox.Text) $EncryptionSyntax $Uncompressed $Logs $EFSSyntax $ContinueCommand"
            }
            else {
                $UsersToInclude += $Script:SelectedProfile | ForEach-Object { "`"/ui:$($_.Domain)\$($_.UserName)`"" }
                $Arguments = "`"$Destination`" $ScanStateConfig /o /vsc /ue:* $UsersToExclude $UsersToInclude $EncryptionSyntax $Uncompressed $Logs $EFSSyntax $ContinueCommand "
            }

            # Begin saving user state to new computer
            # Create a value to show in the log in order to obscure the encryption key if one was used.
            $LogArguments = $Arguments -Replace '/key:".*"', '/key:(Hidden)'

            Update-Log "Command used:"
            Update-Log "$ScanState $LogArguments" -Color 'Cyan'


            # If we're running in debug mode don't actually start the process
            if ($Debug) { return }

            Update-Log "Saving state of $OldComputer to $Destination..." -NoNewLine
            Start-Process -FilePath $ScanState -ArgumentList $Arguments -Verb RunAs

            # Give the process time to start before checking for its existence
            Start-Sleep -Seconds 3

            # Wait until the save state is complete
            try {
                $ScanProcess = Get-Process -Name scanstate -ErrorAction Stop
                while (-not $ScanProcess.HasExited) {
                    Get-USMTProgress
                    Start-Sleep -Seconds 3
                }
                Update-Log "Complete!" -Color 'Green'

                Update-Log 'Results:'
                Get-USMTResults -ActionType 'scan'
            }
            catch {
                Update-Log $_.Exception.Message -Color 'Red'
            }
        }
        ELSE {
            Update-Log "Error when trying to access [$Destination] Please verify that the user account running the utility has appropriate permissions to the folder.: $($_.Exception.Message)" -Color 'Yellow'
        }
    }
}

function Restore-UserState {
    param(
        [switch] $Debug
    )

    Update-Log "`nBeginning migration..."

    # Run scripts before doing actual data migration
    $NewComputerScriptsDataGridView.Rows | ForEach-Object {
        $ScriptName = $NewComputerScriptsDataGridView.Item(0, $_.Index).Value
        $ScriptPath = "$PSScriptRoot\USMT\Scripts\NewComputer\$ScriptName"
        Update-Log "Running $ScriptPath"
        if (-not $Debug) {
            $Result = if ($ScriptPath.EndsWith('ps1')) {
                . $ScriptPath
            }
            else {
                Start-Process $ScriptPath -Wait -PassThru
            }
            Update-Log ($Result | Out-String)
        }
    }

    # If override is enabled, skip network checks
    if (-not $OverrideCheckBox.Checked) {
        # If connection hasn't been verfied, test now
        if (-not $ConnectionCheckBox_NewPage.Checked) {
            $TestComputerConnectionParams = @{
                ComputerNameTextBox = $OldComputerNameTextBox_NewPage
                ComputerIPTextBox   = $OldComputerIPTextBox_NewPage
                ConnectionCheckBox  = $ConnectionCheckBox_NewPage
            }
            Test-ComputerConnection @TestComputerConnectionParams
        }

        # Try and use the IP if the user filled that out, otherwise use the name
        if ($OldComputerIPTextBox_NewPage.Text -ne '') {
            $OldComputer = $OldComputerIPTextBox_NewPage.Text
        }
        else {
            $OldComputer = $OldComputerNameTextBox_NewPage.Text
        }

        if ($ConnectionCheckBox_NewPage.Checked) {
            Update-Log "Connection verified, checking in with $OldComputer..."

            # Check in with the old computer and don't start until the save is complete
            if (Get-Process -Name scanstate -ComputerName $OldComputer -ErrorAction SilentlyContinue) {
                Update-Log "Waiting on $OldComputer to complete save state..."
                while (Get-Process -Name scanstate -ComputerName $OldComputer -ErrorAction SilentlyContinue) {
                    Get-USMTProgress
                    Start-Sleep -Seconds 1
                }
            }
            else {
                Update-Log "Save state process on $OldComputer is complete. Proceeding with migration."
            }
        }
        else {
            Update-Log "Unable to verify connection with $OldComputer. Migration cancelled." -Color 'Red'
            return
        }
    }
    else {
        $OldComputer = $OldComputerNameTextBox_NewPage.Text
        Update-Log "User has verified the save state process on $OldComputer is already completed. Proceeding with migration."
    }
    $OldComputerName = $OldComputerNameTextBox_NewPage.Text

    # Get the location of the save state data
    $Script:Destination = "$($SaveSourceTextBox.Text)\$OldComputerName"

    # Check that the save state data exists
    if (-not (Test-Path $Destination)) {
        Update-Log "No saved state found at [$Destination]. Migration cancelled." -Color 'Red'
        return
    }

    # Clear decryption syntax in case it's already defined.
    $DecryptionSyntax = ""
    # Determine if Encryption has been requested
    if ($Script:EncryptionPasswordSet -eq $True) {
        # Disable Compression
        $Script:UncompressedSource = $false
        $Uncompressed = ''
        # Set the syntax for the encryption
        $DecryptionKey = """$Script:EncryptionPassword"""
        $DecryptionSnytax = "/decrypt /key:$DecryptionKey"
    }

    # Set the value to continue on error if it was specified above
    if ($ContinueOnError -eq $True) {
        $ContinueCommand = "/c"
    }
    if ($ContinueOnError -eq $false) {
        $ContinueCommand = ""
    }

    # Set the value for the Config file if one exists.
    if (Test-Path "$Destination\Config.xml") {
        $LoadStateConfigFile = """$Destination\Config.xml"""
        $LoadStateConfig = "/i:$LoadStateConfigFile"
    }

    # Generate arguments for load state process
    $Logs = "`"/l:$Destination\load.log`" `"/progress:$Destination\load_progress.log`""

    # Set parameter for whether save state is compressed
    if ($UncompressedSource -eq $true) {
        $Uncompressed = '/nocompress'
    }
    else {
        $Uncompressed = ''
    }

    # Options for creating local accounts that don't already exist on new computer
    $LocalAccountOptions = ''
    if ($Script:DefaultLACreate -eq $true) {
        $LocalAccountOptions = "`"/lac:$Script:DefaultLAPassword`""
        if ($Script:DefaultLACEnable -eq $true) {
            $LocalAccountOptions += ' /lae'
        }
    }
    else {
        ''
    }

    # Check if user to be migrated is coming from a different domain and do a cross-domain migration if so
    if ($CrossDomainMigrationGroupBox.Enabled) {
        $OldUser = "$($OldDomainTextBox.Text)\$($OldUserNameTextBox.Text)"
        $NewUser = "$($NewDomainTextBox.Text)\$($NewUserNameTextBox.Text)"

        # Make sure the user entered a new user's user name before continuing
        if ($NewUserNameTextBox.Text -eq '') {
            Update-Log "New user's user name must not be empty." -Color 'Red'
            return
        }

        Update-Log "$OldUser will be migrated as $NewUser."
        $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions `"/mu:$($OldUser):$NewUser`" $DecryptionSnytax $Uncompressed $Logs $ContinueCommand /v:$Script:VerboseLevel"
    }
    else {
        $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions $DecryptionSnytax $Uncompressed $Logs $ContinueCommand /v:$Script:VerboseLevel"
    }

    # Begin loading user state to this computer
    # Create a value in order to obscure the encryption key if one was specified.
    $LogArguments = $Arguments -Replace '/key:".*"', '/key:(Hidden)'
    Update-Log "Command used:"
    Update-Log "$LoadState $LogArguments" -Color 'Cyan'


    # If we're running in debug mode don't actually start the process
    if ($Debug) { return }

    Update-Log "Loading state of $OldComputer..." -NoNewLine
    $USMTLoadState = Start-Process -FilePath $LoadState -ArgumentList $Arguments -Verb RunAs -PassThru
    $USMTLoadState
    # Give the process time to start before checking for its existence
    Start-Sleep -Seconds 3

    # Wait until the load state is complete
    try {
        $LoadProcess = Get-Process -Name loadstate -ErrorAction Stop
        while (-not $LoadProcess.HasExited) {
            Get-USMTProgress
            Start-Sleep -Seconds 1
        }

        Update-Log 'Results:'
        Get-USMTResults -ActionType 'load'

        # Sometimes loadstate will kill the explorer task and it needs to be start again manually
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Update-Log 'Restarting Explorer process.'
            Start-Process explorer
        }

        if ($USMTLoadState.ExitCode -eq 0) {
            Update-Log "Complete!" -Color 'Green'

            # Delete the save state data
            try {
                Get-ChildItem $MigrationStorePath | Remove-Item -Recurse
                Update-Log 'Successfully removed old save state data.'
            }
            catch {
                Update-Log 'There was an issue when trying to remove old save state data.'
            }
        }
        else {
            update-log 'There was an issue during the loadstate process, please review the results. The state data was not deleted.'
        }
    }
    catch {
        Update-Log $_.Exception.Message -Color 'Red'
    }
}

function Test-ComputerConnection {
    param(
        [System.Windows.Forms.TextBox] $ComputerNameTextBox,

        [System.Windows.Forms.TextBox] $ComputerIPTextBox,

        [System.Windows.Forms.CheckBox] $ConnectionCheckBox
    )

    $ConnectionCheckBox.Checked = $false
    Update-Log "Testing yolo"  -Color 'Red'

    # Try and use the IP if the user filled that out, otherwise use the name
    if ($ComputerIPTextBox.Text -ne '') {
        $Computer = $ComputerIPTextBox.Text
        # Try to update the computer's name with its IP address
        if ($ComputerNameTextBox.Text -eq '') {
            try {
                Update-Log 'Computer name is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
                $HostName = ([System.Net.Dns]::GetHostEntry($Computer)).HostName
                $ComputerNameTextBox.Text = $HostName
                Update-Log "Computer name set to $HostName."
            }
            catch {
                Update-Log "Unable to resolve host name from IP address, you'll need to manually set this." -Color 'Red'
                return
            }
        }
    }
    elseif ($ComputerNameTextBox.Text -ne '') {
        $Computer = $ComputerNameTextBox.Text
        # Try to update the computer's IP address using its DNS name
        try {
            Update-Log 'Computer IP address is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
            # Get the first IP address found, which is usually the primary adapter
            $IPAddress = ([System.Net.Dns]::GetHostEntry($Computer)).AddressList.IPAddressToString.Split('.', 1)[0]

            # Set IP address in text box
            $ComputerIPTextBox.Text = $IPAddress
            Update-Log "Computer IP address set to $IPAddress."
        }
        catch {
            Update-Log "Unable to resolve IP address from host name, you'll need to manually set this." -Color 'Red'
            return
        }
    }
    else {
        $Computer = $null
    }

    # Don't even try if both fields are empty
    if ($Computer) {
        # If the computer doesn't appear to have a valid office IP, such as if it's on VPN, don't allow the user to continue
        if ($ComputerIPTextBox.Text -notlike $ValidIPAddress) {
            Update-Log "$IPAddress does not appear to be a valid IP address. The Migration Tool requires an IP address matching $ValidIPAddress." -Color 'Red'
            return
        }

        Update-Log "Testing connection to $Computer..." -NoNewLine

        if (Test-Connection $Computer -Quiet) {
            $ConnectionCheckBox.Checked = $true
            Update-Log "Connection established." -Color 'Green'
        }
        else {
            Update-Log "Unable to reach $Computer." -Color 'Red'
            if ($ComputerIPTextBox.Text -eq '') {
                Update-Log "Try entering $Computer's IP address." -Color 'Yellow'
            }
        }
    }
    else {
        Update-Log "Enter the computer's name or IP address."  -Color 'Red'
    }
}

function Set-Logo {
    Update-Log "             __  __ _                 _   _             " -Color 'LightBlue'
    Update-Log "            |  \/  (_) __ _ _ __ __ _| |_(_) ___  _ __  " -Color 'LightBlue'
    Update-Log "            | |\/| | |/ _`` | '__/ _`` | __| |/ _ \| '_ \ " -Color 'LightBlue'
    Update-Log "            | |  | | | (_| | | | (_| | |_| | (_) | | | |" -Color 'LightBlue'
    Update-Log "            |_|  |_|_|\__, |_|  \__,_|\__|_|\___/|_| |_|" -Color 'LightBlue'
    Update-Log "                _     |___/  _     _              _     " -Color 'LightBlue'
    Update-Log "               / \   ___ ___(_)___| |_ __ _ _ __ | |_   " -Color 'LightBlue'
    Update-Log "              / _ \ / __/ __| / __| __/ _`` | '_ \| __|  " -Color 'LightBlue'
    Update-Log "             / ___ \\__ \__ \ \__ \ || (_| | | | | |_   " -Color 'LightBlue'
    Update-Log "            /_/   \_\___/___/_|___/\__\__,_|_| |_|\__| $ScriptVersion" -Color 'LightBlue'
    Update-Log
    Update-Log '                        by Nick Rodriguez' -Color 'Gold'
    Update-Log
}

function Test-IsISE { if ($psISE) { $true } else { $false } }

function Test-PSVersion {
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Update-Log "You are running a version of PowerShell less than 3.0 - some features have been disabled."
        $ChangeSaveDestinationButton.Enabled = $false
        $ChangeSaveSourceButton.Enabled = $false
        $AddExtraDirectoryButton.Enabled = $false
    }
}

function Test-Email {
    $EmailSubject = "Migration Assistant Email Test"
    if ($SMTPConnectionCheckBox.Checked -or (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
        $SMTPConnectionCheckBox.Checked = $true

        $EmailRecipients = @()

        $EmailRecipientsDataGridView.Rows | ForEach-Object {
            $CurrentRowIndex = $_.Index
            $EmailRecipients += $EmailRecipientsDataGridView.Item(0, $CurrentRowIndex).Value
        }

        Update-Log "Sending test email to: $EmailRecipients"

        try {
            $SendMailMessageParams = @{
                From        = $EmailSenderTextBox.Text
                To          = $EmailRecipients
                Subject     = $EmailSubject
                Body        = $LogTextBox.Text
                SmtpServer  = $SMTPServerTextBox.Text
                ErrorAction = 'Stop'
            }
            Send-MailMessage @SendMailMessageParams
        }
        catch {
            Update-Log "Error occurred sending email: $($_.Exception.Message)" -Color 'Red'
        }
    }
    else {
        Update-Log "Unable to send email of results because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
    }
}

function Read-Password {
    # Set the password set flag to false.
    $Script:EncryptionPasswordSet = $Null
    # Clear the password reset flag.
    $Script:EncryptionPasswordRetry = $Null

    # Prompt the user for an encryption password.
    $Script:EncryptionPassword = $Null
    $Script:EncryptionPassword = Get-Credential -Message "Enter the encryption password" -UserName "Enter a password Below"
    # Prompt the user again for confirmation.
    $Script:EncryptionPasswordConfirm = $Null
    $Script:EncryptionPasswordConfirm = Get-Credential -Message "Please confirm the encryption password" -UserName "Enter a password Below"

    # Convert the password strings to plain text so that they can be compared.
    if ($Script:EncryptionPassword.Password) {
        $Script:EncryptionPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:EncryptionPassword.Password))
    }

    if ($Script:EncryptionPasswordConfirm.Password) {
        $Script:EncryptionPasswordConfirm = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:EncryptionPasswordConfirm.Password))
    }

    # Compare the password strings and verify that they match
    if ($Script:EncryptionPassword -ne $Script:EncryptionPasswordConfirm -or
        $Script:EncryptionPassword -eq "" -or
        $null -eq $Script:EncryptionPassword) {
        Update-Log "Password did not match or was blank." -Color 'Yellow'
    }
    else {
        # Set a flag that the password was successfully set
        $Script:EncryptionPasswordSet = $True
    }

    # Prompt the user to try again if the strings did not match.
    if ($Script:EncryptionPasswordSet -ne $True -and $Script:EncryptionPasswordRetry -ne '7') {
        do {
            $Script:EncryptionPasswordRetry = $WScriptShell.Popup(
                'Encryption password was not successfully set, try again?',
                0,
                'Retry Password',
                4
            )

            # Prompt again if the user opted to retry
            if ($Script:EncryptionPasswordRetry -ne '7') {
                Update-Log 'Retrying password prompt.' -Color Yellow
                Read-Password
            }

        } while ($Script:EncryptionPasswordSet -ne $True -and $Script:EncryptionPasswordRetry -ne '7')
    }
}