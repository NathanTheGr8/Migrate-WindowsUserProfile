

begin {
    # Define the script version
    $ScriptVersion = "3.4.4"

    # Set ScriptRoot variable to the path which the script is executed from
    $ScriptRoot = if ($PSVersionTable.PSVersion.Major -lt 3) {
        Split-Path -Path $MyInvocation.MyCommand.Path
    }
    else {
        $PSScriptRoot
    }

    # Load Helper Functions
    . "$ScriptRoot\HelperFunctions.ps1"

    # Load the options in the Home Office Config file
    . "$ScriptRoot\USMT\Config.ps1"

    # Load the options in the Home Office Config file
    # . "$ScriptRoot\USMT\FieldCustom.ps1"

    # Set a value for the wscript comobject
    $WScriptShell = New-Object -ComObject wscript.shell

     # Hide parent PowerShell window unless run from ISE or set $HidePowershellWindow to false
     <#
     if ((-not $(Test-IsISE)) -and ($HidePowershellWindow) ) {
        $ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
        $ShowWindowAsync::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, 0) | Out-Null
    }
    #>

    # Load assemblies for building forms
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName PresentationFramework

    $Script:Destination = ''

}

process {

    #XAML form designed using Vistual Studio
    [xml]$Form = Get-Content -Path "$PSScriptRoot\USMTGUI.xaml"

    #Create a form
    $XMLReader = (New-Object System.Xml.XmlNodeReader $Form)
    $XMLForm = [Windows.Markup.XamlReader]::Load($XMLReader)

    #Load Controls
    $LogTextBox = $XMLForm.FindName('LogTextBox')
    $OldComputerNameTextBox_OldPage = $XMLForm.FindName('OldComputerNameTextBox_OldPage')
    $OldComputerIPTextBox_OldPage = $XMLForm.FindName('OldComputerIPTextBox_OldPage')
    $NewComputerNameTextBox_OldPage = $XMLForm.FindName('NewComputerNameTextBox_OldPage')
    $NewComputerIPTextBox_OldPage = $XMLForm.FindName('NewComputerIPTextBox_OldPage')
    $TestConnectionButton_OldPage = $XMLForm.FindName('TestConnectionButton_OldPage')
    $ConnectionCheckBox_OldPage = $XMLForm.FindName('ConnectionCheckBox_OldPage')
    $SelectProfileButton = $XMLForm.FindName('SelectProfileButton')
    $RecentProfilesDaysTextBox = $XMLForm.FindName('RecentProfilesDaysTextBox')
    $RecentProfilesCheckBox = $XMLForm.FindName('RecentProfilesCheckBox')
    $SaveDestinationTextBox = $XMLForm.FindName('SaveDestinationTextBox')


    #Set Default Values
    $OldComputerNameTextBox_OldPage.Text = $env:COMPUTERNAME
    $OldComputerIPTextBox_OldPage.Text = Get-IPAddress
    ##$ConnectionCheckBox_OldPage.Enabled = $false
    $RecentProfilesDaysTextBox.Text = $DefaultRecentProfilesDays
    $RecentProfilesCheckBox.Checked = $DefaultRecentProfiles
    $SaveDestinationTextBox.Text = $MigrationStorePath

    # Actions
    $NewComputerNameTextBox_OldPage.Add_TextChanged({
        if ($ConnectionCheckBox_OldPage.Checked) {
            Update-Log 'Computer name changed, connection status unverified.' -Color 'Yellow'
            $ConnectionCheckBox_OldPage.Checked = $false
        }
    })

    $NewComputerIPTextBox_OldPage.Add_TextChanged({
        if ($ConnectionCheckBox_OldPage.Checked) {
            Update-Log 'Computer IP address changed, connection status unverified.' -Color 'Yellow'
            $ConnectionCheckBox_OldPage.Checked = $false
        }
    })

    $TestConnectionButton_OldPage.Add_Click({
        $TestComputerConnectionParams = @{
            ComputerNameTextBox = $NewComputerNameTextBox_OldPage
            ComputerIPTextBox   = $NewComputerIPTextBox_OldPage
            ConnectionCheckBox  = $ConnectionCheckBox_OldPage
        }
        Test-ComputerConnection @TestComputerConnectionParams
    })

    $SelectProfileButton.Add_Click({
        Update-Log "Please wait while profiles are found..."
        $Script:SelectedProfile = Get-UserProfiles |
            Out-GridView -Title 'Profile Selection' -OutputMode Multiple
        Update-Log "Profile(s) selected for migration:"
        $Script:SelectedProfile | ForEach-Object { Update-Log $_.UserName }
    })


    Set-Logo

    #Show XMLform
    $XMLForm.ShowDialog()
}