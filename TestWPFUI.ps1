

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
     if ((-not $(Test-IsISE)) -and ($HidePowershellWindow) ) {
        $ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
        $ShowWindowAsync::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, 0) | Out-Null
    }

    # Load assemblies for building forms
    #Add-Type -AssemblyName System.Windows.Forms
    #Add-Type -AssemblyName System.Drawing
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


    Set-Logo

    #Show XMLform
    $XMLForm.ShowDialog()
}