

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

}

process {
    #Load Assembly and Library
    Add-Type -AssemblyName PresentationFramework

    #XAML form designed using Vistual Studio
    [xml]$Form = Get-Content -Path "$PSScriptRoot\USMTGUI.xaml"

    #Create a form
    $XMLReader = (New-Object System.Xml.XmlNodeReader $Form)
    $XMLForm = [Windows.Markup.XamlReader]::Load($XMLReader)

    #Load Controls
    $LogTextBox = $XMLForm.FindName('LogTextBox')
    $LogTextBox.Foreground = "Red"
    $LogTextBox.AppendText("Testing Color")
    $LogTextBox.Foreground = "Green"
    $LogTextBox.AppendText("Testing Color")
    #Set-Logo

    #Show XMLform
    $XMLForm.ShowDialog()
}