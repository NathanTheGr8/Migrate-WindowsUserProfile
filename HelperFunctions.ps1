function Update-Log {
    param(
        [string] $Message,

        [string] $Color = 'White',

        [switch] $NoNewLine
    )

    $BrushColor = $brushes.$color
    $LogTextBox.Foreground = $Color
    $LogTextBox.AppendText("$Message")
    if (-not $NoNewLine) { $LogTextBox.AppendText("`n") }
    ##$LogTextBox.Update()
    $LogTextBox.ScrollToEnd()
}

function Get-IPAddress { (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString }

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