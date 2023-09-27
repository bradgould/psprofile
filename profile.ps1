# Changes PowerShell execution policies for Windows computers
# -ExecutionPolicy RemoteSigned
# 		Requires that all scripts and configuration files downloaded from the Internet
# 		are signed by a trusted publisher. The default execution policy for Windows server computers
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin))
{
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     Clear-Host
}

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not.
function prompt
{ 
    if ($isAdmin)
    {
        "[" + (Get-Location) + "] # "
    }
    else
    {
        "[" + (Get-Location) + "] $ "
    }
}

$titles =
@(
"BE THE WIZARD"#,
)

# Window title appends [ADMIN] if appropriate for easy taskbar identification
$Host.UI.RawUI.WindowTitle = $($titles | Get-Random)
if ($isAdmin)
{
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Sets working directory to "Scripts" folder
Set-Location C:\Users\$env:UserName\Scripts\

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin
{
    if ($args.Count -gt 0)
    {   
       $argList = "& '" + $args + "'"
       Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else
    {
       Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Compute file hashes
function md5
{
	Get-FileHash -Algorithm MD5 $args
}
function sha1
{
	Get-FileHash -Algorithm SHA1 $args
}
function sha256
{
	Get-FileHash -Algorithm SHA256 $args
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights.
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Clear the command history in the current session and delete the history file
function history-clear
{
	Clear-History
	Remove-Item (Get-PSReadlineOption).HistorySavePath
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal