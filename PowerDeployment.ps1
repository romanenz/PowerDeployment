param (
	[Alias('config', 'c')]
	[String]$ConfigFile = 'config.json',
	[String]$BlockedExe,
	[ValidateSet('none', 'basic', 'full')]
	[String]$UI = 'basic',
	[switch]$ForceReboot = $false
	
)
$ExitCode = -2
# Load assembly
Add-Type -AssemblyName "System.Windows.Forms"

#region Functions	
# Function to read the process
function _Get-Process()
{
	param (
		[Parameter(Mandatory = $True)]
		[String]$Name,
		[switch]$Check = $false
	)
	$Name = [regex]::Escape($Name)
	$process = Get-Process | Where-Object {
		$_.Product -match $Name -or $_.Description -match $Name
	}
	if ($Check -eq $true)
	{
		$Counter = 0
		While ($process -ne $null -and $Counter -lt 4)
		{
			$process = Get-Process | Where-Object {
				$_.Product -match $Name -or $_.Description -match $Name
			}
			$Counter++
		}
		
	}
	return $process
}
# Function to execute an exe
function Execute_ExeFile()
{
	param (
		[Parameter(Mandatory = $True)]
		[String]$file,
		[String]$arguments,
		$ExitCodes = @(0)
	)
	if (-not $arguments)
	{
		$Proc = Start-Process $file -PassThru
	}
	else
	{
		$Proc = Start-Process $file -ArgumentList $arguments -PassThru
	}
	Write-Log -Message ([String]::Format($LogTable.RunExeFile, $file, $arguments))
	Wait-Process -InputObject $Proc -Timeout $ProcessTimeOut -ErrorAction SilentlyContinue
	if ($file -match 'msiexec' -and $Proc.ExitCode -eq '1639' -and $arguments -match '^\/x{')
	{
		$arg = $arguments.Split(' ')[0] + ' /norestart /qn'
		
		Write-Log -Message ([String]::Format($LogTable.RetryRunExeFile, $file, $Proc.ExitCode, $arg))
		Write-Log -Message ([String]::Format($LogTable.RunExeFile, $file, $arg))
		$Proc = Start-Process $file -ArgumentList $arg -PassThru
		Wait-Process -InputObject $Proc -Timeout $ProcessTimeOut -ErrorAction SilentlyContinue
	}
	
	if ($Proc.HasExited -eq $false)
	{
		Write-Log -Message ([String]::Format($LogTable.RunExeFileTimeout, $file, $ProcessTimeOut))
		Stop-Process -InputObject $Proc -Force
	}
	# Write log
	Write-Log -Message ([String]::Format($LogTable.RunExeFileComplete, $file, $Proc.ExitCode))
	# test if exitcode is greater or equal 1 -> error
	$Script:ReceivedExitCodes += $Proc.ExitCode
	if ($Proc.ExitCode -notin $ExitCodes)
	{
		Throw [CustomException]::new('ExeError', ([String]::Format($LogTable.RunExeFileComplete, $file, $Proc.ExitCode)))
	}
}

# Function for the progress display
function Process_Bar()
{
	param (
		[String]$activity = 'Installation',
		[String]$status,
		[Parameter(Mandatory = $true)]
		[Int32]$percent
	)
	Write-Progress -Activity $activity -status $status -PercentComplete $percent
}
# Function to run a additional task
function Run-Task()
{
	param (
		[string]$ScriptPath,
		[string]$Parameters
	)
	# prepare parameters as array
	# split by space or : and replace named parameters
	[array]$Param = $Parameters.Split(" :") | Where-Object {
		$_ -notlike "-*"
	}
	# Write log
	Write-Log -Message ([String]::Format($LogTable.RunTask, $ScriptPath, $Parameters))
	# start  script as job
	$ScriptContent = Get-Content $ScriptPath -Raw
	$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($ScriptContent)
	
	$job = Start-Job -ScriptBlock $scriptblock -ArgumentList $Param -InitializationScript ([ScriptBlock]::Create("Set-Location $pwd;Set-Variable -Name ErrorActionPreference -Value SilentlyContinue")) -ErrorAction Stop
	Receive-Job $job -Wait -AutoRemoveJob
	
	# Write log
	Write-Log -Message ([String]::Format($LogTable.TaskComplete, $job.ChildJobs[0].JobStateInfo.State))
	# test if job exitcode ist greater or equal 1 -> error
	if ($job.ChildJobs[0].JobStateInfo.State -ne "Completed")
	{
		Throw [CustomException]::new('TaskError', ([string]::Format($LogTable.TaskError, $ScriptPath, $job.ChildJobs[0].JobStateInfo.Reason)))
	}
}

function Read-Answer
{
	param (
		[Parameter(Mandatory = $True)]
		[string]$Messsage,
		[ValidateSet('OK', 'YesNo')]
		$Buttons,
		[string]$Title = [System.IO.Path]::GetFileNameWithoutExtension($InvocationExe),

		[int]$Timeout = 0
	)
	$raw = @"
<Window x:Name="PowerDeploy" x:Class="WpfApp1.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        mc:Ignorable="d"
        Title="{0}" Height="300" Width="400" VerticalAlignment="Top" HorizontalAlignment="Left" WindowStartupLocation="CenterScreen" ResizeMode="NoResize">
    <Grid x:Name="ContentGrid">
        <Image x:Name="image" Margin="10,10,0,0" HorizontalAlignment="Left" Width="100" Height="50" VerticalAlignment="Top" Source="{1}"/>
        {2}
    </Grid>
</Window>
"@
	
	switch ($Buttons)
	{
		'OK' {
			$Button = '<Button x:Name="ButtonOK" Content="{0}" Margin="127,0,121,20" Height="20" VerticalAlignment="Bottom" HorizontalAlignment="Center" Width="75" Background="White"/>' -f $stringTable.ok
		}
		'YesNo' {
			$Button = @'
        <Button x:Name="ButtonYes" Content="{0}" HorizontalAlignment="Left" Margin="20,0,0,20" Width="75" IsDefault="True" Height="20" VerticalAlignment="Bottom" Background="White"/>
        <Button x:Name="ButtonNo" Content="{1}" Margin="0,0,20,20" IsCancel="True" Height="20" VerticalAlignment="Bottom" HorizontalAlignment="Right" Width="75" Background="White"/>
'@ -f $stringTable.yes, $stringTable.no
		}
	}
	for ($i = 1; $i -lt (($Messsage.Length / 60)); $i++)
	{
		$Messsage = $Messsage.Insert($Messsage.Substring(0, (60 * $i)).LastIndexOf(' ') + 1, '&#10;')
	}
	$Label = '<Label x:Name="Body" Content="{0}" HorizontalContentAlignment="Center" Margin="20,69,20,0" Height="auto" VerticalAlignment="Top"/>' -f $Messsage
	
	$Controls = $Label
	$Controls += $Button
	$t = [string]::Format($raw, $Title, $PopupPicture, $Controls)
	[xml]$XAML = $t -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window' #-replace wird benötigt, wenn XAML aus Visual Studio kopiert wird.
	
	[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
	$Form = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $XAML))
	switch ($Buttons)
	{
		'OK' {
			$Form.FindName("ButtonOK").Add_Click({
					$Form.Dialogresult = $false
					return
				})
		}
		'YesNo' {
			$Form.FindName("ButtonYes").Add_Click({
					$Form.Dialogresult = $true
					return
				})
			$Form.FindName("ButtonNo").Add_Click({
					$Form.Dialogresult = $false
					return
				})
		}
	}

	if ($Timeout -ne 0)
	{
		Function Timer_Tick()
		{
			--$Script:CountDown
			if ($Script:CountDown -lt 0)
			{
				$Timer.Stop();
				$Form.Close();
				$Timer.Dispose();
				$Script:CountDown = 5
			}
		}
		Write-Log -Message ([string]::Format($LogTable.ReadAnswerTimeout, $Timeout))
		$Timer = New-Object System.Windows.Forms.Timer
		$Timer.Interval = 1000
		$Script:CountDown = $Timeout
		
		$Timer.Add_Tick({ Timer_Tick })
		$Timer.Start()
	}
	$Form.ShowDialog()
}
function Write-Log()
{
	param (
		[Parameter(Mandatory = $true)]
		[String]$Message
	)
	$LogMessage = (Get-Date -Format HH:mm:ss) + ": " + $Message
	Write-Output $LogMessage
}
function Block-AppExecution()
{
	Param (
		[Parameter(Mandatory = $True, ValueFromPipeline = $true)]
		[string[]]$Name,
		[string]$DebuggerPath = $env:TEMP
	)
	foreach ($File in $Name)
	{
		# Checks if a complete path has been specified
		$File = [io.path]::GetFileName($File)
		
		# Defines the corresponding registry key
		[string]$regKeyAppExecution = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
		[string]$debuggerBlockValue = '{0} -BlockedExe {1}' -f $InvocationExe, $File
		[Microsoft.Win32.RegistryValueKind]$Type = 'String'
		
		# Creates the appropriate registry key
		$null = New-Item -Path (Join-Path -Path $regKeyAppExecution -ChildPath $File) -Force
		$null = New-ItemProperty -LiteralPath (Join-Path -Path $regKeyAppExecution -ChildPath $File) -Name 'Debugger' -Value $debuggerBlockValue -PropertyType $Type
	}
}
function Unblock-AppExecution()
{
	Param (
		[Parameter(Mandatory = $True, ValueFromPipeline = $true)]
		[string[]]$Name
	)
	foreach ($File in $Name)
	{
		# Checks if a complete path has been specified
		$File = [io.path]::GetFileName($File)
		
		[string]$regKeyAppExecution = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
		# Checks if this file is blocked
		if (Test-Path (Join-Path -Path $regKeyAppExecution -ChildPath $File))
		{
			Remove-Item -Path (Join-Path -Path $regKeyAppExecution -ChildPath $File) -Force
		}
		else
		{
			# Writes message if not blocked
			Write-Log -Message ([string]::Format($LogTable.WarningFileNotBlocked, $File))
		}
	}
}
#endregion


#region Variable definition

if ($null -ne $hostinvocation)
{
	$InvocationExe = $hostinvocation.MyCommand.path
}
else
{
	$InvocationExe = $script:MyInvocation.MyCommand.Path
}

# create custom errorexeption
class CustomException: System.Exception
{
	[string]$AnotherMessage
	[int]$SomeNumber
	CustomException($Message, $AnotherMessage): base ($Message)
	{
		$this.AnotherMessage = $AnotherMessage
	}
}
$is64Bit = [environment]::Is64BitOperatingSystem
$is64BitProcess = [Environment]::Is64BitProcess

# text messages
$LocalizedData = @{
	"de-DE"	      = @{
		MessageTitle				 = "Programm Installation"
		QuestionCloseApplication	 = "{0} wird noch ausgeführt. Programm schliessen und die Installation fortsetzen?"
		QuestionCloseBlockExe		 = "{0} wird installiert. Folgende Programme schliessen und die Installation fortsetzen? {1}"
		InfoCloseApplication		 = "{0} wird geschlossen und die Installation fortgesetzt"
		InfoCloseByRetrylimit	     = "{0} wird geschlossen. Die Installation kann nicht weiter verzögert werden."
		InfoCloseByRetrylimitBlock   = "{0} wird installiert. Die Installation kann nicht weiter verzögert werden. Folgende Programme werden geschlossen: {1}"
		InfoCancelInstallation	     = "Die Installation von {0} wird abgebrochen und zu einem späteren Zeitpunkt erneut ausgeführt."
		InfoInstallFinished		     = "Die Installation von {0} ist beendet."
		QuestionReboot			     = "{0} Computer jetzt neustarten?"
		InfoReboot				     = "Computer wird jetzt neugestartet!"
		CancelReboot				 = "Bitte Computer später neustarten."
		RebootMsg				     = "Installation benötigt einen Neustart."
		BlockedApplication		     = "Das ausführen von {0} ist vorübergehend gesperrt"
		yes						     = "Ja"
		no						     = "Nein"
		ok						     = "OK"
		ProcessBar				     = @{
			Start		     = "Installation wird gestartet"
			PreTask		     = "Aufgabe vor der Deinstallation wird ausgeführt"
			PreUninstall	 = "Deinstallation wird vorbereitet"
			Uninstall	     = "{0} wird deinstalliert"
			Task			 = "Aufgabe vor der Installation wird ausgeführt."
			PreInstall	     = "Installation wird vorbereitet"
			Install		     = "{0} wird installiert"
			PostTask		 = "Aufgabe nach der Installation wird ausgeführt."
			CleanUp		     = "Daten werden bereinigt"
			End			     = 'Installation beendet'
		}
	}
	"en-EN"	      = @{
		MessageTitle				 = "software installation"
		QuestionCloseApplication	 = "{0} is still running. Close the program and continue the installation?"
		QuestionCloseBlockExe	     = "{0} is being installed. Close the following programmes and continue the installation? {1}"
		InfoCloseApplication		 = "{0} is closed and the installation is continued"		
		InfoCloseByRetrylimit	     = "{0} must be closed. The installation cannot be delayed any further."
		InfoCloseByRetrylimitBlock    = "{0} is being installed. The installation cannot be delayed any further. The following programmes are closed: {1}"
		InfoCancelInstallation	     = "The installation of {0} will be aborted and run again at a later time."
		InfoInstallFinished		     = "The installation of {0} is finished."
		QuestionReboot			     = "{0} Restart computer now?"
		InfoReboot				     = "Computer will be restarted now!"
		CancelReboot				 = "Please restart computer later."
		RebootMsg				     = "Installation requires a reboot."
		BlockedApplication		     = "Running {0} is temporarily blocked"
		yes						     = "Yes"
		no						     = "No"
		ok						     = "OK"
		ProcessBar				     = @{
			Start		     = "Installation wird gestartet"
			PreTask		     = "Aufgabe vor der Deinstallation wird ausgeführt"
			PreUninstall	 = "Deinstallation wird vorbereitet"
			Uninstall	     = "{0} wird deinstalliert"
			Task			 = "Aufgabe vor der Installation wird ausgeführt."
			PreInstall	     = "Installation wird vorbereitet"
			Install		     = "{0} wird installiert"
			PostTask		 = "Aufgabe nach der Installation wird ausgeführt."
			CleanUp		     = "Daten werden bereinigt"
			End			     = 'Installation beendet'
		}
	}
}

$DefaultLocalizedData = 'de-DE'
$SystemLocale = (Get-WinSystemLocale).name.tostring()
if ($SystemLocale -ne $null -and $SystemLocale -in $LocalizedData.Keys)
{
	$stringTable = $LocalizedData.$SystemLocale
}
else
{
	$stringTable = $LocalizedData.$DefaultLocalizedData
}
# Processbar messages
$ProcessBar = $stringTable.ProcessBar

# log messages
$LogTable = @{
	Start				    = 'installation of {0} is started'
	StartInstall		    = 'install...'
	CancelInstall		    = 'installation of {0} was canceled by user'
	VariableNotSet		    = 'variable  {0} not set'
	RunningProcess			= 'process {0} is running'
	StopProcess			    = 'terminating process: {0}'
	RetryLimitReached		= 'Limit of {0} retries reached'
	StoppingService		    = 'stopping service: {0}'
	ProcessRunning		    = "the process {0} could not be terminated"
	RunTask				    = "Script {0} is executed with parameters: "
	TaskComplete		    = "Script finished with status {0}."
	TaskError			    = "Script {0} finished with error: {1}"
	StartUninstall		    = "uninstalling..."
	Uninstall			    = "uninstalling {0}"
	UninstallNotFound	    = "uninstall command for {0} not found"
	UninstallError		    = "uninstall command for {0} finished with error: {1}"
	RunExeFile			    = "running {0} with parameters: {1}"
	RetryRunExeFile		    = "{0} endet with error {1} retry with parameters:: {2}"
	RunExeFileComplete	    = '{0} finished with status {1}'
	RunExeFileTimeout	    = '{0} has run into a timeout of {1}. process is terminated'
	ExeFileError		    = "installing {0} finished with error: {1}"
	UninstallMSI		    = "MSI uninstalling for {0} with parameters: {1}"
	UninstallMSIError	    = "MSI uninstalling for {0} finished with error: {1}"
	BlockApplication	    = "block {0}"
	UnblockApplication	    = "unblock {0}"
	CleanUp				    = "clean up files"
	PathNotFound		    = "file {0} not found"
	Exit				    = "installation {0} aborted"
	Finish				    = "installation finished"
	Reboot				    = "restarting computer"
	CancelReboot		    = "restart aborted by user"
	UnexpectedError		    = "unknown error:"
	is64BitOS			    = "OS 64bit: {0}"
	is64BitProcess		    = "Powershell 64bit: {0}"
	User					= 'user logon: {0}'
	RebootExitcodes		    = "ExitCodes require restart: {0}"
	WorkingDirectory	    = 'Working Directory: {0}'
	Executionpolicy		    = 'Executionpolicy: {0}'
	ExitCode			    = 'Completed with exitcode {0}'
	ReadAnswerTimeout	    = 'wait for {0}s to answer'
	WarningFileNotBlocked   = 'file {0} not blocked'
	InPlaceUpdate		    = 'InPlaceUpdate: {0}'
	Copy					= 'Copy {0} to {1}'
}

$ReceivedExitCodes = @()
$ExitCodes = @{
	Sucessfull		   = 0
	RebootRequired	   = 1
	Failed			   = 2
	Canceled		   = 3
	AdminRequired	   = -1
}

$Silent = if ($UI -eq 'none') { $true }
else { $false }
#endregion


# set working directory
if ([string]::IsNullOrEmpty([System.IO.Path]::GetDirectoryName($ConfigFile)) -eq $true)
{
	$WorkingDirectory = [System.IO.Path]::GetDirectoryName($InvocationExe)
}
else
{
	$WorkingDirectory = [System.IO.Path]::GetDirectoryName($ConfigFile)
}
Set-Location $WorkingDirectory

if ($Commandline -match '[\/-][\?]')
{
	$Message = @'
Parameters:
-Configfile - Json configuration file
-BlockedExe - show BlockExe popup
-UI - define ui style none|basic|full
-ForceReboot - if ui set to none, force required reboot
-Template - create config template file
-? - Show this help

Exitcodes:
0  Sucessfull
1  RebootRequired
2  Failed
3  Canceled by User
101 Blocked Exe
-1 AdminRequired
'@
	[System.Windows.Forms.MessageBox]::Show($Message, 'Help', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Question)
	$ExitCode = 3
	exit
}elseif ($Commandline -match '[\/-][(template)|(t)]') {
$t = @'
{
"ProgramName":"",
"LogFile":"",
"BlockExe":[],
"InPlaceUpdate":"false",
"PreTask":[
					 {
						"File":"",
						"Parameter":""
					}
				],
"Uninstall":[
					 {
						"File":"",
						"Parameter":"",
						"ExitCodes":["0"]
					}
				],
"Task":[],
"Install":[
					{
						"File":"",
						"Parameter":"",
						"ExitCodes":["0"]
					}
				],
"PostTask":[],
"ErrorTask":[],
"Copy":[
					 {
						"Source":"",
						"Desitination":""
					}
				],
"RebootRequiredExitCodes":["1610","3010"],
"ProcessTimeOut":"300",
"CancelCountLimit":"3",
"Picture":"$$pwd$$\\logo.png"
}
'@
	Write-Output $t >> "$($WorkingDirectory)\configtemplate.json"
	
	[System.Windows.Forms.MessageBox]::Show("Config saved to: $($WorkingDirectory)\configtemplate.json", 'Help', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Question)
	$ExitCode = 3
	exit
}
elseif (![string]::IsNullOrEmpty($BlockedExe))
{
	$MessageTitle = [String]::Format($stringTable.MessageTitle)
	$Answer = Read-Answer -Messsage ([String]::Format($stringTable.BlockedApplication, $BlockedExe)) -Title $MessageTitle -Buttons OK
	$ExitCode = 101
	exit
}

try
{
	# Import configuration
	$Config = (Get-Content $ConfigFile).Replace('$$pwd$$', ($WorkingDirectory -replace '\\', '\\')) | ConvertFrom-Json

	$ProcessTimeOut = if ($Config.ProcessTimeOut) { $Config.ProcessTimeOut }
	else { 300 }

	$PopupPicture = if ($Config.Picture) { $Config.Picture }
	else { '' }

	$EventLogName = if ($Config.EventLogName) { $Config.EventLogName }
	else { 'Application' }

	$EventLogSource = if ($Config.EventLogSource) { $Config.EventLogSource }
	else { [System.IO.Path]::GetFileNameWithoutExtension($InvocationExe) }
	
	$EventID = if ($Config.EventID) { $Config.EventID }
	else { '1337' }
	
	$InPlaceUpdate = if ($Config.InPlaceUpdate) { $Config.InPlaceUpdate }
	else { $false }
	
	if ($null -ne $Config.CancelCountLimit)
	{
		$Config.CancelCountLimit = $Config.CancelCountLimit -as [int]
	}
	
	If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Throw ([string]::Format($stringTable.ErrorMissingAdmin, $env:USERNAME))
	}
	
	# create logfile	
	if ($Config.LogFile)
	{
		$log = Start-Transcript -Path $Config.LogFile -Append
	}
	else
	{
		$log = Start-Transcript -OutputDirectory $env:TEMP
	}
	if ([System.Diagnostics.EventLog]::SourceExists($EventLogSource) -eq $False)
	{
		New-EventLog -LogName $EventLogName -Source $EventLogSource
	}
	Write-Log -Message ([String]::Format($LogTable.Start, $Config.ProgramName))
	Write-Log -Message ([String]::Format($LogTable.WorkingDirectory, $WorkingDirectory))
	Write-Log -Message ([String]::Format($LogTable.is64BitOS, $is64Bit.tostring()))
	Write-Log -Message ([String]::Format($LogTable.is64BitProcess, $is64BitProcess.tostring()))
	Write-Log -Message ([String]::Format($LogTable.Executionpolicy, (Get-ExecutionPolicy)))
	Write-Log -Message ([String]::Format($LogTable.InPlaceUpdate, $InPlaceUpdate))
	if ((Get-WmiObject -Class Win32_ComputerSystem).username) {
		Write-Log -Message ([String]::Format($LogTable.User, ((Get-WmiObject -Class Win32_ComputerSystem).username)))
	}
		
	#region Variable validation
	[Array]$FilePaths = @()
	$FilePaths += $Config.Install."64Bit".File
	$FilePaths += $Config.Install."32Bit".File
	$FilePaths += $Config.Install.File
	$FilePaths += $Config.PreTask.File
	$FilePaths += $Config.Task.File
	$FilePaths += $Config.PostTask.File
	$FilePaths += $Config.ErrorTask
	foreach ($FilePath in $FilePaths)
	{
		# test needed files available
		if ($FilePath -and -not (Test-Path $FilePath) -and ($FilePath -notlike "msiexec.exe"))
		{
			# if not write log and exit			
			throw [System.IO.FileNotFoundException] ([String]::Format($LogTable.PathNotFound, $FilePath))
		}
	}
	if (-not $Config.ProgramName)
	{
		Throw [System.Management.Automation.SessionStateException] ([String]::Format($LogTable.VariableNotSet, 'ProgramName'))
	}
	if ($config -eq $null)
	{
		Throw [System.Management.Automation.SessionStateException] ([String]::Format($LogTable.VariableNotSet, 'Config'))
	}
	#endregion
	
	#region Start
	
	# Writes procces bare
	Process_Bar -status $ProcessBar.Start -percent 0
	
	# Check whether the process is running
	$process = _Get-Process -Name $Config.ProgramName
	
	# If the process is running, ask user if this can be closed
	if ($process -and $Silent -eq $false -and $InPlaceUpdate -eq $false)
	{
		Write-Log -Message ([String]::Format($LogTable.RunningProcess, $process.name))
		# check if cancel count is set and get canceld events
		if (![string]::IsNullOrEmpty($Config.CancelCountLimit))
		{
			$CanceledEvents = Get-EventLog -LogName $EventLogName -InstanceId $EventID -After (Get-Date).AddDays(-3) | Where-Object { $_.Message -match $Config.ProgramName -and $_.Message -match "exitcode $($ExitCodes.Canceled)" }
		}
		if ([string]::IsNullOrEmpty($Config.CancelCountLimit) -or ($Config.CancelCountLimit -gt $CanceledEvents.count))
		{
			# ask user if process can be closed 
			$MessageTitle = [String]::Format($stringTable.MessageTitle)
			$Answer = Read-Answer -Messsage ([String]::Format($stringTable.QuestionCloseApplication, $Config.ProgramName)) -Title $MessageTitle -Buttons YesNo
			$CloseAppMessage = ([String]::Format($stringTable.InfoCloseApplication, $Config.ProgramName))
		}
		else
		{
			$Answer = $true
			$CloseAppMessage = ([String]::Format($stringTable.InfoCloseByRetrylimit, $Config.ProgramName))
			Write-Log -Message ([String]::Format($LogTable.RetryLimitReached, $Config.CancelCountLimit))
		}
		If ($Answer -eq $true)
		{
			# if answer is yes, stop process
			$Answer = Read-Answer -Messsage $CloseAppMessage -Title $MessageTitle -Buttons OK
			$process | Stop-Process -Force
			
			# Write log
			Write-Log -Message ([String]::Format($LogTable.StopProcess, $process.name))
			# set variable for userinformation about finishing installation
			$InfoInstallFinished = $true
		}
		else
		{
			# inform user, installation will start later again
			$Answer = Read-Answer -Messsage ([String]::Format($stringTable.InfoCancelInstallation, $Config.ProgramName)) -Title $MessageTitle -Buttons OK
			
			# Write log
			Throw [CustomException]::new('CancelInstall', ([String]::Format($LogTable.CancelInstall, $process.name)))
		}
		# Check whether the process is running. If not, start installation
		$process = _Get-Process -Name $Config.ProgramName -Check
	}
	elseif ($process -and $Silent -eq $true -and $InPlaceUpdate -eq $false)
	{
		# close process
		$process | Stop-Process -Force
		# Write log
		Write-Log -Message ([String]::Format($LogTable.StopProcess, $process.name))
		
		# Check whether the process is running. If not, start installation
		$process = _Get-Process -Name $Config.ProgramName -Check
	}
	if ($Config.BlockExe)
	{
		# check if exe is running and close
		$BlockExeProcesses = Get-Process | Where-Object { [System.IO.Path]::GetFileName($_.Path) -in $Config.BlockExe }
		if ($null -ne $BlockExeProcesses)
		{
			if (![string]::IsNullOrEmpty($Config.CancelCountLimit))
			{
				$CanceledEvents = Get-EventLog -LogName $EventLogName -InstanceId $EventID -After (Get-Date).AddDays(-3) | Where-Object { $_.Message -match $Config.ProgramName -and $_.Message -match "exitcode $($ExitCodes.Canceled)" }
			}
			if ([string]::IsNullOrEmpty($Config.CancelCountLimit) -or ($Config.CancelCountLimit -gt $CanceledEvents.count))
			{
				$Answer = Read-Answer -Messsage ([String]::Format($stringTable.QuestionCloseBlockExe, $Config.ProgramName, ($BlockExeProcesses.Product -join ', '))) -Title ([String]::Format($stringTable.MessageTitle)) -Buttons YesNo
				$CloseAppMessage = ([String]::Format($stringTable.InfoCloseApplication, $Config.ProgramName))
			}
			else
			{
				$Answer = $true
				$CloseAppMessage = ([String]::Format($stringTable.InfoCloseByRetrylimitBlock, $Config.ProgramName, ($BlockExeProcesses.Product -join ', ')))
			}
			If ($Answer -eq $true)
			{
				# if answer is yes, stop process
				$Answer = Read-Answer -Messsage $CloseAppMessage -Title ([String]::Format($stringTable.MessageTitle)) -Buttons OK
				$BlockExeProcesses | Stop-Process -Force
				
				# Write log
				Write-Log -Message ([String]::Format($LogTable.StopProcess, ($BlockExeProcesses.Name -join '|')))
				# set variable for userinformation about finishing installation
				$InfoInstallFinished = $true
			}
			else
			{
				# inform user, installation will start later again
				$Answer = Read-Answer -Messsage ([String]::Format($stringTable.InfoCancelInstallation, $Config.ProgramName)) -Title ([String]::Format($stringTable.MessageTitle)) -Buttons OK
				
				# Write log
				Throw [CustomException]::new('CancelInstall', ([String]::Format($LogTable.CancelInstall, ($BlockExeProcesses.name -join '|'))))
			}
		}
	
		# block exe execution for eache exe
		foreach ($ExeFile in $Config.BlockExe)
		{
			# Write log
			Write-Log -Message ([String]::Format($LogTable.BlockApplication, $ExeFile))
			Block-AppExecution -Name $ExeFile
		}
		
	}
	
	if ($process -and $InPlaceUpdate -eq $false)
	{
		$Service = Get-CimInstance -class win32_service | Where-Object  {
			$_.Name -match $Config.ProgramName -or $_.Description -match $Config.ProgramName -or $_.DisplayName -match $Config.ProgramName
		}
		if ($Service -ne $null)
		{
			Write-Log -Message ([String]::Format($LogTable.StoppingService, $Service.name))
			$Service.Name | Stop-Service -Force
		}
		# Check whether the process is running. If not, start installation
		$process = _Get-Process -Name $Config.ProgramName -Check
		if ($process)
		{
			Throw [CustomException]::new('ProcessRunning', ([String]::Format($LogTable.ProcessRunning, $process.name)))
		}
	}
	Process_Bar -status $ProcessBar.PreTask -percent 5
	
	#endregion
	
	#region PreTask
	if ($Config.PreTask)
	{
		foreach ($Script in $Config.PreTask)
		{
			Run-Task -ScriptPath $Script.File -Parameters $Script.Parameter
		}
	}
	#endregion
	
	#region Uninstall
	Process_Bar -status $ProcessBar.PreUninstall -percent 12
	
	if ($Config.Uninstall)
	{
		# define counter for progressbar
		[Int]$Steps = 20/$Config.Uninstall.count
		[Int]$status = 15
		Write-Log -Message ([String]::Format($LogTable.StartUninstall))
		foreach ($Program in $Config.Uninstall)
		{
			$status = $status + $schritt
			Process_Bar -status ([String]::Format($ProcessBar.Uninstall, $Program.File)) -percent $status
			# get uninstallstring from registry
			if ($Program.File -notlike "*.exe")
			{
				$list = get-itemproperty hklm:\software\microsoft\windows\currentversion\uninstall\*
				$list += get-itemproperty hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\*
				$UninstallComands = ($list | Where-Object { $_.DisplayName -Match [regex]::Escape($Program.File) }).UninstallString
			}
			else
			{
				$UninstallComands = $Program.File
			}
			if ($UninstallComands)
			{
				foreach ($UninstallComand in $UninstallComands)
				{
					# Write log
					Write-Log -Message ([String]::Format($LogTable.Uninstall, $Program.File))
					# test if msiexec or exe uninstallation is needed
					if ($UninstallComand -like "MsiExec*")
					{
						# prepare uninstallcode for msiexec
						[string]$UninstallCode = [regex]::Match($UninstallComands, '\{([^\[]*)\}').Value
						# uninstall with msiexec
						
						Write-Log -Message ([String]::Format($LogTable.UninstallMSI, $UninstallCode, $Program.Parameter))
						
						[string]$arguments = '/x{0} /norestart /qn {1}' -f $UninstallCode, $Program.Parameter
						Execute_ExeFile -file 'msiexec.exe' -arguments $arguments -ExitCodes @(0, 1641, 3010)
						
					}
					elseif ($UninstallComand -like "*.exe")
					{
						$Uninstaller = $UninstallComand
						# execute uninstaller
						Execute_ExeFile -file $Uninstaller -arguments $Program.Parameter -ExitCodes $Program.ExitCodes
					}
					else
					{
						Write-Log -Message ([String]::Format($LogTable.UninstallError, $Program.File, $UninstallComand))
					}
					Remove-Variable uninstallcomand, uninstallcode, uninstaller -ErrorAction SilentlyContinue
				}
			}
			else
			{
				Write-Log -Message ([String]::Format($LogTable.UninstallNotFound, $Program.file))
			}
		}
	}
	#endregion
	
	#region Task
	Process_Bar -status $ProcessBar.Task -percent 35
	
	if ($Config.Task)
	{
		foreach ($Script in $Config.Task)
		{
			Run-Task -ScriptPath $Script.File -Parameters $Script.Parameter
		}
	}
	#endregion
	
	#region Install
	Process_Bar -status $ProcessBar.PreInstall -percent 48
	
	if ($Config.Install)
	{
		# prepare counter for progressbare
		[Int]$Status = 30
		# Write log
		Write-Log -Message ([String]::Format($LogTable.StartInstall))
		$Installer = $Config.Install
		if ($Installer.Count -eq $null -or $Installer.Count -ge 1)
		{
			foreach ($Program in $Installer)
			{
				Process_Bar -status ([String]::Format($ProcessBar.Install, $Program.File)) -percent $status
				Execute_ExeFile -file $Program.File -arguments $Program.Parameter -ExitCodes $Program.ExitCodes
			}
		}
		
		if ($is64Bit -and $Config.Install."64Bit" -ne $null)
		{
			$Installer = $Config.Install."64Bit"
			
			$Steps = 50/$Installer.count
			# execute all installer for 64bis system
			foreach ($Program in $Installer)
			{
				Process_Bar -status ([String]::Format($ProcessBar.Install, $Program.File)) -percent $status
				Execute_ExeFile -file $Program.File -arguments $Program.Parameter -ExitCodes $Program.ExitCodes
				$status = $status + $Step
			}
		}
		elseif (-not $is64Bit -and $Config.Install."32Bit" -ne $null)
		{
			$Installer = $Config.Install."32Bit"
			
			$Steps = 50/$Installer.count
			# execute all installer for 64bis system
			foreach ($Program in $Installer)
			{
				Process_Bar -status ([String]::Format($ProcessBar.Install, $Program.File)) -percent $status
				Execute_ExeFile -file $Program.File -arguments $Program.Parameter -ExitCodes $Program.ExitCodes
				$status = $status + $Step
			}
		}
	}
	#endregion
	
	#region PostTask	
	Process_Bar -status $ProcessBar.PostTask -percent 85
	
	if ($Config.PostTask)
	{
		foreach ($Script in $Config.PostTask)
		{
			Run-Task -ScriptPath $Script.File -Parameters $Script.Parameter
		}
	}
	#endregion
	
	#region PostTask	
	Process_Bar -status $ProcessBar.PostTask -percent 85
	
	if ($Config.Copy)
	{
		foreach ($Item in $Config.Copy)
		{
			Write-Log -Message ([String]::Format($LogTable.Copy, $Item.Source, $Item.Desitination))
			Copy-Item -Path $Item.Source -Destination $Item.Desitination
		}
	}
	#endregion
	
} #region Errorhandling
catch [System.IO.FileNotFoundException] {
	$aborded = $true
	$Message = $_.Exception
	Write-Log -Message $Message
}
catch [System.Management.Automation.SessionStateException] {
	$aborded = $true
	$Message = $_.Exception
	Write-Log -Message $Message
}
catch [CustomException] {
	$aborded = $true
	$Message = $_.Exception
	switch -regex ($_.Exception)
	{
		'CancelInstall' {
			$canceled = $true
			$Message = 'canceled by user'
		}
		'ProcessRunning' { }
		'TaskError' { }
		'ExeError' { }
		Default { }
	}
	Write-Log -Message $Message
}
catch [System.Management.Automation.ParameterBindingException]{
	$aborded = $true
	$Message = $_.Exception
	if ($_.Exception -match "FilePath")
	{
	}
	Write-Log -Message $Message
}
catch
{
	$aborded = $true
	Write-Log -Message ([String]::Format($LogTable.UnexpectedError, $_.Exception, $_.Exception.GetType().FullName, $_.ScriptStackTrace))
}
#endregion
finally
{
	$ExitCode = $ExitCodes.Sucessfull
	#region finnaly
	Process_Bar -status $ProcessBar.CleanUp -percent 95
	if ($aborded -and -not $canceled)
	{
		$ExitCode = $ExitCodes.Failed
		Write-Log -Message ([String]::Format($LogTable.Exit, $Config.ProgramName))
		Write-Log -Message $Error
		if ($Config.ErrorTask)
		{
			foreach ($Script in $Config.ErrorTask)
			{
				Run-Task -ScriptPath $Script.File -Parameters $Script.Parameter
			}
		}
	}elseif ($canceled) {
		$ExitCode = $ExitCodes.Canceled
		Write-Log -Message ([String]::Format($LogTable.Exit, $Config.ProgramName))
		Write-Log -Message $Error
	}
	elseif ($canceled)
	{
		$ExitCode = $ExitCodes.Canceled
		Write-Log -Message ([String]::Format($LogTable.Exit, $Config.ProgramName))
		Write-Log -Message $Error
	}
	if ($Config.BlockExe)
	{
		foreach ($ExeFile in $Config.BlockExe)
		{
			# Write log
			Write-Log -Message ([String]::Format($LogTable.UnblockApplication, $ExeFile))
			# unblock execution of an exe file
			Unblock-AppExecution -Name $ExeFile
		}
	}
	
	# clear unneeded data
	Write-Log -Message ([String]::Format($LogTable.CleanUp))
	
	Remove-Item -Path (Join-Path -Path ${env:PUBLIC} -ChildPath ('\Desktop\*{0}*.lnk' -f $Config.ProgramName)) -Force
	
	Process_Bar -status $ProcessBar.End -percent 100
	
	
	# Write log
	Write-Log -Message ([String]::Format($LogTable.Finish))
	
	if ($InfoInstallFinished -eq $true)
	{
		# informate user installation is finish
		$MessageText = ([String]::Format($stringTable.InfoInstallFinished, $Config.ProgramName))
		$null = Read-Answer -Messsage $MessageText -Title $MessageTitle -Buttons OK
	}
	if (-not $aborded)
	{
		$RebootExitcodes = (Compare-Object -ReferenceObject $ReceivedExitCodes -DifferenceObject @($Config.RebootRequiredExitCodes | Select-Object) -ExcludeDifferent -IncludeEqual).InputObject
		if ($RebootExitcodes)
		{
			Write-Log -Message ([String]::Format($LogTable.RebootExitcodes, $RebootExitcodes))
		}
		# prepare reboot if needet
		if ($RebootExitcodes -and $Silent -eq $false)
		{
			$ExitCode = $ExitCodes.RebootRequired
			$MessageTitle = [String]::Format($stringTable.MessageTitle)
			if ($Config.RebootMsg)
			{
				$Answer = Read-Answer -Messsage ([String]::Format($stringTable.QuestionReboot, $Config.RebootMsg)) -Title $MessageTitle -Buttons YesNo
			}
			else
			{
				$Answer = Read-Answer -Messsage ([String]::Format($stringTable.QuestionReboot, $stringTable.RebootMsg)) -Title $MessageTitle -Buttons YesNo
			}
			If ($Answer -eq $true)
			{
				#$Answer = Read-Answer -Messsage ([String]::Format($stringTable.InfoReboot)) -Title $MessageTitle -Buttons OK
				
				# Write log
				Write-Log -Message ([String]::Format($LogTable.Reboot))
				Start-Job -ScriptBlock { shutdown.exe /r /t 60 } | Receive-Job -Wait
			}
			else
			{
				$Answer = Read-Answer -Messsage ([String]::Format($stringTable.CancelReboot)) -Title $MessageTitle -Buttons OK
				
				# Write log
				Write-Log -Message ([String]::Format($LogTable.CancelReboot))
			}
		}
		elseif ($Silent -eq $true -and $ForceReboot -eq $true)
		{
			# Write log
			Write-Log -Message ([String]::Format($LogTable.Reboot))
			Start-Job -ScriptBlock { shutdown.exe /r /t 60 } | Receive-Job -Wait
		}
	}
	If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		$ExitCode = $ExitCodes.AdminRequired
	}
	Write-Log -Message ([String]::Format($LogTable.ExitCode, $ExitCode))
	Stop-Transcript
	$EventMessage = Get-Content -Path $log.Path -Raw
	switch ($ExitCode)
	{
		$ExitCodes.Sucessfull { $EntryType = 'Information' }
		$ExitCodes.RebootRequired { $EntryType = 'Information' }
		$ExitCodes.Canceled { $EntryType = 'Warning' }
		$ExitCodes.Failed { $EntryType = 'Error' }
		
	}
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventID -Message $EventMessage -EntryType $EntryType
	#endregion
	
	exit $ExitCode
}
