<#	
    .NOTES
    ===========================================================================
	 Modified on:   23.12.2020
    Created by:    roman.enz
    Organization:  esolva ag
     Version:       0.4
    ===========================================================================
    .DESCRIPTION

    .LINK
        GIT
    .LINK
        XWiki 
#>
param (
	[Alias('config', 'c')]
	[String]$ConfigFile = 'config.json',
	[String]$BlockedExe,
	[switch]$Silent = $false,
	[switch]$ForceReboot = $false
	
)

# Load assembly
Add-Type -AssemblyName "System.Windows.Forms"

#region Functions	
# Function to read the process
function _Get-Process()
{
	param (
		[Parameter(Mandatory = $True)]
		[String]$Name
	)
	$Name = [regex]::Escape($Name)
	$process = Get-Process | Select-Object id, Description, Product, name | Where-Object {
		$_.Product -match $Name -or $_.Description -match $Name
	}
	return $process
}91
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
		$Proc = Start-Process $file -Wait -PassThru
	}
	else
	{
		$Proc = Start-Process $file -ArgumentList $arguments -PassThru
	}
	Wait-Process -InputObject $Proc -Timeout $ProcessTimeOut -ErrorAction SilentlyContinue
	
	# Write log
	Write-Log -Message ([String]::Format($LogTable.RunExeFileComplete, $file, $Proc.ExitCode))
	# test if exitcode is greater or equal 1 -> error
	$ReceivedExitCodes += $Proc.ExitCode
	if ($Proc.ExitCode -notin $ExitCodes)
	{
		Throw [CustomException]::new('ExeError', ([String]::Format($LogTable.RunExeFileComplete, $file, $Proc.ExitCode)))
	}
}

# Function for the progress display
function Process_Bar()
{
	param (
		[String]$activity = $stringTable.MainActivity,
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
	$job = Start-Job -FilePath $ScriptPath -ArgumentList $Param -InitializationScript ([ScriptBlock]::Create("Set-Location $pwd;Set-Variable -Name ErrorActionPreference -Value SilentlyContinue")) -ErrorAction Stop
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
		[Alias('Text')]
		[string]$Messsage,
		[System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::None,
		[System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OKCancel,
		[string]$Title = $customizedData.Company
	)
	[System.Windows.Forms.MessageBox]::Show($Messsage, $Title, $Buttons, $Icon, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly)
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
	
	# Verifies if the user is administrator
	try
	{
		If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
		{
			Throw ([string]::Format($stringTable.ErrorMissingAdmin, $env:USERNAME))
		}
		
	}
	catch
	{
		# Catch all other exceptions thrown by one of those commands
		Write-Error $_
		return
	}
	
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
	
	# Verifies if the user is administrator
	try
	{
		If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
		{
			Throw ([string]::Format($stringTable.ErrorMissingAdmin, $env:USERNAME))
		}
		
	}
	catch
	{
		# Catch all other exceptions thrown by one of those commands
		Write-Error $_
		return
	}
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
			Write-Warning ([string]::Format($stringTable.WarningFileNotBlocked, $File))
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

$EventLogName = 'Application'
$EventLogSource = 'Install-Software'

# text messages
$LocalizedData = @{
	"de-DE"    = @{
		MainActivity				 = "Installation"
		MessageTitle				 = "Programm Installation"
		QuestionCloseApplication	 = "{0} wird noch ausgeführt. Programm schliessen und die Installation fortsetzen?"
		InfoCloseApplication		 = "{0} wird geschlossen und die Installation fortgesetzt"
		InfoCancelInstallation	     = "Die Installation von {0} wird abgebrochen und zu einem späteren Zeitpunkt erneut ausgeführt."
		InfoInstallFinished		     = "Die Installation von {0} ist beendet."
		QuestionReboot			     = "{0} Computer jetzt neustarten?"
		InfoReboot				     = "Computer wird jetzt neugestartet!"
		CancelReboot				 = "Bitte Computer später neustarten."
		RebootMsg				     = "Installation benötigt einen Neustart."
		BlockedApplication		     = "Das ausführen von {0} ist vorübergehend gesperrt"
	}
	"en-EN"    = @{
		MainActivity				 = "Installation"
		MessageTitle				 = "software installation"
		QuestionCloseApplication	 = "{0} is still running. Close the program and continue the installation?"
		InfoCloseApplication		 = "{0} is closed and the installation is continued"
		InfoCancelInstallation	     = "The installation of {0} will be aborted and run again at a later time."
		InfoInstallFinished		     = "The installation of {0} is finished."
		QuestionReboot			     = "{0} Restart computer now?"
		InfoReboot				     = "Computer will be restarted now!"
		CancelReboot				 = "Please restart computer later."
		RebootMsg				     = "Installation requires a reboot."
		BlockedApplication		     = "Running {0} is temporarily blocked"
	}
}

$DefaultLocalizedData = 'de-DE'
if ($LocalizedData.((Get-WinSystemLocale).name.tostring()) -ne $null)
{
	$stringTable = $LocalizedData.((Get-WinSystemLocale).name.tostring())
}
else
{
	$stringTable = $LocalizedData.$DefaultLocalizedData
}
$ReceivedExitCodes = @()
$ExitCodes = @{
	Sucessfull	      = 0
	RebootRequired    = 1
	Failed		      = 2
}

# Processbar messages
$ProcessBar = @{
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

# log messages
$LogTable = @{
	Start				   = 'installation of {0} is started'
	StartInstall		   = 'install...'
	CancelInstall		   = 'installation of {0} was canceled by user'
	VariableNotSet		   = 'variable  {0} not set'
	StopProcess		       = 'terminating process: {0}'
	ProcessRunning		   = "the process {0} could not be terminated"
	RunTask			       = "Script {0} is executed with parameters: "
	TaskComplete		   = "Script finished with status {0}."
	TaskError			   = "Script {0} finished with error: {1}"
	StartUninstall		   = "uninstalling..."
	Uninstall			   = "uninstalling {0}"
	UninstallNotFound	   = "uninstall command for {0} not found"
	UninstallError		   = "uninstall command for {0} finished with error: {1}"
	RunExeFile			   = "running installer {0} with parameters:: {1}"
	RunExeFileComplete	   = 'installer {0} finished with status {1}'
	ExeFileError		   = "installing {0} finished with error: {1}"
	UninstallMSI		   = "MSI uninstalling for {0} with parameters: {1}"
	UninstallMSIError	   = "MSI uninstalling for {0} finished with error: {1}"
	BlockApplication	   = "block start of {0}"
	UnblockApplication	   = "unblock start of {0}"
	CleanUp			       = "clean up files"
	PathNotFound		   = "file {0} not found"
	Exit				   = "installation {0} aborted"
	Finish				   = "installation finished"
	Reboot				   = "restarting computer"
	CancelReboot		   = "restart aborted by user"
	UnexpectedError	       = "unknown error:"
	is64BitOS			   = "OS 64bit: {0}"
	is64BitProcess		   = "Powershell 64bit: {0}"
	RebootExitcodes	       = "ExitCodes require restart: {0}"
}
#endregion

if (![string]::IsNullOrEmpty($BlockedExe))
{
	$MessageTitle = [String]::Format($stringTable.MessageTitle)
	$Answer = Read-Answer -Messsage ([String]::Format($stringTable.BlockedApplication, $BlockedExe)) -Title $MessageTitle -Buttons OK
}

# set working directory
if ([string]::IsNullOrEmpty([System.IO.Path]::GetDirectoryName($ConfigFile)) -eq $true)
{
	$WorkingDirectory = $PSScriptRoot
}
else
{
	$WorkingDirectory = [System.IO.Path]::GetDirectoryName($ConfigFile)
}
Set-Location $WorkingDirectory

# Import configuration
$Config = (Get-Content $ConfigFile).Replace('$$pwd$$', [regex]::Escape($WorkingDirectory)) | ConvertFrom-Json
$ProcessTimeOut = if ($Config.ProcessTimeOut) { $Config.ProcessTimeOut }else { 300 }

try
{
	
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
	
	Write-Log -Message ([String]::Format($LogTable.is64BitOS, $is64Bit.tostring()))
	Write-Log -Message ([String]::Format($LogTable.is64BitProcess, $is64BitProcess.tostring()))
	
	
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
	if ($process -and $Silent -eq $false)
	{
		Write-Log -Message ([String]::Format($LogTable.StopProcess, $process.name))
		# ask user if process can be closed 
		$MessageTitle = [String]::Format($stringTable.MessageTitle)
		$Answer = Read-Answer -Messsage ([String]::Format($stringTable.QuestionCloseApplication, $Config.ProgramName)) -Title $MessageTitle -Buttons YesNo
		If ($Answer -like "yes")
		{
			# if answer is yes, stop process
			$Answer = Read-Answer -Messsage ([String]::Format($stringTable.InfoCloseApplication, $Config.ProgramName)) -Title $MessageTitle -Buttons OK
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
		# Wait to close process
		Start-Sleep -Seconds 10
		# Check whether the process is running. If not, start installation
		$process = _Get-Process -Name $Config.ProgramName
	}
	elseif ($Silent -eq $true)
	{
		# close process
		$process | Stop-Process -Force
		# Write log
		Write-Log -Message ([String]::Format($LogTable.StopProcess, $process.name))
		
		# Wait to close process
		Start-Sleep -Seconds 10
		# Check whether the process is running. If not, start installation
		$process = _Get-Process -Name $Config.ProgramName
	}
	if ($Config.BlockExe)
	{
		# block exe execution for eache exe
		foreach ($ExeFile in $Config.BlockExe)
		{
			# Write log
			Write-Log -Message ([String]::Format($LogTable.BlockApplication, $ExeFile))
			Block-AppExecution -Name $ExeFile
		}
	}
	
	if ($process)
	{
		Throw [CustomException]::new('ProcessRunning', ([String]::Format($LogTable.ProcessRunning, $process.name)))
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
						
						[string]$arguments = '/x{0} /norestart /quiet {1}' -f $UninstallCode, $Program.Parameter
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
				Write-Log -Message ([String]::Format($LogTable.UninstallError, $Program, $UninstallComand))
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
		$Installer = $Config.Install | ? { $_ -notmatch '32Bit|64Bit' }
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
	if ($_.Exception -like "CancelInstall")
	{
	}
	if ($_.Exception -like "ProcessRunning")
	{
	}
	if ($_.Exception -like "TaskError")
	{
	}
	if ($_.Exception -like "ExeError")
	{
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
	if ($aborded)
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
		$RebootExitcodes = (Compare-Object -ReferenceObject $ReceivedExitCodes -DifferenceObject $Config.RebootRequiredExitCodes -ExcludeDifferent -IncludeEqual).InputObject
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
			If ($Answer -like "yes")
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
	
	Stop-Transcript
	$EventMessage = Get-Content -Path $log.Path -Raw
	switch ($ExitCode)
	{
		$ExitCodes.Sucessfull { $EntryType = 'Information' }
		$ExitCodes.RebootRequired { $EntryType = 'Information' }
		$ExitCodes.Failed { $EntryType = 'Error' }
		
	}
	Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId 1337 -Message $EventMessage -EntryType $EntryType
	#endregion
}