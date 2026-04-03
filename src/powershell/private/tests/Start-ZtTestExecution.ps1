function Start-ZtTestExecution {
	<#
	.SYNOPSIS
		Sets up and launches Test processing in multiple background runspaces in parallel.

	.DESCRIPTION
		Sets up and launches Test processing in multiple background runspaces in parallel.
		This allows accelerate calculating the Test results, though several factors may limit the performance gained by parallelizing:

		+ Disk IO: Parallel access to the disk-based database may limit performance on HDD disks.
		+ Graph Throttling: When raising the number of Runspaces, throttling Limits against the Graph API might limit performance.

	.PARAMETER Tests
		The Tests to process.

	.PARAMETER DbPath
		Path to the Database with the Cached results.

	.PARAMETER ThrottleLimit
		How many Runspaces to run in parallel to optimize tests processing.
		Defaults to: 5

	.PARAMETER TestTimeout
		Maximum time a single test is allowed to run.
		Passed through to Invoke-ZtTest for per-test timeout enforcement.

	.EXAMPLE
		PS> Start-ZtTestExecution -Tests $testsToRun -DbPath $Database.Database -ThrottleLimit $ThrottleLimit

		Starts parallel processing of the tests specified in $testsToRun.
	#>
	[OutputType([PSFramework.Runspace.RSWorkflow])]
	[CmdletBinding()]
	param (
		[object[]]
		$Tests,

		[string]
		$DbPath,

		[int]
		$ThrottleLimit = 5,

		[string]
		$LogsPath,

		[timespan]
		$TestTimeout = [timespan]::Zero
	)
	begin {
		#region Calculate Resources to Import
		$variables = @{
			databasePath = $DbPath
			moduleRoot   = $script:ModuleRoot
			logsPath     = $LogsPath
			testTimeout  = $TestTimeout
		}
		# Explicitly including all modules required, as we later import the psm1, not the psd1 file
		#TODO: This is brittle
		$modulePsd1Path = Join-Path $script:ModuleRoot "$($PSCmdlet.MyInvocation.MyCommand.Module.Name).psd1"
		$modules = (Import-PSFPowerShellDataFile $modulePsd1Path).RequiredModules | ForEach-Object {
			if ($_ -is [string]) {
				$name = $_
			}
			else {
				$name = $_.ModuleName
			}
			if (-not $name) {
				return
			}
			# Prefer loading the exact same version currently loaded, rather than just by name, in order to respect explicit import choice by the user
			if ($module = Get-Module $name) {
				$module.ModuleBase
			}
			else {
				$name
			}
		}
		# Loading the PSM1 to make internal commands directly accessible
		$modulePsm1Path = Join-Path $script:ModuleRoot "$($PSCmdlet.MyInvocation.MyCommand.Module.Name).psm1"
		$modules = @($modules) + $modulePsm1Path

		# Get the modules loaded from the connected service
		# Add those modules in the runspace initialization to make the service cmdlets available
		# this should allow all tests to be run in parallel.

		#endregion Calculate Resources to Import

		$param = @{
			InQueue       = 'Input'
			OutQueue      = 'Results'
			Count         = $ThrottleLimit
			Variables     = $variables
			CloseOutQueue = $true
			Modules       = $modules
			KillToStop	  = $true
		}
	}

	process {
		$workflow = New-PSFRunspaceWorkflow -Name 'ZeroTrustAssessment.Tests' -Force
		$null = $workflow | Add-PSFRunspaceWorker -Name Tester @param -Begin {
			$script:ModuleRoot = $moduleRoot
			$global:database = Connect-Database -Path $databasePath -PassThru
		} -ScriptBlock {
			$currentTest = $_
			try {
				Invoke-ZtTest -Test $currentTest -Database $global:database -LogsPath $logsPath -TestTimeout $testTimeout
			}
			catch {
				# Worker protection: prevent a single fatal test error from killing the
				# entire worker thread. Without this, an unhandled exception terminates
				# the runspace worker, which stops processing all remaining queued tests.
				$testId = if ($currentTest.TestID) { $currentTest.TestID } else { 'unknown' }
				Write-PSFMessage -Level Warning -Message "Worker caught fatal error for test {0}: {1}" -StringValues $testId, $_.Exception.Message -ErrorRecord $_
				if ($logsPath) {
					try {
						$logFile = Join-Path $logsPath "$testId.md"
						$errorText = "# Test: $testId - Fatal worker error`n`n``````$($_.Exception.Message)``````"
						[System.IO.File]::WriteAllText($logFile, $errorText)
					} catch { }
					try {
						$progressFile = Join-Path $logsPath '_progress.log'
						$entry = "{0}  {1,-12}{2}  {3}  {4}`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), 'FAILED', $testId, '00:00:00.000', 'WorkerError'
						[System.IO.File]::AppendAllText($progressFile, $entry)
					} catch { }
				}
				# Return a minimal result so the Results queue count stays accurate
				[PSCustomObject]@{
					PSTypeName = 'ZeroTrustAssessment.TestStatistics'
					TestID     = $testId
					Test       = $currentTest
					Start      = Get-Date
					End        = Get-Date
					Duration   = [timespan]::Zero
					Success    = $false
					Error      = $_
					Messages   = $null
					TimedOut   = $false
					Output     = $null
				}
			}
		} -End {
			Disconnect-Database -Database $global:database
		}
		$workflow | Write-PSFRunspaceQueue -Name Input -BulkValues @($Tests) -Close
		$workflow | Start-PSFRunspaceWorkflow
		$workflow
	}
}
