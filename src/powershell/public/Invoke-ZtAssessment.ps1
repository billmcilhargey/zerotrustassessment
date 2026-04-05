<#
.SYNOPSIS
Runs the Zero Trust Assessment against the signed in tenant and generates a report of the findings.

.DESCRIPTION
This function runs the Zero Trust Assessment against the signed in tenant and generates a report of the findings.
The assessment can be configured using command-line parameters, a configuration file, or through interactive prompts.

.PARAMETER Path
The path to the folder to output the report to. If not specified, the report will be output to the current directory.

.PARAMETER Days
Optional. Number of days (between 1 and 30) to query sign-in logs. Defaults to 30 days.

.PARAMETER MaximumSignInLogQueryTime
Optional. The maximum time (in minutes) the assessment should spend on querying sign-in logs. Defaults to 60 minutes. Set to 0 for no limit.

.PARAMETER Resume
If specified, the assessment reuses the previously exported data and existing database,
skipping data export and database rebuild.

.PARAMETER ShowLog
If specified, the script will output a high level summary of log messages. Useful for debugging. Use -Verbose and -Debug for more detailed logs.

.PARAMETER ExportLog
If specified, writes the log to a file.

.PARAMETER DisableTelemetry
If specified, disables the collection of telemetry. The only telemetry collected is the tenant id. Defaults to false.

.PARAMETER Tests
The IDs of the specific test(s) to run. If not specified, all tests will be run.

.PARAMETER ConfigurationFile
Path to a configuration file. Parameters specified on the command line will override values from the configuration file.

.PARAMETER ExportThrottleLimit
Maximum number of data collectors processed in parallel.
Raising this number may improve performance, but risk hitting throttling limits.

.PARAMETER TestThrottleLimit
Maximum number of tests processed in parallel.
Raising this number may improve performance, but risk hitting throttling limits.

.PARAMETER Timeout
	The maximum time to wait for all tests to complete before giving up and writing a warning message.
	Defaults to: 24 hours. Adjust this value if you have a large number of tests or expect some tests to take a long time.

.PARAMETER TestTimeout
Maximum time in minutes a single test is allowed to run before it is stopped.
Defaults to 60 minutes. Set to 0 to disable the timeout.
Tests that exceed this limit are recorded as timed out and execution continues with the next test.
For Data pillar tests and other external-module/remoting-heavy operations, timeout is a
best-effort interruption rather than a guaranteed hard stop of the underlying operation.

.EXAMPLE
Invoke-ZtAssessment

Run the Zero Trust Assessment against the signed in tenant and generates a report of the findings using default settings.

.EXAMPLE
Invoke-ZtAssessment -Path "./Reports/ZT" -Days 7 -ShowLog

Run the Zero Trust Assessment with a custom output path, querying 7 days of logs, and showing detailed logging.

.PARAMETER Pillar
The Zero Trust pillar to assess. Valid values are 'All', 'Identity', 'Devices', 'Network', or 'Data'. Defaults to 'All' which runs all tests.

.EXAMPLE
Invoke-ZtAssessment -ConfigurationFile "./config/zt-config.json"

Run the Zero Trust Assessment using settings from a configuration file.

.EXAMPLE
Invoke-ZtAssessment -ConfigurationFile "./config/zt-config.json" -Days 14 -ShowLog

Run the Zero Trust Assessment using settings from a configuration file, but override the Days parameter to 14 and enable ShowLog.

.EXAMPLE
Invoke-ZeroTrustAssessment -Pillar Identity

Run only the Identity pillar tests of the Zero Trust Assessment.

.EXAMPLE
Invoke-ZeroTrustAssessment -Pillar Devices

Run only the Devices pillar tests of the Zero Trust Assessment.
#>

function Invoke-ZtAssessment {
	[Alias('Invoke-ZeroTrustAssessment')]
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	param (
		# The path to the folder folder to output the report to. If not specified, the report will be output to the current directory.
		[Parameter(ParameterSetName = 'Default')]
		[string]
		$Path = $script:ZtDefaultReportPath,

		# Optional. Number of days (between 1 and 30) to query sign-in logs. Defaults to last two days.
		[Parameter(ParameterSetName = 'Default')]
		[ValidateScript({
				$_ -ge 1 -and $_ -le 30
			},
			ErrorMessage = "Logs are only available for 30 days. Please enter a number between 1 and 30.")]
		[int]
		$Days = 30,

		# Optional. The maximum time (in minutes) the assessment should spend on querying sign-in logs. Defaults to collecting sign logs for 60 minutes. Set to 0 for no limit.
		[Parameter(ParameterSetName = 'Default')]
		[int]
		$MaximumSignInLogQueryTime = 60,

		# If specified, the previously exported data will be used to generate the report.
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$Resume,

		# If specified, the script will output a high level summary of log messages. Useful for debugging. Use -Verbose and -Debug for more detailed logs.
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$ShowLog,

		# If specified, writes the log to a file.
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$ExportLog,

		# If specified, disables the collection of telemetry. The only telemetry collected is the tenant id. Defaults to true.
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$DisableTelemetry = $false,

		# The IDs of the specific test(s) to run. If not specified, all tests will be run.
		[Parameter(ParameterSetName = 'Default')]
		[string[]]
		$Tests,

		# Path to a configuration file. Parameters specified on the command line will override values from the configuration file.
		[Parameter(ParameterSetName = 'Default')]
		[ValidateScript({
				if (Test-Path $_ -PathType Leaf) {
					$true
				}
				else {
					throw "Configuration file '$_' does not exist."
				}
			})]
		[string]
		$ConfigurationFile,

		[PsfArgumentCompleter('ZeroTrustAssessment.Tests.Pillar')]
		# The Zero Trust pillar to assess. Defaults to All.
		[ValidateSet('All', 'Identity', 'Devices', 'Network', 'Data')]
		[string]
		$Pillar = 'All',

		# Enable preview features
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$Preview,

		[int]
		$ExportThrottleLimit = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.ThrottleLimit.Export' -Fallback 5),

		[int]
		$TestThrottleLimit = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.ThrottleLimit.Tests' -Fallback 5),

		[TimeSpan]
		$Timeout = '1.00:00:00',

		# Maximum time in minutes a single test is allowed to run. Defaults to 60 minutes. Set to 0 to disable.
		# For Data pillar tests, timeout is best-effort because some external modules/remoting
		# operations cannot be deterministically hard-stopped from within the current process.
		[int]
		$TestTimeout = [math]::Floor((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.Timeout' -Fallback ([timespan]::FromMinutes(60))).TotalMinutes)
	)

	if ($script:ConnectedService -and $script:ConnectedService.Count -le 0) {
		Connect-ZtAssessment
	}

	#region Utility Functions
	function Show-ZtiSecurityWarning {
		[CmdletBinding()]
		param (
			[string]
			$ExportPath
		)

		Write-Host
		Write-Host "⚠️ SECURITY REMINDER: The report and export folder contain sensitive tenant information." -ForegroundColor Yellow
		Write-Host "Please delete the export folder and restrict access to the report." -ForegroundColor Yellow
		Write-Host "Export folder: $ExportPath" -ForegroundColor Yellow
		Write-Host "Share the report only with authorized personnel in your organization." -ForegroundColor Yellow
		Write-Host
	}
	#endregion Utility Functions

	#region Preparation
	if ($env:ZT_BANNER_SHOWN -eq '1') {
		$env:ZT_BANNER_SHOWN = $null  # Reset for next invocation
	}
	else {
		Show-ZtBanner
	}
	Write-Host "🚀 " -NoNewline -ForegroundColor Green
	Write-Host "Starting Zero Trust Assessment..." -ForegroundColor White
	Write-Host

	# Handle configuration file parameter
	$pathSetByConfig = $false
	if ($ConfigurationFile) {
		try {
			Write-Host "📄 " -NoNewline -ForegroundColor Blue
			Write-Host "Loading configuration from file: " -NoNewline -ForegroundColor White
			Write-Host $ConfigurationFile -ForegroundColor Cyan
			$configContent = Get-Content -Path $ConfigurationFile -Raw | ConvertFrom-Json

			# Define parameters that can be configured
			$configurableParameters = @('Path', 'Days', 'MaximumSignInLogQueryTime', 'ShowLog', 'ExportLog', 'DisableTelemetry', 'Resume', 'Tests', 'TestTimeout')

			# Apply configuration values only if parameters weren't explicitly provided
			foreach ($paramName in $configurableParameters) {
				# Skip if parameter was explicitly provided or config doesn't contain the property
				if ($PSBoundParameters.ContainsKey($paramName) -or
					$configContent.PSObject.Properties.Name -notcontains $paramName) {
					continue
				}

				# Special handling for Tests array to ensure it has items
				if ($paramName -eq 'Tests') {
					if ($configContent.$paramName -and $configContent.$paramName.Count -gt 0) {
						Set-Variable -Name $paramName -Value $configContent.$paramName
					}
				}
				else {
					Set-Variable -Name $paramName -Value $configContent.$paramName
					if ($paramName -eq 'Path') { $pathSetByConfig = $true }
				}
			}

			Write-Host "✅ " -NoNewline -ForegroundColor Green
			Write-Host "Configuration loaded successfully. Command line parameters will override configuration file values." -ForegroundColor White
			Write-Host
		}
		catch {
			Write-Host "❌ " -NoNewline -ForegroundColor Red
			Write-Host "Failed to load configuration from file '$ConfigurationFile': $($_.Exception.Message)" -ForegroundColor Red
			return
		}
	}

	if ($ShowLog) {
		$null = New-PSFMessageLevelModifier -Name ZeroTrustAssessment.VeryVerbose -Modifier -1 -IncludeModuleName ZeroTrustAssessment
	}
	else {
		Get-PSFMessageLevelModifier -Name ZeroTrustAssessment.VeryVerbose | Remove-PSFMessageLevelModifier
	}

	# ── Consolidated pre-flight checks ───────────────────────────────────────
	$preflightParams = @{ Pillar = $Pillar }
	if ($Tests) { $preflightParams.Tests = $Tests }
	$preflight = Test-ZtServicePreflight @preflightParams

	if (-not $preflight.Passed) {
		foreach ($failure in $preflight.Failures) {
			Write-Host "❌ " -NoNewline -ForegroundColor Red
			Write-Host "Pre-flight check failed — $($failure.Check): $($failure.Detail)" -ForegroundColor Red
		}
		Write-Host
		return
	}

	# Show license info from preflight
	$licenseCheck = $preflight.Checks | Where-Object { $_.Check -eq 'Licensing' }
	if ($licenseCheck) {
		$licColor = if ($licenseCheck.Passed) { 'Green' } else { 'Yellow' }
		$licIcon = if ($licenseCheck.Passed) { '✅' } else { '⚠️' }
		Write-Host "$licIcon License: $($licenseCheck.Detail)" -ForegroundColor $licColor
	}

	# Show cloud environment info from preflight
	$cloudEnvCheck = $preflight.Checks | Where-Object { $_.Check -eq 'CloudEnvironment' }
	if ($cloudEnvCheck) {
		$envColor = if ($cloudEnvCheck.Passed) { 'Green' } else { 'Yellow' }
		$envIcon = if ($cloudEnvCheck.Passed) { '☁️' } else { '⚠️' }
		Write-Host "$envIcon Cloud: $($cloudEnvCheck.Detail)" -ForegroundColor $envColor
	}

	# Unified skip summary — gather ALL reasons tests will be skipped and display once.
	$allTests = Get-ZtTest
	$skipReasons = [System.Collections.Generic.List[object]]::new()

	# 1. Service coverage gaps (missing/unavailable services)
	$coverage = $preflight.Coverage
	if (-not $coverage.FullCoverage) {
		foreach ($gap in $coverage.ServiceGaps) {
			$reason = if ($gap.Reason) { $gap.Reason }
				elseif ($gap.IsWindowsOnly) { 'Requires Windows' }
				elseif ($gap.NoDeviceCode) { 'No device code flow support' }
				elseif ($gap.RequiresCustomApp) { 'No app registration setup' }
				elseif ($gap.NoClientSecret) { 'No client-secret auth' }
				else { 'Service not connected' }
			$skipReasons.Add([pscustomobject]@{
				Category = 'Service'
				Label    = "$($gap.Service)"
				Reason   = $reason
				Count    = $gap.TestsAffected
			})
		}
	}

	# 1b. Cloud environment gaps — tests whose CloudEnvironment metadata excludes the current cloud
	$currentCloudEnv = $cloudEnvCheck.CloudEnvironment
	if ($currentCloudEnv -and $currentCloudEnv.CloudType -ne 'Unknown') {
		$envSkipCount = 0
		foreach ($test in $allTests) {
			if ($test.CloudEnvironment -and $test.CloudEnvironment.Count -gt 0) {
				if (-not (Test-ZtCloudEnvironment -SupportedCloudType $test.CloudEnvironment)) {
					$envSkipCount++
				}
			}
		}
		if ($envSkipCount -gt 0) {
			$skipReasons.Add([pscustomobject]@{
				Category = 'Environment'
				Label    = $currentCloudEnv.DisplayName
				Reason   = "Not supported in $($currentCloudEnv.DisplayName)"
				Count    = $envSkipCount
			})
		}
	}

	# 2. Licensing gaps (MinimumLicense / CompatibleLicense)
	if ($licenseCheck) {
		$licSummary = Get-ZtLicenseSkipSummary -Tests $allTests
		foreach ($entry in $licSummary.SkipsByTier.GetEnumerator()) {
			$skipReasons.Add([pscustomobject]@{
				Category = 'License'
				Label    = $entry.Key
				Reason   = $entry.Key
				Count    = $entry.Value
			})
		}
	}

	# 3. Permission/scope gaps — tests whose RequiredScopes are not in the current session.
	$ctx = Get-MgContext -ErrorAction Ignore
	if ($ctx) {
		$currentScopes = @($ctx.Scopes)
		$scopeSkipCount = @{}
		foreach ($test in $allTests) {
			if (-not $test.RequiredScopes -or $test.RequiredScopes.Count -eq 0) { continue }
			$missingForTest = @($test.RequiredScopes | Where-Object { $currentScopes -notcontains $_ })
			if ($missingForTest.Count -gt 0) {
				foreach ($scope in $missingForTest) {
					if (-not $scopeSkipCount.ContainsKey($scope)) { $scopeSkipCount[$scope] = 0 }
					$scopeSkipCount[$scope]++
				}
			}
		}
		foreach ($entry in $scopeSkipCount.GetEnumerator()) {
			$skipReasons.Add([pscustomobject]@{
				Category = 'Permission'
				Label    = $entry.Key
				Reason   = "Missing scope: $($entry.Key)"
				Count    = $entry.Value
			})
		}
	}

	# Display unified skip summary
	if ($skipReasons.Count -gt 0) {
		$totalSkipped = ($skipReasons | Measure-Object -Property Count -Sum).Sum
		Write-Host ''
		Write-Host "⚠️ " -NoNewline -ForegroundColor Yellow
		Write-Host "$totalSkipped test(s) will be skipped:" -ForegroundColor Yellow

		$svcReasons = @($skipReasons | Where-Object Category -eq 'Service')
		if ($svcReasons.Count -gt 0) {
			$svcTotal = ($svcReasons | Measure-Object -Property Count -Sum).Sum
			Write-Host "   Services ($svcTotal):" -ForegroundColor DarkYellow
			foreach ($r in $svcReasons | Sort-Object Count -Descending) {
				Write-Host "     • $($r.Label): $($r.Count) test(s) — $($r.Reason)" -ForegroundColor DarkYellow
			}
		}

		$licReasons = @($skipReasons | Where-Object Category -eq 'License')
		if ($licReasons.Count -gt 0) {
			$licTotal = ($licReasons | Measure-Object -Property Count -Sum).Sum
			Write-Host "   Licensing ($licTotal):" -ForegroundColor DarkYellow
			foreach ($r in $licReasons | Sort-Object Count -Descending) {
				Write-Host "     • $($r.Count) test(s) — $($r.Reason)" -ForegroundColor DarkYellow
			}
		}

		$permReasons = @($skipReasons | Where-Object Category -eq 'Permission')
		if ($permReasons.Count -gt 0) {
			$permTotal = ($permReasons | Measure-Object -Property Count -Sum).Sum
			Write-Host "   Permissions ($permTotal):" -ForegroundColor DarkYellow
			foreach ($r in $permReasons | Sort-Object Count -Descending) {
				Write-Host "     • $($r.Count) test(s) — $($r.Reason)" -ForegroundColor DarkYellow
			}
		}

		$envReasons = @($skipReasons | Where-Object Category -eq 'Environment')
		if ($envReasons.Count -gt 0) {
			$envTotal = ($envReasons | Measure-Object -Property Count -Sum).Sum
			Write-Host "   Cloud environment ($envTotal):" -ForegroundColor DarkYellow
			foreach ($r in $envReasons | Sort-Object Count -Descending) {
				Write-Host "     • $($r.Count) test(s) — $($r.Reason)" -ForegroundColor DarkYellow
			}
		}
		Write-Host ''
	}

	# When using the default path, organize reports by tenant ID automatically.
	# Skip if the user explicitly set -Path on the CLI or via a configuration file.
	$isDefaultPath = -not $PSBoundParameters.ContainsKey('Path') -and -not $pathSetByConfig
	if ($isDefaultPath) {
		$Path = Resolve-ZtTenantReportPath -BasePath $Path -IsDefaultPath $true
	}

	# Resolve to absolute paths so .NET APIs (DuckDB, System.IO) use the correct location.
	# .NET resolves relative paths against [Environment]::CurrentDirectory, which can differ
	# from PowerShell's Get-Location after Set-Location / cd.
	$Path = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
	$exportPath = Join-Path $Path $script:ZtExportDirName
	$dbPath = Join-Path $exportPath $script:ZtDbDirName $script:ZtDbFileName

	# Stop if folder has items inside it
	if (-not $Resume -and (Test-Path $Path)) {
		if ((Get-ChildItem $Path).Count -gt 0) {
			Write-Host
			Write-Host "⚠️ " -NoNewline -ForegroundColor Yellow
			Write-Host "Output folder is not empty" -ForegroundColor Yellow
			Write-Host "📁 Path: " -NoNewline -ForegroundColor White
			Write-Host $Path -ForegroundColor Cyan
			Write-Host
			Write-Host "To generate a new report, the existing contents need to be removed." -ForegroundColor White
			Write-Host "Do you want to delete the contents and continue? " -NoNewline -ForegroundColor White
			Write-Host "[y/n]" -NoNewline -ForegroundColor Yellow
			$deleteFolder = Read-Host " "

			if ($deleteFolder -eq "y") {
				Write-Host "🗑️ " -NoNewline -ForegroundColor Red
				Write-Host "Cleaning up existing files..." -ForegroundColor White
				# Close any open module-managed database connection before deleting
				if ($script:_DatabaseConnection) {
					try { Disconnect-Database } catch { }
				}
				Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop -ProgressAction SilentlyContinue | Out-Null
				Write-Host "✅ " -NoNewline -ForegroundColor Green
				Write-Host "Folder cleaned successfully" -ForegroundColor Green
				Write-Host
			}
			else {
				Write-Host "❌ " -NoNewline -ForegroundColor Red
				Write-Host "Assessment cancelled. Please provide a path to an empty folder or use -Resume to continue from existing data." -ForegroundColor Red
				return
			}
		}
	}

	# Create the export path if it doesn't exist
	if (!(Test-Path $exportPath)) {
		New-Item -ItemType Directory -Path $exportPath -Force -ErrorAction Stop | Out-Null
	}

	# Create the logs folder for per-test log files
	# Use .FullName to get the absolute path because .NET file APIs ([System.IO.File]::WriteAllText etc.)
	# resolve relative paths against [Environment]::CurrentDirectory (process CWD), which
	# differs from PowerShell's Get-Location after Set-Location / cd.
	$logsPath = (New-Item -ItemType Directory -Path (Join-Path $exportPath 'logs') -Force -ErrorAction Stop).FullName


	# Send telemetry if not disabled
	if (-not $DisableTelemetry) {
		try {
			$tenantId = (Get-MgContext).TenantId
			if ($tenantId) {
				Send-ZtAppInsightsTelemetry -EventName "ZTv2TenantId" -Properties @{ TenantId = $tenantId }
			}
		}
		catch {
			# Silently continue if sending telemetry fails
			Write-PSFMessage -Level Debug -Message "Failed to send telemetry: $_"
		}
	}

	Clear-ZtModuleVariable # Reset the graph cache and urls to avoid stale data
	$script:__ZtSession.PreviewEnabled = $Preview.IsPresent

	Write-PSFMessage 'Creating report folder $Path'
	$null = New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop

	# Move the interactive configuration file to the report directory if it exists
	if ($Interactive -and $tempConfigFile) {
		try {
			$finalConfigPath = Join-Path $Path "zt-interactive-config.json"
			Move-Item -Path $tempConfigFile.FullName -Destination $finalConfigPath -Force
			Write-Host "Configuration file moved to report directory: $finalConfigPath" -ForegroundColor Green
		}
		catch {
			Write-PSFMessage -Level Warning -Message "Failed to move configuration file to report directory: $_"
		}
	}
	#endregion Preparation

	# Collect data
	if ($Resume) {
		# Guard: verify the requested pillar is compatible with the exported data
		$exportedPillar = Get-ZtConfig -ExportPath $exportPath -Property Pillar
		if ($exportedPillar -and $exportedPillar -ne $Pillar) {
			if ($Pillar -eq 'All' -and $exportedPillar -ne 'All') {
				throw "Resume requested with -Pillar All, but the existing export only contains '$exportedPillar' data. Run without -Resume to export all pillars."
			}
			if ($exportedPillar -ne 'All' -and $Pillar -ne $exportedPillar) {
				throw "Resume requested with -Pillar $Pillar, but the existing export was created with -Pillar $exportedPillar. Run without -Resume or use -Pillar $exportedPillar."
			}
		}
	}

	Write-PSFMessage -Message "Stage 1: Exporting Tenant Data" -Tag stage
	Export-ZtTenantData -ExportPath $exportPath -Days $Days -MaximumSignInLogQueryTime $MaximumSignInLogQueryTime -Pillar $Pillar -ThrottleLimit $ExportThrottleLimit
	$database = Export-Database -ExportPath $exportPath -Pillar $Pillar

	try {
		# Run the tests
		Write-PSFMessage -Message "Stage 2: Running Tests" -Tag stage
		Invoke-ZtTests -Database $database -Tests $Tests -Pillar $Pillar -ThrottleLimit $TestThrottleLimit -LogsPath $logsPath -Timeout $Timeout -TestTimeout $TestTimeout

		Write-PSFMessage -Message "Stage 3: Adding Tenant Information" -Tag stage
		Write-ZtProgress -Activity "Generating report" -Status "Gathering tenant information"
		Invoke-ZtTenantInfo -Database $database -Pillar $Pillar

		Write-PSFMessage -Message "Stage 4: Generating Test-Results" -Tag stage
		Write-ZtProgress -Activity "Generating report" -Status "Compiling assessment results"
		$assessmentResults = Get-ZtAssessmentResults
	}
	finally {
		if ($database) {
			Disconnect-Database -Database $database
		}
	}

	Write-PSFMessage -Message "Stage 5: Writing Assessment report data" -Tag stage
	Write-ZtProgress -Activity "Generating report" -Status "Writing report data"
	$assessmentResultsJson = $assessmentResults | ConvertTo-Json -Depth 10
	$resultsJsonPath = Join-Path -Path $exportPath -ChildPath $script:ZtReportJsonFileName
	$assessmentResultsJson | Set-PSFFileContent -Path $resultsJsonPath

	Write-PSFMessage -Message "Stage 6: Generating Html Report" -Tag stage
	Write-ZtProgress -Activity "Generating report" -Status "Building HTML report"
	$htmlReportPath = Join-Path -Path $Path -ChildPath $script:ZtReportFileName
	$output = Get-HtmlReport -AssessmentResults $assessmentResultsJson -Path $Path
	$output | Set-PSFFileContent -Path $htmlReportPath -Encoding UTF8NoBom

	# Mark the assessment as fully completed so the menu can distinguish
	# a completed run from an interrupted/resumable one.
	Set-ZtConfig -ExportPath $exportPath -Property AssessmentCompleted -Value $true

	# Write the test run summary now that the report is complete
	Write-ZtTestSummary -LogsPath $logsPath

	#region Post Processing
	Write-Host
	Write-Host "🛡️ Zero Trust Assessment report generated at $htmlReportPath" -ForegroundColor Green
	Show-ZtiSecurityWarning -ExportPath $exportPath
	Write-Host "▶▶▶ ✨ Your feedback matters! Help us improve 👉 https://aka.ms/ztassess/feedback ◀◀◀" -ForegroundColor Yellow
	Write-Host
	Write-Host
	Open-ZtReport -Path $htmlReportPath -ServeHttp

	if ($ExportLog) {
		Write-ZtProgress -Activity "Creating support package"
		$logPath = Join-Path $Path "log"
		if (-not (Test-Path $logPath)) {
			$null = New-Item -ItemType Directory -Path $logPath -Force -ErrorAction Stop
		}
		New-PSFSupportPackage -Path $logPath
	}
	#endregion Post Processing
}
