function Invoke-ZtTests {
	<#
	.SYNOPSIS
		Runs all the Zero Trust Assessment tests.

	.DESCRIPTION
		Runs all the Zero Trust Assessment tests.

	.PARAMETER Database
		The Database object where the cached tenant data is stored

	.PARAMETER Tests
		The IDs of the specific test(s) to run. If not specified, all tests will be run.

	.PARAMETER Pillar
		The Zero Trust pillar to assess.
		Defaults to: All.

	.PARAMETER ThrottleLimit
		Maximum number of tests processed in parallel.
		Defaults to: 5

	.PARAMETER LogsPath
		Optional path to output logs for each test. If not specified, logs will not be written
		to disk but will still be available in the database.

	.PARAMETER Timeout
		The maximum time to wait for all tests to complete before giving up and writing a warning message.
		Defaults to: 24 hours. Adjust this value if you have a large number of tests or expect some tests to take a long time.

	.PARAMETER ConnectedService
		The services that are connected and can be used for testing.
		This is used to skip tests that require a service connection when the service is not connected.
		If not specified, it will use the value from $script:ConnectedService, which is set based on the
		connected services populated by Connect-ZtAssessment.

	.PARAMETER TestTimeout
		Maximum time in minutes a single test is allowed to run.
		Defaults to: 60. Set to 0 to disable.
		For Data pillar tests and external-module/remoting-heavy operations,
		this is a best-effort interruption rather than a guaranteed hard stop.

	.EXAMPLE
		PS> Invoke-ZtTests -Database $database -Tests $Tests -Pillar $Pillar -ThrottleLimit $TestThrottleLimit

		Executes all tests specified.
	#>
	[CmdletBinding()]
	param (
		[DuckDB.NET.Data.DuckDBConnection]
		$Database,

		[string[]]
		$Tests,

		[ValidateSet('All', 'Identity', 'Devices', 'Network', 'Data')]
		[string]
		$Pillar = 'All',

		[int]
		$ThrottleLimit = 5,

		[string]
		$LogsPath,

		[Parameter(DontShow)]
		[ValidateSet('Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')]
		[string[]]
		$ConnectedService = $script:ConnectedService,

		[TimeSpan]
		$Timeout = '1.00:00:00',

		[int]
		$TestTimeout = 60
	)

	# Get Tenant Type (AAD = Workforce, CIAM = EEID)
	$org = Invoke-ZtGraphRequest -RelativeUri 'organization'
	$tenantType = $org.TenantType
	Write-PSFMessage "$tenantType tenant detected. This will determine the tests that are run."

	# Map input parameters to config file values
	$tenantTypeMapping = @{
		"AAD"  = "Workforce"
		"CIAM" = "External"
	}

	$testsToRun = Get-ZtTest -Tests $Tests -Pillar $Pillar -TenantType $tenantTypeMapping[$TenantType]

	# Filter based on preview feature flag
	if (-not $script:__ZtSession.PreviewEnabled) {
		# Non-preview mode: Only include stable/released pillars
		$stablePillars = @('Identity', 'Devices', 'Network', 'Data')
		$testsToRun = $testsToRun.Where{ $_.Pillar -in $stablePillars }
	}

	# Filter based on service connection. If no service is specified in the test metadata, it will be run.
	# Sync tracked services with live session state — earlier errors (e.g. DLL conflicts)
	# may have removed services even though the sessions are still active.
	Sync-ZtConnectedServices
	$ConnectedService = @($script:ConnectedService)

	$skippedTestsForService = $testsToRun.Where{ $_.Service.count -gt 0 -and $_.Service.Count -notin $_.Service.Where{ $_ -in $ConnectedService}.count }
	$skippedTestsForService.ForEach{
		$notConnectedService = ($_).Service.Where{ $_ -notin $ConnectedService }
		# Mark the test as skipped.
		Add-ZtTestResultDetail -SkippedBecause NotConnectedToService -TestId $_.TestId -NotConnectedService $notConnectedService
	}
	# Log a summary of tests skipped per missing service so users have clear visibility
	if ($skippedTestsForService.Count -gt 0) {
		$skippedByService = @{}
		foreach ($skippedTest in $skippedTestsForService) {
			foreach ($missingSvc in $skippedTest.Service.Where{ $_ -notin $ConnectedService }) {
				if (-not $skippedByService.ContainsKey($missingSvc)) { $skippedByService[$missingSvc] = 0 }
				$skippedByService[$missingSvc]++
			}
		}
		foreach ($entry in $skippedByService.GetEnumerator()) {
			Write-PSFMessage -Message ('Skipping {0} test(s) — service "{1}" is not connected.' -f $entry.Value, $entry.Key) -Level Important
		}
	}
	$testsToRun = $testsToRun.Where{ $_.TestId -notin $skippedTestsForService.TestId }

	# Filter based on licensing (CompatibleLicense + MinimumLicense)
	# Build tier cache once via Get-ZtLicenseSkipSummary
	$licSummary = Get-ZtLicenseSkipSummary -Tests $testsToRun
	$tierCache = $licSummary.TierCache

	# Map product names to SkippedBecause reasons for result detail recording
	$productToSkipReason = @{
		'EntraIDP1'         = 'NotLicensedEntraIDP1'
		'EntraIDP2'         = 'NotLicensedEntraIDP2'
		'EntraIDGovernance' = 'NotLicensedEntraIDGovernance'
		'Intune'            = 'NotLicensedIntune'
		'EntraWorkloadID'   = 'NotLicensedEntraWorkloadID'
	}

	$skippedTestsForLicense = [System.Collections.Generic.List[object]]::new()
	foreach ($test in $testsToRun) {
		$skipReason = Test-ZtTestLicenseSkip -Test $test -TierCache $tierCache
		if (-not $skipReason) { continue }

		$skippedTestsForLicense.Add($test)

		# Determine the specific SkippedBecause value for result detail
		if ($test.CompatibleLicense.Count -gt 0) {
			Add-ZtTestResultDetail -SkippedBecause NoCompatibleLicenseFound -TestId $test.TestId
		}
		else {
			# Map first unmet MinimumLicense tier to its skip reason
			$detailReason = $null
			foreach ($tier in @($test.MinimumLicense)) {
				$product = $script:ZtLicenseTierToProduct[$tier]
				if ($product -and -not $tierCache[$tier] -and $productToSkipReason[$product]) {
					$detailReason = $productToSkipReason[$product]
					break
				}
			}
			if ($detailReason) {
				Add-ZtTestResultDetail -SkippedBecause $detailReason -TestId $test.TestId
			}
		}
	}
	if ($skippedTestsForLicense.Count -gt 0) {
		$skippedByLabel = @{}
		foreach ($t in $skippedTestsForLicense) {
			$label = if ($t.CompatibleLicense.Count -gt 0) { 'compatible license' }
			         else { ($t.MinimumLicense -join '/') }
			if (-not $skippedByLabel[$label]) { $skippedByLabel[$label] = 0 }
			$skippedByLabel[$label]++
		}
		foreach ($entry in $skippedByLabel.GetEnumerator()) {
			Write-PSFMessage -Message ('Skipping {0} test(s) — requires {1} license (not active).' -f $entry.Value, $entry.Key) -Level Important
		}
	}
	$testsToRun = $testsToRun.Where{ $_.TestId -notin $skippedTestsForLicense.TestId }

	# Filter based on required Graph permission scopes (RequiredScopes attribute).
	# Pre-skip tests whose declared scopes are not present in the current MgGraph context.
	$skippedTestsForScope = [System.Collections.Generic.List[object]]::new()
	$scopeCheckCache = @{} # scope → bool
	foreach ($test in $testsToRun) {
		if (-not $test.RequiredScopes -or $test.RequiredScopes.Count -eq 0) { continue }
		$missingForTest = @()
		foreach ($scope in $test.RequiredScopes) {
			if (-not $scopeCheckCache.ContainsKey($scope)) {
				$scopeCheckCache[$scope] = Test-ZtRequiredScope -RequiredScopes @($scope)
			}
			if (-not $scopeCheckCache[$scope]) {
				$missingForTest += $scope
			}
		}
		if ($missingForTest.Count -gt 0) {
			$skippedTestsForScope.Add($test)
			Add-ZtTestResultDetail -SkippedBecause MissingRequiredScope -TestId $test.TestId -MissingScopes $missingForTest
		}
	}
	if ($skippedTestsForScope.Count -gt 0) {
		$allMissingScopes = @($skippedTestsForScope.RequiredScopes | Sort-Object -Unique)
		$sessionMissing = @($allMissingScopes | Where-Object { -not $scopeCheckCache[$_] })
		Write-PSFMessage -Message ('Skipping {0} test(s) — missing Graph scope(s): {1}.' -f $skippedTestsForScope.Count, ($sessionMissing -join ', ')) -Level Important
	}
	$testsToRun = $testsToRun.Where{ $_.TestId -notin $skippedTestsForScope.TestId }

	# Filter based on cloud environment (CloudEnvironment attribute).
	# Pre-skip tests whose declared CloudEnvironment does not include the current cloud.
	$skippedTestsForEnv = [System.Collections.Generic.List[object]]::new()
	$currentCloudEnv = Get-ZtCloudEnvironment
	if ($currentCloudEnv -and $currentCloudEnv.CloudType -ne 'Unknown') {
		foreach ($test in $testsToRun) {
			if (-not $test.CloudEnvironment -or $test.CloudEnvironment.Count -eq 0) { continue }
			if (-not (Test-ZtCloudEnvironment -SupportedCloudType $test.CloudEnvironment)) {
				$skippedTestsForEnv.Add($test)
				Add-ZtTestResultDetail -SkippedBecause NotSupportedEnvironment -TestId $test.TestId
			}
		}
		if ($skippedTestsForEnv.Count -gt 0) {
			Write-PSFMessage -Message ('Skipping {0} test(s) — not supported in {1} cloud environment.' -f $skippedTestsForEnv.Count, $currentCloudEnv.DisplayName) -Level Important
		}
	}
	$testsToRun = $testsToRun.Where{ $_.TestId -notin $skippedTestsForEnv.TestId }

	# Separate Sync Tests (Compliance/ExchangeOnline/SharePoint) from Parallel Tests (because of DLL order to manage in runspaces & remoting into WPS)
	[int[]]$syncTestIds   = $testsToRun.Where{ $_.Pillar -eq 'Data'}.TestId
	$syncTests     = $testsToRun.Where{ $_.TestId -in $syncTestIds }
	$parallelTests = $testsToRun.Where{ $_.TestId -notin $syncTestIds }

	[dateTime] $startTime = [datetime]::Now
	$workflow = $null
	try {
		# Convert timeout minutes to timespan (0 = disabled)
		$timeoutSpan = if ($TestTimeout -gt 0) { [timespan]::FromMinutes($TestTimeout) } else { [timespan]::Zero }

		# Run Sync Tests in the main thread
		foreach ($test in $syncTests) {
			$null = Invoke-ZtTest -Test $test -Database $Database -LogsPath $LogsPath -TestTimeout $timeoutSpan
		}

		# Then run Parallel Tests
		if ($parallelTests) {
			$workflow = Start-ZtTestExecution -Tests $parallelTests -DbPath $Database.Database -ThrottleLimit $ThrottleLimit -LogsPath $LogsPath -TestTimeout $timeoutSpan
			Wait-ZtTest -Workflow $workflow -StartedAt $startTime -Timeout $Timeout
			$workflow.Queues['Input'].ForEach{
				Write-PSFMessage -Level Debug -Message "Test $_ was not processed before timeout was reached."
				Add-ZtTestResultDetail -SkippedBecause TimeoutReached -TestId $_
			}
		}
	}
	finally {
		if ($workflow) {
			# Disable CTRL+C to prevent impatient users from finishing the cleanup. Failing to do so may lead to a locked database, preventing a clean restart.
			Disable-PSFConsoleInterrupt
			$workflow | Stop-PSFRunspaceWorkflow
			$workflow | Remove-PSFRunspaceWorkflow
			Enable-PSFConsoleInterrupt
		}
	}
}
