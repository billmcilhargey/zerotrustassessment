function Test-ZtServicePreflight {
	<#
	.SYNOPSIS
		Consolidated pre-flight check before running the Zero Trust Assessment.

	.DESCRIPTION
		Runs all prerequisite validations in the recommended order and returns
		a single result object. Each check is non-fatal by default — the result
		object reports what passed, what failed, and what was skipped.

		Checks performed (in order):
		1. Language mode   — PowerShell must be in FullLanguage mode.
		2. Database        — DuckDB native library must load (auto-downloads if missing).
		3. Graph context   — Must be connected with required scopes and roles.
		4. Service health  — Verifies tracked service sessions are still alive.
		5. Service coverage — Compares services needed by tests vs. connected services.

		Invoke-ZtAssessment calls this automatically before the export phase.
		It can also be called standalone for diagnostics.

	.PARAMETER Pillar
		The pillar to evaluate for service coverage. Defaults to 'All'.

	.PARAMETER Tests
		Optional list of specific test IDs. When specified, coverage analysis
		is scoped to only those tests.

	.EXAMPLE
		PS> Test-ZtServicePreflight

		Runs all pre-flight checks and returns a result summary.

	.EXAMPLE
		PS> $result = Test-ZtServicePreflight -Pillar Identity
		PS> if (-not $result.Passed) { $result.Failures }

		Checks prerequisites for Identity pillar and inspects failures.
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param (
		[string]
		$Pillar = 'All',

		[string[]]
		$Tests
	)

	$checks = [System.Collections.Generic.List[PSCustomObject]]::new()
	$allPassed = $true

	# ── 1. Language mode ─────────────────────────────────────────────────────
	$langOk = Test-ZtLanguageMode
	$checks.Add([PSCustomObject]@{
		Check   = 'LanguageMode'
		Passed  = $langOk
		Detail  = if ($langOk) { 'FullLanguage' } else { 'Constrained Language Mode is not supported' }
	})
	if (-not $langOk) { $allPassed = $false }

	# ── 2. Database assembly ─────────────────────────────────────────────────
	$dbOk = $false
	try {
		$dbOk = Test-DatabaseAssembly
	}
	catch {
		# Test-DatabaseAssembly already writes user-friendly messages
	}
	$checks.Add([PSCustomObject]@{
		Check   = 'DatabaseAssembly'
		Passed  = $dbOk
		Detail  = if ($dbOk) { 'DuckDB ready' } else { 'DuckDB native library not available' }
	})
	if (-not $dbOk) { $allPassed = $false }

	# ── 3. Graph context (scopes + roles) ────────────────────────────────────
	$graphOk = $false
	$graphDetail = $null
	try {
		$graphOk = Test-ZtContext
		$graphDetail = 'Connected with required scopes and roles'
	}
	catch {
		$graphDetail = $_.Exception.Message
	}
	$checks.Add([PSCustomObject]@{
		Check   = 'GraphContext'
		Passed  = $graphOk
		Detail  = $graphDetail
	})
	if (-not $graphOk) { $allPassed = $false }

	# ── 3a. Cloud environment detection ──────────────────────────────────────
	# Detect the cloud environment (Commercial, GCC, GCC High, DoD, China, Germany)
	# early so tests and the report can use it. This is informational — does not block the run.
	$cloudEnvDetail = $null
	$cloudEnv = $null
	if ($graphOk) {
		try {
			$cloudEnv = Get-ZtCloudEnvironment -Force
			$cloudEnvDetail = '{0} (detected from {1})' -f $cloudEnv.DisplayName, $cloudEnv.DetectedFrom
		}
		catch {
			$cloudEnvDetail = "Unable to detect cloud environment: $($_.Exception.Message)"
		}
	}
	else {
		$cloudEnvDetail = 'Skipped (no Graph context)'
	}
	$checks.Add([PSCustomObject]@{
		Check            = 'CloudEnvironment'
		Passed           = $null -ne $cloudEnv -and $cloudEnv.CloudType -ne 'Unknown'
		Detail           = $cloudEnvDetail
		CloudEnvironment = $cloudEnv
	})
	# Cloud environment detection is informational — does not block the run

	# ── 3b. Licensing ────────────────────────────────────────────────────────
	# Detect tenant licenses early so per-test checks can use the cache.
	# This is a warning only — missing licenses don't block the run.
	$licenseDetail = $null
	$licenseTier = 'Unknown'
	$licenseProducts = @{}
	if ($graphOk) {
		try {
			$null = Get-ZtCurrentLicense -Force
			# Prime the plan ID cache used by Get-ZtLicense / Get-ZtLicenseInformation
			$null = Get-ZtActiveServicePlanId -Force
			$licenseTier = Get-ZtLicenseInformation -Product EntraID
			# Detect all product licenses for pre-filtering decisions
			$licenseProducts = @{
				EntraID    = $licenseTier
				Intune     = Get-ZtLicenseInformation -Product Intune
				WorkloadID = Get-ZtLicenseInformation -Product EntraWorkloadID
			}
			$parts = @("Entra ID: $licenseTier")
			if ($licenseProducts.Intune) { $parts += "Intune: $($licenseProducts.Intune)" }
			if ($licenseProducts.WorkloadID) { $parts += "Workload ID: $($licenseProducts.WorkloadID)" }
			$licenseDetail = $parts -join '  |  '
		}
		catch {
			$licenseDetail = "Unable to detect licenses: $($_.Exception.Message)"
		}
	}
	else {
		$licenseDetail = 'Skipped (no Graph context)'
	}
	$checks.Add([PSCustomObject]@{
		Check           = 'Licensing'
		Passed          = $licenseTier -in @('P1', 'P2', 'Governance')
		Detail          = $licenseDetail
		LicenseTier     = $licenseTier
		LicenseProducts = $licenseProducts
	})
	# Licensing gaps are a warning, not a hard failure

	# ── 3c. Global Secure Access ─────────────────────────────────────────────
	# Detect whether GSA is activated so the summary shows skip count context.
	# This primes the cache used by individual GSA tests.
	$gsaDetail = $null
	$gsaActive = $false
	if ($graphOk) {
		$gsaSkipOverride = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Assessment.SkipGlobalSecureAccess' -Fallback $false
		if ($gsaSkipOverride) {
			$gsaDetail = 'Skipped by user configuration (Assessment.SkipGlobalSecureAccess = $true)'
		}
		else {
			try {
				$gsaActive = Test-ZtGsaEnabled -Force
				$gsaDetail = if ($gsaActive) { 'Enabled (at least one forwarding profile active)' } else { 'Not configured — GSA tests will be skipped' }
			}
			catch {
				$gsaDetail = "Unable to detect: $($_.Exception.Message)"
			}
		}
	}
	else {
		$gsaDetail = 'Skipped (no Graph context)'
	}
	$checks.Add([PSCustomObject]@{
		Check     = 'GlobalSecureAccess'
		Passed    = $gsaActive
		Detail    = $gsaDetail
		GsaActive = $gsaActive
	})
	# GSA status is informational — does not block the run

	# ── 4. Service health ────────────────────────────────────────────────────
	$healthResults = Test-ZtServiceHealth
	$unhealthy = @($healthResults | Where-Object { -not $_.Healthy })
	$healthPassed = $unhealthy.Count -eq 0

	$checks.Add([PSCustomObject]@{
		Check   = 'ServiceHealth'
		Passed  = $healthPassed
		Detail  = if ($healthPassed) {
			"All $($healthResults.Count) service(s) healthy"
		}
		else {
			"$($unhealthy.Count) service(s) failed: $($unhealthy.Service -join ', ')"
		}
		Services = $healthResults
	})
	if (-not $healthPassed) { $allPassed = $false }

	# ── 5. Service coverage ──────────────────────────────────────────────────
	$coverageParams = @{}
	if ($Tests) { $coverageParams.Tests = $Tests }
	if ($Pillar) { $coverageParams.Pillar = $Pillar }
	# Detect auth mode so classification reasons propagate to coverage gaps
	if (Get-ZtEffectiveDeviceCode) { $coverageParams.UseDeviceCode = $true }
	$coverage = Test-ZtServiceCoverage @coverageParams

	$checks.Add([PSCustomObject]@{
		Check    = 'ServiceCoverage'
		Passed   = $coverage.FullCoverage
		Detail   = if ($coverage.FullCoverage) {
			"All needed services connected ($($coverage.TotalTests) tests)"
		}
		else {
			"$($coverage.SkippedTestCount) test(s) will be skipped — missing: $($coverage.MissingServices -join ', ')"
		}
		Coverage = $coverage
	})
	# Service coverage gaps are a warning, not a hard failure — tests will be skipped but the run continues
	# We don't set $allPassed = $false here

	# ── Build result ─────────────────────────────────────────────────────────
	$failures = @($checks | Where-Object { -not $_.Passed -and $_.Check -notin 'ServiceCoverage', 'Licensing', 'CloudEnvironment', 'GlobalSecureAccess' })

	[PSCustomObject]@{
		Passed        = $allPassed
		Checks        = $checks.ToArray()
		Failures      = $failures
		Coverage      = $coverage
		HealthResults = $healthResults
	}
}
