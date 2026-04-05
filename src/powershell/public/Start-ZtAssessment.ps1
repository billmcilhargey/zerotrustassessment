function Start-ZtAssessment {
	<#
	.SYNOPSIS
		Interactive launcher for the Zero Trust Assessment.

	.DESCRIPTION
		Provides a menu-driven interface for end users to connect, run assessments,
		view test lists, check status, and manage reports.

		This is the recommended entry point for interactive usage after installing
		from the PowerShell Gallery:

		  Install-PSResource ZeroTrustAssessment
		  Start-ZtAssessment

		For non-interactive / automated usage, call Connect-ZtAssessment and
		Invoke-ZtAssessment directly.

	.PARAMETER Action
		Skip the interactive menu and run a specific action directly.

	.PARAMETER Pillar
		When Action is RunPillar, specifies which pillar to assess.

	.PARAMETER Tests
		When Action is RunTests, specifies one or more test IDs to run.

	.PARAMETER Path
		Output folder for assessment reports. Default: ./ZeroTrustReport

	.PARAMETER Days
		Number of days of sign-in logs to query (1-30). Default: 30

	.PARAMETER UseDeviceCode
		Use device code flow for authentication.
		Auto-enabled in Codespaces and headless environments.

	.PARAMETER TenantId
		Target a specific tenant for authentication.

	.PARAMETER Service
		Which services to connect. Default: All

	.PARAMETER ShowLog
		Show verbose log output during the assessment.

	.EXAMPLE
		PS> Start-ZtAssessment

		Launches the interactive menu.

	.EXAMPLE
		PS> Start-ZtAssessment -Action RunAll

		Runs the full assessment without showing the menu.

	.EXAMPLE
		PS> Start-ZtAssessment -Action RunPillar -Pillar Identity -Days 7

		Runs only the Identity pillar with 7 days of logs.

	.EXAMPLE
		PS> Start-ZtAssessment -Action Connect -UseDeviceCode

		Connects using device code flow.
	#>
	[Alias('Start-ZeroTrustAssessment')]
	[CmdletBinding()]
	param (
		[ValidateSet('Connect', 'RunAll', 'RunPillar', 'RunTests', 'ListTests',
			'Status', 'Resume', 'Disconnect', 'DeleteResults', 'ListReports')]
		[string]
		$Action,

		[ValidateSet('Identity', 'Devices', 'Network', 'Data')]
		[string]
		$Pillar,

		[string[]]
		$Tests,

		[string]
		$Path = $script:ZtDefaultReportPath,

		[ValidateRange(1, 30)]
		[int]
		$Days = 30,

		[switch]
		$UseDeviceCode,

		[string]
		$TenantId,

		[ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')]
		[string[]]
		$Service = 'All',

		[switch]
		$ShowLog
	)

	# ── Helpers ──────────────────────────────────────────────────────────────

	function Get-ZtaEffectiveDeviceCode {
		# Local param takes priority, then delegate to shared detection
		if ($UseDeviceCode) { return $true }
		return Get-ZtEffectiveDeviceCode
	}

	# Track whether the user explicitly provided -Path.
	# When true, Invoke-ZtAssessment will auto-resolve to ./ZeroTrustReport/{tenantId}/.
	# We replicate that logic here only for UI operations (menu display, view, delete, resume).
	$isDefaultPath = -not $PSBoundParameters.ContainsKey('Path')

	function Get-ZtaEffectivePath {
		# Returns the tenant-specific report path when connected, or the base path otherwise.
		# Used for UI operations only — Invoke-ZtAssessment handles its own path resolution.
		Resolve-ZtTenantReportPath -BasePath $Path -IsDefaultPath $isDefaultPath
	}

	function Step-ZtaListReports {
		Write-Host "`n── Saved Reports ──`n" -ForegroundColor DarkCyan
		$reports = Get-ZtReportIndex -BasePath $Path
		if (-not $reports -or $reports.Count -eq 0) {
			Write-Host '  No reports found.' -ForegroundColor Yellow
			return
		}
		$i = 0
		foreach ($r in $reports) {
			$i++
			$tenantLabel = if ($r.TenantId) { $r.TenantId } else { '(unknown tenant)' }
			$status = if ($r.Completed) { '✅' } else { '⚠️' }
			$dateStr = $r.LastModified.ToString('yyyy-MM-dd HH:mm')
			Write-Host "  [$i]  $status  Tenant: $tenantLabel" -ForegroundColor White
			Write-Host "       Pillar: $($r.Pillar)  |  Date: $dateStr" -ForegroundColor Gray
			Write-Host "       Path: $($r.Path)" -ForegroundColor DarkGray
		}
		Write-Host ''
		$pick = Read-Host '  Open a report? Enter number or press Enter to skip'
		if ($pick -match '^\d+$') {
			$idx = [int]$pick - 1
			if ($idx -ge 0 -and $idx -lt $reports.Count) {
				$selected = $reports[$idx]
				Write-Host "`n── Opening Report ──`n" -ForegroundColor Cyan
				Open-ZtReport -Path $selected.ReportFile -ServeHttp
			}
			else {
				Write-Host '  Invalid selection.' -ForegroundColor Red
			}
		}
	}

	# ── Dependencies ─────────────────────────────────────────────────────────

	# Track whether we already attempted a fix this session to avoid loops
	$script:_ztaDependencyFixAttempted = $false

	function Step-ZtaVerifyDependencies {
		# Early startup check: are installed dependency versions meeting manifest requirements?
		# Catches version mismatches before the user hits a cryptic error at Connect time.
		$classification = Get-ZtServiceClassification
		$platformServices = @($classification | Where-Object { $_.Available } | ForEach-Object { $_.Name })
		if (-not $platformServices) { return }

		$resolved = Resolve-ZtServiceRequiredModule -Service $platformServices
		$issues = @($resolved.Errors | Where-Object {
			$_.ErrorMessage -match 'below the required minimum|does not match required version|cannot be found'
		})
		if ($issues.Count -eq 0) { return }

		if ($script:_ztaDependencyFixAttempted) {
			Write-Host ''
			Write-Host '  ⚠️  Dependency issues persist after update attempt:' -ForegroundColor Yellow
			foreach ($err in $issues) {
				Write-Host "    ❌ $($err.Service): $($err.ErrorMessage)" -ForegroundColor Red
			}
			Write-Host '  Try restarting PowerShell and reimporting the module.' -ForegroundColor DarkGray
			Write-Host ''
			return
		}

		Write-Host ''
		Write-Host '  ⚠️  Module dependency issues detected:' -ForegroundColor Yellow
		foreach ($err in $issues) {
			Write-Host "    ❌ $($err.Service): $($err.ErrorMessage)" -ForegroundColor Red
		}
		Write-Host ''
		$answer = Read-Host '  Fix now? This will re-download the correct module versions. (Y/N) [Y]'
		if ($answer.Trim().Length -eq 0 -or $answer.Trim().ToUpper() -eq 'Y') {
			$script:_ztaDependencyFixAttempted = $true
			Write-Host ''
			Update-ZtRequiredModule -Confirm:$false
			Write-Host ''
		}
		else {
			Write-Host '  Skipping — some services may be unavailable.' -ForegroundColor DarkGray
			Write-Host ''
		}
	}

	# ── Steps ────────────────────────────────────────────────────────────────

	function Step-ZtaConnect {
		# Early-out: if already connected (in-memory) with valid context, skip
		$conn = Get-ZtConnectionState
		if ($conn.IsConnected -and $conn.ScopesValid) {
			Write-Host "`n── Already Connected ──`n" -ForegroundColor DarkCyan
			Write-Host "  ✅ $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
			Write-Host "     Services: $($conn.Services -join ', ')" -ForegroundColor DarkGray
			Write-Host "  📁 Report path: $(Get-ZtaEffectivePath)" -ForegroundColor DarkGray
			return
		}

		# Try silent restore from token cache before prompting
		Write-Host "  Checking for cached login..." -ForegroundColor DarkGray
		if (Restore-ZtCachedConnection) {
			$conn = Get-ZtConnectionState
			Write-Host "`n── Restored from Cache ──`n" -ForegroundColor DarkCyan
			Write-Host "  ✅ $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
			Write-Host "     Services: $($conn.Services -join ', ')" -ForegroundColor DarkGray
			Write-Host "  📁 Report path: $(Get-ZtaEffectivePath)" -ForegroundColor DarkGray
			return
		}

		Write-Host "`n── Connecting to Tenant ──`n" -ForegroundColor DarkCyan

		$connectParams = @{}
		if (Get-ZtaEffectiveDeviceCode) { $connectParams['UseDeviceCode'] = $true }
		if (Get-ZtTokenCacheEnabled) { $connectParams['UseTokenCache'] = $true }
		if ($TenantId)   { $connectParams['TenantId'] = $TenantId }
		if ($Service -and $Service -ne 'All') { $connectParams['Service'] = $Service }

		Write-Host "  Connecting..." -ForegroundColor Gray
		try {
			Connect-ZtAssessment @connectParams
		}
		catch {
			Write-Host "  Connection failed: $_" -ForegroundColor Red
			if ($_.Exception.Message -notmatch 'skipped') {
				Write-Host '  Tips:' -ForegroundColor Yellow
				Write-Host '    - Use -UseDeviceCode for remote/container sessions' -ForegroundColor White
				Write-Host '    - Ensure you have Global Reader or Global Administrator role' -ForegroundColor White
			}
		}
	}

	function Get-ZtaServiceSummary {
		# Expand configured services and determine availability via classification
		$configured = if ($Service -contains 'All') {
			@($script:AllowedServices)
		} else { @($Service) }
		$classifyParams = @{}
		if (Get-ZtaEffectiveDeviceCode) { $classifyParams['UseDeviceCode'] = $true }
		$classification = Get-ZtServiceClassification @classifyParams
		$classified = @($classification | Where-Object { $_.Name -in $configured })
		$available = @($classified | Where-Object { -not $_.Reason } | ForEach-Object { $_.Name })
		$constrained = @($classified | Where-Object { $_.Reason })
		[PSCustomObject]@{
			Configured  = $configured
			Available   = $available
			Constrained = $constrained
		}
	}

	function Step-ZtaStatus {
		Write-Host "`n── Connection Status ──`n" -ForegroundColor DarkCyan
		$conn = Get-ZtConnectionState
		$svcSummary = Get-ZtaServiceSummary
		$tokenCache = Get-ZtTokenCacheEnabled
		if ($conn.IsConnected) {
			Write-Host "  Account   : $($conn.Account)" -ForegroundColor Gray
			Write-Host "  Tenant    : $($conn.Tenant)" -ForegroundColor Gray
			$cloudEnv = $conn.CloudEnvironment
			if ($cloudEnv) {
				$envColor = if ($cloudEnv.IsGovernment) { 'Cyan' } elseif ($cloudEnv.IsSovereignCloud) { 'Yellow' } else { 'Gray' }
				Write-Host "  Cloud     : $($cloudEnv.DisplayName)" -ForegroundColor $envColor
			}
			Write-Host "  Connected : $($conn.Services -join ', ')" -ForegroundColor Gray
			Write-Host "  Available : $($svcSummary.Available -join ', ')" -ForegroundColor Gray
			if ($svcSummary.Constrained.Count -gt 0) {
				$constrainedDisplay = ($svcSummary.Constrained | ForEach-Object { "$($_.Name) ($($_.Reason))" }) -join ', '
				Write-Host "  Limited   : $constrainedDisplay" -ForegroundColor Yellow
			}
			Write-Host "  TokenCache: $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
			Write-Host "  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip')) (Skip = hide, Warn = show as failed)" -ForegroundColor Gray

			# License detection
			Show-ZtLicenseStatus
			Show-ZtPermissionStatus
			Write-Host "  📁 Report path: $(Get-ZtaEffectivePath)" -ForegroundColor DarkGray
		}
		else {
			Write-Host '  Not connected to Microsoft Graph.' -ForegroundColor Yellow
			Write-Host "  Available : $($svcSummary.Available -join ', ')" -ForegroundColor Gray
			if ($svcSummary.Constrained.Count -gt 0) {
				$constrainedDisplay = ($svcSummary.Constrained | ForEach-Object { "$($_.Name) ($($_.Reason))" }) -join ', '
				Write-Host "  Limited   : $constrainedDisplay" -ForegroundColor Yellow
			}
			Write-Host "  TokenCache: $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
			Write-Host "  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip')) (Skip = hide, Warn = show as failed)" -ForegroundColor Gray
		}
	}

	function Step-ZtaListTests {
		Write-Host "`n── Available Tests ──`n" -ForegroundColor DarkCyan
		$listParams = @{}
		if ($Pillar) { $listParams['Pillar'] = $Pillar }

		$allTests = Get-ZtTest @listParams
		if (-not $allTests) { Write-Host '  No tests found.' -ForegroundColor Yellow; return }

		# Get service classification to determine which tests will be skipped
		$classifyParams = @{}
		if (Get-ZtaEffectiveDeviceCode) { $classifyParams['UseDeviceCode'] = $true }
		$classification = Get-ZtServiceClassification @classifyParams
		$unavailableSvcs = @($classification | Where-Object { -not $_.Available } | ForEach-Object { $_.Name })
		$warningSvcs = @($classification | Where-Object { $_.Available -and $_.Reason } | ForEach-Object { $_.Name })
		$skipSvcs = $unavailableSvcs + $warningSvcs

		# License-aware skip detection (only when connected)
		$conn = Get-ZtConnectionState
		$licSkipTiers = @{}
		$tierCache = @{}
		if ($conn.IsConnected) {
			$licSummary = Get-ZtLicenseSkipSummary -Tests $allTests
			$tierCache = $licSummary.TierCache
		}

		$grouped = $allTests | Group-Object Pillar | Sort-Object Name
		$skippedSvc = 0
		$skippedLic = 0
		foreach ($g in $grouped) {
			Write-Host "`n  ── $($g.Name) ($($g.Count) tests) ──" -ForegroundColor Magenta
			foreach ($t in ($g.Group | Sort-Object TestID)) {
				$svc = if ($t.Service) { "[$(($t.Service) -join ',')]" } else { '' }
				$blockedSvc = if ($t.Service) { $t.Service | Where-Object { $_ -in $skipSvcs } | Select-Object -First 1 } else { $null }
				if ($blockedSvc) {
					$svcReason = ($classification | Where-Object { $_.Name -eq $blockedSvc }).Reason
					Write-Host "    SKIP  $($t.TestID)  $($t.Title)  $svc  ($svcReason)" -ForegroundColor DarkGray
					$skippedSvc++
				}
				elseif ($conn.IsConnected) {
					$licSkipReason = Test-ZtTestLicenseSkip -Test $t -TierCache $tierCache
					if ($licSkipReason) {
						Write-Host "    SKIP  $($t.TestID)  $($t.Title)  $svc  ($licSkipReason)" -ForegroundColor DarkYellow
						$skippedLic++
						if (-not $licSkipTiers[$licSkipReason]) { $licSkipTiers[$licSkipReason] = 0 }
						$licSkipTiers[$licSkipReason]++
					}
					else {
						Write-Host "          $($t.TestID)  $($t.Title)  $svc" -ForegroundColor Gray
					}
				}
				else {
					Write-Host "          $($t.TestID)  $($t.Title)  $svc" -ForegroundColor Gray
				}
			}
		}
		$totalSkipped = $skippedSvc + $skippedLic
		$available = $allTests.Count - $totalSkipped
		Write-Host ""
		Write-Host "  Available : $available" -ForegroundColor Green
		if ($totalSkipped -gt 0) {
			Write-Host "  Skipped   : $totalSkipped" -ForegroundColor Yellow
			if ($skippedSvc -gt 0) {
				Write-Host "    Service : $skippedSvc (service constraints)" -ForegroundColor Yellow
			}
			if ($skippedLic -gt 0) {
				$licDetail = ($licSkipTiers.GetEnumerator() | ForEach-Object { "$($_.Value) $($_.Key)" }) -join ', '
				Write-Host "    License : $skippedLic ($licDetail)" -ForegroundColor DarkYellow
			}
		}
		Write-Host "  Total     : $($allTests.Count)" -ForegroundColor DarkGray
	}

	function Step-ZtaRunAssessment {
		param(
			[string]   $RunPillar,
			[string[]] $RunTests,
			[switch]   $Resume
		)

		$conn = Get-ZtConnectionState
		if (-not $conn.IsConnected) {
			Write-Host '  Not connected. Connecting automatically...' -ForegroundColor Yellow
			Step-ZtaConnect
			$conn = Get-ZtConnectionState
			if (-not $conn.IsConnected) {
				Write-Host '  Connection failed. Cannot run assessment.' -ForegroundColor Red
				return
			}
		}

		# Resolve to tenant-specific path
		$effectivePath = Get-ZtaEffectivePath

		# Offer to delete previous results (unless resuming)
		if (-not $Resume -and (Test-Path $effectivePath)) {
			$items = Get-ChildItem -Path $effectivePath -ErrorAction SilentlyContinue
			if ($items.Count -gt 0) {
				Write-Host "  Previous results found at: $effectivePath" -ForegroundColor Yellow
				$confirm = Read-Host '  Delete all contents? (Y/N) [N]'
				if ($confirm.Trim().ToUpper() -eq 'Y') {
					# Close any open module-managed database connection before deleting
					if ($script:_DatabaseConnection) {
						try { Disconnect-Database } catch { }
					}
					Remove-Item -Path $effectivePath -Recurse -Force
					Write-Host "  Deleted: $effectivePath" -ForegroundColor Green
				}
				else {
					Write-Host '  Assessment cancelled.' -ForegroundColor DarkGray
					return
				}
				Write-Host ''
			}
		}

		$invokeParams = @{ Path = $effectivePath; Days = $Days }
		if ($ShowLog)   { $invokeParams['ShowLog'] = $true }
		if ($Resume)    { $invokeParams['Resume'] = $true }
		if ($RunPillar) { $invokeParams['Pillar'] = $RunPillar }
		if ($RunTests)  { $invokeParams['Tests'] = $RunTests }

		$desc = if ($Resume) { 'Resuming previous assessment' }
		elseif ($RunTests)   { "Running tests: $($RunTests -join ', ')" }
		elseif ($RunPillar)  { "Running $RunPillar pillar" }
		else                 { 'Running full assessment' }

		Write-Host "`n── $($desc) ──`n" -ForegroundColor DarkCyan
		Write-Host "  Output : $effectivePath" -ForegroundColor Gray
		Write-Host "  Days   : $Days" -ForegroundColor Gray
		if ($RunPillar) { Write-Host "  Pillar : $RunPillar" -ForegroundColor Gray }
		if ($RunTests)  { Write-Host "  Tests  : $($RunTests -join ', ')" -ForegroundColor Gray }
		Write-Host ''

		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		try {
			Invoke-ZtAssessment @invokeParams
			$sw.Stop()
			Write-Host ''
			Write-Host "  Assessment completed in $([math]::Round($sw.Elapsed.TotalMinutes, 1)) minutes." -ForegroundColor Green
			Write-Host "  Report: $((Resolve-Path $effectivePath -ErrorAction SilentlyContinue) ?? $effectivePath)" -ForegroundColor Green
		}
		catch [System.Management.Automation.PipelineStoppedException] {
			$sw.Stop()
			Write-Host ''
			Write-Host "  Assessment was interrupted after $([math]::Round($sw.Elapsed.TotalMinutes, 1)) minutes." -ForegroundColor Yellow
			Write-Host '  Resume: Start-ZtAssessment -Action Resume' -ForegroundColor Cyan
		}
		catch {
			$sw.Stop()
			Write-Host ''
			Write-Host "  Assessment failed after $([math]::Round($sw.Elapsed.TotalMinutes, 1)) minutes: $_" -ForegroundColor Red
			if (Test-Path (Join-Path $effectivePath $script:ZtExportDirName $script:ZtConfigFileName)) {
				Write-Host '  Resume: Start-ZtAssessment -Action Resume' -ForegroundColor Cyan
			}
		}
	}

	function Step-ZtaDeleteResults {
		$effectivePath = Get-ZtaEffectivePath
		Write-Host "`n── Delete All Reports and Test Results ──`n" -ForegroundColor DarkCyan
		if (-not (Test-Path $effectivePath)) {
			Write-Host "  No report folder found at: $effectivePath" -ForegroundColor Yellow
			return
		}
		$items = Get-ChildItem -Path $effectivePath -Recurse -ErrorAction SilentlyContinue
		$fileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
		$sizeMB = [math]::Round(($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum / 1MB, 1)

		# Show database info if present
		$dbFiles = @($items | Where-Object { $_.Name -eq $script:ZtDbFileName })
		$dbSizeMB = 0
		if ($dbFiles.Count -gt 0) {
			$dbSizeMB = [math]::Round(($dbFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
		}

		Write-Host "  Path  : $effectivePath" -ForegroundColor Gray
		Write-Host "  Files : $fileCount   Size : $sizeMB MB" -ForegroundColor Gray
		if ($dbFiles.Count -gt 0) {
			Write-Host "  DB    : $($dbFiles.Count) database file(s), $dbSizeMB MB" -ForegroundColor Gray
		}
		$confirm = Read-Host '  Delete? (Y/N) [N]'
		if ($confirm.Trim().ToUpper() -eq 'Y') {
			# Close any open module-managed database connection before deleting
			if ($script:_DatabaseConnection) {
				try {
					Write-Host "  Closing open database connection..." -ForegroundColor DarkGray
					Disconnect-Database
				}
				catch {
					Write-PSFMessage "Failed to close DB before deletion: $_" -Level Debug
				}
			}
			Remove-Item -Path $effectivePath -Recurse -Force
			Write-Host "  Deleted: $effectivePath" -ForegroundColor Green
		}
	}

	function Step-ZtaDisconnect {
		Write-Host "`n── Disconnecting ──`n" -ForegroundColor DarkCyan
		try {
			$null = Disconnect-ZtAssessment -IncludeCleanup
			Write-Host '  Disconnected from all services.' -ForegroundColor Green
		}
		catch {
			Write-Host "  Disconnect issue: $_" -ForegroundColor Yellow
		}
	}

	function Step-ZtaViewReport {
		$effectivePath = Get-ZtaEffectivePath
		$htmlReportPath = Join-Path -Path $effectivePath -ChildPath $script:ZtReportFileName
		if (-not (Test-Path $htmlReportPath)) {
			Write-Host '  No report found for current tenant.' -ForegroundColor Yellow
			Write-Host '  Tip: Use [T] to browse reports from all tenants.' -ForegroundColor DarkGray
			return
		}
		Write-Host "`n── Opening Report ──`n" -ForegroundColor Cyan
		Open-ZtReport -Path $htmlReportPath -ServeHttp
	}

	# ── Menu ─────────────────────────────────────────────────────────────────

	function Show-ZtaMenu {
		$conn = Get-ZtConnectionState
		$effectivePath = Get-ZtaEffectivePath

		Write-Host ''
		if ($env:ZT_BANNER_SHOWN -ne '1') { Show-ZtBanner }

		if ($conn.IsConnected) {
			Step-ZtaStatus
		}
		else {
			$svcSummary = Get-ZtaServiceSummary
			$tokenCache = Get-ZtTokenCacheEnabled
			$svcLine = "Not connected  |  Available: $($svcSummary.Available -join ', ')"
			if ($svcSummary.Constrained.Count -gt 0) {
				$svcLine += "  (limited: $(($svcSummary.Constrained | ForEach-Object { $_.Name }) -join ', '))"
			}
			Write-Host "  $svcLine  |  TokenCache: $(if ($tokenCache) { 'On' } else { 'Off' })  |  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip'))" -ForegroundColor DarkGray
		}
		Write-Host ''

		$hasReport = Test-Path (Join-Path $effectivePath $script:ZtReportFileName)

		if (-not $conn.IsConnected) {
			Write-Host '  [1]  Connect to tenant' -ForegroundColor White
			Write-Host '  [2]  List available tests' -ForegroundColor DarkGray
			Write-Host ''
			Write-Host '  ── Report ──' -ForegroundColor DarkCyan
			if ($hasReport) {
				Write-Host '  [V]  View last assessment report' -ForegroundColor White
			}
			else {
				Write-Host '  [V]  View last assessment report' -ForegroundColor DarkGray
			}
			Write-Host '  [T]  Browse all tenant reports' -ForegroundColor White
			Write-Host ''
			Write-Host '  ── Manage ──' -ForegroundColor DarkCyan
			Write-Host '  [U]  Update required modules' -ForegroundColor White
		}
		else {
			Write-Host '  ── Assessment ──' -ForegroundColor DarkCyan
			Write-Host '  [2]  List available tests' -ForegroundColor White
			Write-Host '  [3]  Run FULL assessment (all pillars)' -ForegroundColor White
			Write-Host '  [4]  Run a specific PILLAR' -ForegroundColor White
			Write-Host '  [5]  Run specific TEST(s) by ID' -ForegroundColor White
			if (Test-ZtResumeAvailable -Path $effectivePath) {
				Write-Host '  [6]  Resume previous assessment' -ForegroundColor White
			}
			else {
				Write-Host '  [6]  Resume previous assessment' -ForegroundColor DarkGray
			}
			Write-Host ''
			Write-Host '  ── Report ──' -ForegroundColor DarkCyan
			if ($hasReport) {
				Write-Host '  [V]  View last assessment report' -ForegroundColor White
			}
			else {
				Write-Host '  [V]  View last assessment report' -ForegroundColor DarkGray
			}
			Write-Host '  [T]  Browse all tenant reports' -ForegroundColor White
			Write-Host ''
			Write-Host '  ── Manage ──' -ForegroundColor DarkCyan
			Write-Host '  [S]  Connection status & permissions' -ForegroundColor White
			Write-Host '  [U]  Update required modules' -ForegroundColor White
			Write-Host '  [9]  Delete test results' -ForegroundColor White
			Write-Host '  [D]  Disconnect' -ForegroundColor White
		}
		Write-Host '  [Q]  Quit' -ForegroundColor White
		Write-Host ''
	}

	function Invoke-ZtaInteractiveMenu {
		# Helper: connection guard used by most menu actions
		function Assert-ZtaConnected {
			$conn = Get-ZtConnectionState
			if (-not $conn.IsConnected) {
				Write-Host '  Connect first with [1].' -ForegroundColor Yellow
			}
			$conn.IsConnected
		}

		while ($true) {
			Show-ZtaMenu
			$choice = Read-Host 'Select an option'
			switch ($choice.Trim().ToUpper()) {
				'1' { Step-ZtaConnect }
				'2' {
					if (Assert-ZtaConnected) { $Pillar = $null; Step-ZtaListTests }
				}
				'3' {
					if (Assert-ZtaConnected) { Step-ZtaRunAssessment }
				}
				'4' {
					if (Assert-ZtaConnected) {
						$p = Read-Host 'Which pillar? (Identity/Devices/Network/Data)'
						if ($p -in 'Identity', 'Devices', 'Network', 'Data') { Step-ZtaRunAssessment -RunPillar $p }
						else { Write-Host "  Invalid pillar: $p" -ForegroundColor Red }
					}
				}
				'5' {
					if (Assert-ZtaConnected) {
						$ids = Read-Host 'Enter test ID(s), comma-separated'
						$testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
						if ($testIds) { Step-ZtaRunAssessment -RunTests $testIds }
						else { Write-Host '  No test IDs entered.' -ForegroundColor Red }
					}
				}
				'6' {
					if (-not (Test-ZtResumeAvailable -Path (Get-ZtaEffectivePath))) {
						Write-Host '  No resumable assessment found.' -ForegroundColor Yellow
					}
					elseif (Assert-ZtaConnected) { Step-ZtaRunAssessment -Resume }
				}
				'V' { Step-ZtaViewReport }
				'T' { Step-ZtaListReports }
				'S' {
					if (Assert-ZtaConnected) { Step-ZtaStatus }
				}
				'9' { Step-ZtaDeleteResults }
				'U' {
					Write-Host "`n── Update Required Modules ──`n" -ForegroundColor DarkCyan
					$script:_ztaDependencyFixAttempted = $false
					# Check for issues first
					$classification = Get-ZtServiceClassification
					$platformServices = @($classification | Where-Object { $_.Available } | ForEach-Object { $_.Name })
					$hasIssues = $false
					if ($platformServices) {
						$resolved = Resolve-ZtServiceRequiredModule -Service $platformServices
						$issues = @($resolved.Errors | Where-Object {
							$_.ErrorMessage -match 'below the required minimum|does not match required version|cannot be found'
						})
						$hasIssues = $issues.Count -gt 0
					}
					if ($hasIssues) {
						Step-ZtaVerifyDependencies
					}
					else {
						Write-Host '  All module dependencies look good.' -ForegroundColor Green
						$answer = Read-Host '  Force re-download anyway? (Y/N) [N]'
						if ($answer.Trim().ToUpper() -eq 'Y') {
							Update-ZtRequiredModule -Confirm:$false
						}
					}
				}
				'D' {
					if (Assert-ZtaConnected) { Step-ZtaDisconnect }
				}
				'Q' { Write-Host '  Bye!' -ForegroundColor Cyan; return }
				default { Write-Host "  Invalid option: $choice" -ForegroundColor Red }
			}
			Write-Host ''
		}
	}

	# ── Entry point ──────────────────────────────────────────────────────────

	# Check dependency versions early — before menu or action — so the user gets
	# a clear prompt instead of a cryptic error during Connect-ZtAssessment.
	Step-ZtaVerifyDependencies

	if ($Action) {
		if ($env:ZT_BANNER_SHOWN -ne '1') { Show-ZtBanner }
		switch ($Action) {
			'Connect'      { Step-ZtaConnect }
			'RunAll'       { Step-ZtaRunAssessment }
			'RunPillar' {
				if (-not $Pillar) {
					Write-Host 'ERROR: -Pillar is required with -Action RunPillar' -ForegroundColor Red
					return
				}
				Step-ZtaRunAssessment -RunPillar $Pillar
			}
			'RunTests' {
				if (-not $Tests) {
					Write-Host 'ERROR: -Tests is required with -Action RunTests' -ForegroundColor Red
					return
				}
				Step-ZtaRunAssessment -RunTests $Tests
			}
			'ListTests' {
				if (-not (Get-ZtConnectionState).IsConnected) {
					Write-Host 'Not connected. Run Start-ZtAssessment -Action Connect first.' -ForegroundColor Yellow
					return
				}
				Step-ZtaListTests
			}
			'Status'         { Step-ZtaStatus }
			'Resume'         { Step-ZtaRunAssessment -Resume }
			'Disconnect'     { Step-ZtaDisconnect }
			'DeleteResults'  { Step-ZtaDeleteResults }
			'ListReports'    { Step-ZtaListReports }
		}
	}
	else {
		Invoke-ZtaInteractiveMenu
	}
}
