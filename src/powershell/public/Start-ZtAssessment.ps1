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
			'Status', 'Resume', 'Disconnect', 'DeleteResults')]
		[string]
		$Action,

		[ValidateSet('Identity', 'Devices', 'Network', 'Data')]
		[string]
		$Pillar,

		[string[]]
		$Tests,

		[string]
		$Path = './ZeroTrustReport',

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
		if ($UseDeviceCode) { return $true }
		$cfgVal = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseDeviceCode' -Fallback $false
		if ($cfgVal) { return $true }
		$env = Test-ZtHeadlessEnvironment
		if ($env.IsCodespaces) {
			Write-Host '  Codespaces/container detected — using device code auth automatically.' -ForegroundColor Yellow
			return $true
		}
		if ($env.IsHeadless) {
			Write-Host '  No display detected — using device code auth automatically.' -ForegroundColor Yellow
			return $true
		}
		return $false
	}

	# ── Steps ────────────────────────────────────────────────────────────────

	function Step-ZtaConnect {
		# Early-out: if already connected (in-memory) with valid context, skip
		$conn = Get-ZtConnectionState
		if ($conn.IsConnected -and $conn.ScopesValid) {
			Write-Host "`n── Already Connected ──`n" -ForegroundColor DarkCyan
			Write-Host "  ✅ $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
			Write-Host "     Services: $($conn.Services -join ', ')" -ForegroundColor DarkGray
			return
		}

		# Try silent restore from token cache before prompting
		if (Restore-ZtCachedConnection) {
			$conn = Get-ZtConnectionState
			Write-Host "`n── Restored from Cache ──`n" -ForegroundColor DarkCyan
			Write-Host "  ✅ $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
			Write-Host "     Services: $($conn.Services -join ', ')" -ForegroundColor DarkGray
			return
		}

		Write-Host "`n── Connecting to Tenant ──`n" -ForegroundColor DarkCyan

		$connectParams = @{}
		if (Get-ZtaEffectiveDeviceCode) { $connectParams['UseDeviceCode'] = $true }
		$tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
		if ($tokenCache) { $connectParams['UseTokenCache'] = $true }
		if ($TenantId)   { $connectParams['TenantId'] = $TenantId }
		if ($Service -and $Service -ne 'All') { $connectParams['Service'] = $Service }

		Write-Host "  Connecting..." -ForegroundColor Gray
		try {
			Connect-ZtAssessment @connectParams
			Write-Host '  Connected successfully.' -ForegroundColor Green
		}
		catch {
			Write-Host "  Connection failed: $_" -ForegroundColor Red
			Write-Host '  Tips:' -ForegroundColor Yellow
			Write-Host '    - Use -UseDeviceCode for remote/container sessions' -ForegroundColor White
			Write-Host '    - Ensure you have Global Reader or Global Administrator role' -ForegroundColor White
		}
	}

	function Get-ZtaServiceSummary {
		# Expand configured services and determine platform availability
		$configured = if ($Service -contains 'All') {
			@($script:AllowedServices)
		} else { @($Service) }
		$available = @($configured | Where-Object { $IsWindows -or $_ -notin $script:WindowsOnlyServices })
		$unavailable = @($configured | Where-Object { -not $IsWindows -and $_ -in $script:WindowsOnlyServices })
		[PSCustomObject]@{
			Configured  = $configured
			Available   = $available
			Unavailable = $unavailable
		}
	}

	function Step-ZtaStatus {
		Write-Host "`n── Connection Status ──`n" -ForegroundColor DarkCyan
		$conn = Get-ZtConnectionState
		$svcSummary = Get-ZtaServiceSummary
		$tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
		if ($conn.IsConnected) {
			Write-Host "  Account   : $($conn.Account)" -ForegroundColor Gray
			Write-Host "  Tenant    : $($conn.Tenant)" -ForegroundColor Gray
			Write-Host "  Connected : $($conn.Services -join ', ')" -ForegroundColor Gray
			Write-Host "  Available : $($svcSummary.Available -join ', ')" -ForegroundColor Gray
			if ($svcSummary.Unavailable.Count -gt 0) {
				Write-Host "  Unavailable: $($svcSummary.Unavailable -join ', ') (Windows only)" -ForegroundColor DarkGray
			}
			Write-Host "  TokenCache: $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
			Write-Host "  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip')) (Skip = hide, Warn = show as failed)" -ForegroundColor Gray
			if ($conn.ScopesValid) {
				Write-Host '  Scopes    : All required scopes present' -ForegroundColor Green
			}
			else {
				Write-Host "  Missing   : $($conn.MissingScopes -join ', ')" -ForegroundColor Red
			}
		}
		else {
			Write-Host '  Not connected to Microsoft Graph.' -ForegroundColor Yellow
			Write-Host "  Available : $($svcSummary.Available -join ', ')" -ForegroundColor Gray
			if ($svcSummary.Unavailable.Count -gt 0) {
				Write-Host "  Unavailable: $($svcSummary.Unavailable -join ', ') (Windows only)" -ForegroundColor DarkGray
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

		$grouped = $allTests | Group-Object Pillar | Sort-Object Name
		$skipped = 0
		foreach ($g in $grouped) {
			Write-Host "`n  ── $($g.Name) ($($g.Count) tests) ──" -ForegroundColor Magenta
			foreach ($t in ($g.Group | Sort-Object TestID)) {
				$svc = if ($t.Service) { "[$(($t.Service) -join ',')]" } else { '' }
				$wOnly = -not $IsWindows -and $t.Service -and ($t.Service | Where-Object { $_ -in $script:WindowsOnlyServices })
				if ($wOnly) {
					Write-Host "    SKIP  $($t.TestID)  $($t.Title)  $svc  (Windows only)" -ForegroundColor DarkGray
					$skipped++
				}
				else {
					Write-Host "          $($t.TestID)  $($t.Title)  $svc" -ForegroundColor Gray
				}
			}
		}
		$available = $allTests.Count - $skipped
		Write-Host ""
		Write-Host "  Available : $available" -ForegroundColor Green
		if ($skipped -gt 0) {
			Write-Host "  Skipped   : $skipped" -ForegroundColor Yellow
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

		# Offer to delete previous results (unless resuming)
		if (-not $Resume -and (Test-Path $Path)) {
			$items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
			if ($items.Count -gt 0) {
				Write-Host "  Previous results found at: $Path" -ForegroundColor Yellow
				$confirm = Read-Host '  Delete all contents? (Y/N) [N]'
				if ($confirm.Trim().ToUpper() -eq 'Y') {
					Remove-Item -Path $Path -Recurse -Force
					Write-Host "  Deleted: $Path" -ForegroundColor Green
				}
				else {
					Write-Host '  Assessment cancelled.' -ForegroundColor DarkGray
					return
				}
				Write-Host ''
			}
		}

		$invokeParams = @{ Path = $Path; Days = $Days }
		if ($ShowLog)   { $invokeParams['ShowLog'] = $true }
		if ($Resume)    { $invokeParams['Resume'] = $true }
		if ($RunPillar) { $invokeParams['Pillar'] = $RunPillar }
		if ($RunTests)  { $invokeParams['Tests'] = $RunTests }

		$desc = if ($Resume) { 'Resuming previous assessment' }
		elseif ($RunTests)   { "Running tests: $($RunTests -join ', ')" }
		elseif ($RunPillar)  { "Running $RunPillar pillar" }
		else                 { 'Running full assessment' }

		Write-Host "`n── $($desc) ──`n" -ForegroundColor DarkCyan
		Write-Host "  Output : $Path" -ForegroundColor Gray
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
			Write-Host "  Report: $((Resolve-Path $Path -ErrorAction SilentlyContinue) ?? $Path)" -ForegroundColor Green
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
			if (Test-Path (Join-Path $Path 'zt-export/ztConfig.json')) {
				Write-Host '  Resume: Start-ZtAssessment -Action Resume' -ForegroundColor Cyan
			}
		}
	}

	function Step-ZtaDeleteResults {
		Write-Host "`n── Delete All Reports and Test Results ──`n" -ForegroundColor DarkCyan
		if (-not (Test-Path $Path)) {
			Write-Host "  No report folder found at: $Path" -ForegroundColor Yellow
			return
		}
		$items = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue
		$fileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
		$sizeMB = [math]::Round(($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
		Write-Host "  Path  : $Path" -ForegroundColor Gray
		Write-Host "  Files : $fileCount   Size : $sizeMB MB" -ForegroundColor Gray
		$confirm = Read-Host '  Delete? (Y/N) [N]'
		if ($confirm.Trim().ToUpper() -eq 'Y') {
			Remove-Item -Path $Path -Recurse -Force
			Write-Host "  Deleted: $Path" -ForegroundColor Green
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
		$htmlReportPath = Join-Path -Path $Path -ChildPath 'ZeroTrustAssessmentReport.html'
		if (-not (Test-Path $htmlReportPath)) {
			Write-Host '  No report found.' -ForegroundColor Yellow
			return
		}
		Write-Host "`n── Opening Report ──`n" -ForegroundColor Cyan
		Open-ZtReport -Path $htmlReportPath
	}

	# ── Menu ─────────────────────────────────────────────────────────────────

	function Show-ZtaMenu {
		$conn = Get-ZtConnectionState

		Write-Host ''
		if ($env:ZT_BANNER_SHOWN -ne '1') { Show-ZtBanner }

		if ($conn.IsConnected) {
			Write-Host "  Connected: $($conn.Account) | Tenant: $($conn.Tenant)" -ForegroundColor Green
			$svcSummary = Get-ZtaServiceSummary
			$tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
			$svcLine = $conn.Services -join ', '
			if ($svcSummary.Unavailable.Count -gt 0) {
				$svcLine += "  (unavailable: $($svcSummary.Unavailable -join ', '))"
			}
			Write-Host "  Services : $svcLine  |  TokenCache: $(if ($tokenCache) { 'On' } else { 'Off' })  |  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip'))" -ForegroundColor Gray
		}
		else {
			$svcSummary = Get-ZtaServiceSummary
			$tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
			$svcLine = "Not connected  |  Available: $($svcSummary.Available -join ', ')"
			if ($svcSummary.Unavailable.Count -gt 0) {
				$svcLine += "  (unavailable: $($svcSummary.Unavailable -join ', '))"
			}
			Write-Host "  $svcLine  |  TokenCache: $(if ($tokenCache) { 'On' } else { 'Off' })  |  Unlicensed: $((Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip'))" -ForegroundColor DarkGray
		}
		Write-Host ''

		$hasReport = Test-Path (Join-Path $Path 'ZeroTrustAssessmentReport.html')

		if (-not $conn.IsConnected) {
			Write-Host '  [1]  Connect to tenant' -ForegroundColor White
			Write-Host '  [2]  List available tests' -ForegroundColor White
			Write-Host ''
			Write-Host '  ── Report ──' -ForegroundColor DarkCyan
			if ($hasReport) {
				Write-Host '  [V]  View last assessment report' -ForegroundColor White
			}
			else {
				Write-Host '  [V]  View last assessment report' -ForegroundColor DarkGray
			}
		}
		else {
			Write-Host '  ── Assessment ──' -ForegroundColor DarkCyan
			Write-Host '  [2]  List available tests' -ForegroundColor White
			Write-Host '  [3]  Run FULL assessment (all pillars)' -ForegroundColor White
			Write-Host '  [4]  Run a specific PILLAR' -ForegroundColor White
			Write-Host '  [5]  Run specific TEST(s) by ID' -ForegroundColor White
			if (Test-ZtResumeAvailable -Path $Path) {
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
			Write-Host ''
			Write-Host '  ── Manage ──' -ForegroundColor DarkCyan
			Write-Host '  [S]  Connection status & permissions' -ForegroundColor White
			Write-Host '  [9]  Delete test results' -ForegroundColor White
			Write-Host '  [D]  Disconnect' -ForegroundColor White
		}
		Write-Host '  [Q]  Quit' -ForegroundColor White
		Write-Host ''
	}

	function Invoke-ZtaInteractiveMenu {
		while ($true) {
			Show-ZtaMenu
			$choice = Read-Host 'Select an option'
			switch ($choice.Trim().ToUpper()) {
				'1' { Step-ZtaConnect; Step-ZtaStatus }
				'2' {
					$Pillar = $null; Step-ZtaListTests
				}
				'3' {
					if ((Get-ZtConnectionState).IsConnected) { Step-ZtaRunAssessment }
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
				'4' {
					if ((Get-ZtConnectionState).IsConnected) {
						$p = Read-Host 'Which pillar? (Identity/Devices/Network/Data)'
						if ($p -in 'Identity', 'Devices', 'Network', 'Data') { Step-ZtaRunAssessment -RunPillar $p }
						else { Write-Host "  Invalid pillar: $p" -ForegroundColor Red }
					}
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
				'5' {
					if ((Get-ZtConnectionState).IsConnected) {
						$ids = Read-Host 'Enter test ID(s), comma-separated'
						$testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
						if ($testIds) { Step-ZtaRunAssessment -RunTests $testIds }
						else { Write-Host '  No test IDs entered.' -ForegroundColor Red }
					}
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
				'6' {
					if (-not (Test-ZtResumeAvailable -Path $Path)) {
						Write-Host '  No resumable assessment found.' -ForegroundColor Yellow
					}
					elseif ((Get-ZtConnectionState).IsConnected) { Step-ZtaRunAssessment -Resume }
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
				'V' { Step-ZtaViewReport }
				'S' {
					if ((Get-ZtConnectionState).IsConnected) { Step-ZtaStatus }
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
				'9' { Step-ZtaDeleteResults }
				'D' {
					if ((Get-ZtConnectionState).IsConnected) { Step-ZtaDisconnect }
					else { Write-Host '  Not connected.' -ForegroundColor Yellow }
				}
				'Q' { Write-Host '  Bye!' -ForegroundColor Cyan; return }
				default { Write-Host "  Invalid option: $choice" -ForegroundColor Red }
			}
			Write-Host ''
		}
	}

	# ── Entry point ──────────────────────────────────────────────────────────

	if ($Action) {
		if ($env:ZT_BANNER_SHOWN -ne '1') { Show-ZtBanner }
		switch ($Action) {
			'Connect'      { Step-ZtaConnect; Step-ZtaStatus }
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
			'ListTests'      { Step-ZtaListTests }
			'Status'         { Step-ZtaStatus }
			'Resume'         { Step-ZtaRunAssessment -Resume }
			'Disconnect'     { Step-ZtaDisconnect }
			'DeleteResults'  { Step-ZtaDeleteResults }
		}
	}
	else {
		Invoke-ZtaInteractiveMenu
	}
}
