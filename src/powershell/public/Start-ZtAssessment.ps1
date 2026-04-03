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

		[ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePointOnline')]
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
		Write-Host "`n── Connecting to Tenant ──`n" -ForegroundColor Yellow

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

	function Step-ZtaStatus {
		Write-Host "`n── Connection Status ──`n" -ForegroundColor Yellow
		$conn = Get-ZtConnectionState
		if ($conn.IsConnected) {
			Write-Host "  Account   : $($conn.Account)" -ForegroundColor Gray
			Write-Host "  Tenant    : $($conn.Tenant)" -ForegroundColor Gray
			Write-Host "  Services  : $($conn.Services -join ', ')" -ForegroundColor Gray
			if ($conn.ScopesValid) {
				Write-Host '  Scopes    : All required scopes present' -ForegroundColor Green
			}
			else {
				Write-Host "  Missing   : $($conn.MissingScopes -join ', ')" -ForegroundColor Red
			}
		}
		else {
			Write-Host '  Not connected to Microsoft Graph.' -ForegroundColor Yellow
		}
	}

	function Step-ZtaListTests {
		Write-Host "`n── Available Tests ──`n" -ForegroundColor Yellow
		$listParams = @{}
		if ($Pillar) { $listParams['Pillar'] = $Pillar }

		$allTests = Get-ZtTest @listParams
		if (-not $allTests) { Write-Host '  No tests found.' -ForegroundColor Yellow; return }

		$windowsOnly = @('AipService', 'SharePointOnline')
		$grouped = $allTests | Group-Object Pillar | Sort-Object Name
		$skipped = 0
		foreach ($g in $grouped) {
			Write-Host "`n  $($g.Name) ($($g.Count) tests)" -ForegroundColor Cyan
			foreach ($t in ($g.Group | Sort-Object TestID)) {
				$svc = if ($t.Service) { "[$(($t.Service) -join ',')]" } else { '' }
				$wOnly = -not $IsWindows -and $t.Service -and ($t.Service | Where-Object { $_ -in $windowsOnly })
				if ($wOnly) {
					Write-Host "    $($t.TestID)  $($t.Title)  $svc  (Windows only)" -ForegroundColor DarkGray
					$skipped++
				}
				else {
					Write-Host "    $($t.TestID)  $($t.Title)  $svc" -ForegroundColor Gray
				}
			}
		}
		$available = $allTests.Count - $skipped
		Write-Host "`n  Total: $available / $($allTests.Count) tests available" -ForegroundColor Green
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

		Write-Host "`n── $($desc) ──`n" -ForegroundColor Yellow
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
		Write-Host "`n── Delete Test Results ──`n" -ForegroundColor Yellow
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
		Write-Host "`n── Disconnecting ──`n" -ForegroundColor Yellow
		try {
			$null = Disconnect-ZtAssessment -IncludeCleanup
			Write-Host '  Disconnected from all services.' -ForegroundColor Green
		}
		catch {
			Write-Host "  Disconnect issue: $_" -ForegroundColor Yellow
		}
	}

	# ── Menu ─────────────────────────────────────────────────────────────────

	function Show-ZtaMenu {
		$conn = Get-ZtConnectionState

		Write-Host ''
		Show-ZtBanner

		if ($conn.IsConnected) {
			Write-Host "  Connected: $($conn.Account) | Tenant: $($conn.Tenant)" -ForegroundColor Green
			Write-Host "  Services : $($conn.Services -join ', ')" -ForegroundColor Gray
		}
		else {
			Write-Host '  Not connected' -ForegroundColor DarkGray
		}
		Write-Host ''

		if (-not $conn.IsConnected) {
			Write-Host '  [1]  Connect to tenant' -ForegroundColor White
		}
		else {
			Write-Host '  ── Assessment ──' -ForegroundColor DarkCyan
			Write-Host '  [2]  List available tests' -ForegroundColor White
			Write-Host '  [3]  Run FULL assessment (all pillars)' -ForegroundColor White
			Write-Host '  [4]  Run a specific PILLAR' -ForegroundColor White
			Write-Host '  [5]  Run specific TEST(s) by ID' -ForegroundColor White
			Write-Host '  [6]  Resume previous assessment' -ForegroundColor White
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
					if ((Get-ZtConnectionState).IsConnected) { $Pillar = $null; Step-ZtaListTests }
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
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
					if ((Get-ZtConnectionState).IsConnected) { Step-ZtaRunAssessment -Resume }
					else { Write-Host '  Connect first with [1].' -ForegroundColor Yellow }
				}
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
		Show-ZtBanner
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
