function Write-ZtTestSummary {
	<#
	.SYNOPSIS
		Writes a summary table of test execution results to the console.

	.DESCRIPTION
		Collects data from both TestStatistics (execution metrics) and
		TestResultDetail (assessment outcomes) to produce a consolidated
		summary showing counts by status, skip-reason details, warnings,
		errors, and planned test information.

	.PARAMETER LogsPath
		Optional path to the logs folder. If specified, the summary is
		also appended to _progress.log.

	.EXAMPLE
		PS> Write-ZtTestSummary

		Writes the test run summary to the console.
	#>
	[CmdletBinding()]
	param (
		[string]
		$LogsPath
	)

	process {
		# Collect test result details (Passed/Failed/Skipped/Planned from each test's Add-ZtTestResultDetail)
		$resultDetails = @{}
		if ($script:__ZtSession -and $script:__ZtSession.TestResultDetail) {
			$resultDetails = $script:__ZtSession.TestResultDetail.Value
		}

		# Collect execution statistics (Success/Error/TimedOut from Invoke-ZtTest)
		$execStats = @{}
		if ($script:__ZtSession -and $script:__ZtSession.TestStatistics) {
			$execStats = $script:__ZtSession.TestStatistics.Value
		}

		# Build a merged view per test
		$allTestIds = @($resultDetails.Keys) + @($execStats.Keys) | Select-Object -Unique | Sort-Object

		$passed      = [System.Collections.Generic.List[string]]::new()
		$failed      = [System.Collections.Generic.List[string]]::new()
		$skipped     = [System.Collections.Generic.List[string]]::new()
		$timedOut    = [System.Collections.Generic.List[string]]::new()
		$workerError = [System.Collections.Generic.List[string]]::new()
		$planned     = [System.Collections.Generic.List[string]]::new()
		$warnings    = [System.Collections.Generic.List[object]]::new()

		foreach ($testId in $allTestIds) {
			$detail = $resultDetails[$testId]
			$exec   = $execStats[$testId]

			# Determine the final status
			$status = $null

			# Check result detail first (this is the assessment outcome)
			if ($detail) {
				$status = $detail.TestStatus  # Passed, Failed, Skipped, Planned, Investigate
			}

			# Override with execution-level issues if present
			if ($exec) {
				if ($exec.TimedOut) {
					$status = 'TimedOut'
				}
				elseif (-not $exec.Success -and -not $detail) {
					# No result detail was written — test crashed before calling Add-ZtTestResultDetail
					$status = 'Error'
				}
			}

			if (-not $status) { $status = 'Error' }

			switch ($status) {
				'Passed'      { $passed.Add($testId) }
				'Failed'      { $failed.Add($testId) }
				'Skipped'     { $skipped.Add($testId) }
				'TimedOut'    { $timedOut.Add($testId) }
				'Planned'     { $planned.Add($testId) }
				default       { $workerError.Add($testId) }
			}

			# Collect warnings from PSFramework messages
			if ($exec -and $exec.Messages) {
				$warnMessages = $exec.Messages | Where-Object Level -eq 'Warning'
				foreach ($msg in $warnMessages) {
					$title = if ($detail) { $detail.TestTitle } else { '' }
					$warnings.Add([PSCustomObject]@{
						TestID  = $testId
						Title   = $title
						Warning = $msg.Message
					})
				}
			}
		}

		$totalCount = $allTestIds.Count

		# Build the summary output
		$lines = [System.Collections.Generic.List[string]]::new()
		$lines.Add('')
		$lines.Add('─────────────────────────────────────────────────────')
		$lines.Add('  📊 Test Run Summary')
		$lines.Add('─────────────────────────────────────────────────────')
		$lines.Add("  Total tests       : $totalCount")
		$lines.Add("  ✅ Passed          : $($passed.Count)")
		$lines.Add("  ❌ Failed          : $($failed.Count)")
		$lines.Add("  ⏭️  Skipped         : $($skipped.Count)")
		if ($timedOut.Count -gt 0) {
			$lines.Add("  ⏱️  Timed out       : $($timedOut.Count)")
		}
		if ($workerError.Count -gt 0) {
			$lines.Add("  💥 Errors          : $($workerError.Count)")
		}
		if ($planned.Count -gt 0) {
			$lines.Add("  🔜 Planned         : $($planned.Count)")
		}

		# Show errored tests (worker crashes / unhandled exceptions)
		if ($workerError.Count -gt 0) {
			$lines.Add('')
			$lines.Add('  ── Errors ──')
			foreach ($testId in $workerError) {
				$exec = $execStats[$testId]
				$detail = $resultDetails[$testId]
				$title = if ($detail -and $detail.TestTitle) { $detail.TestTitle } else { $null }
				$errMsg = if ($exec -and $exec.Error) { "$($exec.Error)" } else { 'No error details captured' }
				if ($errMsg.Length -gt 100) { $errMsg = $errMsg.Substring(0, 100) + '...' }
				$label = if ($title) { "$testId - $title" } else { $testId }
				$lines.Add("    💥 $label")
				$lines.Add("       $errMsg")
			}
		}

		# Show timed out tests
		if ($timedOut.Count -gt 0) {
			$lines.Add('')
			$lines.Add('  ── Timed Out ──')
			foreach ($testId in $timedOut) {
				$detail = $resultDetails[$testId]
				$title = if ($detail) { $detail.TestTitle } else { 'Unknown' }
				$exec = $execStats[$testId]
				$duration = if ($exec -and $exec.Duration) { " ($([math]::Round($exec.Duration.TotalSeconds, 1))s)" } else { '' }
				$lines.Add("    ⏱️  $testId - $title$duration")
			}
		}

		# Show warnings (non-fatal issues during execution)
		if ($warnings.Count -gt 0) {
			$lines.Add('')
			$lines.Add("  ── Warnings ($($warnings.Count)) ──")
			$shownWarnings = $warnings | Select-Object -First 15
			foreach ($w in $shownWarnings) {
				$warnMsg = $w.Warning
				if ($warnMsg.Length -gt 100) { $warnMsg = $warnMsg.Substring(0, 100) + '...' }
				$lines.Add("    ⚠️  $($w.TestID) - $warnMsg")
			}
			if ($warnings.Count -gt 15) {
				$lines.Add("    ... and $($warnings.Count - 15) more warnings (see test logs)")
			}
		}

		# Show skip reasons breakdown with descriptions
		if ($skipped.Count -gt 0) {
			$skipReasons = @{}
			foreach ($testId in $skipped) {
				$detail = $resultDetails[$testId]
				$reason = if ($detail -and $detail.TestSkipped) { $detail.TestSkipped } else { 'Unknown' }
				if (-not $skipReasons[$reason]) { $skipReasons[$reason] = [System.Collections.Generic.List[string]]::new() }
				$skipReasons[$reason].Add($testId)
			}
			$lines.Add('')
			$lines.Add('  ── Skipped ──')
			foreach ($reason in $skipReasons.Keys | Sort-Object) {
				$count = $skipReasons[$reason].Count
				$description = switch ($reason) {
					'NotConnectedToService'        { 'Service not connected' }
					'NoCompatibleLicenseFound'     { 'Missing required license' }
					'NotApplicable'                { 'Not applicable to this environment' }
					'NotLicensedEntraIDP1'         { 'Requires Entra ID P1 license' }
					'NotLicensedEntraIDP2'         { 'Requires Entra ID P2 license' }
					'NotLicensedEntraIDGovernance' { 'Requires Entra ID Governance license' }
					'NotLicensedEntraWorkloadID'   { 'Requires Entra Workload ID license' }
					'NotLicensedIntune'            { 'Requires Intune license' }
					'NotConnectedAzure'            { 'Azure connection required' }
					'NotConnectedExchange'         { 'Exchange Online connection required' }
					'NotConnectedSecurityCompliance' { 'Security & Compliance connection required' }
					'NotSupported'                 { 'Platform not supported (e.g. Windows-only cmdlets)' }
					'NotDotGovDomain'              { 'Federal .gov domain required' }
					'NoAzureAccess'                { 'Azure subscription access required' }
					'TimeoutReached'               { 'Report execution timed out' }
					default                        { $reason }
				}
				$lines.Add("    ⏭️  $count  $description ($reason)")
			}
		}

		# Show planned tests with details
		if ($planned.Count -gt 0) {
			$lines.Add('')
			$lines.Add('  ── Planned (Preview) ──')
			foreach ($testId in ($planned | Sort-Object)) {
				$detail = $resultDetails[$testId]
				$title = if ($detail -and $detail.TestTitle) { $detail.TestTitle } else { 'Unknown' }
				$pillar = if ($detail -and $detail.TestPillar) { $detail.TestPillar } else { '' }
				$pillarTag = if ($pillar) { " [$pillar]" } else { '' }
				$lines.Add("    🔜 $testId - $title$pillarTag  (Preview)")
			}
		}

		$lines.Add('─────────────────────────────────────────────────────')
		$lines.Add('')

		# Write to console with colors
		foreach ($line in $lines) {
			$color = 'White'
			if ($line -match '✅') { $color = 'Green' }
			elseif ($line -match '❌') { $color = 'Red' }
			elseif ($line -match '💥') { $color = 'Red' }
			elseif ($line -match '⏱️') { $color = 'Yellow' }
			elseif ($line -match '⚠️') { $color = 'Yellow' }
			elseif ($line -match '⏭️') { $color = 'DarkGray' }
			elseif ($line -match '🔜') { $color = 'Cyan' }
			elseif ($line -match '📊|──') { $color = 'Cyan' }
			Write-Host $line -ForegroundColor $color
		}

		# Write summary to progress log file if available
		if ($LogsPath) {
			try {
				$progressFile = Join-Path $LogsPath '_progress.log'
				$summaryText = "`n" + ($lines -join "`n") + "`n"
				[System.IO.File]::AppendAllText($progressFile, $summaryText)
			}
			catch {
				Write-PSFMessage -Level Warning -Message "Failed to write summary to progress log: {0}" -StringValues $_
			}
		}
	}
}
