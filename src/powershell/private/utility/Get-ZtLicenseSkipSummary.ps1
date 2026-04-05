function Get-ZtLicenseSkipSummary {
	<#
	.SYNOPSIS
		Counts tests that will be skipped due to licensing gaps.

	.DESCRIPTION
		Iterates through test metadata and checks MinimumLicense / CompatibleLicense
		requirements against the tenant's active licenses. Returns a summary object
		with per-tier skip counts.

		Uses the canonical $script:ZtLicenseTierToProduct mapping from variables.ps1.

	.PARAMETER Tests
		Array of test objects (from Get-ZtTest). If omitted, fetches all tests.

	.OUTPUTS
		[PSCustomObject] with properties:
		  TierCache   - hashtable of tier → bool (cached license checks)
		  SkipsByTier - hashtable of label → count
		  TotalSkipped - int total skipped
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter()]
		[object[]]$Tests
	)

	if (-not $Tests) { $Tests = Get-ZtTest }

	# Build tier cache once
	$tierCache = @{}
	foreach ($kv in $script:ZtLicenseTierToProduct.GetEnumerator()) {
		$tierCache[$kv.Key] = Get-ZtLicense $kv.Value
	}

	$skipsByTier = @{}
	$totalSkipped = 0

	foreach ($test in $Tests) {
		$skipReason = Test-ZtTestLicenseSkip -Test $test -TierCache $tierCache
		if ($skipReason) {
			if (-not $skipsByTier[$skipReason]) { $skipsByTier[$skipReason] = 0 }
			$skipsByTier[$skipReason]++
			$totalSkipped++
		}
	}

	[PSCustomObject]@{
		TierCache    = $tierCache
		SkipsByTier  = $skipsByTier
		TotalSkipped = $totalSkipped
	}
}
