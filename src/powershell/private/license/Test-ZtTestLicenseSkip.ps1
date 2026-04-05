function Test-ZtTestLicenseSkip {
	<#
	.SYNOPSIS
		Checks whether a test should be skipped due to licensing requirements.

	.DESCRIPTION
		Evaluates a test's CompatibleLicense and MinimumLicense attributes against
		the tenant's active licenses. Uses a tier cache to avoid repeated API calls.

	.PARAMETER Test
		A test object from Get-ZtTest with MinimumLicense and CompatibleLicense properties.

	.PARAMETER TierCache
		Hashtable mapping tier names (e.g. 'P2') to booleans from Get-ZtLicenseSkipSummary.

	.OUTPUTS
		$null if the test should run, or a string reason if it should be skipped.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[object]$Test,

		[Parameter(Mandatory)]
		[hashtable]$TierCache
	)

	# CompatibleLicense takes precedence
	if ($Test.CompatibleLicense.Count -gt 0) {
		if (-not (Test-ZtLicense -CompatibleLicense $Test.CompatibleLicense)) {
			return 'Missing required license'
		}
		return $null
	}

	if (-not $Test.MinimumLicense) { return $null }

	$minLicenses = @($Test.MinimumLicense)
	foreach ($tier in $minLicenses) {
		if (-not $script:ZtLicenseTierToProduct.ContainsKey($tier)) { return $null } # Unknown tier → don't skip
		if ($TierCache[$tier]) { return $null }
	}

	return "Requires $($minLicenses -join '/') license"
}
