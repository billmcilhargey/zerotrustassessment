function Test-ZtServiceCoverage {
	<#
	.SYNOPSIS
		Compares the services required by the tests against the currently connected services.

	.DESCRIPTION
		Loads the test metadata (from [ZtTest] attributes) for the requested pillar
		and tests, collects the union of all Service values, and compares them
		against $script:ConnectedService.

		Returns a result object showing which services are needed, which are
		connected, and which are missing. Also estimates how many tests will be
		skipped due to each missing service.

	.PARAMETER Pillar
		The pillar to evaluate. Defaults to 'All'.

	.PARAMETER Tests
		Optional list of specific test IDs. When specified, only those tests are
		evaluated for service requirements.

	.EXAMPLE
		PS> Test-ZtServiceCoverage

		Returns coverage analysis for all tests against the current connections.

	.EXAMPLE
		PS> Test-ZtServiceCoverage -Pillar Identity

		Returns coverage analysis for Identity pillar tests only.
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param (
		[string]
		$Pillar = 'All',

		[string[]]
		$Tests
	)

	# Get all tests that would run for this pillar/test-set
	$getTestParams = @{}
	if ($Tests) { $getTestParams.Tests = $Tests }
	if ($Pillar -and $Pillar -ne 'All') { $getTestParams.Pillar = $Pillar }
	$allTests = Get-ZtTest @getTestParams

	# Build a map of service → test count
	$serviceTestMap = @{}
	foreach ($svc in $script:AllowedServices) {
		$serviceTestMap[$svc] = @($allTests | Where-Object { $_.Service -contains $svc }).Count
	}

	$neededServices = @($serviceTestMap.GetEnumerator() | Where-Object { $_.Value -gt 0 } | ForEach-Object { $_.Key })
	$connectedServices = @($script:ConnectedService)
	$missingServices = @($neededServices | Where-Object { $connectedServices -notcontains $_ })
	$skippedTestCount = 0
	$serviceGaps = [System.Collections.Generic.List[PSCustomObject]]::new()

	foreach ($svc in $missingServices) {
		$count = $serviceTestMap[$svc]
		$skippedTestCount += $count
		$serviceGaps.Add([PSCustomObject]@{
			Service         = $svc
			TestsAffected   = $count
			IsWindowsOnly   = $svc -in $script:WindowsOnlyServices
		})
	}

	[PSCustomObject]@{
		TotalTests        = $allTests.Count
		NeededServices    = [string[]]$neededServices
		ConnectedServices = [string[]]$connectedServices
		MissingServices   = [string[]]$missingServices
		ServiceGaps       = $serviceGaps.ToArray()
		SkippedTestCount  = $skippedTestCount
		FullCoverage      = $missingServices.Count -eq 0
	}
}
