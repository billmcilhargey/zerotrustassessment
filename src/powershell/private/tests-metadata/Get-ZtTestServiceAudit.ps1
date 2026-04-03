function Get-ZtTestServiceAudit {
	<#
	.SYNOPSIS
		Compares declared Service metadata with auto-detected services for each test file.

	.DESCRIPTION
		Scans all test files under the specified path, reads the [ZtTest(Service = (...))]
		attribute from each, and compares it against services auto-detected by
		Get-ZtRequiredServiceFromContent. Returns an object per test with both sets of
		services and whether they differ ("IsStale").

	.PARAMETER TestsPath
		Path to the tests directory to scan. Defaults to the module's tests folder.

	.EXAMPLE
		PS> Get-ZtTestServiceAudit | Where-Object IsStale

		Returns only tests whose declared Service metadata differs from what the code actually uses.
	#>
	[CmdletBinding()]
	[OutputType('ZeroTrustAssessment.TestServiceAudit')]
	param (
		[string]
		$TestsPath = (Join-Path $script:ModuleRoot 'tests')
	)

	$files = Get-ChildItem -Path $TestsPath -Filter '*.ps1' -File -Recurse
	foreach ($file in $files) {
		$content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
		$detected = Get-ZtRequiredServiceFromContent -Content $content

		# Parse current [ZtTest(Service = (...))] from the file
		$declared = @()
		$ztTestRegex = '\[ZtTest\((?<body>[\s\S]*?)\)\]'
		$m = [regex]::Match($content, $ztTestRegex)
		if (-not $m.Success) { continue }  # No [ZtTest] attribute — skip non-test files

		$body = $m.Groups['body'].Value
		if ($body -match "Service\s*=\s*\(([^)]*)\)") {
			$declared = $Matches[1] -replace "'" , '' -split ',' |
				ForEach-Object { $_.Trim() } |
				Where-Object { $_ }
		}

		# Extract test ID from filename
		$testId = ''
		if ($file.Name -match 'Test-Assessment\.(\d+)\.ps1') {
			$testId = $Matches[1]
		}

		[PSCustomObject]@{
			PSTypeName       = 'ZeroTrustAssessment.TestServiceAudit'
			TestId           = $testId
			FileName         = $file.Name
			FilePath         = $file.FullName
			DeclaredServices = [string[]]$declared
			DetectedServices = [string[]]$detected
			IsStale          = ($declared -join ',') -ne ($detected -join ',')
			Content          = $content
		}
	}
}
