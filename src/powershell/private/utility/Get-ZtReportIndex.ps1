function Get-ZtReportIndex {
	<#
	.SYNOPSIS
		Lists all existing assessment reports found under a base report directory.

	.DESCRIPTION
		Scans the base report path for tenant-specific subdirectories that contain
		completed assessment reports. Returns objects describing each report with
		tenant ID, report path, export date, and pillar information.

		Supports both the legacy flat layout (report directly in BasePath) and the
		new tenant-organized layout (report in BasePath/{tenantId}/).

	.PARAMETER BasePath
		The base report directory to scan. Default: ./ZeroTrustReport

	.EXAMPLE
		PS> Get-ZtReportIndex -BasePath './ZeroTrustReport'
		Lists all tenant reports found under the base path.
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param (
		[string]
		$BasePath = $script:ZtDefaultReportPath
	)

	$results = [System.Collections.Generic.List[PSCustomObject]]::new()

	if (-not (Test-Path $BasePath)) {
		return $results
	}

	# Helper: build a report entry from a report directory
	$buildEntry = {
		param([string]$ReportDir, [string]$Label)
		$htmlPath = Join-Path $ReportDir $script:ZtReportFileName
		$exportDir = Join-Path $ReportDir $script:ZtExportDirName

		if (-not (Test-Path $htmlPath)) { return $null }

		$tenantId = $null
		$pillar = $null
		$completed = $false
		$lastModified = (Get-Item $htmlPath).LastWriteTime

		if (Test-Path $exportDir) {
			try {
				$config = Get-ZtConfig -ExportPath $exportDir
				$tenantId = $config['TenantID']
				$pillar = $config['Pillar']
				$completed = [bool]$config['AssessmentCompleted']
			}
			catch {
				# Config unreadable — still return the entry
			}
		}

		[PSCustomObject]@{
			TenantId     = $tenantId
			Label        = $Label
			Path         = $ReportDir
			ReportFile   = $htmlPath
			Pillar       = if ($pillar) { $pillar } else { 'Unknown' }
			Completed    = $completed
			LastModified = $lastModified
		}
	}

	# Check for legacy flat layout (report directly in BasePath)
	$legacyHtml = Join-Path $BasePath $script:ZtReportFileName
	if (Test-Path $legacyHtml) {
		$entry = & $buildEntry $BasePath '(legacy/flat)'
		if ($entry) { $results.Add($entry) }
	}

	# Scan subdirectories for tenant-organized reports
	$subDirs = Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue
	foreach ($dir in $subDirs) {
		# Skip the zt-export folder (belongs to legacy layout)
		if ($dir.Name -eq $script:ZtExportDirName) { continue }

		$entry = & $buildEntry $dir.FullName $dir.Name
		if ($entry) { $results.Add($entry) }
	}

	# Sort by most recent first
	$results | Sort-Object -Property LastModified -Descending
}
