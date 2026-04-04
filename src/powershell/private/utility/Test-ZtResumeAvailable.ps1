function Test-ZtResumeAvailable {
	<#
	.SYNOPSIS
		Checks whether a previous assessment can be resumed.

	.DESCRIPTION
		Returns $true if a zt-export/ztConfig.json exists and the assessment
		has not been marked as completed (AssessmentCompleted property).

	.PARAMETER Path
		The assessment output folder (contains zt-export/).
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[string]$Path
	)

	$exportPath = Join-Path $Path 'zt-export'
	$configPath = Join-Path $exportPath 'ztConfig.json'

	if (-not (Test-Path $configPath)) {
		return $false
	}

	$isCompleted = Get-ZtConfig -ExportPath $exportPath -Property AssessmentCompleted
	return -not $isCompleted
}
