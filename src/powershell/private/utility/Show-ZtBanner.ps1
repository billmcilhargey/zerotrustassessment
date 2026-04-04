function Show-ZtBanner {
	<#
	.SYNOPSIS
		Displays the Zero Trust Assessment banner.

	.DESCRIPTION
		Writes the standard Zero Trust Assessment banner to the host.
		Used by Invoke-ZtAssessment, Start-ZtAssessment, and the developer test runner (Invoke-ZtDev.ps1)
		to ensure a single consistent banner definition.
	#>
	[CmdletBinding()]
	param (
		# Optional version string (e.g. 'v2.1.8'). When omitted,
		# read from the loaded module or the manifest on disk.
		[string]$Version,

		# When set, omit the bottom border so the caller can continue the box.
		[switch]$Open
	)

	if (-not $Version) {
		$mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
		if ($mod) {
			$Version = "v$($mod.Version)"
		}
		else {
			# Fallback: read from the manifest (works when dot-sourced before import).
			$manifestPath = Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'ZeroTrustAssessment.psd1'
			if (Test-Path $manifestPath) {
				try {
					$data = Import-PowerShellDataFile $manifestPath -ErrorAction Stop
					$Version = "v$($data.ModuleVersion)"
				} catch { $Version = 'v2' }
			}
			else { $Version = 'v2' }
		}
	}

	$boxWidth = 77
	$plainTitle = "Microsoft Zero Trust Assessment $Version"
	$titlePadTotal = $boxWidth - $plainTitle.Length
	$titlePadLeft = [math]::Floor($titlePadTotal / 2)
	$titlePadRight = $titlePadTotal - $titlePadLeft
	$titleLine = "║$(' ' * $titlePadLeft)${plainTitle}$(' ' * $titlePadRight)║"

	$subtitleText = 'Comprehensive security posture evaluation for your Microsoft 365 tenant'
	$subtitlePadTotal = $boxWidth - $subtitleText.Length
	$subtitlePadLeft = [math]::Floor($subtitlePadTotal / 2)
	$subtitlePadRight = $subtitlePadTotal - $subtitlePadLeft
	$subtitleLine = "║$(' ' * $subtitlePadLeft)$subtitleText$(' ' * $subtitlePadRight)║"

	$topBottom = "═" * $boxWidth
	$emptyLine = "║$(' ' * $boxWidth)║"

	$banner = @"
╔$topBottom╗
$titleLine
$emptyLine
$subtitleLine
"@

	if (-not $Open) {
		$banner += "`n╚$topBottom╝"
	}

	Write-Host $banner -ForegroundColor Cyan
	if (-not $Open) { Write-Host }
}
