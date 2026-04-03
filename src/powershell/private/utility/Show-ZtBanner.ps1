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
	param ()

	$mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
	$ver = if ($mod) { "v$($mod.Version)" } else { 'v2' }

	$banner = @"
╔═════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  Microsoft Zero Trust Assessment $ver                  ║
║                                                                             ║
║    Comprehensive security posture evaluation for your Microsoft 365 tenant  ║
╚═════════════════════════════════════════════════════════════════════════════╝
"@

	Write-Host $banner -ForegroundColor Cyan
	Write-Host
}
