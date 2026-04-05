function Show-ZtLicenseStatus {
	<#
	.SYNOPSIS
		Displays a formatted license status block to the console.

	.DESCRIPTION
		Queries license tiers for EntraID, Intune, and WorkloadID and writes
		a consistent, color-coded status display. Used by Connect-ZtAssessment,
		Start-ZtAssessment, and anywhere a license summary is needed.
	#>
	[CmdletBinding()]
	param()

	try {
		$entraIdTier = Get-ZtLicenseInformation -Product EntraID
		$intuneTier  = Get-ZtLicenseInformation -Product Intune
		$workloadTier = Get-ZtLicenseInformation -Product EntraWorkloadID

		Write-Host '' -ForegroundColor DarkCyan
		Write-Host '  ── Licensing ──' -ForegroundColor DarkCyan

		$licColor = if ($entraIdTier -in 'P2', 'Governance') { 'Green' }
			elseif ($entraIdTier -eq 'P1') { 'Yellow' }
			else { 'Red' }
		Write-Host "  Entra ID  : $entraIdTier" -ForegroundColor $licColor
		if ($entraIdTier -eq 'Free') {
			Write-Host '  ⚠️  Entra ID Free tier — tests requiring P1, P2, or Governance will be skipped.' -ForegroundColor Yellow
			Write-Host '      Upgrade to Entra ID P2 for full assessment coverage.' -ForegroundColor DarkYellow
		}
		elseif ($entraIdTier -eq 'P1') {
			Write-Host '  ⚠️  Entra ID P1 tier — tests requiring P2 or Governance will be skipped.' -ForegroundColor Yellow
			Write-Host '      Upgrade to Entra ID P2 for full assessment coverage.' -ForegroundColor DarkYellow
		}
		if ($intuneTier)  { Write-Host "  Intune    : $intuneTier" -ForegroundColor Green }
		if ($workloadTier) { Write-Host "  Workload  : $workloadTier" -ForegroundColor Green }
	}
	catch {
		Write-Host '' -ForegroundColor DarkCyan
		Write-Host '  ── Licensing ──' -ForegroundColor DarkCyan
		Write-Host "  Unable to detect licensing: $($_.Exception.Message)" -ForegroundColor DarkGray
	}
}
