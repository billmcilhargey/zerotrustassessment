function Show-ZtPermissionStatus {
	<#
	.SYNOPSIS
		Displays a formatted permissions status block to the console.

	.DESCRIPTION
		Queries the current Microsoft Graph context and compares granted scopes
		against required scopes. Writes a consistent, color-coded permissions
		display. Used by Connect-ZtAssessment, Start-ZtAssessment (via
		Step-ZtaStatus), and Invoke-ZtDev.ps1 (via Step-CheckPermissions).
	#>
	[CmdletBinding()]
	param()

	try {
		$context = Get-MgContext -ErrorAction Stop
		if (-not $context) {
			Write-Host ''
			Write-Host '  ── Permissions ──' -ForegroundColor DarkCyan
			Write-Host '  Not connected to Microsoft Graph.' -ForegroundColor Yellow
			return
		}

		$requiredScopes = Get-ZtGraphScope
		$granted = @($requiredScopes | Where-Object { $context.Scopes -contains $_ })
		$missing = @($requiredScopes | Where-Object { $context.Scopes -notcontains $_ })

		Write-Host '' -ForegroundColor DarkCyan
		Write-Host '  ── Permissions ──' -ForegroundColor DarkCyan

		$summaryColor = if ($missing.Count -eq 0) { 'Green' } else { 'Yellow' }
		Write-Host "  Graph     : $($granted.Count) / $($requiredScopes.Count) scopes granted" -ForegroundColor $summaryColor

		foreach ($scope in ($requiredScopes | Sort-Object)) {
			if ($context.Scopes -contains $scope) {
				Write-Host "    ✅ $scope" -ForegroundColor Green
			}
			else {
				Write-Host "    ❌ $scope" -ForegroundColor Red
			}
		}

		if ($missing.Count -gt 0) {
			Write-Host ''
			Write-Host "  ⚠️  $($missing.Count) missing scope(s). Reconnect to request the required permissions." -ForegroundColor Yellow
		}
	}
	catch {
		Write-Host ''
		Write-Host '  ── Permissions ──' -ForegroundColor DarkCyan
		Write-Host "  Unable to check permissions: $($_.Exception.Message)" -ForegroundColor DarkGray
	}
}
