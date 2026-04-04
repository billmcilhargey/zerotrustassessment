function Get-ZtServiceClassification {
	<#
	.SYNOPSIS
		Returns the canonical list of services with their platform availability and auth constraints.

	.DESCRIPTION
		Single source of truth for which services exist, which require Windows,
		and which don't support device code flow. Used by the dev runner banner,
		Start-ZtAssessment, Connect-ZtAssessment, and any UI that displays
		service availability.

	.OUTPUTS
		[PSCustomObject[]] Array of objects with Name, Available, Reason, ModuleVersion properties.

	.EXAMPLE
		PS> Get-ZtServiceClassification | Where-Object { $_.Available }
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param ()

	# Load service-to-module mapping from manifest
	$manifestPath = Join-Path $PSScriptRoot '..' '..' '..' 'ZeroTrustAssessment.psd1'
	$serviceModuleMap = @{}
	if (Test-Path $manifestPath) {
		try {
			$manifest = Import-PowerShellDataFile $manifestPath
			$serviceModuleMap = $manifest.PrivateData.ServiceToRequiredModuleMap
		}
		catch { }
	}

	foreach ($svc in $script:AllowedServices) {
		$available = $true
		$reason = $null

		if (-not $IsWindows -and $svc -in $script:WindowsOnlyServices) {
			$available = $false
			$reason = 'Requires Windows'
		}
		elseif ($svc -in $script:NoDeviceCodeServices) {
			$reason = 'No device code flow support'
		}

		# Get version of the primary module for this service
		$moduleVersion = $null
		$primaryModule = if ($serviceModuleMap[$svc]) { $serviceModuleMap[$svc][0] } else { $null }
		if ($primaryModule) {
			$mod = Get-Module -Name $primaryModule -ListAvailable -ErrorAction Ignore | Sort-Object Version -Descending | Select-Object -First 1
			if ($mod) { $moduleVersion = $mod.Version.ToString() }
		}

		[PSCustomObject]@{
			Name           = $svc
			Available      = $available
			WindowsOnly    = $svc -in $script:WindowsOnlyServices
			NoDeviceCode   = $svc -in $script:NoDeviceCodeServices
			Reason         = $reason
			ModuleName     = $primaryModule
			ModuleVersion  = $moduleVersion
		}
	}
}
