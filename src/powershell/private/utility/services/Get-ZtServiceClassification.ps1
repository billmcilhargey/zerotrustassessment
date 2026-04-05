function Get-ZtServiceClassification {
	<#
	.SYNOPSIS
		Returns the canonical list of services with their platform availability and auth constraints.

	.DESCRIPTION
		Single source of truth for which services exist, which require Windows,
		and which don't support device code flow. Used by the dev runner banner,
		Start-ZtAssessment, Connect-ZtAssessment, and any UI that displays
		service availability.

		When -UseDeviceCode or -UseClientSecret is specified, services that
		don't support those auth methods are marked unavailable.

	.PARAMETER UseDeviceCode
		When set, services in $script:NoDeviceCodeServices will be marked unavailable.

	.PARAMETER UseClientSecret
		When set, services in $script:NoClientSecretServices will be marked unavailable.

	.PARAMETER HasCertificateOrMI
		When set, device-code and client-secret restrictions are bypassed for services
		that support certificate or managed identity auth.

	.OUTPUTS
		[PSCustomObject[]] Array of objects with Name, Available, Reason, ModuleVersion properties.

	.EXAMPLE
		PS> Get-ZtServiceClassification | Where-Object { $_.Available }

	.EXAMPLE
		PS> Get-ZtServiceClassification -UseDeviceCode
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param (
		[switch] $UseDeviceCode,
		[switch] $UseClientSecret,
		[switch] $HasCertificateOrMI
	)

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

		# Config/auth constraints: service stays available (yellow ⚠) with a reason.
		# Only hard platform constraints above set $available = $false (red ✗).
		if ($available -and $svc -in $script:RequiresCustomAppServices) {
			$pnpId = Get-ZtPnPClientId
			if (-not $pnpId) {
				$reason = 'No app registration setup'
			}
		}
		if ($available -and $UseDeviceCode -and -not $HasCertificateOrMI -and $svc -in $script:NoDeviceCodeServices) {
			$reason = 'No device code flow support'
		}
		if ($available -and $UseClientSecret -and -not $HasCertificateOrMI -and $svc -in $script:NoClientSecretServices) {
			$reason = 'No client-secret app-only auth — use certificate or managed identity'
		}

		# Get version of the primary module for this service
		$moduleVersion = $null
		$primaryModule = if ($serviceModuleMap[$svc]) { $serviceModuleMap[$svc][0] } else { $null }
		if ($primaryModule) {
			$mod = Get-Module -Name $primaryModule -ListAvailable -ErrorAction Ignore | Sort-Object Version -Descending | Select-Object -First 1
			if ($mod) { $moduleVersion = $mod.Version.ToString() }
		}

		[PSCustomObject]@{
			Name              = $svc
			Available         = $available
			WindowsOnly       = $svc -in $script:WindowsOnlyServices
			NoDeviceCode      = $svc -in $script:NoDeviceCodeServices
			NoClientSecret    = $svc -in $script:NoClientSecretServices
			RequiresCustomApp = $svc -in $script:RequiresCustomAppServices
			Reason            = $reason
			ModuleName        = $primaryModule
			ModuleVersion     = $moduleVersion
		}
	}
}
