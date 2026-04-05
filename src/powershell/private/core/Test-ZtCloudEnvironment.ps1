function Test-ZtCloudEnvironment {
	<#
	.SYNOPSIS
		Tests whether the current cloud environment is supported for a given operation.

	.DESCRIPTION
		Compares the current cloud environment against a list of supported cloud types.
		Returns $true if the current environment matches any of the supported types,
		or if no restrictions are specified (all environments supported).

		This function is designed to be called from test scripts to standardize
		environment checks, replacing inline `(Get-AzContext).Environment.Name -ne 'AzureCloud'`
		patterns.

		Supported cloud type values:
		  Commercial  — Global/AzureCloud (non-government)
		  GCC         — US Government Community Cloud (shares Global endpoints, .gov domain)
		  GCCHigh     — US Government GCC High (USGov endpoints)
		  DoD         — US Department of Defense (USGovDoD endpoints)
		  China       — China (21Vianet) cloud
		  Germany     — Germany (Microsoft Cloud Deutschland)

		Shorthand groups:
		  Global        — Commercial + GCC (all Global-endpoint tenants)
		  USGovernment  — GCC + GCCHigh + DoD
		  Sovereign     — GCCHigh + DoD + China + Germany

	.PARAMETER SupportedCloudType
		One or more cloud types that the calling test supports.
		If not specified, all environments are considered supported.

	.EXAMPLE
		PS> Test-ZtCloudEnvironment -SupportedCloudType 'Commercial', 'GCC'

		Returns $true if the current environment is Commercial or GCC.

	.EXAMPLE
		PS> if (-not (Test-ZtCloudEnvironment -SupportedCloudType 'Commercial')) {
		>>     Add-ZtTestResultDetail -SkippedBecause NotSupportedEnvironment
		>>     return
		>> }

		Standard pattern to skip a test when the environment is not supported.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param (
		[ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD', 'China', 'Germany', 'Global', 'USGovernment', 'Sovereign')]
		[string[]]
		$SupportedCloudType
	)

	if (-not $SupportedCloudType -or $SupportedCloudType.Count -eq 0) {
		return $true
	}

	# Expand shorthand groups
	$expandedTypes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
	foreach ($type in $SupportedCloudType) {
		switch ($type) {
			'Global' {
				$null = $expandedTypes.Add('Commercial')
				$null = $expandedTypes.Add('GCC')
			}
			'USGovernment' {
				$null = $expandedTypes.Add('GCC')
				$null = $expandedTypes.Add('GCCHigh')
				$null = $expandedTypes.Add('DoD')
			}
			'Sovereign' {
				$null = $expandedTypes.Add('GCCHigh')
				$null = $expandedTypes.Add('DoD')
				$null = $expandedTypes.Add('China')
				$null = $expandedTypes.Add('Germany')
			}
			default {
				$null = $expandedTypes.Add($type)
			}
		}
	}

	$env = Get-ZtCloudEnvironment
	if (-not $env -or $env.CloudType -eq 'Unknown') {
		Write-PSFMessage -Message 'Cloud environment is unknown; allowing test to proceed.' -Level Debug
		return $true
	}

	return $expandedTypes.Contains($env.CloudType)
}
