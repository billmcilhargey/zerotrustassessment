function Get-ZtEffectiveDeviceCode {
	<#
	.SYNOPSIS
		Determines whether device code authentication should be used.

	.DESCRIPTION
		Single source of truth for the device code decision across the module.
		Checks in order:
		  1. Explicit -UseDeviceCode parameter (via PSFConfig)
		  2. Container / Codespaces environment
		  3. Headless / no-display environment

		Returns $true if device code should be used, $false for interactive browser.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	$cfgVal = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseDeviceCode' -Fallback $false
	if ($cfgVal) { return $true }

	$env = Test-ZtHeadlessEnvironment
	if ($env.IsCodespaces -or $env.IsHeadless) { return $true }

	return $false
}
