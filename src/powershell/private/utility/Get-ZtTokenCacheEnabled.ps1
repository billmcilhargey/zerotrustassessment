function Get-ZtTokenCacheEnabled {
	<#
	.SYNOPSIS
		Returns whether token caching is enabled.

	.DESCRIPTION
		Reads the ZeroTrustAssessment.Connection.UseTokenCache PSFConfig value.
		Falls back to $true (enabled by default).
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
}
