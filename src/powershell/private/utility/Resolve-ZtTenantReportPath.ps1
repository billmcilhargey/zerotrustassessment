function Resolve-ZtTenantReportPath {
	<#
	.SYNOPSIS
		Returns a tenant-specific report path when using the default output location.

	.DESCRIPTION
		Appends the connected tenant ID to the base path (e.g. ./ZeroTrustReport/{tenantId}).
		Returns the base path unchanged when not connected or when the caller
		explicitly provided a custom path.

	.PARAMETER BasePath
		The base report output path.

	.PARAMETER IsDefaultPath
		True when the caller is using the default path (not user-specified).
		Tenant-specific pathing only applies when this is true.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(Mandatory)]
		[string]
		$BasePath,

		[bool]
		$IsDefaultPath = $true
	)

	if (-not $IsDefaultPath) {
		return $BasePath
	}

	$tenantId = $null
	try {
		$ctx = Get-MgContext -ErrorAction Ignore
		if ($ctx) { $tenantId = $ctx.TenantId }
	}
	catch { }

	if (-not $tenantId) {
		return $BasePath
	}

	Join-Path -Path $BasePath -ChildPath $tenantId
}
