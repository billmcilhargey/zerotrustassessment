function Get-ZtPnPClientId {
	<#
	.SYNOPSIS
		Resolves the Entra ID app (client) ID to use for PnP PowerShell (SharePoint) connections.

	.DESCRIPTION
		The PnP Management Shell multi-tenant app (31359c7f-bd7e-475c-86db-fdb8c937548e) was
		permanently deleted in September 2024. A custom app registration is now mandatory.
		See https://github.com/pnp/powershell/issues/4250

		Resolution order (first non-empty wins):
		  1. -ClientId parameter passed to Connect-ZtAssessment
		  2. $env:ENTRAID_APP_ID
		  3. $env:ENTRAID_CLIENT_ID
		  4. $env:AZURE_CLIENT_ID

		This matches the precedence documented by PnP PowerShell:
		https://pnp.github.io/powershell/articles/defaultclientid.html

	.PARAMETER ClientId
		An explicit client ID passed by the caller (e.g. from Connect-ZtAssessment -ClientId).

	.OUTPUTS
		[string] The resolved client ID, or an empty string if none is configured.

	.EXAMPLE
		$pnpClientId = Get-ZtPnPClientId -ClientId $ClientId
		if (-not $pnpClientId) { Write-Warning "No PnP app registration configured." }
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[AllowEmptyString()]
		[string] $ClientId
	)

	if ($ClientId)              { return $ClientId }
	if ($env:ENTRAID_APP_ID)    { return $env:ENTRAID_APP_ID }
	if ($env:ENTRAID_CLIENT_ID) { return $env:ENTRAID_CLIENT_ID }
	if ($env:AZURE_CLIENT_ID)   { return $env:AZURE_CLIENT_ID }

	return ''
}
