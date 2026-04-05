function Get-ZtActiveServicePlanId {
	<#
	.SYNOPSIS
		Returns active service plan IDs from the tenant's subscribed SKUs.

	.DESCRIPTION
		Fetches subscribedSkus from Graph, filters to Enabled/Warning capability status,
		expands service plans, and returns their IDs. Caches the result in
		$script:__ZtLicensePlanIds to avoid repeated API calls.

	.PARAMETER Force
		Bypass the cache and re-query the Graph API.

	.OUTPUTS
		[string[]] Array of service plan GUIDs.
	#>
	[CmdletBinding()]
	[OutputType([string[]])]
	param(
		[switch]$Force
	)

	if (-not $Force -and $script:__ZtLicensePlanIds) {
		return $script:__ZtLicensePlanIds
	}

	$script:__ZtLicensePlanIds = Invoke-ZtGraphRequest -RelativeUri 'subscribedSkus' |
		Where-Object { $_.capabilityStatus -in 'Enabled', 'Warning' } |
		Select-Object -ExpandProperty servicePlans |
		Select-Object -ExpandProperty servicePlanId

	return $script:__ZtLicensePlanIds
}
