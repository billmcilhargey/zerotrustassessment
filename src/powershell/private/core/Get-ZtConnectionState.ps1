function Get-ZtConnectionState {
	<#
	.SYNOPSIS
		Returns a summary of the current connection state for all tracked services.

	.DESCRIPTION
		Inspects the Microsoft Graph context and the module's ConnectedService tracker
		to return a single object with connection status, account, tenant, services,
		and scope validation results.

		Used by Start-ZtAssessment (interactive menu), Invoke-ZtDev.ps1 (dev menu),
		and Test-ZtServicePreflight (pre-flight checks).

	.EXAMPLE
		PS> $state = Get-ZtConnectionState
		PS> if ($state.IsConnected) { "Ready" }
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param ()

	$state = [PSCustomObject]@{
		IsConnected      = $false
		Account          = $null
		Tenant           = $null
		CloudEnvironment = $null
		Services         = @()
		ScopesValid      = $false
		MissingScopes    = @()
	}

	try {
		# Sync tracked services with live session state (re-adds sessions
		# removed by transient errors, removes truly dead sessions).
		Sync-ZtConnectedServices

		$ctx = Get-MgContext -ErrorAction Ignore
		if ($null -ne $ctx) {
			$state.IsConnected = $true
			$state.Account = $ctx.Account
			$state.Tenant = $ctx.TenantId
			$state.CloudEnvironment = Get-ZtCloudEnvironment
			$state.Services = @($script:ConnectedService)

			$required = Get-ZtGraphScope
			$missing = @($required | Where-Object { $ctx.Scopes -notcontains $_ })
			$state.MissingScopes = $missing
			$state.ScopesValid = $missing.Count -eq 0
		}
		elseif ($script:ConnectedService.Count -gt 0) {
			# Non-Graph services connected (e.g. Azure, Exchange) but Graph was skipped
			$state.IsConnected = $true
			$state.Services = @($script:ConnectedService)
			$state.CloudEnvironment = Get-ZtCloudEnvironment

			# Try to get account/tenant from Azure context as fallback
			$azCtx = Get-AzContext -ErrorAction Ignore
			if ($null -ne $azCtx) {
				$state.Account = $azCtx.Account.Id
				$state.Tenant = $azCtx.Tenant.Id
			}
		}
	}
	catch {
		# Non-fatal — unable to check context
	}

	$state
}
