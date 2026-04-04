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
		IsConnected   = $false
		Account       = $null
		Tenant        = $null
		Services      = @()
		ScopesValid   = $false
		MissingScopes = @()
	}

	try {
		$ctx = Get-MgContext -ErrorAction Ignore
		if ($null -ne $ctx) {
			# If Graph context exists but ConnectedService was reset (e.g. module reimport),
			# re-register Graph so the services list stays accurate.
			if ($script:ConnectedService -notcontains 'Graph') {
				Add-ZtConnectedService -Service 'Graph'
			}

			$state.IsConnected = $true
			$state.Account = $ctx.Account
			$state.Tenant = $ctx.TenantId
			$state.Services = @($script:ConnectedService)

			$required = Get-ZtGraphScope
			$missing = @($required | Where-Object { $ctx.Scopes -notcontains $_ })
			$state.MissingScopes = $missing
			$state.ScopesValid = $missing.Count -eq 0
		}
	}
	catch {
		# Non-fatal — unable to check context
	}

	$state
}
