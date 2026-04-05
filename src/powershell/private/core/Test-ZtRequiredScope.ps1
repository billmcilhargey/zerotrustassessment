function Test-ZtRequiredScope {
	<#
	.SYNOPSIS
		Checks whether the current Graph session has all the required scopes for a test.

	.DESCRIPTION
		Compares the RequiredScopes declared on a test against the scopes present
		in the current MgGraph context. Returns $true when all scopes are granted
		or when the test declares no specific scope requirements.

		Used by Invoke-ZtTests to pre-filter tests before execution, and can be
		called by individual tests at runtime for an early-exit guard.

	.PARAMETER RequiredScopes
		One or more Microsoft Graph permission scope names (e.g. 'Policy.Read.All').

	.PARAMETER MissingScopes
		An optional [ref] variable that will be populated with the list of missing scopes.

	.EXAMPLE
		PS> Test-ZtRequiredScope -RequiredScopes 'Policy.Read.All','RoleManagement.Read.All'
		True

	.EXAMPLE
		PS> $missing = $null
		PS> if (-not (Test-ZtRequiredScope -RequiredScopes 'NetworkAccess.Read.All' -MissingScopes ([ref]$missing))) {
		PS>     Write-Warning "Missing scopes: $($missing -join ', ')"
		PS> }
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory = $true)]
		[AllowEmptyCollection()]
		[string[]]$RequiredScopes,

		[ref]$MissingScopes
	)

	if (-not $RequiredScopes -or $RequiredScopes.Count -eq 0) {
		return $true
	}

	$ctx = Get-MgContext -ErrorAction Ignore
	if (-not $ctx) {
		if ($MissingScopes) { $MissingScopes.Value = @($RequiredScopes) }
		return $false
	}

	$currentScopes = @($ctx.Scopes)
	$missing = @($RequiredScopes | Where-Object { $currentScopes -notcontains $_ })

	if ($MissingScopes) { $MissingScopes.Value = $missing }

	return ($missing.Count -eq 0)
}
