function Test-ZtGsaEnabled {
	<#
	.SYNOPSIS
		Returns whether Global Secure Access is activated in the tenant.

	.DESCRIPTION
		Queries networkAccess/forwardingProfiles (beta) and returns $true if at
		least one profile has state = 'enabled'. The result is cached for the
		lifetime of the module session so subsequent calls (from multiple GSA
		tests) don't repeat the API call.

		Use -Force to bypass the cache and re-query.

		The PSFConfig setting 'Assessment.SkipGlobalSecureAccess' can override
		this check. When set to $true, the function always returns $false so
		GSA tests are skipped without querying the API.

	.PARAMETER Force
		Bypass the cached result and re-query the API.

	.EXAMPLE
		PS> if (-not (Test-ZtGsaEnabled)) {
		        Add-ZtTestResultDetail -SkippedBecause NotApplicable
		        return
		    }
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param (
		[switch]$Force
	)

	# User override — skip all GSA tests
	if (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Assessment.SkipGlobalSecureAccess' -Fallback $false) {
		Write-PSFMessage -Message 'Global Secure Access checks skipped by user configuration (Assessment.SkipGlobalSecureAccess = $true).' -Level Verbose
		return $false
	}

	# Return cached result unless forced
	if (-not $Force -and $null -ne $script:__ZtGsaEnabled) {
		return $script:__ZtGsaEnabled
	}

	$enabled = $false
	try {
		$profiles = Invoke-ZtGraphRequest -RelativeUri 'networkAccess/forwardingProfiles' -ApiVersion beta
		if ($profiles -and $profiles.Count -gt 0) {
			$active = @($profiles | Where-Object { $_.state -eq 'enabled' })
			$enabled = $active.Count -gt 0
		}
	}
	catch {
		Write-PSFMessage -Message "Unable to check Global Secure Access status: $_" -Level Warning
		# If the API fails (e.g. no NetworkAccess.Read.All scope), assume not enabled.
		$enabled = $false
	}

	$script:__ZtGsaEnabled = $enabled

	if ($enabled) {
		Write-PSFMessage -Message 'Global Secure Access is enabled (at least one forwarding profile active).' -Level Verbose
	}
	else {
		Write-PSFMessage -Message 'Global Secure Access is not enabled in this tenant.' -Level Verbose
	}

	$enabled
}
