function Restore-ZtCachedConnection {
	<#
	.SYNOPSIS
		Attempts to silently restore a Microsoft Graph connection from cached tokens.

	.DESCRIPTION
		When token caching is enabled, tries to reconnect to Microsoft Graph without
		user interaction. If a valid cached token exists (from a previous interactive
		browser login, device code flow, or any other delegated authentication),
		the connection is restored silently. If no cached token is available or
		the token is expired, this function returns $false without prompting.

		This is the single shared implementation for silent cache restoration,
		used by Connect-ZtAssessment, Start-ZtAssessment, and Invoke-ZtDev.ps1.

	.OUTPUTS
		[bool] $true if connection was restored from cache, $false otherwise.

	.EXAMPLE
		PS> if (Restore-ZtCachedConnection) { "Connected from cache" }
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	$tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true
	if (-not $tokenCache) { return $false }

	# Already connected?
	$ctx = Get-MgContext -ErrorAction Ignore
	if ($null -ne $ctx) {
		# Validate the existing context has the required scopes
		try {
			$valid = Test-ZtContext -ErrorAction Stop
			if ($valid) { return $true }
		}
		catch { }
		# Context exists but invalid — disconnect so a fresh connect can be attempted
		$null = Disconnect-MgGraph -ErrorAction Ignore
		return $false
	}

	# Try silent connect from cached tokens (no user interaction).
	# In headless/container environments, Connect-MgGraph without -UseDeviceCode
	# may fall back to an interactive device code prompt that appears to hang.
	# Only attempt if we're in a windowed environment (not container/SSH).
	$isHeadless = ($env:CODESPACES -eq 'true') -or ($env:REMOTE_CONTAINERS -eq 'true') -or (-not $IsWindows -and -not $env:DISPLAY)
	if ($isHeadless) {
		Write-PSFMessage -Message "Skipping silent Connect-MgGraph in headless environment (would trigger interactive auth)." -Level Debug
		return $false
	}

	try {
		$silentParams = @{
			NoWelcome = $true
			Scopes    = (Get-ZtGraphScope)
		}
		$null = Connect-MgGraph @silentParams -ErrorAction Stop
		$ctx = Get-MgContext -ErrorAction Ignore
		if ($null -ne $ctx) {
			try {
				$valid = Test-ZtContext -ErrorAction Stop
				if ($valid) {
					Add-ZtConnectedService -Service 'Graph'
					return $true
				}
			}
			catch { }
			$null = Disconnect-MgGraph -ErrorAction Ignore
		}
	}
	catch {
		Write-PSFMessage -Message "Silent cache restore failed: $_" -Level Debug
	}

	return $false
}
