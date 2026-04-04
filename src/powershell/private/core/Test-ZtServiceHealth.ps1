function Test-ZtServiceHealth {
	<#
	.SYNOPSIS
		Validates that tracked service connections are still alive.

	.DESCRIPTION
		For each service in $script:ConnectedService, performs a lightweight health
		check to verify the session is still active (token not expired, remote
		session not dropped, etc.).

		Returns a list of service health results. Services that fail the check
		are automatically removed from $script:ConnectedService so downstream
		code (Invoke-ZtTests) skips tests for dead sessions instead of failing.

	.EXAMPLE
		PS> Test-ZtServiceHealth

		Checks all connected services and returns health status for each.
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param ()

	$results = [System.Collections.Generic.List[PSCustomObject]]::new()

	foreach ($svc in @($script:ConnectedService)) {
		$healthy = $false
		$detail = $null

		switch ($svc) {
			'Graph' {
				try {
					$ctx = Get-MgContext -ErrorAction Stop
					$healthy = $null -ne $ctx
					if (-not $healthy) { $detail = 'Get-MgContext returned null' }
				}
				catch { $detail = $_.Exception.Message }
			}
			'Azure' {
				try {
					$azCtx = Get-AzContext -ErrorAction Stop
					$healthy = $null -ne $azCtx
					if (-not $healthy) { $detail = 'Get-AzContext returned null' }
				}
				catch { $detail = $_.Exception.Message }
			}
			'ExchangeOnline' {
				try {
					$connInfo = Get-ConnectionInformation -ErrorAction Stop
					$healthy = ($null -ne $connInfo -and $connInfo.State -eq 'Connected')
					if (-not $healthy) { $detail = 'Exchange Online session not connected' }
				}
				catch { $detail = $_.Exception.Message }
			}
			'SecurityCompliance' {
				try {
					# S&C shares the EXO module; check for an EOP session
					$connInfo = Get-ConnectionInformation -ErrorAction Stop
					$eopSession = $connInfo | Where-Object { $_.IsEopSession -eq $true -and $_.State -eq 'Connected' }
					$healthy = $null -ne $eopSession
					if (-not $healthy) { $detail = 'Security & Compliance session not found or disconnected' }
				}
				catch { $detail = $_.Exception.Message }
			}
			'AipService' {
				# AipService has no lightweight "am I connected?" check.
				# Trust the tracked state unless the module isn't loaded.
				$healthy = $null -ne (Get-Command Connect-AipService -ErrorAction Ignore)
				if (-not $healthy) { $detail = 'AipService module not loaded' }
			}
			'SharePoint' {
				# SPO also lacks a quick health-check cmdlet.
				$healthy = $null -ne (Get-Command Get-SPOSite -ErrorAction Ignore)
				if (-not $healthy) { $detail = 'SharePoint module not loaded' }
			}
			default {
				$healthy = $true
			}
		}

		if (-not $healthy) {
			Write-PSFMessage -Level Warning -Message "Service '$svc' health check failed: $detail"
			Remove-ZtConnectedService -Service $svc
		}

		$results.Add([PSCustomObject]@{
			Service = $svc
			Healthy = $healthy
			Detail  = $detail
		})
	}

	$results
}
