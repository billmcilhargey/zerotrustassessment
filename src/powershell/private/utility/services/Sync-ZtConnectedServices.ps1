function Sync-ZtConnectedServices {
	<#
	.SYNOPSIS
		Synchronizes $script:ConnectedService with actual live session state.

	.DESCRIPTION
		Performs bi-directional sync between the ConnectedService tracker and
		real service sessions:

		1. Discovers active sessions that are missing from the tracker
		   (e.g. removed by transient errors like DLL conflicts) and re-adds them.
		2. Detects tracked services whose sessions are no longer alive and removes them.

		This is the single authoritative check for service connectivity. Called by
		Get-ZtConnectionState and Invoke-ZtTests to ensure accurate state.

	.EXAMPLE
		PS> Sync-ZtConnectedServices
	#>
	[CmdletBinding()]
	param ()

	# ── Check Graph ──
	try {
		$ctx = Get-MgContext -ErrorAction Ignore
		if ($null -ne $ctx -and $script:ConnectedService -notcontains 'Graph') {
			Write-PSFMessage -Message 'Graph context is active but missing from ConnectedService — re-adding.' -Level Warning
			Add-ZtConnectedService -Service 'Graph'
		}
		elseif ($null -eq $ctx -and $script:ConnectedService -contains 'Graph') {
			Write-PSFMessage -Message 'Graph context is gone — removing from ConnectedService.' -Level Warning
			Remove-ZtConnectedService -Service 'Graph'
		}
	}
	catch { <# non-fatal #> }

	# ── Check Azure ──
	try {
		$azCtx = Get-AzContext -ErrorAction Ignore
		if ($null -ne $azCtx -and $script:ConnectedService -notcontains 'Azure') {
			Write-PSFMessage -Message 'Azure context is active but missing from ConnectedService — re-adding.' -Level Warning
			Add-ZtConnectedService -Service 'Azure'
		}
		elseif ($null -eq $azCtx -and $script:ConnectedService -contains 'Azure') {
			Write-PSFMessage -Message 'Azure context is gone — removing from ConnectedService.' -Level Warning
			Remove-ZtConnectedService -Service 'Azure'
		}
	}
	catch { <# non-fatal #> }

	# ── Check Exchange Online ──
	try {
		if (Get-Command Get-ConnectionInformation -ErrorAction Ignore) {
			$exoConn = Get-ConnectionInformation -ErrorAction Ignore
			$exoAlive = $null -ne $exoConn -and ($exoConn | Where-Object { -not $_.IsEopSession -and $_.State -eq 'Connected' })
			if ($exoAlive -and $script:ConnectedService -notcontains 'ExchangeOnline') {
				Write-PSFMessage -Message 'Exchange Online session is active but missing from ConnectedService — re-adding.' -Level Warning
				Add-ZtConnectedService -Service 'ExchangeOnline'
			}
			elseif (-not $exoAlive -and $script:ConnectedService -contains 'ExchangeOnline') {
				Write-PSFMessage -Message 'Exchange Online session is gone — removing from ConnectedService.' -Level Warning
				Remove-ZtConnectedService -Service 'ExchangeOnline'
			}

			# ── Check Security & Compliance (shares EXO module) ──
			$eopAlive = $null -ne $exoConn -and ($exoConn | Where-Object { $_.IsEopSession -eq $true -and $_.State -eq 'Connected' })
			if ($eopAlive -and $script:ConnectedService -notcontains 'SecurityCompliance') {
				Write-PSFMessage -Message 'Security & Compliance session is active but missing from ConnectedService — re-adding.' -Level Warning
				Add-ZtConnectedService -Service 'SecurityCompliance'
			}
			elseif (-not $eopAlive -and $script:ConnectedService -contains 'SecurityCompliance') {
				Write-PSFMessage -Message 'Security & Compliance session is gone — removing from ConnectedService.' -Level Warning
				Remove-ZtConnectedService -Service 'SecurityCompliance'
			}
		}
	}
	catch { <# non-fatal #> }
}
