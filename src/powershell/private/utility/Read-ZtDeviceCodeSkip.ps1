function Read-ZtDeviceCodeSkip {
	<#
	.SYNOPSIS
		Prompts the user to skip or continue device code authentication for a service.

	.DESCRIPTION
		Displays a timed prompt before the blocking device code sign-in flow begins.
		The user can press [S] to skip the service or any other key to continue immediately.
		If no key is pressed within the configured timeout, authentication proceeds automatically.

		The timeout is controlled by the PSFConfig value 'ZeroTrustAssessment.Connection.DeviceCodeTimeout'
		(default 30 seconds). Set to 0 to disable the prompt entirely.

	.PARAMETER ServiceName
		The display name of the service being authenticated (e.g. 'Graph', 'Azure').

	.OUTPUTS
		[bool] $true if the user chose to skip; $false to continue with authentication.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[string]$ServiceName
	)

	$timeout = [int](Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.DeviceCodeTimeout' -Fallback 30)

	if ($timeout -le 0) { return $false }

	try {
		Write-Host ("   Press [S] to skip {0} or any key to continue (auto-continues in {1}s)..." -f $ServiceName, $timeout) -ForegroundColor Yellow
		$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

		while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq [ConsoleKey]::S) {
					Write-Host ("   ⏭️  Skipping {0} authentication." -f $ServiceName) -ForegroundColor DarkGray
					return $true
				}
				# Any other key = continue immediately
				return $false
			}
			Start-Sleep -Milliseconds 200
		}

		# Timeout expired — auto-continue
		Write-Host ("   Continuing with {0} authentication..." -f $ServiceName) -ForegroundColor DarkGray
		return $false
	}
	catch {
		# Non-interactive console — cannot read keys, just proceed
		Write-PSFMessage -Message "Cannot read console input; proceeding with authentication." -Level Debug
		return $false
	}
}
