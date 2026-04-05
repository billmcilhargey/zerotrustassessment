function Open-ZtDeviceCodeBrowser {
	<#
	.SYNOPSIS
		Auto-opens the device code login page when a browser is available.

	.DESCRIPTION
		Called immediately before device code authentication (Connect-MgGraph -UseDeviceCode,
		Connect-AzAccount -UseDeviceAuthentication, Connect-ExchangeOnline -Device, etc.).

		In VS Code dev containers / Codespaces the $env:BROWSER helper forwards URLs to the
		host machine's default browser. This function detects that capability and pre-opens
		https://microsoft.com/devicelogin so the user only needs to enter the code shown
		in the terminal.

		On headless systems without browser support this function is a no-op.
	#>
	[CmdletBinding()]
	param ()

	$envInfo = Test-ZtHeadlessEnvironment
	if (-not $envInfo.CanLaunchBrowser) { return }

	$url = 'https://microsoft.com/devicelogin'

	try {
		if ($env:BROWSER) {
			Start-Process -FilePath $env:BROWSER -ArgumentList $url -ErrorAction Stop
		}
		elseif ($IsMacOS) {
			Start-Process -FilePath 'open' -ArgumentList $url -ErrorAction Stop
		}
		elseif ($IsLinux) {
			Start-Process -FilePath 'xdg-open' -ArgumentList $url -ErrorAction Stop
		}
		else {
			# Windows — Start-Process handles URLs directly
			Start-Process -FilePath $url -ErrorAction Stop
		}

		Write-Host '   🌐 Opened device code page in your browser.' -ForegroundColor DarkGray
		Write-Host '   Enter the code shown below to authenticate.' -ForegroundColor DarkGray
	}
	catch {
		Write-PSFMessage -Message "Could not auto-open device code page: $_" -Level Debug
		Write-Host "   Open $url in a browser and enter the code shown below." -ForegroundColor DarkGray
	}
}
