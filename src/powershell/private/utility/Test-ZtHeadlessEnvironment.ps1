function Test-ZtHeadlessEnvironment {
	<#
	.SYNOPSIS
		Detects whether the current session is running in a headless or container environment.

	.DESCRIPTION
		Returns a PSCustomObject with boolean flags indicating whether the session is:
		  - Codespaces / dev container
		  - Headless (no display server)
		  - Non-Windows (cannot load Windows-only modules)

		Used by Connect-ZtAssessment to auto-enable device code flow and by
		Start-ZtAssessment for platform notices.

	.EXAMPLE
		PS> Test-ZtHeadlessEnvironment

		IsCodespaces IsHeadless IsNonWindows
		------------ ---------- ------------
		True         True       True
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param ()

	$isCodespaces = ($env:CODESPACES -eq 'true') -or
		($env:REMOTE_CONTAINERS -eq 'true') -or
		($env:DEVCONTAINER -eq 'true') -or
		(Test-Path '/.dockerenv')

	$isHeadless = $false
	if ($IsLinux -or $IsMacOS) {
		$isHeadless = -not $env:DISPLAY -and -not $env:WAYLAND_DISPLAY
	}

	# VS Code dev containers / Codespaces expose $env:BROWSER, which uses
	# VS Code's --openExternal to open URLs on the host machine's browser.
	# When available, device code URLs can be auto-opened for a better UX.
	$canLaunchBrowser = $false
	if ($env:BROWSER -and (Test-Path $env:BROWSER -ErrorAction Ignore)) {
		$canLaunchBrowser = $true
	}
	elseif (-not $isHeadless -and -not $isCodespaces) {
		# Native desktop with a display server
		$canLaunchBrowser = $true
	}

	[PSCustomObject]@{
		IsCodespaces     = $isCodespaces
		IsHeadless       = $isHeadless
		IsNonWindows     = -not $IsWindows
		CanLaunchBrowser = $canLaunchBrowser
	}
}
