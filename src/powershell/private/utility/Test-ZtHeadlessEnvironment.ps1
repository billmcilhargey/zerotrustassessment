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

	[PSCustomObject]@{
		IsCodespaces = $isCodespaces
		IsHeadless   = $isHeadless
		IsNonWindows = -not $IsWindows
	}
}
