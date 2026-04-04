function Get-ZtRequiredServiceFromContent {
	<#
	.SYNOPSIS
		Auto-detect which services a test script uses based on cmdlet patterns.

	.DESCRIPTION
		Scans the text content of a PowerShell test script for cmdlet patterns
		that indicate which services the test depends on (Graph, Azure,
		AipService, ExchangeOnline, SecurityCompliance, SharePoint).

		Returns the detected services in the canonical order defined by the
		module manifest. Defaults to 'Graph' when no patterns match.

	.PARAMETER Content
		The raw text content of a PowerShell script file.

	.EXAMPLE
		PS> $content = Get-Content -Path ./tests/Test-Assessment.21770.ps1 -Raw
		PS> Get-ZtRequiredServiceFromContent -Content $content
		Graph

		Detects that test 21770 uses Graph cmdlets.
	#>
	[CmdletBinding()]
	[OutputType([string[]])]
	param (
		[Parameter(Mandatory)]
		[string]
		$Content
	)

	$services = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

	# Graph
	if ($Content -match '\b(Get|Invoke|Connect|Disconnect)-Mg\w+\b' -or
		$Content -match '\bInvoke-ZtGraphRequest\b' -or
		$Content -match '\bGet-MgContext\b' -or
		$Content -match '\bMicrosoft\s+Graph\b') {
		$null = $services.Add('Graph')
	}
	# Azure (Az.* cmdlets)
	if ($Content -match '\b(Get|Set|New|Remove|Connect|Disconnect|Invoke|Start|Stop)-Az\w+\b') {
		$null = $services.Add('Azure')
	}
	# AIP
	if ($Content -match '\b(Get|Set|New|Remove|Connect|Disconnect)-Aip\w+\b') {
		$null = $services.Add('AipService')
	}
	# Exchange Online
	if ($Content -match '\b(Get|Set|New|Remove|Connect|Disconnect)-(EXO\w+|Exo\w+|ExchangeOnline)\b' -or
		$Content -match '\bConnect-ExchangeOnline\b') {
		$null = $services.Add('ExchangeOnline')
	}
	# Security & Compliance
	if ($Content -match '\bConnect-IPPSSession\b' -or
		$Content -match '\b(Get|Set|New|Remove)-(Label|Dlp\w+|Retention\w+|Case\w+|Compliance\w+)\b') {
		$null = $services.Add('SecurityCompliance')
	}
	# SharePoint (PnP.PowerShell)
	if ($Content -match '\b(Get|Set|New|Remove|Connect|Disconnect)-PnP\w+\b' -or
		$Content -match '\bGet-ZtSharePointTenantSettings\b') {
		$null = $services.Add('SharePoint')
	}

	# Safe default — every test needs Graph at minimum
	if ($services.Count -eq 0) {
		$null = $services.Add('Graph')
	}

	# Return in canonical order
	$ordered = foreach ($s in $script:AllowedServices) {
		if ($services.Contains($s)) { $s }
	}
	[string[]]$ordered
}
