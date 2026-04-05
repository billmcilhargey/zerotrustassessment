function Get-ZtCloudEnvironment {
	<#
	.SYNOPSIS
		Detects and returns the current cloud environment (Commercial, GCC, GCC High, DoD, China, Germany).

	.DESCRIPTION
		Auto-detects the cloud environment from the connected Microsoft Graph and Azure contexts.
		Returns a standardized environment object with the cloud type, display name, and
		endpoint information.

		Results are cached in the module session for the duration of the assessment run.
		Use -Force to re-detect.

		The mapping between different SDK environment names is:
		  Graph (Get-MgContext)   Azure (Get-AzContext)    Cloud Type
		  ─────────────────────   ─────────────────────    ──────────
		  Global                  AzureCloud               Commercial
		  USGov                   AzureUSGovernment        USGov (GCC High)
		  USGovDoD                AzureUSGovernment        USGovDoD
		  China                   AzureChinaCloud          China
		  Germany                 AzureGermanCloud         Germany

		Note: GCC (Government Community Cloud) uses the same endpoints as Commercial (Global/AzureCloud)
		and cannot be distinguished by endpoint alone. The function detects GCC by checking
		for .gov domains on the tenant's verified domains.

	.PARAMETER Force
		Re-detect the environment even if a cached result exists.

	.EXAMPLE
		PS> Get-ZtCloudEnvironment

		Returns the detected cloud environment for the current session.

	.EXAMPLE
		PS> (Get-ZtCloudEnvironment).CloudType

		Returns just the cloud type string (e.g. 'Commercial', 'GCC', 'GCCHigh', 'DoD', 'China', 'Germany').

	.EXAMPLE
		PS> (Get-ZtCloudEnvironment).IsGovernment

		Returns $true if the tenant is in any US Government cloud (GCC, GCC High, or DoD).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param (
		[switch]
		$Force
	)

	# Return cached result if available
	if (-not $Force -and $script:__ZtSession.CloudEnvironment) {
		return $script:__ZtSession.CloudEnvironment
	}

	# ── Detect from Graph context ────────────────────────────────────────────
	$mgContext = Get-MgContext -ErrorAction Ignore
	$graphEnvironment = if ($mgContext) { $mgContext.Environment } else { $null }

	# ── Detect from Azure context ────────────────────────────────────────────
	$azContext = Get-AzContext -ErrorAction Ignore
	$azEnvironmentName = if ($azContext) { $azContext.Environment.Name } else { $null }

	# ── Detect from configuration ────────────────────────────────────────────
	$configEnvironment = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.Environment' -Fallback $null

	# ── Resolve cloud type ───────────────────────────────────────────────────
	# Priority: Graph context > Azure context > Configuration
	$cloudType = 'Unknown'
	$displayName = 'Unknown'
	$graphEndpoint = $null
	$azureEndpoint = $null
	$isGovernment = $false
	$isGCC = $false
	$detectedFrom = $null

	if ($graphEnvironment) {
		$detectedFrom = 'GraphContext'
		$mgEnv = Get-MgEnvironment -Name $graphEnvironment -ErrorAction Ignore
		if ($mgEnv) {
			$graphEndpoint = $mgEnv.GraphEndpoint
			$azureEndpoint = $mgEnv.AzureADEndpoint
		}

		switch ($graphEnvironment) {
			'Global' {
				$cloudType = 'Commercial'
				$displayName = 'Commercial (Global)'
			}
			'USGov' {
				$cloudType = 'GCCHigh'
				$displayName = 'US Government GCC High'
				$isGovernment = $true
			}
			'USGovDoD' {
				$cloudType = 'DoD'
				$displayName = 'US Government DoD'
				$isGovernment = $true
			}
			'China' {
				$cloudType = 'China'
				$displayName = 'China (21Vianet)'
			}
			'Germany' {
				$cloudType = 'Germany'
				$displayName = 'Germany (Microsoft Cloud Deutschland)'
			}
		}
	}
	elseif ($azEnvironmentName) {
		$detectedFrom = 'AzureContext'
		switch ($azEnvironmentName) {
			'AzureCloud' {
				$cloudType = 'Commercial'
				$displayName = 'Commercial (Global)'
			}
			'AzureUSGovernment' {
				# Azure SDK uses AzureUSGovernment for both GCC High and DoD.
				# Disambiguate using the config setting if available.
				if ($configEnvironment -eq 'USGovDoD') {
					$cloudType = 'DoD'
					$displayName = 'US Government DoD'
				}
				else {
					$cloudType = 'GCCHigh'
					$displayName = 'US Government GCC High'
				}
				$isGovernment = $true
			}
			'AzureChinaCloud' {
				$cloudType = 'China'
				$displayName = 'China (21Vianet)'
			}
			'AzureGermanCloud' {
				$cloudType = 'Germany'
				$displayName = 'Germany (Microsoft Cloud Deutschland)'
			}
		}
	}
	elseif ($configEnvironment) {
		$detectedFrom = 'Configuration'
		switch ($configEnvironment) {
			'Global'   { $cloudType = 'Commercial'; $displayName = 'Commercial (Global)' }
			'USGov'    { $cloudType = 'GCCHigh'; $displayName = 'US Government GCC High'; $isGovernment = $true }
			'USGovDoD' { $cloudType = 'DoD'; $displayName = 'US Government DoD'; $isGovernment = $true }
			'China'    { $cloudType = 'China'; $displayName = 'China (21Vianet)' }
			'Germany'  { $cloudType = 'Germany'; $displayName = 'Germany (Microsoft Cloud Deutschland)' }
		}
	}

	# ── GCC detection ────────────────────────────────────────────────────────
	# GCC (IL2) uses the same Global/AzureCloud endpoints as Commercial.
	# Detect it by checking for .gov domains on the tenant's verified domains.
	if ($cloudType -eq 'Commercial' -and $mgContext) {
		try {
			$org = Invoke-ZtGraphRequest -RelativeUri 'organization' -ErrorAction Stop
			$domains = @($org.verifiedDomains)
			$hasGovDomain = $domains | Where-Object { $_.name -match '\.gov$' -or $_.name -match '\.mil$' }
			if ($hasGovDomain) {
				$isGCC = $true
				$cloudType = 'GCC'
				$displayName = 'US Government GCC'
				$isGovernment = $true
			}
		}
		catch {
			Write-PSFMessage -Message "Unable to check for .gov domains for GCC detection: $_" -Level Debug
		}
	}

	if ($cloudType -in 'GCCHigh', 'DoD') {
		$isGovernment = $true
	}

	# ── Map to Azure environment name ────────────────────────────────────────
	$azureEnvironmentName = switch ($cloudType) {
		'Commercial' { 'AzureCloud' }
		'GCC'        { 'AzureCloud' }
		'GCCHigh'    { 'AzureUSGovernment' }
		'DoD'        { 'AzureUSGovernment' }
		'China'      { 'AzureChinaCloud' }
		'Germany'    { 'AzureGermanCloud' }
		default      { $null }
	}

	# ── Map to Graph environment name ────────────────────────────────────────
	$graphEnvironmentName = switch ($cloudType) {
		'Commercial' { 'Global' }
		'GCC'        { 'Global' }
		'GCCHigh'    { 'USGov' }
		'DoD'        { 'USGovDoD' }
		'China'      { 'China' }
		'Germany'    { 'Germany' }
		default      { $null }
	}

	# ── Map to Exchange environment name ─────────────────────────────────────
	$exchangeEnvironmentName = switch ($cloudType) {
		'Commercial' { 'O365Default' }
		'GCC'        { 'O365Default' }
		'GCCHigh'    { 'O365USGovGCCHigh' }
		'DoD'        { 'O365USGovDoD' }
		'China'      { 'O365China' }
		'Germany'    { 'O365GermanyCloud' }
		default      { 'O365Default' }
	}

	$result = [PSCustomObject]@{
		PSTypeName              = 'ZeroTrustAssessment.CloudEnvironment'
		CloudType               = $cloudType
		DisplayName             = $displayName
		IsGovernment            = $isGovernment
		IsGCC                   = $isGCC
		IsCommercial            = $cloudType -in 'Commercial', 'GCC'
		IsSovereignCloud        = $cloudType -in 'China', 'Germany', 'GCCHigh', 'DoD'
		GraphEnvironmentName    = $graphEnvironmentName
		AzureEnvironmentName    = $azureEnvironmentName
		ExchangeEnvironmentName = $exchangeEnvironmentName
		GraphEndpoint           = $graphEndpoint
		AzureADEndpoint         = $azureEndpoint
		DetectedFrom            = $detectedFrom
	}

	# Cache in session
	$script:__ZtSession.CloudEnvironment = $result

	Write-PSFMessage -Message ("Cloud environment detected: {0} (from {1})" -f $result.DisplayName, $result.DetectedFrom) -Level Verbose

	$result
}
