function Connect-ZtAssessment {
	<#
	.SYNOPSIS
		Helper method to connect to Microsoft Graph and other services with the appropriate parameters
		and scopes for the Zero Trust Assessment.

	.DESCRIPTION
		Use this cmdlet to connect to Microsoft Graph and other services using the appropriate parameters and scopes
		for the Zero Trust Assessment.
		This cmdlet will import the necessary modules and establish connections based on the specified parameters.

		Authentication methods (use only one at a time):
		  Interactive  — Default on Windows. Opens a browser for sign-in.
		  Device code  — Use -UseDeviceCode. Works in headless/SSH/Codespaces environments.
		  Certificate  — Use -Certificate or -CertificateThumbprint with -ClientId and -TenantId.
		                  App-only (application permissions). Requires admin consent.
		  Client secret — Use -ClientSecret with -ClientId and -TenantId.
		                  App-only (application permissions). Requires admin consent.
		  Managed identity — Use -ManagedIdentity. For Azure-hosted automation (Functions, Automation, VMs).

		For unattended/automated execution the app registration must have the required
		Application permissions (not Delegated) with admin consent granted. Use
		Get-ZtGraphScope to see the Graph permissions needed.

	.PARAMETER UseDeviceCode
		If specified, the cmdlet will use the device code flow to authenticate to Graph and Azure.
		This will open a browser window to prompt for authentication and is useful for non-interactive sessions and on Windows when SSO is not desired.

	.PARAMETER Environment
		The environment to connect to. Default is Global.

	.PARAMETER UseTokenCache
		Uses Graph Powershell's cached authentication tokens.

	.PARAMETER TenantId
		The tenant ID to connect to. If not specified, the default tenant will be used.
		Required for service principal authentication (-ClientSecret, -Certificate, -CertificateThumbprint).

	.PARAMETER ClientId
		If specified, connects using a custom application identity.
		Required for service principal and managed identity (user-assigned) authentication.
		See https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands

	.PARAMETER Certificate
		The certificate to use for the connection(s).
		Use this to authenticate in Application mode, rather than in Delegate (user) mode.
		The application will need to be configured to have the matching Application scopes, compared to the Delegate scopes and may need to be added into roles.
		If this certificate is also used for connecting to Azure, it must come from a certificate store on the local computer.

	.PARAMETER ClientSecret
		A SecureString containing the client secret for service principal (app-only) authentication.
		Requires -ClientId and -TenantId. The app registration must have the required Application
		permissions with admin consent. Do not embed secrets in scripts; pass via parameter or
		environment variable (e.g. $env:ZT_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force).

	.PARAMETER CertificateThumbprint
		The thumbprint of a certificate installed in the current user or local machine certificate store.
		Simpler alternative to -Certificate when you only need the thumbprint.
		Requires -ClientId and -TenantId. The corresponding public key must be uploaded to the app registration.

	.PARAMETER ManagedIdentity
		Use managed identity authentication for Azure-hosted environments (Azure Functions, Automation, VMs).
		Uses the system-assigned managed identity by default. For user-assigned, also specify -ClientId.

	.EXAMPLE
		PS> Connect-ZtAssessment

		Connects to Microsoft Graph and other services using Connect-MgGraph with the required scopes and other services.
		By default, this connects to Graph, Azure, Exchange Online, Security & Compliance, SharePoint, and Azure Information Protection.
		On non-Windows platforms, Azure Information Protection is skipped (requires Windows).
		Security & Compliance is skipped when using device code flow.

	.EXAMPLE
		PS> Connect-ZtAssessment -UseDeviceCode

		Connects to Microsoft Graph and Azure using the device code flow. This will open a browser window to prompt for authentication.

	.EXAMPLE
		PS> Connect-ZtAssessment -ClientID $clientID -TenantID $tenantID -Certificate 'CN=ZeroTrustAssessment' -Service Graph,Azure

		Connects to Microsoft Graph and Azure using the specified client/application ID & tenant ID, using the latest, valid certificate available with the subject 'CN=ZeroTrustAssessment'.
		This assumes the correct scopes and permissions are assigned to the application used.

	.EXAMPLE
		PS> $secret = $env:ZT_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force
		PS> Connect-ZtAssessment -ClientId $appId -TenantId $tenantId -ClientSecret $secret

		Connects using client credentials with a secret. For CI/CD automation and unattended runs.
		The app registration must have Application permissions with admin consent.

	.EXAMPLE
		PS> Connect-ZtAssessment -ClientId $appId -TenantId $tenantId -CertificateThumbprint 'A1B2C3D4E5F6...'

		Connects using a certificate thumbprint for app-only authentication.
		The certificate must be installed locally and its public key uploaded to the app registration.

	.EXAMPLE
		PS> Connect-ZtAssessment -ManagedIdentity

		Connects using the system-assigned managed identity of the Azure host (e.g. Azure Automation, Azure Functions).

	.EXAMPLE
		PS> Connect-ZtAssessment -ManagedIdentity -ClientId $userAssignedMiClientId

		Connects using a user-assigned managed identity.
	#>
	[CmdletBinding()]
	param (
		[switch]
		$UseDeviceCode = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseDeviceCode' -Fallback $false),

		[ValidateSet('China', 'Germany', 'Global', 'USGov', 'USGovDoD')]
		[string]
		$Environment = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.Environment' -Fallback 'Global'),

		[switch]
		$UseTokenCache = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true),

		[string]
		$TenantId = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.TenantId' -Fallback ''),

		[string]
		$ClientId = (Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.ClientId' -Fallback ''),

		[PSFramework.Parameter.CertificateParameter]
		$Certificate,

		# Client secret for service principal (app-only) authentication.
		# Never embed secrets in scripts; pass via parameter or $env:ZT_CLIENT_SECRET.
		[SecureString]
		$ClientSecret,

		# Certificate thumbprint — simpler alternative to -Certificate for app-only auth.
		[string]
		$CertificateThumbprint,

		# Managed identity authentication for Azure-hosted automation.
		[switch]
		$ManagedIdentity,

		# The services to connect to such as Azure and ExchangeOnline. Default is All.
		[ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')]
		[string[]]
		$Service = 'All',

		# The Exchange environment to connect to. Default is O365Default. Supported values include O365China, O365Default, O365GermanyCloud, O365USGovDoD, O365USGovGCCHigh.
		[ValidateSet('O365China', 'O365Default', 'O365GermanyCloud', 'O365USGovDoD', 'O365USGovGCCHigh')]
		[string]
		$ExchangeEnvironmentName = 'O365Default',

		# The User Principal Name to use for Security & Compliance PowerShell connection.
		[string]
		$UserPrincipalName,

		# The SharePoint Admin URL to use for SharePoint Online connection.
		[string]
		$SharePointAdminUrl,

		# When specified, forces reconnection to services even if an existing connection is detected.
		# This is useful to refresh the connection context and permissions.
		[switch]
		$Force
	)

	if (-not (Test-ZtLanguageMode)) {
		Stop-PSFFunction -Message "PowerShell is running in Constrained Language Mode, which is not supported." -EnableException $true -Cmdlet $PSCmdlet
		return
	}

	# ── Authentication method validation ──
	# Only one credential type may be specified at a time.
	$credentialMethods = @(
		$PSBoundParameters.ContainsKey('ClientSecret'),
		($PSBoundParameters.ContainsKey('Certificate') -or $PSBoundParameters.ContainsKey('CertificateThumbprint')),
		$ManagedIdentity.IsPresent
	).Where({ $_ }).Count

	if ($credentialMethods -gt 1) {
		Stop-PSFFunction -Message "Specify only one authentication method: -ClientSecret, -Certificate/-CertificateThumbprint, or -ManagedIdentity." -EnableException $true -Cmdlet $PSCmdlet
		return
	}

	if ($PSBoundParameters.ContainsKey('Certificate') -and $PSBoundParameters.ContainsKey('CertificateThumbprint')) {
		Stop-PSFFunction -Message "Specify either -Certificate or -CertificateThumbprint, not both." -EnableException $true -Cmdlet $PSCmdlet
		return
	}

	$isAppOnlyAuth = $PSBoundParameters.ContainsKey('ClientSecret') -or
		$PSBoundParameters.ContainsKey('Certificate') -or
		$PSBoundParameters.ContainsKey('CertificateThumbprint')

	if ($isAppOnlyAuth -and -not $TenantId) {
		Stop-PSFFunction -Message "-TenantId is required for service principal authentication (-ClientSecret, -Certificate, -CertificateThumbprint)." -EnableException $true -Cmdlet $PSCmdlet
		return
	}

	if ($isAppOnlyAuth -and -not $ClientId) {
		Stop-PSFFunction -Message "-ClientId is required for service principal authentication (-ClientSecret, -Certificate, -CertificateThumbprint)." -EnableException $true -Cmdlet $PSCmdlet
		return
	}

	if ($Service -contains 'All') {
		$Service = [string[]]@($script:AllowedServices)
	}
	elseif ($Service -notcontains 'Graph' -and $script:ConnectedService -notcontains 'Graph') {
		# If not already connected, always connect Graph.
		$Service += 'Graph'
	}

	#region Validate Services
	$Service = $Service | Select-Object -Unique
	$resolvedRequiredModules = Resolve-ZtServiceRequiredModule -Service $Service

	# ── Pre-flight: classify services & skip those known to be unavailable ──
	# Uses Get-ZtServiceClassification to detect Windows-only, no-device-code,
	# no-client-secret, and missing-app-registration constraints *before* attempting connections.
	$hasCertOrMI = ($CertificateThumbprint -or $Certificate -or $ManagedIdentity)
	$classifyParams = @{}
	if ($UseDeviceCode) { $classifyParams.UseDeviceCode = $true }
	if ($ClientSecret -and -not $hasCertOrMI) { $classifyParams.UseClientSecret = $true }
	if ($hasCertOrMI) { $classifyParams.HasCertificateOrMI = $true }
	$serviceClassification = Get-ZtServiceClassification @classifyParams
	$servicesToSkip = @()

	foreach ($svcInfo in $serviceClassification) {
		$svcName = $svcInfo.Name
		# Only check services the user requested
		if ($svcName -notin $resolvedRequiredModules.ServiceAvailable) { continue }

		$skipReason = $null
		if (-not $svcInfo.Available) {
			# Hard platform constraint (e.g. Requires Windows)
			$skipReason = $svcInfo.Reason
		}
		elseif ($svcInfo.RequiresCustomApp -and -not (Get-ZtPnPClientId -ClientId $ClientId)) {
			$skipReason = $svcInfo.Reason
		}
		elseif ($svcInfo.NoDeviceCode -and $UseDeviceCode -and -not $hasCertOrMI) {
			$skipReason = $svcInfo.Reason
		}
		elseif ($svcInfo.NoClientSecret -and $ClientSecret -and -not $hasCertOrMI) {
			$skipReason = $svcInfo.Reason
		}

		if ($skipReason) {
			$servicesToSkip += $svcName
			Write-Host -Object (' ⚠️ Service "{0}" — {1}.' -f $svcName, $skipReason) -ForegroundColor Yellow
			Write-Host -Object ('      Tests requiring {0} will be skipped.' -f $svcName) -ForegroundColor Yellow
			Remove-ZtConnectedService -Service $svcName
		}
	}

	# Filter the available services list so the switch loop never attempts skipped ones
	$connectableServices = @($resolvedRequiredModules.ServiceAvailable | Where-Object { $_ -notin $servicesToSkip })

	Write-Host -Object ('🔑 Authentication to {0}.' -f ($Service -join ', ')) -ForegroundColor DarkGray
	if ($ManagedIdentity) {
		Write-Host -Object 'Using managed identity authentication (no interactive prompts).' -ForegroundColor DarkGray
	}
	elseif ($isAppOnlyAuth) {
		Write-Host -Object 'Using service principal (app-only) authentication (no interactive prompts).' -ForegroundColor DarkGray
	}
	elseif ($UseDeviceCode) {
		$deviceCodeServices = @($connectableServices) -notmatch 'SecurityCompliance'
		Write-Host -Object ("Each service requires a separate device code. You will be prompted {0} time(s)." -f $deviceCodeServices.Count) -ForegroundColor DarkGray
	}
	else {
		Write-Host -Object ('During the next steps, you may be prompted to authenticate separately for several services.') -ForegroundColor DarkGray
	}
	$resolvedRequiredModules.ServiceAvailable.ForEach{
		Write-PSFMessage -Message ("Service '{0}' is available with its required modules:" -f $_) -Level Debug
		$resolvedRequiredModules.($_).Foreach{
			Write-PSFMessage -Message (" - {0} v{1}" -f $_.Name,$_.Version) -Level Debug
		}
	}

	$resolvedRequiredModules.ServiceUnavailable.ForEach{
		$serviceName = $_
		if ($serviceName -in $resolvedRequiredModules.ServiceInvalidForOS) {
			Write-Host -Object (' ⚠️ Service "{0}" is not available because it requires Windows.' -f $serviceName) -ForegroundColor Yellow
		} else {
			Write-Host -Object (' ⚠️ Service "{0}" is not available due to missing required modules: {1}.' -f $serviceName, ($resolvedRequiredModules.Errors.Where({ $_.Service -eq $serviceName }).ModuleSpecification -join ', ')) -ForegroundColor Yellow
		}
	}

	#endregion

	# For services where their requiredModules are available, attempt to import and connect.
	# If errors occurs, mark them as service unavailable and continue with the rest, instead of stopping the entire connection process.
	# if the connection is successful, add them to service available (module scope).
	switch ($connectableServices) {
		'Graph' {
			Write-Host -Object "`nConnecting to Microsoft Graph" -ForegroundColor Cyan
			Write-PSFMessage -Message 'Connecting to Microsoft Graph' -Level Verbose
			try {
				#region loading graph modules
				Write-PSFMessage -Message ('Loading graph required modules: {0}' -f ($resolvedRequiredModules.Graph.Name -join ', ')) -Level Verbose
				Write-Host -Object ('   Loading modules: {0} (this may take a moment)...' -f ($resolvedRequiredModules.Graph.Name -join ', ')) -ForegroundColor DarkGray
				$loadedGraphModules = $resolvedRequiredModules.Graph.ForEach{
					$_ | Import-Module -Global -ErrorAction Stop -PassThru
				}

				$loadedGraphModules.ForEach{
					Write-Debug -Message ('Module ''{0}'' v{1} loaded for Graph.' -f $_.Name, $_.Version)
				}
				#endregion

				#region is Graph connected?

				# Assume we're not connected and we need to connect.
				[bool] $isGraphConnected = $false
				$context = Get-MgContext -ErrorAction Ignore
				if ($null -ne $context) {
					Write-PSFMessage -Message ('A connection to Microsoft Graph is already established with account "{0}".' -f $context.Account) -Level Debug
					$isGraphConnected = $true
					Write-PSFMessage -Message "Testing connection with ClientId ({0}), tenant ({1}) account ({2}) and Force ({3})." -Level Debug -StringValues @($context.ClientId, $context.TenantId, $context.Account, $Force.IsPresent)
				}
				else {
					Write-PSFMessage -Message "No existing connection to Microsoft Graph found." -Level Debug
				}

				#endregion

				# Graph might be connected, but:
				#   - with the wrong ClientId,
				#   - to the wrong tenant,
				#   - with the wrong Certificate,
				#   - without the required scopes/permissions for the assessment,
				# so we need to validate the context.
				# Validate the existing context separately so that missing scopes/roles trigger a reconnect
				# instead of causing the outer Graph connection logic to treat it as a fatal error.
				$isContextValid = $true
				if ($isGraphConnected) {
					try {
						$isContextValid = Test-ZtContext -ErrorAction Stop
					}
					catch {
						Write-PSFMessage -Message "Existing Graph context is invalid or missing required permissions. A reconnect will be attempted." -Level Debug
						$isContextValid = $false
					}
				}

				if ( #Comparing connection with parameters to determine if we can reuse the existing connection or need to reconnect.
					($isGraphConnected -and $Force.IsPresent) -or # If -Force is specified, ignore the existing context and reconnect regardless of parameters
					(
						$isGraphConnected -and
						(
							($PSBoundParameters.ContainsKey('ClientId') -and $context.ClientId -ne $ClientId) -or
							($PSBoundParameters.ContainsKey('TenantId') -and $context.TenantId -ne $TenantId) -or
							($PSBoundParameters.ContainsKey('Certificate') -and [string]::IsNullOrEmpty($context.Certificate.Thumbprint))
							#TODO: compare certificate thumbprint & Subject if possible
						)
					) -or
					($isGraphConnected -and -not $isContextValid) # if missing permission, reconnect to ask for the permissions needed for the assessment
				) {
					Write-PSFMessage -Message "Disconnecting from ClientId ({0}), tenant ({1}) account ({2})." -Level Debug -StringValues @($context.ClientId, $context.TenantId, $context.Account)
					$null = Disconnect-MgGraph -ErrorAction Ignore
					Remove-ZtConnectedService -Service 'Graph'
				}
				elseif ($isGraphConnected) { # if it's connected, and everything is ok.
					# Test the existing context to ensure it has the required permissions and is valid for use in the assessment. If not, disconnect and reconnect with the correct parameters.
					Write-PSFMessage -Message "Connected to Graph with the same info as specified in parameters." -Level Debug
					Add-ZtConnectedService -Service 'Graph'
					Write-Host -Object "   ✅ Already connected to Microsoft Graph." -ForegroundColor Green
					$contextTenantId = $context.TenantId
					continue
				}

				$connectMgGraphParams = @{
					NoWelcome   = $true
					Environment = $Environment
				}

				# ── Build auth-method-specific parameters ──
				if ($ManagedIdentity) {
					# Managed identity (system-assigned; user-assigned when ClientId specified)
					$connectMgGraphParams.Identity = $true
					if ($ClientId) { $connectMgGraphParams.ClientId = $ClientId }
				}
				elseif ($ClientSecret) {
					# Client credentials with secret — app-only permissions from app registration
					$credential = [PSCredential]::new($ClientId, $ClientSecret)
					$connectMgGraphParams.ClientSecretCredential = $credential
					$connectMgGraphParams.TenantId = $TenantId
				}
				elseif ($CertificateThumbprint) {
					# Client credentials with certificate thumbprint — app-only
					$connectMgGraphParams.ClientId = $ClientId
					$connectMgGraphParams.TenantId = $TenantId
					$connectMgGraphParams.CertificateThumbprint = $CertificateThumbprint
				}
				elseif ($Certificate) {
					# Client credentials with certificate object — app-only
					$connectMgGraphParams.Certificate = $Certificate
					if ($ClientId) { $connectMgGraphParams.ClientId = $ClientId }
					if ($TenantId) { $connectMgGraphParams.TenantId = $TenantId }
				}
				else {
					# Delegated (interactive or device code) — request scopes at sign-in
					$connectMgGraphParams.UseDeviceCode = [bool]$UseDeviceCode
					$connectMgGraphParams.Scopes = Get-ZtGraphScope
					if ($ClientId) { $connectMgGraphParams.ClientId = $ClientId }
					if ($TenantId) { $connectMgGraphParams.TenantId = $TenantId }
				}

				if (-not $UseTokenCache) {
					$connectMgGraphParams.ContextScope = 'Process'
				}

				# Log connection parameters without sensitive credential material.
				$safeLogParams = $connectMgGraphParams.Clone()
				foreach ($sensitiveKey in @('ClientSecretCredential', 'Certificate', 'CertificateThumbprint')) {
					if ($safeLogParams.ContainsKey($sensitiveKey)) {
						$safeLogParams[$sensitiveKey] = '***REDACTED***'
					}
				}
				Write-PSFMessage -Message "Connecting to Microsoft Graph with params: $($safeLogParams | Out-String)" -Level Verbose

				# For any delegated flow (interactive or device code) with token caching,
				# try silent restore first to avoid unnecessary login prompts.
				$isDelegated = -not ($ManagedIdentity -or $ClientSecret -or $CertificateThumbprint -or $Certificate)
				if ($isDelegated -and $UseTokenCache) {
					Write-PSFMessage -Message "Attempting silent Graph connect from token cache..." -Level Debug
					if (Restore-ZtCachedConnection) {
						Write-Host -Object '   ✅ Connected to Microsoft Graph (from cached token).' -ForegroundColor Green
						$contextTenantId = (Get-MgContext).TenantId
						continue
					}
				}

				if ($connectMgGraphParams.ContainsKey('UseDeviceCode') -and $connectMgGraphParams.UseDeviceCode) {
					if (Read-ZtDeviceCodeSkip -ServiceName 'Graph') {
						Remove-ZtConnectedService -Service 'Graph'
						Write-Host -Object '   ⏭️  Skipped Graph — tests requiring Microsoft Graph will be skipped.' -ForegroundColor Yellow
						continue
					}
					Write-Host -Object '   Requesting device code (watch for the sign-in prompt below)...' -ForegroundColor DarkGray
					Open-ZtDeviceCodeBrowser
					Connect-MgGraph @connectMgGraphParams -ErrorAction Stop
				}
				elseif ($ManagedIdentity -or $ClientSecret -or $CertificateThumbprint -or $Certificate) {
					Write-Host -Object '   Authenticating (app-only)...' -ForegroundColor DarkGray
					$null = Connect-MgGraph @connectMgGraphParams -ErrorAction Stop
				}
				else {
					$null = Connect-MgGraph @connectMgGraphParams -ErrorAction Stop
				}
				$contextTenantId = (Get-MgContext).TenantId
				Write-Host -Object "   ✅ Connected to Microsoft Graph." -ForegroundColor Green
				Add-ZtConnectedService -Service 'Graph'
			}
			catch {
				$graphException = $_
				Write-PSFMessage -Message ("Failed to authenticate to Graph: {0}" -f $graphException.Message) -Level Error -ErrorRecord $_
				# Remove service from the connected list.
				Remove-ZtConnectedService -Service 'Graph'
				Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
				Write-Host -Object "       Tests requiring Microsoft Graph cannot be executed." -ForegroundColor Yellow
				Write-Host -Object "       Graph is critical to the ZeroTrustAssessment report. Aborting." -ForegroundColor Yellow
				$methodNotFound = $null
				$dllConflict = $null
				if ($graphException.Exception.InnerException -is [System.MissingMethodException]) {
					$methodNotFound = $graphException.Exception.InnerException
				}
				elseif ($graphException.Exception -is [System.MissingMethodException]) {
					$methodNotFound = $graphException.Exception
				}

				# Detect TypeLoadException (e.g. AzureIdentityAccessTokenProvider from Microsoft.Graph.Core)
				$innerEx = $graphException.Exception
				while ($innerEx) {
					if ($innerEx -is [System.TypeLoadException]) {
						$dllConflict = $innerEx
						break
					}
					$innerEx = $innerEx.InnerException
				}

				if ($methodNotFound -and $methodNotFound.Message -like '*Microsoft.Identity*') {
					Write-Warning -Message "DLL conflict detected (MissingMethodException in Microsoft.Identity). This typically occurs when incompatible versions of Microsoft.Identity.Client or Microsoft.IdentityModel.Abstractions are loaded."
					Write-Warning -Message "Please RESTART your PowerShell session and run Connect-ZtAssessment again, ensuring no other Microsoft modules are imported first."
				}
				elseif ($dllConflict) {
					Write-Warning -Message "DLL conflict detected (TypeLoadException): $($dllConflict.Message)"
					Write-Warning -Message "This typically occurs when another module (e.g. Az.Accounts) loaded an incompatible version of Microsoft.Graph.Core or related assemblies."
					Write-Warning -Message "Please RESTART your PowerShell session and run Connect-ZtAssessment again, ensuring no other Microsoft modules are imported first."
				}

				Stop-PSFFunction -Message "Failed to authenticate to Graph. The requirements for the ZeroTrustAssessment are not met by the established session:`n$graphException" -ErrorRecord $graphException -EnableException $true -Cmdlet $PSCmdlet
			}

			try {
				if ($script:ConnectedService -contains 'Graph') {
					Write-PSFMessage -Message "Verifying Graph connection and permissions..." -Level Debug
					$null = Test-ZtContext
					Write-PSFMessage -Message "Ok." -Level Debug
				}
			}
			catch {
				Remove-ZtConnectedService -Service 'Graph'

				# Check for DLL conflicts that surface during post-connection verification
				$verifyEx = $_.Exception
				$typeLoadEx = $null
				while ($verifyEx) {
					if ($verifyEx -is [System.TypeLoadException]) { $typeLoadEx = $verifyEx; break }
					$verifyEx = $verifyEx.InnerException
				}
				if ($typeLoadEx) {
					Write-Host -Object "   ❌ Graph verification failed due to a DLL conflict." -ForegroundColor Yellow
					Write-Warning -Message "TypeLoadException: $($typeLoadEx.Message)"
					Write-Warning -Message "This typically occurs when another module (e.g. Az.Accounts) loaded an incompatible version of Microsoft.Graph.Core or related assemblies."
					Write-Warning -Message "Please RESTART your PowerShell session and run Connect-ZtAssessment again, ensuring no other Microsoft modules are imported first."
				}

				Stop-PSFFunction -Message "Authenticated to Graph, but the requirements for the ZeroTrustAssessment are not met by the established session:`n$_" -ErrorRecord $_ -EnableException $true -Cmdlet $PSCmdlet
			}
		}

		'Azure' {
			Write-Host -Object "`nConnecting to Azure" -ForegroundColor Cyan
			Write-PSFMessage -Message 'Connecting to Azure' -Level Verbose
			try {
				#region Load Azure Modules
				Write-PSFMessage -Message ('Loading Azure required modules: {0}' -f ($resolvedRequiredModules.Azure.Name -join ', ')) -Level Verbose
				Write-Host -Object ('   Loading modules: {0} (this may take a moment)...' -f ($resolvedRequiredModules.Azure.Name -join ', ')) -ForegroundColor DarkGray
				$loadedAzureModules = $resolvedRequiredModules.Azure.ForEach{
					$_ | Import-Module -Global -ErrorAction Stop -PassThru
				}

				$loadedAzureModules.ForEach{
					Write-Debug -Message ('Module ''{0}'' v{1} loaded for Azure.' -f $_.Name, $_.Version)
				}
				#endregion

				$azEnvironment = 'AzureCloud'
				if ($Environment -eq 'China') {
					$azEnvironment = Get-AzEnvironment -Name AzureChinaCloud
				}
				elseif ($Environment -in 'USGov', 'USGovDoD') {
					$azEnvironment = 'AzureUSGovernment'
				}

				# Grab the Tenant ID from parameters if specified, otherwise from Graph context if available, otherwise rely on default tenant.
				$isAzureConnected = $false
				$azContext = Get-AzContext -ErrorAction Ignore
				if ($null -ne $azContext) {
					Write-PSFMessage -Message ('A connection to Azure is already established with account "{0}".' -f $azContext.Account) -Level Debug
					$isAzureConnected = $true
				}
				else {
					Write-PSFMessage -Message "No existing connection to Azure found." -Level Debug
				}

				# Determine whether Azure will use service principal or managed identity authentication.
				$useAzureServicePrincipalAuth = $isAppOnlyAuth -or $ManagedIdentity

				# Azure might be connected, but:
				#   - with the wrong ClientId,
				#   - to the wrong tenant,
				#   - with the wrong Certificate,
				#   - without the required scopes/permissions for the assessment,
				# so we need to validate the context.
				if (
					($isAzureConnected -and $Force.IsPresent) -or
					(
						$isAzureConnected -and
						(
							(
								$PSBoundParameters.ContainsKey('TenantId') -and
								$azContext.Tenant.Id -ne $TenantId
							) -or
							(
								$useAzureServicePrincipalAuth -and
								$PSBoundParameters.ContainsKey('ClientId') -and
								$azContext.Account.Id -ne $ClientId
							) -or
							(
								$useAzureServicePrincipalAuth -and
								$PSBoundParameters.ContainsKey('Certificate') -and
								[string]::IsNullOrEmpty($azContext.Account.CertificateThumbprint)
							)
						)
					)
				) {
					Write-PSFMessage -Message "Current connection with TenantId ({0}) and Account ({1}) is different than the one specified in parameters." -Level Debug -StringValues @($azContext.Tenant.Id, $azContext.Account.Id)
					$null = Disconnect-AzAccount -ErrorAction Ignore
					$isAzureConnected = $false
					Remove-ZtConnectedService -Service 'Azure'
				}
				elseif ($isAzureConnected) {
					Write-PSFMessage -Message "Connected to Azure with the same info as specified in parameters." -Level Debug
					Add-ZtConnectedService -Service 'Azure'
					Write-Host -Object "   ✅ Already connected to Azure." -ForegroundColor Green
					continue
				}

				$tenantParam = $TenantId
				if (-not $tenantParam) {
					if ($contextTenantId) {
						$tenantParam = $contextTenantId
					}
				}

				$azParams = @{
					Environment = $azEnvironment
				}

				# ── Build auth-method-specific parameters for Azure ──
				if ($ManagedIdentity) {
					$azParams.Identity = $true
					if ($ClientId) { $azParams.AccountId = $ClientId }
				}
				elseif ($ClientSecret) {
					$azCredential = [PSCredential]::new($ClientId, $ClientSecret)
					$azParams.ServicePrincipal = $true
					$azParams.Credential = $azCredential
					$azParams.Tenant = $TenantId
				}
				elseif ($CertificateThumbprint) {
					$azParams.ServicePrincipal = $true
					$azParams.ApplicationId = $ClientId
					$azParams.CertificateThumbprint = $CertificateThumbprint
					if ($tenantParam) { $azParams.Tenant = $tenantParam }
				}
				elseif ($Certificate -and $ClientId) {
					$azParams.ServicePrincipal = $true
					$azParams.ApplicationId = $ClientId
					$azParams.CertificateThumbprint = $Certificate.Certificate.Thumbprint
					if ($tenantParam) { $azParams.Tenant = $tenantParam }
				}
				else {
					$azParams.UseDeviceAuthentication = [bool]$UseDeviceCode
					if ($tenantParam) { $azParams.Tenant = $tenantParam }
				}

				# Log Azure connection parameters without sensitive credential material.
				$safeAzLogParams = $azParams.Clone()
				foreach ($sensitiveKey in @('Credential', 'CertificateThumbprint')) {
					if ($safeAzLogParams.ContainsKey($sensitiveKey)) {
						$safeAzLogParams[$sensitiveKey] = '***REDACTED***'
					}
				}
				Write-Verbose -Message ("Connecting to Azure with parameters: {0}" -f ($safeAzLogParams | Out-String))
				if ($azParams.ContainsKey('UseDeviceAuthentication') -and $azParams.UseDeviceAuthentication) {
					if (Read-ZtDeviceCodeSkip -ServiceName 'Azure') {
						Remove-ZtConnectedService -Service 'Azure'
						Write-Host -Object '   ⏭️  Skipped Azure — tests requiring Azure will be skipped.' -ForegroundColor Yellow
						continue
					}
					Write-Host -Object '   Requesting device code (watch for the sign-in prompt below)...' -ForegroundColor DarkGray
					Open-ZtDeviceCodeBrowser
					$null = Connect-AzAccount @azParams -ErrorAction Stop
				}
				elseif ($ManagedIdentity -or $ClientSecret -or $CertificateThumbprint -or $Certificate) {
					Write-Host -Object '   Authenticating (app-only)...' -ForegroundColor DarkGray
					$null = Connect-AzAccount @azParams -ErrorAction Stop
				}
				else {
					$null = Connect-AzAccount @azParams -ErrorAction Stop
				}
				Write-Host -Object "   ✅ Connected to Azure." -ForegroundColor Green
				Add-ZtConnectedService -Service 'Azure'
			}
			catch {
				Write-PSFMessage -Message ("Failed to authenticate to Azure: {0}" -f $_) -Level Debug -ErrorRecord $_
				Remove-ZtConnectedService -Service 'Azure'
				Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
				Write-Host -Object "      Tests requiring Azure will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_) -ForegroundColor Red
			}
		}

		'AipService' {
			Write-Host -Object "`nConnecting to Azure Information Protection" -ForegroundColor Cyan
			Write-PSFMessage -Message 'Connecting to Azure Information Protection' -Level Verbose
			try {
			Write-PSFMessage -Message ('Loading Azure Information Protection required modules: {0}' -f ($resolvedRequiredModules.AipService.Name -join ', ')) -Level Verbose
				$loadedAipServiceModules = $resolvedRequiredModules.AipService.ForEach{
					$importParams = @{ Global = $true; ErrorAction = 'Stop'; PassThru = $true; WarningAction = 'SilentlyContinue' }
					if ($IsWindows) { $importParams['UseWindowsPowerShell'] = $true }
					$_ | Import-Module @importParams
				}

				$loadedAipServiceModules.ForEach{
					Write-Debug -Message ('Module ''{0}'' v{1} loaded for Azure Information Protection.' -f $_.Name, $_.Version)
				}

			}
			catch {
				Write-Host -Object "   ❌ Failed to load Azure Information Protection modules." -ForegroundColor Yellow
				Write-Host -Object "       Tests requiring Azure Information Protection will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_) -ForegroundColor Red
				Write-PSFMessage -Message ("Error loading AipService Module in WindowsPowerShell: {0}" -f $_) -Level Debug -ErrorRecord $_
				# Mark service as unavailable and skip connection attempt.
				Remove-ZtConnectedService -Service 'AipService'
				continue
			}

			try {
					Write-PSFMessage -Message "Connecting to Azure Information Protection" -Level Verbose
					# Connect-AipService does not have parameters for non-interactive auth, so it will use the existing Graph connection context if available, or prompt if not.
					$null = Connect-AipService -ErrorAction Stop
					Write-Host -Object "   ✅ Connected to Azure Information Protection." -ForegroundColor Green
					Add-ZtConnectedService -Service 'AipService'
			}
			catch {
				Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
				Write-Host -Object "       Tests requiring Azure Information Protection will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_) -ForegroundColor Red
				Write-PSFMessage -Message ("Failed to connect to Azure Information Protection: {0}" -f $_) -Level Debug -ErrorRecord $_
				# Mark service as unavailable.
				Remove-ZtConnectedService -Service 'AipService'
			}
		}

		'ExchangeOnline' {
			Write-Host -Object "`nConnecting to Exchange Online" -ForegroundColor Cyan
			try {
				Write-PSFMessage -Message ('Loading Exchange Online required modules: {0}' -f ($resolvedRequiredModules.ExchangeOnline.Name -join ', ')) -Level Verbose
				Write-Host -Object ('   Loading modules: {0} (this may take a moment)...' -f ($resolvedRequiredModules.ExchangeOnline.Name -join ', ')) -ForegroundColor DarkGray
				$loadedExoModules = $resolvedRequiredModules.ExchangeOnline.ForEach{
					$_ | Import-Module -Global -ErrorAction Stop -PassThru -WarningAction SilentlyContinue
				}

				$loadedExoModules.ForEach{
					Write-Debug -Message ('Module ''{0}'' v{1} loaded for Exchange Online.' -f $_.Name, $_.Version)
				}

				#region is Exchange Online connected?
				$isExoConnected = $false
				try {
					$exoConnectionInfo = Get-ConnectionInformation -ErrorAction Stop
					if ($null -ne $exoConnectionInfo -and $exoConnectionInfo.State -eq 'Connected') {
						Write-PSFMessage -Message ('An existing Exchange Online connection is established as "{0}".' -f $exoConnectionInfo.UserPrincipalName) -Level Debug
						$isExoConnected = $true
					}
				}
				catch {
					Write-PSFMessage -Message "No existing Exchange Online connection found." -Level Debug
				}

				if ($isExoConnected -and -not $Force.IsPresent) {
					Write-Host -Object "   ✅ Already connected to Exchange Online." -ForegroundColor Green
					Add-ZtConnectedService -Service 'ExchangeOnline'
					continue
				}
				elseif ($isExoConnected -and $Force.IsPresent) {
					Write-PSFMessage -Message "Force reconnect requested. Disconnecting existing Exchange Online session." -Level Debug
					Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Ignore
				}
				#endregion

				Write-Verbose -Message 'Connecting to Microsoft Exchange Online'
				# Resolve the organization domain needed for app-only / managed identity connections
				$exoOrgDomain = $null
				if ($isAppOnlyAuth -or $ManagedIdentity) {
					try {
						$org = Invoke-ZtGraphRequest -RelativeUri 'organization' -ErrorAction Stop
						$exoOrgDomain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
					}
					catch {
						Write-PSFMessage -Message "Unable to resolve organization domain for EXO app-only: $_" -Level Debug
					}
				}

				if ($ManagedIdentity) {
					# Managed identity — Connect-ExchangeOnline -ManagedIdentity
					$exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
					$exoParams.ManagedIdentity = $true
					if ($ClientId) { $exoParams.ManagedIdentityAccountId = $ClientId }
					if ($exoOrgDomain) { $exoParams.Organization = $exoOrgDomain }
					if ($ExchangeEnvironmentName -ne 'O365Default') { $exoParams.ExchangeEnvironmentName = $ExchangeEnvironmentName }
					Write-Host -Object '   Authenticating (managed identity)...' -ForegroundColor DarkGray
					Connect-ExchangeOnline @exoParams
				}
				elseif (($CertificateThumbprint -or $Certificate) -and $ClientId) {
					# App-only with certificate — Connect-ExchangeOnline -AppId -CertificateThumbprint -Organization
					$exoThumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $Certificate.Certificate.Thumbprint }
					$exoParams = @{
						AppId                  = $ClientId
						CertificateThumbprint  = $exoThumbprint
						ShowBanner             = $false
						ErrorAction            = 'Stop'
					}
					if ($exoOrgDomain) { $exoParams.Organization = $exoOrgDomain }
					if ($ExchangeEnvironmentName -ne 'O365Default') { $exoParams.ExchangeEnvironmentName = $ExchangeEnvironmentName }
					Write-Host -Object '   Authenticating (app-only certificate)...' -ForegroundColor DarkGray
					$null = Connect-ExchangeOnline @exoParams
				}
				elseif ($ClientSecret) {
					# Pre-flight should have skipped this — safety net for direct Connect-ZtAssessment calls
					Write-PSFMessage -Message 'Exchange Online does not support client-secret auth — skipping.' -Level Warning
					Remove-ZtConnectedService -Service 'ExchangeOnline'
					continue
				}
				elseif ($UseDeviceCode) {
					if (Read-ZtDeviceCodeSkip -ServiceName 'Exchange Online') {
						Remove-ZtConnectedService -Service 'ExchangeOnline'
						Write-Host -Object '   ⏭️  Skipped Exchange Online — tests requiring Exchange Online will be skipped.' -ForegroundColor Yellow
						continue
					}
					Write-Host -Object '   Requesting device code (each service requires separate authentication)...' -ForegroundColor DarkGray
					Open-ZtDeviceCodeBrowser
					Connect-ExchangeOnline -ShowBanner:$false -Device:$UseDeviceCode -ExchangeEnvironmentName $ExchangeEnvironmentName -ErrorAction Stop
				}
				else {
					$null = Connect-ExchangeOnline -ShowBanner:$false -ExchangeEnvironmentName $ExchangeEnvironmentName -ErrorAction Stop
				}

				# Fix for Get-Label visibility in other scopes
				if (Get-Command -Name Get-Label -ErrorAction Ignore) {
					$module = Get-Command -Name Get-Label | Select-Object -ExpandProperty Module
					if ($module -and $module.Name -like 'tmp_*') {
						Import-Module $module -Global #-Force
					}
				}

				Write-Host -Object "   ✅ Connected to Exchange Online." -ForegroundColor Green
				Add-ZtConnectedService -Service 'ExchangeOnline'
			}
			catch {
				Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
				Write-Host -Object "      Tests requiring Exchange Online will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_) -ForegroundColor Red
				Write-PSFMessage -Message ("Failed to connect to Exchange Online: {0}" -f $_) -Level Debug -ErrorRecord $_
				Remove-ZtConnectedService -Service 'ExchangeOnline'
			}
		}

		'SecurityCompliance' {
			Write-Host -Object "`nConnecting to Microsoft Security & Compliance PowerShell" -ForegroundColor Cyan
			$Environments = @{
				'O365China'        = @{
					ConnectionUri    = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
					AuthZEndpointUri = 'https://login.chinacloudapi.cn/common'
				}
				'O365GermanyCloud' = @{
					ConnectionUri    = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
					AuthZEndpointUri = 'https://login.microsoftonline.com/common'
				}
				'O365Default'      = @{
					ConnectionUri    = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
					AuthZEndpointUri = 'https://login.microsoftonline.com/common'
				}
				'O365USGovGCCHigh' = @{
					ConnectionUri    = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
					AuthZEndpointUri = 'https://login.microsoftonline.us/common'
				}
				'O365USGovDoD'     = @{
					ConnectionUri    = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
					AuthZEndpointUri = 'https://login.microsoftonline.us/common'
				}
				Default            = @{
					ConnectionUri    = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
					AuthZEndpointUri = 'https://login.microsoftonline.com/common'
				}
			}

			$exoSnCModulesLoaded = $false
			try {
				$loadedExoSnCModules = $resolvedRequiredModules.SecurityCompliance.ForEach{
					$_ | Import-Module -Global -ErrorAction Stop -PassThru -WarningAction SilentlyContinue
				}

				$loadedExoSnCModules.ForEach{
					Write-PSFMessage -Message ('Module ''{0}'' v{1} loaded for Security & Compliance.' -f $_.Name, $_.Version) -Level Debug
				}

				$exoSnCModulesLoaded = $true
			}
			catch {
				Write-Host -Object "   ❌ Failed to load required modules for Security & Compliance." -ForegroundColor Yellow
				Write-Host -Object "      Tests requiring Security & Compliance will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_) -ForegroundColor Red
				Remove-ZtConnectedService -Service 'SecurityCompliance'
				Write-PSFMessage -Message "Failed to load required modules for Security & Compliance: $_" -Level Debug -ErrorRecord $_
			}

			if ($ClientSecret -and -not ($CertificateThumbprint -or $Certificate)) {
				# Pre-flight should have skipped this — safety net for direct Connect-ZtAssessment calls
				Write-PSFMessage -Message 'Security & Compliance does not support client-secret auth — skipping.' -Level Warning
				Remove-ZtConnectedService -Service 'SecurityCompliance'
			}
			elseif ($UseDeviceCode -and -not ($CertificateThumbprint -or $Certificate -or $ManagedIdentity)) {
				# Pre-flight should have skipped this — safety net for direct Connect-ZtAssessment calls
				Write-PSFMessage -Message 'Security & Compliance does not support device code flow — skipping.' -Level Warning
				Remove-ZtConnectedService -Service 'SecurityCompliance'
			}
			elseif ($exoSnCModulesLoaded) {
				try {
					# Resolve org domain for app-only/MI if not already resolved by the EXO block
					if (($isAppOnlyAuth -or $ManagedIdentity) -and -not $exoOrgDomain) {
						try {
							$org = Invoke-ZtGraphRequest -RelativeUri 'organization' -ErrorAction Stop
							$exoOrgDomain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
						}
						catch {
							Write-PSFMessage -Message "Unable to resolve organization domain for S&C app-only: $_" -Level Debug
						}
					}

					$ippSessionParams = @{
						ShowBanner  = $false
						ErrorAction = 'Stop'
					}

					if ($ManagedIdentity) {
						# S&C via managed identity (same EXO module)
						$ippSessionParams.ManagedIdentity = $true
						if ($ClientId) { $ippSessionParams.ManagedIdentityAccountId = $ClientId }
						if ($exoOrgDomain) { $ippSessionParams.Organization = $exoOrgDomain }
						Write-Host -Object '   Authenticating (managed identity)...' -ForegroundColor DarkGray
					}
					elseif (($CertificateThumbprint -or $Certificate) -and $ClientId) {
						# S&C via certificate (app-only)
						$sncThumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $Certificate.Certificate.Thumbprint }
						$ippSessionParams.AppId = $ClientId
						$ippSessionParams.CertificateThumbprint = $sncThumbprint
						if ($exoOrgDomain) { $ippSessionParams.Organization = $exoOrgDomain }
						Write-Host -Object '   Authenticating (app-only certificate)...' -ForegroundColor DarkGray
					}
					else {
						# Interactive (delegated) — needs UPN
						# Get UPN from Exchange connection or Graph context
						$ExoUPN = $UserPrincipalName

						# Attempt to resolve UPN before any connection to avoid token acquisition failures without identity
						$connectionInformation = $null
						try {
							$connectionInformation = Get-ConnectionInformation
						}
						catch {
							# Intentionally swallow errors here; fall back to provided UPN if any
							$connectionInfoError = $_
							Write-Verbose -Message "Get-ConnectionInformation failed; falling back to provided UserPrincipalName if available. Error: $($connectionInfoError.Exception.Message)"
						}

						if (-not $ExoUPN) {
							$ExoUPN = $connectionInformation | Where-Object { $_.IsEopSession -ne $true -and $_.State -eq 'Connected' } | Select-Object -ExpandProperty UserPrincipalName -First 1 -ErrorAction SilentlyContinue
						}

						if (-not $ExoUPN) {
							throw "`nUnable to determine a UserPrincipalName for Security & Compliance. Please supply -UserPrincipalName or connect to Exchange Online first."
						}

						$ippSessionParams.BypassMailboxAnchoring = $true
						$ippSessionParams.UserPrincipalName = $ExoUPN

						# Only override endpoints for non-default clouds to reduce token acquisition failures in Default
						if ($ExchangeEnvironmentName -ne 'O365Default') {
							$ippSessionParams.ConnectionUri = $Environments[$ExchangeEnvironmentName].ConnectionUri
							$ippSessionParams.AzureADAuthorizationEndpointUri = $Environments[$ExchangeEnvironmentName].AuthZEndpointUri
						}
					}

					Write-Verbose -Message "Connecting to Security & Compliance"
					Connect-IPPSSession @ippSessionParams
					Write-Host -Object "   ✅ Connected to Security & Compliance." -ForegroundColor Green

					# Fix for Get-Label visibility in other scopes
					if (Get-Command -Name Get-Label -ErrorAction Ignore) {
						$module = Get-Command -Name Get-Label | Select-Object -ExpandProperty Module
						if ($module -and $module.Name -like 'tmp_*') {
							Import-Module $module -Global #-Force
						}
					}

					Add-ZtConnectedService -Service 'SecurityCompliance'
				}
				catch {
					Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
					Write-Host -Object "      Tests requiring Security & Compliance will be skipped." -ForegroundColor Yellow
					Write-Host -Object ("       Error details: {0}" -f $_.Exception.Message) -ForegroundColor Red
					Write-PSFMessage -Message ("Failed to connect to Security & Compliance PowerShell: {0}" -f $_.Exception.Message) -Level Debug -ErrorRecord $_

					Remove-ZtConnectedService -Service 'SecurityCompliance'
					$exception = $_
					$methodNotFoundException = $null

					# Detect DLL conflict via a specific MissingMethodException, preferring the inner exception when present
					if ($exception.Exception.InnerException -is [System.MissingMethodException]) {
						$methodNotFoundException = $exception.Exception.InnerException
					}
					elseif ($exception.Exception -is [System.MissingMethodException]) {
						$methodNotFoundException = $exception.Exception
					}

					if ($methodNotFoundException -and $methodNotFoundException.Message -like "*Microsoft.Identity.Client*") {
						Write-Warning "DLL Conflict detected (Method not found in Microsoft.Identity.Client). This usually happens if Microsoft.Graph is loaded before ExchangeOnlineManagement."
						Write-Warning "Please RESTART your PowerShell session and run Connect-ZtAssessment again."
					}
				}
			}
		}

		'SharePoint' {
			Write-Host -Object "`nConnecting to SharePoint" -ForegroundColor Cyan
			try {
				Write-PSFMessage -Message ('Loading SharePoint required modules: {0}' -f ($resolvedRequiredModules.SharePoint.Name -join ', ')) -Level Verbose
				$loadedSharePointModules = $resolvedRequiredModules.SharePoint.ForEach{
					$importParams = @{ Global = $true; ErrorAction = 'Stop'; PassThru = $true; WarningAction = 'SilentlyContinue' }
					$_ | Import-Module @importParams
				}

				$loadedSharePointModules.ForEach{
					Write-Debug -Message ('Module ''{0}'' v{1} loaded for SharePoint.' -f $_.Name, $_.Version)
				}
			}
			catch {
				Write-Host -Object "   ❌ Failed to load required modules for SharePoint." -ForegroundColor Yellow
				Write-Host -Object "      Tests requiring SharePoint will be skipped." -ForegroundColor Yellow
				Write-Host -Object ("       Error details: {0}" -f $_.Exception.Message) -ForegroundColor Red
				Write-PSFMessage -Message ("Failed to load required modules for SharePoint: {0}" -f $_) -Level Debug -ErrorRecord $_
				# Mark service as unavailable
				Remove-ZtConnectedService -Service 'SharePoint'
				continue
			}

			[string] $adminUrl = $null
			if (-not [string]::IsNullOrEmpty($SharePointAdminUrl)) {
				Write-Verbose -Message "Using provided SharePoint Admin URL: $SharePointAdminUrl"
				$adminUrl = $SharePointAdminUrl # Attempt to read from parameter
			}
			elseif (-not $adminUrl  -and (Get-Command -Name Get-MgContext -ErrorAction Ignore) -and ($graphContext = Get-MgContext -ErrorAction Ignore)) {
				# Try to infer from Graph context
				if ($graphContext.TenantId) {
					try {
						$org = Invoke-ZtGraphRequest -RelativeUri 'organization'
						$initialDomain = $org.verifiedDomains | Where-Object { $_.isInitial } | Select-Object -ExpandProperty name -First 1
						if ($initialDomain) {
							$tenantName = $initialDomain.Split('.')[0]
							$adminUrl = "https://$tenantName-admin.sharepoint.com"
							Write-Verbose -Message "Inferred SharePoint Admin URL from Graph: $adminUrl"
						}
					}
					catch {
						Write-Verbose -Message "Failed to infer SharePoint Admin URL from Graph: $($_.Exception.Message)"
					}
				}
			}
			elseif(-not $adminUrl) {
				Write-Verbose -Message "No Graph context available to infer SharePoint Admin URL."
				# We don't want to let the service 'Graph' be marked as connected, it's not.
				Remove-ZtConnectedService -Service 'Graph'
			}

			if (-not $adminUrl -and (Get-Command -Name Get-AzTenant -ErrorAction Ignore) -and ($tenantDetails = Get-AzTenant -ErrorAction Ignore)) {
				# Try to infer from Azure context
				try {
					# initial domain are <tenantName>.onmicrosoft.com as per https://learn.microsoft.com/en-us/entra/fundamentals/add-custom-domain
					$initialDomain = $tenantDetails.Domains.Where({ $_ -match '^[^.]+\.onmicrosoft\.com$' }, 1) | Select-Object -First 1
					if ($initialDomain) {
						$tenantName = $initialDomain.Split('.')[0]
						$adminUrl = "https://$tenantName-admin.sharepoint.com"
						Write-Verbose -Message "Inferred SharePoint Admin URL from Azure context: $adminUrl"
					}
				}
				catch {
					Write-Verbose -Message "Failed to infer SharePoint Admin URL from Azure context: $($_.Exception.Message)"
				}
			}
			elseif (-not $adminUrl) {
				Write-Verbose -Message "No Azure context available to infer SharePoint Admin URL."
				Remove-ZtConnectedService -Service 'Azure'
			}

			if (-not $adminUrl) {
				Write-Host -Object "   ❌ SharePoint Admin URL not provided and could not be inferred." -ForegroundColor Red
				Write-Host -Object "       The SharePoint tests will be skipped." -ForegroundColor Red
				Write-PSFMessage -Message "SharePoint Admin URL not provided and could not be inferred. Skipping SharePoint connection." -Level debug
				Remove-ZtConnectedService -Service 'SharePoint'
			}
			else {
				try {
					$pnpParams = @{
						Url         = $adminUrl
						ErrorAction = 'Stop'
					}

					# Use the shared function to resolve the PnP client ID.
					$pnpClientId = Get-ZtPnPClientId -ClientId $ClientId

					if ($ManagedIdentity) {
						$pnpParams.ManagedIdentity = $true
						Write-Host -Object '   Authenticating (managed identity)...' -ForegroundColor DarkGray
					}
					elseif ($ClientSecret) {
						$pnpParams.ClientId = $ClientId
						$pnpParams.ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
							[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
						)
						Write-Host -Object '   Authenticating (app-only client secret)...' -ForegroundColor DarkGray
					}
					elseif ($CertificateThumbprint -and $ClientId) {
						$pnpParams.ClientId  = $ClientId
						$pnpParams.Thumbprint = $CertificateThumbprint
						if ($TenantId) { $pnpParams.Tenant = $TenantId }
						Write-Host -Object '   Authenticating (app-only certificate)...' -ForegroundColor DarkGray
					}
					elseif ($Certificate -and $ClientId) {
						$pnpParams.ClientId  = $ClientId
						$pnpParams.Thumbprint = $Certificate.Certificate.Thumbprint
						if ($TenantId) { $pnpParams.Tenant = $TenantId }
						Write-Host -Object '   Authenticating (app-only certificate)...' -ForegroundColor DarkGray
					}
					elseif ($UseDeviceCode) {
						if (-not $pnpClientId) {
							# Pre-flight should have skipped this — safety net
							Write-Host -Object "   ❌ No Entra ID app registration for SharePoint. Set ENTRAID_APP_ID env var." -ForegroundColor Yellow
							Remove-ZtConnectedService -Service 'SharePoint'
							continue
						}

						# PnP.PowerShell's built-in DeviceLogin has a threading bug on Linux/PS7
						# (the MSAL callback can't call WriteWarning from a background thread).
						# Work around by doing the MSAL device code flow ourselves, then passing
						# the access token to Connect-PnPOnline.
						if (Read-ZtDeviceCodeSkip -ServiceName 'SharePoint') {
							Remove-ZtConnectedService -Service 'SharePoint'
							Write-Host -Object '   ⏭️  Skipped SharePoint — tests requiring SharePoint will be skipped.' -ForegroundColor Yellow
							continue
						}
						Write-Host -Object '   Requesting device code (watch for the sign-in prompt below)...' -ForegroundColor DarkGray
						Open-ZtDeviceCodeBrowser

						$pnpTenant = if ($TenantId) { $TenantId }
							elseif ($graphContext.TenantId) { $graphContext.TenantId }
							else { 'common' }

						# SharePoint resource scope: derive from admin URL
						$spHost = ([uri]$adminUrl).Host -replace '-admin\.', '.'
						$pnpScopes = [string[]]@("https://$spHost/.default")

						$pnpApp = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($pnpClientId).WithAuthority(
							"https://login.microsoftonline.com/$pnpTenant"
						).WithDefaultRedirectUri().Build()

						$pnpDeviceCodeCallback = [System.Func[Microsoft.Identity.Client.DeviceCodeResult, System.Threading.Tasks.Task]] {
							param($dcr)
							# Write directly to Console to avoid the cmdlet threading restriction
							[Console]::Error.WriteLine('')
							[Console]::Error.WriteLine("   $($dcr.Message)")
							[Console]::Error.WriteLine('')
							return [System.Threading.Tasks.Task]::CompletedTask
						}

						$pnpAuthResult = $pnpApp.AcquireTokenWithDeviceCode($pnpScopes, $pnpDeviceCodeCallback).ExecuteAsync().GetAwaiter().GetResult()
						$pnpParams.AccessToken = $pnpAuthResult.AccessToken
					}
					else {
						if (-not $pnpClientId) {
							# Pre-flight should have skipped this — safety net
							Write-Host -Object "   ❌ No Entra ID app registration for SharePoint. Set ENTRAID_APP_ID env var." -ForegroundColor Yellow
							Remove-ZtConnectedService -Service 'SharePoint'
							continue
						}
						$pnpParams.ClientId = $pnpClientId
						$pnpParams.Interactive = $true
					}

					Connect-PnPOnline @pnpParams
					Write-Host -Object "   ✅ Connected to SharePoint." -ForegroundColor Green
					Add-ZtConnectedService -Service 'SharePoint'
				}
				catch {
					Write-PSFMessage -Message ('Failed to connect to SharePoint: {0}' -f $_.Exception.Message) -Level Debug -ErrorRecord $_
					Write-Host -Object "   ❌ Failed to connect." -ForegroundColor Yellow
					Write-Host -Object "      Tests requiring SharePoint will be skipped." -ForegroundColor Yellow
					Write-Host -Object ("       Error details: {0}" -f $_.Exception.Message) -ForegroundColor Red
					if ($_.Exception.Message -match 'AADSTS700016|not found in the directory') {
						Write-Host -Object "       Hint: The Entra ID app is not registered or consented in this tenant." -ForegroundColor Yellow
						Write-Host -Object "       Register your own app: https://pnp.github.io/powershell/articles/registerapplication.html" -ForegroundColor Yellow
						Write-Host -Object "       Auth guide: https://pnp.github.io/powershell/articles/authentication.html" -ForegroundColor Yellow
						Write-Host -Object "       Set default Client ID: https://pnp.github.io/powershell/articles/defaultclientid.html" -ForegroundColor Yellow
						Write-Host -Object "       Then pass -ClientId or set ENTRAID_APP_ID / ENTRAID_CLIENT_ID / AZURE_CLIENT_ID env var." -ForegroundColor Yellow
						Write-Host -Object "       Minimum permission: SharePoint > Delegated > AllSites.FullControl" -ForegroundColor Yellow
						Write-Host -Object "       Ensure 'Allow public client flows' is enabled if using device code auth." -ForegroundColor Yellow
					}
					Remove-ZtConnectedService -Service 'SharePoint'
				}
			}
		}
	}

	# Show connection summary after all services have been processed
	$conn = Get-ZtConnectionState
	if ($conn.IsConnected) {
		Write-Host ''
		Write-Host '── Connection Status ──' -ForegroundColor DarkCyan
		Write-Host ''
		if ($conn.Account) {
			Write-Host "  Account   : $($conn.Account)" -ForegroundColor Gray
		}
		if ($conn.Tenant) {
			Write-Host "  Tenant    : $($conn.Tenant)" -ForegroundColor Gray
		}
		$cloudEnv = $conn.CloudEnvironment
		if ($cloudEnv) {
			Write-Host "  Cloud     : $($cloudEnv.DisplayName)" -ForegroundColor Magenta
		}
		Write-Host "  Connected : $($conn.Services -join ', ')" -ForegroundColor Gray
		Write-Host "  Token Cache: $(if ($UseTokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
		Show-ZtLicenseStatus
		Show-ZtPermissionStatus
		Write-Host ''
	}
	else {
		Write-Host ''
		Write-Host '── Connection Status ──' -ForegroundColor DarkCyan
		Write-Host ''
		Write-Host '  Not connected to any services.' -ForegroundColor Yellow
		Write-Host ''
	}
}
