# Initialize Module Variables
## Update Clear-ModuleVariable function in private/Clear-ModuleVariable.ps1 if you add new variables here

# Read module version from the manifest once, including any prerelease suffix (e.g. "2.1.8-preview")
$manifest = Import-PSFPowerShellDataFile -Path (Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1')
$moduleVersion = $manifest.ModuleVersion
$prerelease = $manifest.PrivateData.PSData.Prerelease
if ($prerelease) { $moduleVersion = "$moduleVersion-$prerelease" }

$script:__ZtSession = @{
	# A DCO dictionary is the same threadsafe dictionary across all runspaces, allowing parallelized checks to write results to the same store safely
	GraphCache   = Set-PSFDynamicContentObject -Name "ZtAssessment.GraphCache" -Dictionary -PassThru
	AzureCache   = Set-PSFDynamicContentObject -Name "ZtAssessment.AzureCache" -Dictionary -PassThru
	GraphBaseUri = $null
	TestMeta     = @()
	TestResultDetail = Set-PSFDynamicContentObject -Name "ZtAssessment.TestResultDetails" -Dictionary -PassThru
	TestStatistics = Set-PSFDynamicContentObject -Name "ZtAssessment.TestStatistics" -Dictionary -PassThru
	TenantInfo = Set-PSFDynamicContentObject -Name "ZtAssessment.TenantInfo" -Dictionary -PassThru
	ModuleVersion = $moduleVersion
}

$script:__ZtThrottling = Set-PSFDynamicContentObject -Name "ZtAssessment.Throttles" -Dictionary -PassThru
## Intune API Limits: 1000 / 20 seconds
if (-not $script:__ZtThrottling.Value['deviceManagement']) {
	$script:__ZtThrottling.Value['deviceManagement'] = New-PSFThrottle -Interval 20s -Limit 1000
}

# Canonical list of allowed/supported service names, in display order.
# Referenced by service-detection, audit, connection, and validation code.
$script:AllowedServices = @('Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')

# Services that require Windows (Windows PowerShell modules not available on Linux/macOS).
$script:WindowsOnlyServices = @('AipService')

# Services that do not support device code authentication flow.
$script:NoDeviceCodeServices = @('SecurityCompliance')

# Tracks which services are currently connected. Managed by Add-ZtConnectedService / Remove-ZtConnectedService.
# Must be initialized as an array to avoid string-concatenation when using +=.
$script:ConnectedService = @()

# Tracks detected license SKUs for the tenant. Set during Connect-ZtAssessment.
[string[]] $script:CurrentLicense = @()

# Cached service plan IDs for license checks. Populated on first call to Get-ZtLicense/Get-ZtLicenseInformation.
$script:__ZtLicensePlanIds = $null

# DuckDB native library version — authoritative value lives in PSFConfig 'DuckDB.Version'.
# This variable is a convenience alias read from config at module load time.
$script:DuckDbVersion = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.DuckDB.Version' -Fallback 'v1.1.1'
$script:DuckDbReleaseBaseUrl = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.DuckDB.ReleaseBaseUrl' -Fallback 'https://github.com/duckdb/duckdb/releases/download'

# The Database Connection used by Invoke-DatabaseQuery. Established by Connect-Database, cleared by Disconnect-Database
$script:_DatabaseConnection = $null

# Load the graph scope risk mapping. Used in Get-GraphPermissionRisk.
$graphPermissionsTable = Import-Csv -Path (Join-Path -Path $Script:ModuleRoot -ChildPath 'assets/aadconsentgrantpermissiontable.csv') -Delimiter ','
$Script:_GraphPermissions = @{}
$script:_GraphPermissionsHash = @{}
foreach ($perm in $graphPermissionsTable) {
	$key = $perm.Type + $perm.Permission
	$script:_GraphPermissionsHash[$key] = $perm
	if ($perm.permission -match "\.") {
		$key = $perm.Type + $perm.Permission.Split(".")[0]
		$script:_GraphPermissionsHash[$key] = $perm
	}
}
