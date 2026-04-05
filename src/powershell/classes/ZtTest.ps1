# Used in the Test-Functions to declare their metadata
class ZtTest : System.Attribute
{
	[string]$Category

	# Supported cloud environments for this test.
	# When specified, the test is automatically skipped in unsupported environments.
	# Values: Commercial, GCC, GCCHigh, DoD, China, Germany
	# Shorthand groups: Global (Commercial+GCC), USGovernment (GCC+GCCHigh+DoD), Sovereign (GCCHigh+DoD+China+Germany)
	# If omitted, the test runs in all environments.
	[string[]]$CloudEnvironment

	[ValidateSet('Low','Medium','High')][string]$ImplementationCost
	[string[]]$MinimumLicense

	[string[]]$CompatibleLicense

	# Required Microsoft Graph permission scopes for this test (e.g. 'Policy.Read.All').
	# Tests are pre-skipped when the connected session lacks any listed scope.
	[string[]]$RequiredScopes

	[string[]]$Service

	[string]$Pillar
	[ValidateSet('Low','Medium','High')][string]$RiskLevel
	[string]$SfiPillar
	[ValidateSet('Workforce','External')][string[]]$TenantType
	[int]$TestId
	[string]$Title
	[ValidateSet('Low','Medium','High')][string]$UserImpact

}
<#
Example Usage:

function Get-Test {
	[ZtTest(
		Category = 'Access control',
		ImplementationCost = 'Low',
		Pillar = 'Identity',
		RiskLevel = 'High',
		SfiPillar = "Protect identities and secrets",
		TenantType = ('Workforce', 'External'),
		TestId = 21786,
		Title = "User sign-in activity uses token protection",
		UserImpact = 'Low'
	)]
	[CmdletBinding()]
	param ()
}
#>
