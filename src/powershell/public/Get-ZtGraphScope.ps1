<#
 .Synopsis
    Returns the list of Graph scopes required to run the Zero Trust Assessment.

 .Description
    Use this cmdlet to connect to Microsoft Graph using Connect-MgGraph.

 .Example
    Connect-MgGraph -Scopes (Get-ZtGraphScope)

    Connects to Microsoft Graph with the required scopes to run Zero Trust Assessment.
#>

Function Get-ZtGraphScope {
	<#
	.SYNOPSIS
		List the Graph scopes needed for the ZeroTrustAssessment.

	.DESCRIPTION
		List the Graph scopes needed for the ZeroTrustAssessment.

	.EXAMPLE
		PS> Get-ZtGraphScope

		List the Graph scopes needed for the ZeroTrustAssessment.
	#>
    [CmdletBinding()]
    param()

    # Any changes made to these permission scopes should be reflected in the documentation.
    # /zerotrustassessment/website/docs/sections/permissions.md

    # Default read-only scopes required for the assessment.
    # Principle of least privilege: only request what is needed, all scopes are .Read.
    # Policy.Read.ConditionalAccess is NOT listed because Policy.Read.All already covers it.
    $scopes = @( #IMPORTANT: Read note above before adding any new scopes.
        'AuditLog.Read.All'
        'CrossTenantInformation.ReadBasic.All'
        'DeviceManagementApps.Read.All'
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementRBAC.Read.All'
        'DeviceManagementServiceConfig.Read.All'
        'Directory.Read.All'
        'DirectoryRecommendations.Read.All'
        'EntitlementManagement.Read.All'
        'IdentityRiskEvent.Read.All'
        'IdentityRiskyServicePrincipal.Read.All'
        'IdentityRiskyUser.Read.All'
        'NetworkAccess.Read.All'
        'Policy.Read.All'
        'Policy.Read.PermissionGrant'
        'PrivilegedAccess.Read.AzureAD'
        'Reports.Read.All'
        'RoleManagement.Read.All'
        'UserAuthenticationMethod.Read.All'
    )

    $scopes | Sort-Object -Unique
}
