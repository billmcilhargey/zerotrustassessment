<#
.SYNOPSIS
    Checks that user is not able to register apps.
#>

function Test-Assessment-21807 {
    [ZtTest(
    	Category = 'Application management',
    	ImplementationCost = 'Low',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'Medium',
    	SfiPillar = 'Protect engineering systems',
    	TenantType = ('Workforce'),
    	TestId = 21807,
    	Title = 'Creating new applications and service principals is restricted to privileged users',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = "Checking user app registration policy"
    Write-ZtProgress -Activity $activity

    $result = Invoke-ZtGraphRequest -RelativeUri "policies/authorizationPolicy" -ApiVersion v1.0

    $passed = $result.defaultUserRolePermissions.allowedToCreateApps -eq $false

    if ($passed) {
        $testResultMarkdown = "Tenant is configured to prevent users from registering applications.`n`n**[Users can register applications](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings)** → **No** ✅"
    }
    else {
        $testResultMarkdown = "Tenant allows all non-privileged users to register applications.`n`n**[Users can register applications](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings)** → **Yes** ❌"
    }

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}