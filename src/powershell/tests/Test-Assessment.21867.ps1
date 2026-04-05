<#
.SYNOPSIS
    Tests if all enterprise applications with high privilege permissions have at least two owners.
#>

function Test-Assessment-21867 {
    [ZtTest(
    	Category = 'Application management',
    	ImplementationCost = 'Medium',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Monitor and detect cyberthreats',
    	TenantType = ('Workforce','External'),
    	TestId = 21867,
    	RequiredScopes = "Directory.Read.All",
    	Title = 'Enterprise applications with high privilege Microsoft Graph API permissions have owners',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    Test-ZtApplicationOwnership `
        -Database $Database `
        -TestId '21867' `
        -PrivilegeLevel 'High' `
        -PassMessage 'All enterprise applications with high privilege have owners' `
        -FailMessage 'Not all enterprise applications with high privilege permissions have owners' `
        -ReportTitle 'Applications lacking sufficient owners' `
        -Activity 'Checking if enterprise applications with high privilege permissions have owners'
}
