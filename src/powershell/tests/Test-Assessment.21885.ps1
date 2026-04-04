<#
.SYNOPSIS
    Checking App registrations must not have reply URLs containing *.azurewebsites.net
#>

function Test-Assessment-21885 {
    [ZtTest(
    	Category = 'Application management',
    	ImplementationCost = 'High',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect engineering systems',
    	TenantType = ('Workforce','External'),
    	TestId = 21885,
    	Title = 'App registrations use safe redirect URIs',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param($Database)

    # NOTE: This test is very similar to
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = "Checking app registrations use safe redirect URIs "
    Write-ZtProgress -Activity $activity -Status "Getting policy"


    $results = Get-ZtAppWithUnsafeRedirectUris -Database $Database -Type 'Application'

    $passed = $results.Passed
    $testResultMarkdown = $results.TestResultMarkdown

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}