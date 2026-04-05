<#
.SYNOPSIS
    Checking App registrations must not have dangling or abandoned domain redirect URIs
#>

function Test-Assessment-21888{
    [ZtTest(
    	Category = 'Application management',
    	ImplementationCost = 'Low',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect engineering systems',
    	TenantType = ('Workforce','External'),
    	TestId = 21888,
    	RequiredScopes = "Directory.Read.All",
    	Title = 'App registrations must not have dangling or abandoned domain redirect URIs',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Database
    )

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = "Checking App registrations must not have dangling or abandoned domain redirect URIs"
    Write-ZtProgress -Activity $activity -Status "Getting policy"

    $results = Get-ZtAppWithUnsafeRedirectUris -Database $Database -Type 'Application' -DnsCheckOnly

    $passed = $results.Passed
    $testResultMarkdown = $results.TestResultMarkdown


    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}