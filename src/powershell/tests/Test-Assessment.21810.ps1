<#
.SYNOPSIS

#>

function Test-Assessment-21810 {
    [ZtTest(
    	Category = 'Access control',
    	ImplementationCost = 'Medium',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'Medium',
    	SfiPillar = 'Protect engineering systems',
    	TenantType = ('Workforce','External'),
    	TestId = 21810,
    	RequiredScopes = "Directory.Read.All",
    	Title = 'Resource-specific consent is restricted',
    	UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = "Checking Resource-Specific Consent is restricted"
    Write-ZtProgress -Activity $activity -Status "Getting resource-specific consent status"

    $result = Get-MgBetaTeamRscConfiguration

    $testResultMarkdown = ""

    if ($result.State -eq 'EnabledForPreApprovedAppsOnly' -or $result.State -eq 'DisabledForAllApps') {
        $passed = $true
        $testResultMarkdown += "Resource-Specific Consent is restricted.`n`n%TestResult%"
    }
    else {
        $passed = $false
        $testResultMarkdown += "Resource-Specific Consent is not restricted.`n`n%TestResult%"
    }

    $mdInfo = "The current state is {0}.`n" -f $result.State

    # Replace the placeholder with the detailed information
    $testResultMarkdown = $testResultMarkdown -replace "%TestResult%", $mdInfo

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}