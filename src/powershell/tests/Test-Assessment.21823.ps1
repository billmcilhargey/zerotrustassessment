<#
.SYNOPSIS
    Guest self-service sign-up via user flow is disabled
#>

function Test-Assessment-21823{
    [ZtTest(
    	Category = 'External collaboration',
    	ImplementationCost = 'Low',
    	MinimumLicense = ('Free'),
    	Pillar = 'Identity',
    	RiskLevel = 'Medium',
    	SfiPillar = 'Protect tenants and isolate production systems',
    	TenantType = ('Workforce'),
    	TestId = 21823,
    	RequiredScopes = "Directory.Read.All",
    	Title = 'Guest self-service sign-up via user flow is disabled',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = "Checking Guest self-service sign-up via user flow is disabled"
    Write-ZtProgress -Activity $activity -Status "Getting policy"

    if((Get-MgContext).Environment -ne 'Global')
    {
        Write-PSFMessage "This test is only applicable to the Global environment." -Tag Test -Level VeryVerbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable
        return
    }

    $authFlowPolicy = Invoke-ZtGraphRequest -RelativeUri "policies/authenticationFlowsPolicy" -ApiVersion v1.0
    #endregion Data Collection

    #region Assessment Logic
    $passed = $authFlowPolicy.selfServiceSignUp.isEnabled -eq $false

    if ($passed) {
        $testResultMarkdown = "[Guest self-service sign up via user flow](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/Settings/menuId/ExternalIdentitiesGettingStarted) is disabled.`n"
    }
    else {
        $testResultMarkdown = "[Guest self-service sign up via user flow](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/Settings/menuId/ExternalIdentitiesGettingStarted) is enabled.`n"
    }

    #endregion Assessment Logic

    #region Report Generation
    $activity = "Checking Guest self-service sign-up via user flow is disabled"
    Write-ZtProgress -Activity $activity -Status "Getting policy"

    #endregion Report Generation

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}