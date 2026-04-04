<#
.SYNOPSIS

#>

function Test-Assessment-21803 {
    [ZtTest(
    	Category = 'Credential management',
    	ImplementationCost = 'Medium',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect identities and secrets',
    	TenantType = ('Workforce','External'),
    	TestId = 21803,
    	Title = 'Migrate from legacy MFA and SSPR policies',
    	UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = 'Checking Migrate from legacy MFA and SSPR policies'
    Write-ZtProgress -Activity $activity -Status 'Getting policy'

    $result = Invoke-ZtGraphRequest -RelativeUri 'policies/authenticationMethodsPolicy' -ApiVersion beta
    if ($null -eq $result) {
        Write-ZtProgress -Activity $activity -Status 'Failed to retrieve policy'
        Add-ZtTestResultDetail -SkippedBecause NotApplicable
        return
    }

    # Check if combined security information registration is enabled in the tenant
    if ($result.policyMigrationState -eq 'migrationComplete' -or $null -eq $result.policyMigrationState) {
        $passed = $true
        if ($null -eq $result.policyMigrationState) {
            $testResultMarkdown = "No legacy policies to migrate. This tenant is using modern authentication methods.`n`n"
        }
        else {
            $testResultMarkdown = "Combined registration is enabled.`n`n"
        }
    }
    else {
        $passed = $false
        $testResultMarkdown = "Combined registration is not enabled.`n`n"
    }

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}