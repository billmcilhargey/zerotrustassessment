<#
.SYNOPSIS

#>

function Test-Assessment-21804 {
    [ZtTest(
    	Category = 'Credential management',
    	ImplementationCost = 'Medium',
    	MinimumLicense = ('P1'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect identities and secrets',
    	TenantType = ('Workforce','External'),
    	TestId = 21804,
    	RequiredScopes = ("Directory.Read.All", "Policy.Read.All"),
    	Title = 'SMS and Voice Call authentication methods are disabled',
    	UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if ( -not (Get-ZtLicense EntraIDP1) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP1
        return
    }

    $activity = "Checking Weak authentication methods are disabled"
    Write-ZtProgress -Activity $activity -Status "Getting policy"

 $authMethodsPolicy = Get-ZtAuthenticationMethodsPolicy
$matchedMethods = $authMethodsPolicy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Sms' -or $_.id -eq 'Voice' }

$testResultMarkdown = ""

# If the "state" property of any of the matched methods is "enabled", fail the test. Else pass the test.
if ($matchedMethods.state -contains 'enabled') {
    $passed = $false
    $testResultMarkdown += "Found weak authentication methods that are still enabled.`n`n%TestResult%"
}
else {
    $passed = $true
    $testResultMarkdown += "SMS and voice calls authentication methods are disabled in the tenant.`n`n%TestResult%"
}

    # Build the detailed sections of the markdown

    # Define variables to insert into the format string
    $reportTitle = "Weak authentication methods"
    $tableRows = ""

        # Create a here-string with format placeholders {0}, {1}, etc.
        $formatTemplate = @'
## {0}
| Method ID | Is method weak? | State |
| :-------- | :-------------- | :---- |
{1}
'@

        foreach ($method in $matchedMethods) {

            $tableRows += @"
| $($method.id) | Yes | $($method.state) |`n
"@
        }

        # Format the template by replacing placeholders with values
        $mdInfo = $formatTemplate -f $reportTitle, $tableRows

    # Replace the placeholder with the detailed information
    $testResultMarkdown = $testResultMarkdown -replace "%TestResult%", $mdInfo


    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}
