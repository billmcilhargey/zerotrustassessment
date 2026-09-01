function Test-Assessment-50002 {
    [ZtTest(
        Category = 'Microsoft Defender for Cloud',
        ImplementationCost = 'Low',
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        Service = ('Azure'),
        SfiPillar = 'Protect tenants and isolate production systems',
        TenantType = ('Workforce'),
        TestId = 50002,
        Title = 'Microsoft Defender for Cloud connectors are configured completely',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage 'Start' -Tag Test -Level VeryVerbose
    $activity = 'Checking Microsoft Defender for Cloud connectors'
    Write-ZtProgress -Activity $activity -Status 'Discovering security connectors'

    $connectorQuery = @'
resources
| where type =~ 'microsoft.security/securityconnectors'
| extend environmentType = tostring(properties.environmentData.environmentType)
| extend environmentName = tostring(properties.environmentName)
| extend hierarchyIdentifier = tostring(properties.hierarchyIdentifier)
| extend offerings = properties.offerings
| extend offeringCount = array_length(offerings)
| project id, name, resourceGroup, subscriptionId, location, environmentType, environmentName, hierarchyIdentifier, offeringCount
| order by environmentType asc, environmentName asc, name asc
'@

    try {
        $connectors = @(Invoke-ZtAzureResourceGraphRequest -Query $connectorQuery)
    }
    catch {
        $httpStatusCode = $null
        if ($_.Exception.Message -match 'with status (\d+):') {
            $httpStatusCode = [int]$Matches[1]
        }

        $result = if ($httpStatusCode -in @(401, 403)) {
            'The connector inventory could not be read because Azure authorization failed. Verify Reader access on every subscription that owns a Defender for Cloud connector, then run the assessment again.'
        }
        else {
            'The connector inventory could not be read because Azure Resource Graph returned an unexpected error. Run the assessment again after verifying Azure Resource Graph availability.'
        }

        Add-ZtTestResultDetail -TestId '50002' -Status $false -CustomStatus 'Investigate' -Result $result
        return
    }

    if ($connectors.Count -eq 0) {
        Add-ZtTestResultDetail -TestId '50002' -SkippedBecause NotApplicable -Result 'No Microsoft Defender for Cloud security connectors were discovered. Confirm whether AWS, GCP, Azure DevOps, GitHub, GitLab, Docker Hub, or JFrog environments are expected in this tenant.'
        return
    }

    $evaluatedConnectors = foreach ($connector in $connectors) {
        $environmentType = $connector.environmentType
        $environmentName = $connector.environmentName
        if ([string]::IsNullOrWhiteSpace($environmentName)) {
            $environmentName = $connector.name
        }

        $issues = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrWhiteSpace($environmentType)) {
            $issues.Add('Environment type is missing')
        }
        if ([string]::IsNullOrWhiteSpace($connector.hierarchyIdentifier)) {
            $issues.Add('Hierarchy identifier is missing')
        }
        if ([int]$connector.offeringCount -le 0) {
            $issues.Add('No Defender offerings are configured')
        }

        [PSCustomObject]@{
            EnvironmentType = $environmentType
            EnvironmentName = $environmentName
            SubscriptionId = $connector.subscriptionId
            OfferingCount = [int]$connector.offeringCount
            Status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
            Details = $issues -join '; '
        }
    }

    $failedConnectors = @($evaluatedConnectors | Where-Object Status -eq 'Fail')
    $passed = $failedConnectors.Count -eq 0
    $result = if ($passed) {
        'All discovered Microsoft Defender for Cloud connectors include an environment type, hierarchy identifier, and at least one Defender offering.'
    }
    else {
        'One or more Microsoft Defender for Cloud connectors are incomplete and might not provide the expected multicloud or DevOps coverage.'
    }

    $tableRows = foreach ($connector in $evaluatedConnectors) {
        $environmentType = Get-SafeMarkdown $connector.EnvironmentType
        $environmentName = Get-SafeMarkdown $connector.EnvironmentName
        $subscriptionId = Get-SafeMarkdown $connector.SubscriptionId
        $details = if ($connector.Status -eq 'Pass') { 'Configured' } else { Get-SafeMarkdown $connector.Details }
        $status = if ($connector.Status -eq 'Pass') { 'Pass' } else { 'Fail' }
        "| $environmentType | $environmentName | $subscriptionId | $($connector.OfferingCount) | $status | $details |"
    }

    $result += @"

## [Defender for Cloud environment settings](https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings)

| Environment type | Environment | Connector subscription | Offerings | Status | Details |
| :--------------- | :---------- | :--------------------- | --------: | :----- | :------ |
$($tableRows -join "`n")
"@

    Add-ZtTestResultDetail -TestId '50002' -Status $passed -Result $result
}
