Describe 'Test-Assessment-50002' {
    BeforeAll {
        $srcRoot = Join-Path $PSScriptRoot '../../src/powershell'

        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function global:Write-PSFMessage {}
        }
        if (-not (Get-Command Write-ZtProgress -ErrorAction SilentlyContinue)) {
            function global:Write-ZtProgress {}
        }
        if (-not (Get-Command Invoke-ZtAzureResourceGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-ZtAzureResourceGraphRequest {
                [CmdletBinding()]
                param([string] $Query)
            }
        }
        if (-not (Get-Command Get-SafeMarkdown -ErrorAction SilentlyContinue)) {
            function global:Get-SafeMarkdown { param($Text) return $Text }
        }
        if (-not (Get-Command Add-ZtTestResultDetail -ErrorAction SilentlyContinue)) {
            function global:Add-ZtTestResultDetail {
                param(
                    [string] $TestId, [bool] $Status, [string] $Result,
                    [string] $CustomStatus, [string] $SkippedBecause
                )
            }
        }

        if (-not ('ZtTest' -as [type])) {
            . (Join-Path $srcRoot 'classes/ZtTest.ps1')
        }
        . (Join-Path $srcRoot 'tests/Test-Assessment.50002.ps1')

        function global:New-TestSecurityConnector {
            param(
                [string] $Name = 'github-production',
                [string] $EnvironmentType = 'GitHubScope',
                [string] $HierarchyIdentifier = 'contoso',
                [int] $OfferingCount = 1
            )

            [PSCustomObject]@{
                name = $Name
                environmentName = $Name
                environmentType = $EnvironmentType
                hierarchyIdentifier = $HierarchyIdentifier
                offeringCount = $OfferingCount
                subscriptionId = '00000000-0000-0000-0000-000000000001'
            }
        }
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
        Mock Get-SafeMarkdown { param($Text) return $Text }

        $script:capturedStatus = $null
        $script:capturedResult = $null
        $script:capturedCustomStatus = $null
        $script:capturedSkippedBecause = $null

        Mock Add-ZtTestResultDetail {
            param($TestId, $Status, $Result, $CustomStatus, $SkippedBecause)
            $TestId | Should -Be '50002'
            $script:capturedStatus = $Status
            $script:capturedResult = $Result
            $script:capturedCustomStatus = $CustomStatus
            $script:capturedSkippedBecause = $SkippedBecause
        }
    }

    It 'passes and renders the discovered connector inventory' {
        Mock Invoke-ZtAzureResourceGraphRequest { New-TestSecurityConnector }

        Test-Assessment-50002

        Should -Invoke Invoke-ZtAzureResourceGraphRequest -Times 1 -Exactly -ParameterFilter {
            $Query -match "microsoft.security/securityconnectors" -and
            $Query -match 'array_length\(offerings\)'
        }
        $script:capturedStatus | Should -BeTrue
        $script:capturedResult | Should -Match 'GitHubScope'
        $script:capturedResult | Should -Match 'github-production'
        $script:capturedResult | Should -Match '\| 1 \| Pass \| Configured \|'
    }

    It 'fails when a connector has no offerings or hierarchy identifier' {
        Mock Invoke-ZtAzureResourceGraphRequest {
            New-TestSecurityConnector -EnvironmentType 'AwsAccount' -HierarchyIdentifier '' -OfferingCount 0
        }

        Test-Assessment-50002

        $script:capturedStatus | Should -BeFalse
        $script:capturedResult | Should -Match 'Hierarchy identifier is missing'
        $script:capturedResult | Should -Match 'No Defender offerings are configured'
    }

    It 'is not applicable when no connectors are discovered' {
        Mock Invoke-ZtAzureResourceGraphRequest { @() }

        Test-Assessment-50002

        $script:capturedSkippedBecause | Should -Be 'NotApplicable'
        $script:capturedResult | Should -Match 'No Microsoft Defender for Cloud security connectors'
    }

    It 'investigates Azure authorization failures' {
        Mock Invoke-ZtAzureResourceGraphRequest { throw 'Azure REST request failed with status 403: Forbidden' }

        { Test-Assessment-50002 } | Should -Not -Throw

        $script:capturedStatus | Should -BeFalse
        $script:capturedCustomStatus | Should -Be 'Investigate'
        $script:capturedResult | Should -Match 'authorization failed'
        $script:capturedResult | Should -Match 'Reader access'
    }
}
