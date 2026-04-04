Describe "Test-Assessment-35007" {
    BeforeAll {
        $here = $PSScriptRoot
        $srcRoot = Join-Path $here "../../src/powershell"

        # Mock external module dependencies if they are not present
        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function Write-PSFMessage {}
        }

        # Load the class
        $classPath = Join-Path $srcRoot "classes/ZtTest.ps1"
        if (-not ("ZtTest" -as [type])) {
            . $classPath
        }

        # Load shared helper
        . (Join-Path $srcRoot "private/tests-shared/Get-ZtSharePointTenantSettings.ps1")

        # Load the SUT
        $sut = Join-Path $srcRoot "tests/Test-Assessment.35007.ps1"
        . $sut

        # Setup output file
        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.35007.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
        "# Test Results for 35007`n" | Set-Content $script:outputFile
    }

    # Mock common module functions
    BeforeEach {
        Mock Write-PSFMessage {}
        Mock Write-ZtProgress {}
    }

    Context "When querying SharePoint tenant settings fails" {
        It "Should return Investigate status" {
            Mock Get-ZtSharePointTenantSettings { [PSCustomObject]@{ Tenant = $null; ErrorMessage = 'Connection error' } }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: Error querying settings`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35007

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $Result -match "Unable to query SharePoint Tenant Settings"
            }
        }
    }

    Context "When IRM is enabled (Fail)" {
        It "Should return Fail status" {
            Mock Get-ZtSharePointTenantSettings {
                [PSCustomObject]@{ Tenant = [PSCustomObject]@{ IrmEnabled = $true }; ErrorMessage = $null }
            }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: IRM enabled`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35007

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $Result -match 'IrmEnabled: True'
            }
        }
    }

    Context "When IRM is disabled (Pass)" {
        It "Should return Pass status" {
            Mock Get-ZtSharePointTenantSettings {
                [PSCustomObject]@{ Tenant = [PSCustomObject]@{ IrmEnabled = $false }; ErrorMessage = $null }
            }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: IRM disabled`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35007

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $true -and $Result -match 'IrmEnabled: False'
            }
        }
    }
}
