Describe "Test-Assessment-35006" {
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
        $sut = Join-Path $srcRoot "tests/Test-Assessment.35006.ps1"
        . $sut

        # Setup output file
        $script:outputFile = Join-Path $here "../TestResults/Report-Test-Assessment.35006.md"
        $outputDir = Split-Path $script:outputFile
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
        "# Test Results for 35006`n" | Set-Content $script:outputFile
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

            Test-Assessment-35006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $Result -match "Unable to query SharePoint Tenant Settings"
            }
        }
    }

    Context "When PDF labeling support is enabled" {
        It "Should return Pass status" {
            Mock Get-ZtSharePointTenantSettings {
                [PSCustomObject]@{ Tenant = [PSCustomObject]@{ EnableSensitivityLabelforPDF = $true }; ErrorMessage = $null }
            }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: PDF labeling enabled`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $true -and $Result -match 'EnableSensitivityLabelforPDF: True'
            }
        }
    }

    Context "When PDF labeling support is disabled" {
        It "Should return Fail status" {
            Mock Get-ZtSharePointTenantSettings {
                [PSCustomObject]@{ Tenant = [PSCustomObject]@{ EnableSensitivityLabelforPDF = $false }; ErrorMessage = $null }
            }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: PDF labeling disabled`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $Result -match 'EnableSensitivityLabelforPDF: False'
            }
        }
    }

    Context "When Get-ZtSharePointTenantSettings returns null tenant" {
        It "Should return Fail status" {
            Mock Get-ZtSharePointTenantSettings { [PSCustomObject]@{ Tenant = $null; ErrorMessage = $null } }
            Mock Add-ZtTestResultDetail {
                param($TestId, $Title, $Status, $Result)
                "## Scenario: Get-PnPTenant returns null`n`n$Result`n" | Add-Content $script:outputFile
            }

            Test-Assessment-35006

            Should -Invoke Add-ZtTestResultDetail -ParameterFilter {
                $Status -eq $false -and $Result -match 'EnableSensitivityLabelforPDF: False'
            }
        }
    }
}
