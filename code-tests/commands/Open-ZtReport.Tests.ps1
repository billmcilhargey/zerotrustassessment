Describe 'Open-ZtReport' {
    BeforeAll {
        . (Join-Path $global:__testData.ModuleRoot 'private/utility/report/Open-ZtReport.ps1')
        if (-not (Get-Command Write-PSFMessage -ErrorAction SilentlyContinue)) {
            function global:Write-PSFMessage {}
        }
    }

    BeforeEach {
        Mock Write-PSFMessage {}
        $script:openedReport = $null
        $script:reportPath = Join-Path $TestDrive 'assessment report.html'
        Set-Content -LiteralPath $script:reportPath -Value '<html></html>'
    }

    It 'opens an existing report and returns true' {
        $result = Open-ZtReport -Path $script:reportPath -OpenAction {
            param($Path)
            $script:openedReport = $Path
        }

        $result | Should -BeTrue
        $script:openedReport | Should -Be $script:reportPath
    }

    It 'returns false without throwing when the opener fails' {
        $result = Open-ZtReport -Path $script:reportPath -OpenAction { throw 'No browser available' }

        $result | Should -BeFalse
        Should -Invoke Write-PSFMessage -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*could not be opened automatically*'
        }
    }

    It 'does not invoke an opener when the report is missing' {
        $script:openerCalled = $false
        $result = Open-ZtReport -Path (Join-Path $TestDrive 'missing.html') -OpenAction {
            $script:openerCalled = $true
        }

        $result | Should -BeFalse
        $script:openerCalled | Should -BeFalse
        Should -Invoke Write-PSFMessage -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*was not found*'
        }
    }
}
