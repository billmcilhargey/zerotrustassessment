Describe 'ZeroTrustAssessment Bash wrapper' {
    BeforeAll {
        $script:RepositoryRoot = (Resolve-Path (Join-Path $global:__testData.TestRoot '..')).Path
        $script:WrapperPath = Join-Path $script:RepositoryRoot 'ZeroTrustAssessment.sh'
        $script:WrapperContent = Get-Content -LiteralPath $script:WrapperPath -Raw
    }

    It 'exists at the repository root' {
        $script:WrapperPath | Should -Exist
    }

    It 'requires an existing PowerShell 7 installation instead of installing packages' {
        $script:WrapperContent | Should -Match 'PowerShell 7 or later must already be installed'
        $script:WrapperContent | Should -Not -Match 'apt-get|yum|brew|curl|wget|sudo'
    }

    It 'imports the source module manifest and validates exported module commands' {
        $script:WrapperContent | Should -Match 'src/powershell/ZeroTrustAssessment\.psd1'
        $script:WrapperContent | Should -Match 'Get-Command -Name \$CommandName -Module ZeroTrustAssessment'
    }

    It 'runs Connect-ZtAssessment before Invoke-ZtAssessment in the same session' {
        $script:WrapperContent | Should -Match ([regex]::Escape('[[ "$command_name" == ''Invoke-ZtAssessment'' ]]'))
        $script:WrapperContent | Should -Match 'Connect-ZtAssessment'
        $script:WrapperContent | Should -Match '& \$CommandName @CommandArguments'
    }
}
