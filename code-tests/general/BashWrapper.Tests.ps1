Describe 'ZeroTrustAssessment Bash wrapper' {
    BeforeAll {
        $script:RepositoryRoot = (Resolve-Path (Join-Path $global:__testData.TestRoot '..')).Path
        $script:WrapperPath = Join-Path $script:RepositoryRoot 'ZeroTrustAssessment.sh'
        $script:WrapperContent = Get-Content -LiteralPath $script:WrapperPath -Raw
    }

    It 'exists at the repository root' {
        $script:WrapperPath | Should -Exist
    }

    It 'offers only an explicit per-user PowerShell installation' {
        $script:WrapperContent | Should -Match '--install-pwsh'
        $script:WrapperContent | Should -Match 'read -r -p .*\[y/N\]'
        $script:WrapperContent | Should -Match 'dotnet tool install --global PowerShell'
        $script:WrapperContent | Should -Match 'dotnet tool update --global PowerShell'
        $script:WrapperContent | Should -Match '\[\[ -e "\$PWSH" \]\]'
        $script:WrapperContent | Should -Not -Match 'dotnet tool list'
        $script:WrapperContent | Should -Not -Match 'apt-get|yum|brew|curl|wget|sudo'
    }

    It 'refuses elevated installation and reuses the user tool directory' {
        $script:WrapperContent | Should -Match 'Refusing to install PowerShell as root'
        $script:WrapperContent | Should -Match '\$HOME/\.dotnet/tools/pwsh'
    }

    It 'validates PowerShell 7 and launches the selected executable' {
        $script:WrapperContent | Should -Match '\$PSVersionTable\.PSVersion\.Major'
        $script:WrapperContent | Should -Match '\^\[0-9\]\+\$'
        $script:WrapperContent | Should -Match 'installation could not be verified'
        $script:WrapperContent | Should -Match 'exec "\$PWSH" -NoProfile -Command'
    }

    It 'requires explicit installation approval when no terminal is attached' {
        $script:WrapperContent | Should -Match 'Re-run with --install-pwsh'
        $script:WrapperContent | Should -Match '\[\[ "\$\{INSTALL_PWSH:-0\}" -ne 1 && -t 0 \]\]'
    }

    It 'imports the source module manifest and delegates to one PowerShell process' {
        $script:WrapperContent | Should -Match 'src/powershell/ZeroTrustAssessment\.psd1'
        ([regex]::Matches($script:WrapperContent, '(?m)^\s*.*\bexec "\$PWSH"')).Count | Should -Be 1
    }

    It 'executes only the explicitly supplied PowerShell command text' {
        $script:WrapperContent | Should -Match 'ZTA_COMMAND="\$1"'
        $script:WrapperContent | Should -Match '\[scriptblock\]::Create\(\$env:ZTA_COMMAND\)'
        $script:WrapperContent | Should -Not -Match ([regex]::Escape('[[ "$command_name" == ''Invoke-ZtAssessment'' ]]'))
        $script:WrapperContent | Should -Not -Match 'Get-Command -Name \$CommandName'
    }
}
