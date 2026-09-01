Describe 'DuckDB native library resolution' {
    BeforeAll {
        $engineRoot = Join-Path $global:__testData.ModuleRoot 'private/db/engine'
        . (Join-Path $engineRoot 'Get-ZtDuckDbRuntimeIdentifier.ps1')
        . (Join-Path $engineRoot 'Import-ZtDuckDbNativeLibrary.ps1')
    }

    It 'maps <OperatingSystem> <Architecture> to <ExpectedRuntime>' -TestCases @(
        @{ OperatingSystem = 'Windows'; Architecture = 'X64'; ExpectedRuntime = 'win-x64' }
        @{ OperatingSystem = 'Windows'; Architecture = 'Arm64'; ExpectedRuntime = 'win-arm64' }
        @{ OperatingSystem = 'Linux'; Architecture = 'X64'; ExpectedRuntime = 'linux-x64' }
        @{ OperatingSystem = 'Linux'; Architecture = 'Arm64'; ExpectedRuntime = 'linux-arm64' }
        @{ OperatingSystem = 'macOS'; Architecture = 'X64'; ExpectedRuntime = 'osx' }
        @{ OperatingSystem = 'macOS'; Architecture = 'Arm64'; ExpectedRuntime = 'osx' }
    ) {
        param($OperatingSystem, $Architecture, $ExpectedRuntime)

        Get-ZtDuckDbRuntimeIdentifier -OperatingSystem $OperatingSystem -Architecture $Architecture |
            Should -Be $ExpectedRuntime
    }

    It 'rejects unsupported processor architectures' {
        { Get-ZtDuckDbRuntimeIdentifier -OperatingSystem Linux -Architecture X86 } |
            Should -Throw '*not supported on Linux X86*'
    }

    It 'reports the expected path when the current runtime asset is missing' {
        $emptyModuleRoot = Join-Path $TestDrive 'empty-module'
        New-Item -ItemType Directory -Path $emptyModuleRoot | Out-Null
        [AppDomain]::CurrentDomain.SetData('ZeroTrustAssessment.DuckDBNativeLibrary', $null)

        { Import-ZtDuckDbNativeLibrary -ModuleRoot $emptyModuleRoot } |
            Should -Throw '*DuckDB native library is missing for runtime*Expected path*'
    }

    It 'ships matching managed DuckDB assemblies' {
        $dataAssemblyPath = Join-Path $global:__testData.ModuleRoot 'lib/duckdb/1.2.1/DuckDB.NET.Data.dll'
        $bindingsAssemblyPath = Join-Path $global:__testData.ModuleRoot 'lib/duckdb/1.2.1/DuckDB.NET.Bindings.dll'

        Test-Path $dataAssemblyPath -PathType Leaf | Should -BeTrue
        Test-Path $bindingsAssemblyPath -PathType Leaf | Should -BeTrue
        [Reflection.AssemblyName]::GetAssemblyName($dataAssemblyPath).Version | Should -Be '1.2.1.0'
        [Reflection.AssemblyName]::GetAssemblyName($bindingsAssemblyPath).Version | Should -Be '1.2.1.0'
    }

    It 'ships native assets for every supported runtime' {
        $expectedAssets = @(
            'lib/runtimes/win-x64/native/duckdb.dll'
            'lib/runtimes/win-arm64/native/duckdb.dll'
            'lib/runtimes/linux-x64/native/libduckdb.so'
            'lib/runtimes/linux-arm64/native/libduckdb.so'
            'lib/runtimes/osx/native/libduckdb.dylib'
        )

        foreach ($relativePath in $expectedAssets) {
            Join-Path $global:__testData.ModuleRoot $relativePath |
                Should -Exist -Because "$relativePath is required for cross-platform assessment execution"
        }
    }
}
