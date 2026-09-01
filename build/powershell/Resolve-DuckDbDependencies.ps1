[CmdletBinding()]
param (
    [string]
    $ProjectPath = (Join-Path $PSScriptRoot '../../src/powershell/lib/DuckDB.Dependencies.csproj'),

    [string]
    $OutputPath = (Join-Path $PSScriptRoot '../../src/powershell/lib')
)

$ErrorActionPreference = 'Stop'
$projectFile = (Resolve-Path -LiteralPath $ProjectPath).Path
$outputDirectory = [IO.Path]::GetFullPath($OutputPath)
$project = [xml](Get-Content -LiteralPath $projectFile -Raw)
$packageReference = $project.Project.ItemGroup.PackageReference |
    Where-Object Include -eq 'DuckDB.NET.Data.Full' |
    Select-Object -First 1

if (-not $packageReference.Version) {
    throw "DuckDB.NET.Data.Full must have an explicit version in '$projectFile'."
}

$version = [string]$packageReference.Version
$restoreRoot = Join-Path ([IO.Path]::GetTempPath()) "ZeroTrustAssessment/DuckDB/$version"
$packagesPath = Join-Path $restoreRoot 'packages'
$intermediatePath = Join-Path $restoreRoot 'obj/'

dotnet restore $projectFile --locked-mode --packages $packagesPath -p:BaseIntermediateOutputPath=$intermediatePath
if ($LASTEXITCODE -ne 0) {
    throw "Failed to restore DuckDB.NET.Data.Full $version."
}
Write-Host "Restored DuckDB.NET.Data.Full $version from the locked dependency graph."

$dataPackage = Join-Path $packagesPath "duckdb.net.data.full/$version"
$bindingsPackage = Join-Path $packagesPath "duckdb.net.bindings.full/$version"
$managedOutput = Join-Path $outputDirectory "duckdb/$version"
New-Item -ItemType Directory -Path $managedOutput -Force | Out-Null

[IO.File]::Copy((Join-Path $dataPackage 'lib/netstandard2.0/DuckDB.NET.Data.dll'), (Join-Path $managedOutput 'DuckDB.NET.Data.dll'), $true)
[IO.File]::Copy((Join-Path $bindingsPackage 'lib/netstandard2.0/DuckDB.NET.Bindings.dll'), (Join-Path $managedOutput 'DuckDB.NET.Bindings.dll'), $true)
[IO.File]::Copy((Join-Path $dataPackage 'LICENSE.md'), (Join-Path $managedOutput 'LICENSE-DuckDB.NET.md'), $true)
[IO.File]::Copy((Join-Path $dataPackage 'LICENSE-DuckDB.txt'), (Join-Path $managedOutput 'LICENSE-DuckDB.txt'), $true)
Write-Host 'Staged DuckDB.NET managed assemblies and licenses.'

$nativeAssets = @{
    'win-x64' = 'duckdb.dll'
    'win-arm64' = 'duckdb.dll'
    'linux-x64' = 'libduckdb.so'
    'linux-arm64' = 'libduckdb.so'
    'osx' = 'libduckdb.dylib'
}

foreach ($runtimeIdentifier in $nativeAssets.Keys) {
    $libraryName = $nativeAssets[$runtimeIdentifier]
    $source = Join-Path $bindingsPackage "runtimes/$runtimeIdentifier/native/$libraryName"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "DuckDB.NET.Bindings.Full $version does not contain '$runtimeIdentifier/native/$libraryName'."
    }

    $nativeOutput = Join-Path $outputDirectory "runtimes/$runtimeIdentifier/native"
    New-Item -ItemType Directory -Path $nativeOutput -Force | Out-Null
    [IO.File]::Copy($source, (Join-Path $nativeOutput $libraryName), $true)
    Write-Host "Staged DuckDB native asset for $runtimeIdentifier."
}

Write-Host "DuckDB.NET $version dependencies resolved to '$outputDirectory'."
