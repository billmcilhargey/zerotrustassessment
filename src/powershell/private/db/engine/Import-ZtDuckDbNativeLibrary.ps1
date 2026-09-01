function Import-ZtDuckDbNativeLibrary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ModuleRoot
    )

    $runtimeIdentifier = Get-ZtDuckDbRuntimeIdentifier
    $libraryName = if ($IsWindows) { 'duckdb.dll' } elseif ($IsMacOS) { 'libduckdb.dylib' } else { 'libduckdb.so' }
    $libraryPath = Join-Path $ModuleRoot 'lib' 'runtimes' $runtimeIdentifier 'native' $libraryName

    $loadedLibrary = [AppDomain]::CurrentDomain.GetData('ZeroTrustAssessment.DuckDBNativeLibrary')
    if ($loadedLibrary -and $loadedLibrary.Path -eq $libraryPath) {
        return $loadedLibrary
    }

    if (-not (Test-Path -LiteralPath $libraryPath -PathType Leaf)) {
        throw "DuckDB native library is missing for runtime '$runtimeIdentifier'. Expected path: $libraryPath"
    }

    try {
        $nativeHandle = [System.Runtime.InteropServices.NativeLibrary]::Load($libraryPath)
    }
    catch {
        throw "DuckDB native library failed to load for runtime '$runtimeIdentifier' from '$libraryPath': $($_.Exception.Message)"
    }

    $loadedLibrary = [PSCustomObject]@{
        RuntimeIdentifier = $runtimeIdentifier
        Path = $libraryPath
        Handle = $nativeHandle
    }
    [AppDomain]::CurrentDomain.SetData('ZeroTrustAssessment.DuckDBNativeLibrary', $loadedLibrary)
    $loadedLibrary
}
