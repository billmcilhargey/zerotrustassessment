function Test-DatabaseAssembly
{
	<#
	.SYNOPSIS
		Validates that DuckDB is installed and auto-downloads the native library if missing.

	.DESCRIPTION
		Validates that DuckDB is installed and auto-downloads the native library if missing.
		This is done by connecting to the automatic in-memory database.
		If the native library is missing, it will be downloaded automatically from GitHub releases.

	.EXAMPLE
		PS> Test-DatabaseAssembly

		Validates that DuckDB is installed and - if needed - downloads and installs the native library.
	#>
	[CmdletBinding()]
	param ()

    try {
		# Try connecting with in memory db. Should always work if the assemblies can be loaded
        $null = Connect-Database -Transient
        return $true
    }
    catch {
        Write-PSFMessage 'Database binaries not ready to use' -ErrorRecord $_ -Tag DB -Level Debug # Log silently

        # Check for specific DuckDB initialization error (native lib missing)
        if ($_.Exception.Message -like "*The type initializer for 'DuckDB.NET*") {
            # Check if running on ARM Windows (unsupported)
            if ($IsWindows -and [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64') {
                Write-Host
                Write-Host "⚠️ UNSUPPORTED PLATFORM: Windows on ARM" -ForegroundColor Red
                Write-Host "ZeroTrustAssessment is not currently supported on Windows on ARM devices." -ForegroundColor Yellow
                Write-Host
                return $false
            }

            # Auto-download the native library
            Write-Host
            Write-Host "DuckDB native library not found. Downloading automatically..." -ForegroundColor Yellow
            try {
                Install-DuckDbNativeLibrary
                # Retry the connection after installing
                $null = Connect-Database -Transient
                Write-Host
                return $true
            }
            catch {
                # Check if the install succeeded but .NET cached the failed type initializer
                $libName = if ($IsWindows) { 'duckdb.dll' } elseif ($IsMacOS) { 'libduckdb.dylib' } else { 'libduckdb.so' }
                $libDir = Join-Path $script:ModuleRoot 'lib'
                $libPath = Join-Path $libDir $libName
                if (Test-Path $libPath) {
                    # Library was installed but .NET won't re-probe the native library in this session
                    Write-Host
                    Write-Host "✅ DuckDB native library installed successfully." -ForegroundColor Green
                    Write-Host "⚠️ PowerShell must be restarted to load the new library." -ForegroundColor Yellow
                    Write-Host "   Please close this PowerShell session and re-run the command." -ForegroundColor Yellow
                    Write-Host
                    return $false
                }

                $os = if ($IsWindows) { 'Windows' } elseif ($IsMacOS) { 'macOS' } else { 'Linux' }
                Write-Host
                Write-Host "⚠️ DuckDB native library ($libName) could not be installed automatically." -ForegroundColor Red
                Write-Host "The assessment requires the DuckDB native library for $os." -ForegroundColor Yellow
                Write-Host "Expected location: $libDir" -ForegroundColor Yellow
                Write-Host "Download from: https://github.com/duckdb/duckdb/releases/tag/$script:DuckDbVersion" -ForegroundColor Yellow
                Write-Host "  Extract $libName into the lib folder above." -ForegroundColor Yellow
                if ($IsWindows) {
                    Write-Host "  Also ensure the Visual C++ Redistributable is installed: https://aka.ms/vcredist" -ForegroundColor Yellow
                }
                Write-Host
                return $false
            }
        }
        else {
            # Throw exceptions
            throw
        }
    }
}
