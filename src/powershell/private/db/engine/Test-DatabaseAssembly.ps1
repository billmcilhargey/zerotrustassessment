function Test-DatabaseAssembly
{
	<#
	.SYNOPSIS
		Validates that DuckDB is installed and provides instruction on how to install.

	.DESCRIPTION
		Validates that DuckDB is installed and provides instruction on how to install.
		This is done by connecting to the automatic in-memory database.
		If that works, then the database binaries must be ready to work.

	.EXAMPLE
		PS C:\> Test-DatabaseAssembly

		Validates that DuckDB is installed and - if needed - provides instruction on how to install.
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

        # Check for specific DuckDB initialization error
        if ($_.Exception.Message -like "*The type initializer for 'DuckDB.NET*") {
            # Check if running on ARM architecture
            if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq 'Arm64') {
                Write-Host
                Write-Host "⚠️ UNSUPPORTED PLATFORM: Windows on ARM" -ForegroundColor Red
                Write-Host "ZeroTrustAssessment is not currently supported on Windows on ARM devices." -ForegroundColor Yellow
                Write-Host
            }
            elseif (-not $IsWindows) {
                $os = if ($IsMacOS) { 'macOS' } else { 'Linux' }
                $libName = if ($IsMacOS) { 'libduckdb.dylib' } else { 'libduckdb.so' }
                $libDir = Join-Path $PSScriptRoot '..' '..' '..' 'lib'
                $libDir = (Resolve-Path $libDir -ErrorAction SilentlyContinue)?.Path ?? $libDir
                Write-Host
                Write-Host "⚠️ PREREQUISITE REQUIRED: DuckDB native library ($libName) is missing" -ForegroundColor Red
                Write-Host "The assessment requires the DuckDB native library for $os." -ForegroundColor Yellow
                Write-Host "Expected location: $libDir/$libName" -ForegroundColor Yellow
                Write-Host "Download from: https://github.com/duckdb/duckdb/releases/tag/v1.1.1" -ForegroundColor Yellow
                Write-Host "  (get libduckdb-linux-amd64.zip, extract $libName into the lib folder)" -ForegroundColor Yellow
                Write-Host
            }
            else {
                Write-Host
                Write-Host "⚠️ PREREQUISITE REQUIRED: Visual C++ Redistributable is missing" -ForegroundColor Red
                Write-Host "ZeroTrustAssessment requires the Microsoft Visual C++ Redistributable to function properly." -ForegroundColor Yellow
                Write-Host "Please download and install it from: https://aka.ms/vcredist" -ForegroundColor Yellow
                Write-Host "After installation, restart PowerShell and try running the assessment again." -ForegroundColor Yellow
                Write-Host
            }
        }
        else {
            # Throw exceptions
            throw
        }
        return $false
    }
}
