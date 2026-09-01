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
    $database = $null
    try {
		# Try connecting with in memory db. Should always work if the assemblies can be loaded
        $database = Connect-Database -Transient
        return $true
    }
    catch {
        Write-PSFMessage 'Database binaries not ready to use' -ErrorRecord $_ -Tag DB -Level Debug # Log silently

        # Check for a native DuckDB initialization error and provide platform-specific guidance.
        if ($_.Exception.Message -like "*The type initializer for 'DuckDB.NET*") {
            $runtimeIdentifier = Get-ZtDuckDbRuntimeIdentifier
            Write-Host
            Write-Host "⚠️ DuckDB failed to initialize for runtime $runtimeIdentifier" -ForegroundColor Red
            if ($IsWindows) {
                Write-Host "⚠️ PREREQUISITE REQUIRED: Visual C++ Redistributable is missing" -ForegroundColor Red
                Write-Host "ZeroTrustAssessment requires the Microsoft Visual C++ Redistributable to function properly." -ForegroundColor Yellow
                Write-Host "Please download and install it from: https://aka.ms/vcredist" -ForegroundColor Yellow
                Write-Host "After installation, restart PowerShell and try running the assessment again." -ForegroundColor Yellow
            }
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host
        }
        else {
            # Throw exceptions
            throw
        }
        return $false
    }
    finally {
        if ($database) {
            Disconnect-Database -Database $database
        }
    }
}
