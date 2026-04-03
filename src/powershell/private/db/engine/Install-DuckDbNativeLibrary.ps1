function Install-DuckDbNativeLibrary {
	<#
	.SYNOPSIS
		Downloads and installs the DuckDB native library for the current platform.

	.DESCRIPTION
		Detects the current OS and architecture, downloads the appropriate DuckDB native
		library from GitHub releases, and extracts it into the module's lib/ directory.

		This is called automatically by Test-DatabaseAssembly when the native library
		is missing. The managed .NET bindings (DuckDB.NET.Data.dll, DuckDB.NET.Bindings.dll)
		are included in the module; only the platform-specific native library needs to be
		downloaded.

	.PARAMETER LibPath
		The directory to install the native library into. Defaults to the module's lib/ folder.

	.PARAMETER Force
		Re-download even if the native library already exists.

	.EXAMPLE
		PS> Install-DuckDbNativeLibrary

		Downloads the appropriate native library for the current platform.
	#>
	[CmdletBinding()]
	param (
		[string]
		$LibPath = (Join-Path $script:ModuleRoot 'lib'),

		[switch]
		$Force
	)

	$version = $script:DuckDbVersion
	$releaseBaseUrl = $script:DuckDbReleaseBaseUrl

	# Determine platform-specific file and download URL
	if ($IsWindows) {
		$libName = 'duckdb.dll'
		$zipName = 'libduckdb-windows-amd64.zip'
	}
	elseif ($IsMacOS) {
		$libName = 'libduckdb.dylib'
		$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
		$zipName = if ($arch -eq 'Arm64') { 'libduckdb-osx-universal.zip' } else { 'libduckdb-osx-universal.zip' }
	}
	else {
		# Linux
		$libName = 'libduckdb.so'
		$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
		$zipName = if ($arch -eq 'Arm64') { 'libduckdb-linux-aarch64.zip' } else { 'libduckdb-linux-amd64.zip' }
	}

	$targetPath = Join-Path $LibPath $libName

	if ((Test-Path $targetPath) -and -not $Force) {
		Write-PSFMessage -Level Verbose -Message "DuckDB native library already exists: $targetPath"
		return $targetPath
	}

	$downloadUrl = "$releaseBaseUrl/$version/$zipName"

	Write-Host "    Downloading DuckDB $version native library for $([System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier)..." -ForegroundColor Yellow
	Write-Host "    Source: $downloadUrl" -ForegroundColor DarkGray

	# Ensure lib directory exists
	if (-not (Test-Path $LibPath)) {
		$null = New-Item -Path $LibPath -ItemType Directory -Force
	}

	$tempZip = Join-Path ([System.IO.Path]::GetTempPath()) $zipName
	try {
		# Download
		$ProgressPreference = 'SilentlyContinue'
		Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
		$ProgressPreference = 'Continue'

		# Extract just the native library file
		$tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) "duckdb-extract-$([guid]::NewGuid().ToString('N').Substring(0,8))"
		$null = New-Item -Path $tempExtract -ItemType Directory -Force

		Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

		$extractedLib = Get-ChildItem -Path $tempExtract -Filter $libName -Recurse | Select-Object -First 1
		if (-not $extractedLib) {
			throw "Could not find $libName in downloaded archive $zipName"
		}

		Copy-Item -Path $extractedLib.FullName -Destination $targetPath -Force

		# Make executable on Unix
		if (-not $IsWindows) {
			chmod +x $targetPath 2>$null
		}

		Write-Host "    ✅ DuckDB native library installed: $targetPath" -ForegroundColor Green
		return $targetPath
	}
	catch {
		Write-Host "    ❌ Failed to download DuckDB native library: $_" -ForegroundColor Red
		Write-Host "    Manual download: $downloadUrl" -ForegroundColor Yellow
		Write-Host "    Extract $libName into: $LibPath" -ForegroundColor Yellow
		throw
	}
	finally {
		# Cleanup temp files
		if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
		if ($tempExtract -and (Test-Path $tempExtract)) { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue }
	}
}
