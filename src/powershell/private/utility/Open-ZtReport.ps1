function Open-ZtReport {
	<#
	.SYNOPSIS
		Opens the Zero Trust Assessment HTML report in the default browser.

	.DESCRIPTION
		Platform-aware report opening:
		  - Windows: Invoke-Item
		  - Container/Codespaces: HTTP server via npx, or $BROWSER fallback
		  - Linux: $BROWSER, xdg-open
		  - macOS: open

	.PARAMETER Path
		Full path to the HTML report file.

	.PARAMETER ServeHttp
		In container environments, start an HTTP server to serve the report
		(enables Codespaces port forwarding). Default: $false.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Path,

		[switch]$ServeHttp
	)

	if (-not (Test-Path $Path)) {
		Write-Host "  Report not found: $Path" -ForegroundColor Yellow
		return
	}

	$env = Test-ZtHeadlessEnvironment
	$isContainer = $env.IsCodespaces

	try {
		if ($IsWindows) {
			Invoke-Item $Path | Out-Null
		}
		elseif ($isContainer -and $ServeHttp) {
			$reportDir = Split-Path $Path -Parent
			$reportFile = Split-Path $Path -Leaf
			$port = $script:ZtHttpPortStart

			# Kill any stale http-server jobs so the port is freed
			Get-Job | Where-Object { $_.Command -match 'http-server' } | Stop-Job -PassThru | Remove-Job -Force -ErrorAction Ignore
			# Also kill orphan http-server processes
			try { Get-Process -Name 'http-server','node' -ErrorAction Ignore | Where-Object { $_.CommandLine -match 'http-server' } | Stop-Process -Force -ErrorAction Ignore } catch { }
			Start-Sleep -Milliseconds 500

			# Find an available port
			for ($p = $script:ZtHttpPortStart; $p -le $script:ZtHttpPortEnd; $p++) {
				$inUse = $false
				try {
					$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
					$listener.Start()
					$listener.Stop()
				}
				catch {
					$inUse = $true
				}
				if (-not $inUse) { $port = $p; break }
			}

			$hasNpx = Get-Command npx -ErrorAction Ignore
			if ($hasNpx) {
				Write-Host ""
				Write-Host "  🌐 Starting HTTP server on port $port to serve the report..." -ForegroundColor Cyan
				$null = Start-Job -ScriptBlock {
					param($dir, $port)
					npx -y http-server $dir -p $port -s -c-1 2>&1 | Out-Null
				} -ArgumentList $reportDir, $port

				Start-Sleep -Milliseconds 1500
				$reportUrl = "http://localhost:$port/$reportFile"

				Write-Host "  📄 Report URL: " -NoNewline -ForegroundColor White
				Write-Host $reportUrl -ForegroundColor Green
				Write-Host ""

				if ($env:BROWSER) {
					Write-Host "  Opening in browser..." -ForegroundColor DarkGray
					try { & $env:BROWSER $reportUrl } catch { }
				}

				Write-Host "  💡 In Codespaces: check the Ports tab if it doesn't open automatically." -ForegroundColor Yellow
				Write-Host "     The server will stop when the PowerShell session ends." -ForegroundColor DarkGray
			}
			else {
				if ($env:BROWSER) {
					& $env:BROWSER $Path
				}
				else {
					Write-Host "  Open the report manually: $Path" -ForegroundColor DarkGray
				}
			}
		}
		elseif ($isContainer -or $env:BROWSER) {
			if ($env:BROWSER) {
				& $env:BROWSER $Path
			}
			else {
				Write-Host "  Open the report manually: $Path" -ForegroundColor DarkGray
			}
		}
		elseif (Get-Command xdg-open -ErrorAction Ignore) {
			xdg-open $Path
		}
		elseif ($IsMacOS -and (Get-Command open -ErrorAction Ignore)) {
			open $Path
		}
		else {
			Write-Host "  Open the report manually: $Path" -ForegroundColor DarkGray
		}
	}
	catch {
		Write-PSFMessage -Level Verbose -Message "Could not open report automatically: $_"
		Write-Host "  Open the report manually: $Path" -ForegroundColor DarkGray
	}
}
