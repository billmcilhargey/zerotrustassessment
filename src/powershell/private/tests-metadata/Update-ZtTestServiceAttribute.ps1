function Update-ZtTestServiceAttribute {
	<#
	.SYNOPSIS
		Updates the Service attribute in [ZtTest(...)] for tests with stale service metadata.

	.DESCRIPTION
		Takes results from Get-ZtTestServiceAudit (filtered to IsStale), rewrites the
		Service = (...) line in each test file's [ZtTest()] attribute to match the
		auto-detected services.

		Supports -WhatIf / -Confirm via ShouldProcess.

	.PARAMETER AuditResult
		One or more audit result objects from Get-ZtTestServiceAudit.
		Only objects with IsStale = $true are processed.

	.EXAMPLE
		PS> Get-ZtTestServiceAudit | Where-Object IsStale | Update-ZtTestServiceAttribute

		Updates the Service metadata for all stale tests.

	.EXAMPLE
		PS> Get-ZtTestServiceAudit | Where-Object IsStale | Update-ZtTestServiceAttribute -WhatIf

		Shows what would be changed without writing files.
	#>
	[CmdletBinding(SupportsShouldProcess)]
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSTypeName('ZeroTrustAssessment.TestServiceAudit')]
		$AuditResult
	)

	begin {
		$changed = 0
	}

	process {
		foreach ($t in $AuditResult) {
			if (-not $t.IsStale) { continue }

			$serviceLiteral = "Service = ('" + ($t.DetectedServices -join "','") + "'),"
			$ztTestRegex = '\[ZtTest\((?<body>[\s\S]*?)\)\]'
			$m = [regex]::Match($t.Content, $ztTestRegex)
			if (-not $m.Success) { continue }

			$body = $m.Groups['body'].Value
			$newBody = $body

			if ($body -match '(?m)^\s*Service\s*=\s*\([^\)]*\)\s*,?\s*$') {
				$newBody = [regex]::Replace(
					$body,
					'(?m)^\s*Service\s*=\s*\([^\)]*\)\s*,?\s*$',
					('        ' + $serviceLiteral)
				)
			}
			else {
				$newBody = $body.TrimEnd() + "`r`n        $serviceLiteral`r`n    "
			}

			$newAttr = "[ZtTest($newBody)]"
			$newContent = $t.Content.Substring(0, $m.Index) + $newAttr + $t.Content.Substring($m.Index + $m.Length)

			if ($newContent -ne $t.Content -and $PSCmdlet.ShouldProcess($t.FilePath, "Update Service = ($($t.DetectedServices -join ', '))")) {
				Set-Content -Path $t.FilePath -Value $newContent -Encoding UTF8
				$changed++
				Write-PSFMessage -Level Host -Message "Updated: {0} (Test {1})" -StringValues $t.FileName, $t.TestId
			}
		}
	}

	end {
		Write-PSFMessage -Level Host -Message "Done. Updated {0} file(s)." -StringValues $changed
	}
}
