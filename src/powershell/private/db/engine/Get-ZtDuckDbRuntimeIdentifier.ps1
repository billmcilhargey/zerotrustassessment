function Get-ZtDuckDbRuntimeIdentifier {
    [CmdletBinding()]
    param (
        [ValidateSet('Windows', 'Linux', 'macOS')]
        [string]
        $OperatingSystem = $(
            if ($IsWindows) { 'Windows' }
            elseif ($IsLinux) { 'Linux' }
            elseif ($IsMacOS) { 'macOS' }
            else { throw 'DuckDB is not supported on this operating system.' }
        ),

        [System.Runtime.InteropServices.Architecture]
        $Architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    )

    switch ("$OperatingSystem/$Architecture") {
        'Windows/X64' { 'win-x64' }
        'Windows/Arm64' { 'win-arm64' }
        'Linux/X64' { 'linux-x64' }
        'Linux/Arm64' { 'linux-arm64' }
        'macOS/X64' { 'osx' }
        'macOS/Arm64' { 'osx' }
        default { throw "DuckDB is not supported on $OperatingSystem $Architecture." }
    }
}
