#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_MANIFEST="${SCRIPT_DIR}/src/powershell/ZeroTrustAssessment.psd1"
readonly MIN_PWSH_MAJOR=7
readonly SAFE_COMMANDS=(Get-Command Get-Help Get-Module)

usage() {
    cat <<'USAGE'
Usage: ./ZeroTrustAssessment.sh <command> [arguments]

Examples:
  ./ZeroTrustAssessment.sh Connect-ZtAssessment
  ./ZeroTrustAssessment.sh Invoke-ZtAssessment -Path ./reports -NoBrowser
  ./ZeroTrustAssessment.sh Get-Help Invoke-ZtAssessment -Detailed

Invoke-ZtAssessment automatically runs Connect-ZtAssessment first in the same PowerShell session.
PowerShell 7 or later must already be installed and available as 'pwsh'.
USAGE
}

fail() {
    printf 'ZeroTrustAssessment.sh: %s\n' "$1" >&2
    exit 1
}

ensure_pwsh() {
    command -v pwsh >/dev/null 2>&1 || fail "PowerShell 7 or later is required. Install PowerShell and ensure 'pwsh' is on PATH."

    local major
    major="$(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.Major')"
    [[ "$major" =~ ^[0-9]+$ ]] || fail 'Unable to determine PowerShell version.'
    (( major >= MIN_PWSH_MAJOR )) || fail "PowerShell $MIN_PWSH_MAJOR or later is required. Found major version $major."
}

is_safe_command() {
    local command_name="$1"
    local safe_command

    for safe_command in "${SAFE_COMMANDS[@]}"; do
        [[ "$command_name" == "$safe_command" ]] && return 0
    done

    return 1
}

validate_command() {
    local command_name="$1"

    is_safe_command "$command_name" && return 0

    pwsh -NoProfile -Command '& {
        param([string] $ModuleManifest, [string] $CommandName)
        $ErrorActionPreference = "Stop"
        Import-Module -Name $ModuleManifest -Force
        $command = Get-Command -Name $CommandName -Module ZeroTrustAssessment -ErrorAction SilentlyContinue
        if (-not $command) {
            throw "Command ''$CommandName'' is not exported by the ZeroTrustAssessment module."
        }
    }' "$MODULE_MANIFEST" "$command_name" >/dev/null
}

run_command() {
    local command_name="$1"
    shift || true

    local connect_first='false'
    if [[ "$command_name" == 'Invoke-ZtAssessment' ]]; then
        connect_first='true'
    fi

    pwsh -NoProfile -Command '& {
        param(
            [string] $ModuleManifest,
            [string] $CommandName,
            [string] $ConnectFirst,
            [string[]] $CommandArguments
        )

        $ErrorActionPreference = "Stop"
        Import-Module -Name $ModuleManifest -Force

        if ([System.Convert]::ToBoolean($ConnectFirst)) {
            Connect-ZtAssessment
        }

        & $CommandName @CommandArguments
    }' "$MODULE_MANIFEST" "$command_name" "$connect_first" "$@"
}

main() {
    if [[ $# -eq 0 || "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
        usage
        exit 0
    fi

    [[ -f "$MODULE_MANIFEST" ]] || fail "Cannot find module manifest at '$MODULE_MANIFEST'. Run this script from a source checkout."

    ensure_pwsh
    validate_command "$1"
    run_command "$@"
}

main "$@"
