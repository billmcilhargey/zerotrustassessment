#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_MANIFEST="${SCRIPT_DIR}/src/powershell/ZeroTrustAssessment.psd1"

usage() {
    cat <<'USAGE'
Usage: ./ZeroTrustAssessment.sh [--install-pwsh] '<PowerShell command>'

Examples:
  ./ZeroTrustAssessment.sh 'Connect-ZtAssessment'
  ./ZeroTrustAssessment.sh 'Invoke-ZtAssessment -Path ./reports -NoBrowser'
  ./ZeroTrustAssessment.sh 'Get-Help Invoke-ZtAssessment -Detailed'
  ./ZeroTrustAssessment.sh --install-pwsh 'Connect-ZtAssessment'

When pwsh is missing, an interactive terminal offers to install PowerShell as a
per-user .NET global tool. Use --install-pwsh to approve this noninteractively.
USAGE
}

install_pwsh() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        printf '%s\n' 'Refusing to install PowerShell as root. Run this script as a regular user.' >&2
        exit 1
    fi

    command -v dotnet >/dev/null 2>&1 || {
        printf '%s\n' 'Automatic installation requires the .NET SDK.' >&2
        printf '%s\n' 'Install PowerShell: https://learn.microsoft.com/powershell/scripting/install/installing-powershell' >&2
        exit 1
    }

    PWSH="$HOME/.dotnet/tools/pwsh"
    if [[ -e "$PWSH" ]]; then
        dotnet tool update --global PowerShell
    else
        dotnet tool install --global PowerShell
    fi
    export PATH="$PATH:$HOME/.dotnet/tools"
}

is_pwsh7() {
    [[ -x "${PWSH:-}" ]] || return 1

    local major
    major="$($PWSH -NoProfile -Command '$PSVersionTable.PSVersion.Major' 2>/dev/null || true)"
    [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 7 ))
}

ensure_pwsh() {
    PWSH="$(command -v pwsh 2>/dev/null || true)"
    [[ -n "$PWSH" ]] || PWSH="$HOME/.dotnet/tools/pwsh"
    is_pwsh7 && return

    if [[ "${INSTALL_PWSH:-0}" -ne 1 && -t 0 ]]; then
        read -r -p 'PowerShell 7 is missing. Install it for this user? [y/N] ' reply
        [[ "$reply" =~ ^[Yy]$ ]] || exit 1
    elif [[ "${INSTALL_PWSH:-0}" -ne 1 ]]; then
        printf '%s\n' "PowerShell 7 is required. Re-run with --install-pwsh to install it." >&2
        exit 1
    fi

    install_pwsh
    is_pwsh7 || {
        printf '%s\n' 'PowerShell 7 installation could not be verified.' >&2
        exit 1
    }
}

main() {
    INSTALL_PWSH=0
    if [[ "${1:-}" == '--install-pwsh' ]]; then
        INSTALL_PWSH=1
        shift
    fi

    if [[ $# -ne 1 || "$1" == '-h' || "$1" == '--help' ]]; then
        usage
        [[ $# -eq 1 ]] && exit 0
        exit 2
    fi

    [[ -f "$MODULE_MANIFEST" ]] || {
        printf '%s\n' "Module manifest not found: $MODULE_MANIFEST" >&2
        exit 1
    }

    ensure_pwsh

    ZTA_MODULE_MANIFEST="$MODULE_MANIFEST" ZTA_COMMAND="$1" exec "$PWSH" -NoProfile -Command '& {
        $ErrorActionPreference = "Stop"
        Import-Module -Name $env:ZTA_MODULE_MANIFEST -Force
        & ([scriptblock]::Create($env:ZTA_COMMAND))
    }'
}

main "$@"
