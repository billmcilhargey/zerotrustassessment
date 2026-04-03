#!/usr/bin/env bash
# Bash launcher for Invoke-ZtDev.ps1 (developer test runner)
# Works in Codespaces, dev containers, and any Linux/macOS environment.
# Ensures PowerShell 7+ is available, then delegates to the PowerShell script.
#
# Usage:
#   ./invoke-ztdev.sh                          # Interactive developer menu
#   ./invoke-ztdev.sh -Action Connect          # Direct action
#   ./invoke-ztdev.sh -Action RunPillar -Pillar Identity -Days 7
#   ./invoke-ztdev.sh -Action Pester
#   ./invoke-ztdev.sh -Action UpdateTestServices
#
# All arguments are passed through to Invoke-ZtDev.ps1.
#
# For end-user usage (PSGallery install), use Start-ZtAssessment directly
# in PowerShell — this script is for contributors and developers only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS_SCRIPT="$SCRIPT_DIR/Invoke-ZtDev.ps1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Find or install PowerShell ───────────────────────────────────────────────

find_pwsh() {
    if command -v pwsh &>/dev/null; then
        echo "pwsh"
        return 0
    fi
    for p in /usr/bin/pwsh /usr/local/bin/pwsh /snap/bin/pwsh ~/.dotnet/tools/pwsh; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

install_pwsh() {
    echo -e "${YELLOW}PowerShell (pwsh) not found. Installing...${NC}"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_ID="macos"
    else
        OS_ID="unknown"
    fi

    case "$OS_ID" in
        ubuntu|debian)
            echo -e "${CYAN}Installing via Microsoft package repository (Debian/Ubuntu)...${NC}"
            if command -v dotnet &>/dev/null; then
                dotnet tool install --global PowerShell
            else
                sudo apt-get update -qq
                sudo apt-get install -y -qq wget apt-transport-https software-properties-common
                source /etc/os-release
                wget -q "https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb"
                sudo dpkg -i packages-microsoft-prod.deb
                rm packages-microsoft-prod.deb
                sudo apt-get update -qq
                sudo apt-get install -y -qq powershell
            fi
            ;;
        macos)
            if command -v brew &>/dev/null; then
                echo -e "${CYAN}Installing via Homebrew...${NC}"
                brew install powershell/tap/powershell
            else
                echo -e "${RED}Please install PowerShell: https://aka.ms/install-powershell${NC}"
                exit 1
            fi
            ;;
        *)
            if command -v dotnet &>/dev/null; then
                echo -e "${CYAN}Installing via dotnet global tool...${NC}"
                dotnet tool install --global PowerShell
                export PATH="$HOME/.dotnet/tools:$PATH"
            elif command -v snap &>/dev/null; then
                echo -e "${CYAN}Installing via snap...${NC}"
                sudo snap install powershell --classic
            else
                echo -e "${RED}Cannot auto-install PowerShell on this system.${NC}"
                echo -e "${YELLOW}Install manually: https://aka.ms/install-powershell${NC}"
                exit 1
            fi
            ;;
    esac

    if ! find_pwsh &>/dev/null; then
        echo -e "${RED}PowerShell installation failed. Install manually: https://aka.ms/install-powershell${NC}"
        exit 1
    fi
    echo -e "${GREEN}PowerShell installed successfully.${NC}"
}

# ── Main ─────────────────────────────────────────────────────────────────────

PWSH=$(find_pwsh 2>/dev/null || true)

if [ -z "$PWSH" ]; then
    install_pwsh
    PWSH=$(find_pwsh)
fi

echo -e "${CYAN}Using PowerShell: $PWSH ($($PWSH --version 2>/dev/null || echo 'unknown'))${NC}"

# ── Platform compatibility notice ────────────────────────────────────────────
if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != CYGWIN* && "$(uname -s)" != MSYS* ]]; then
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}  Platform notice: Running on $(uname -s) (non-Windows)${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────────${NC}"
    echo -e "  The following services require Windows and will be unavailable:"
    echo -e "    ${RED}✗${NC} AipService (Azure Information Protection)"
    echo -e "    ${RED}✗${NC} SharePointOnline (SharePoint Online Management Shell)"
    echo ""
    echo -e "  Tests depending on these services (~5 Data pillar tests) will be"
    echo -e "  skipped. All other services work cross-platform:"
    echo -e "    ${GREEN}✓${NC} Graph  ${GREEN}✓${NC} Azure  ${GREEN}✓${NC} ExchangeOnline  ${GREEN}✓${NC} SecurityCompliance"
    echo ""
    echo -e "  For full coverage, run on Windows or use a Windows-based CI agent."
    echo -e "${YELLOW}────────────────────────────────────────────────────────────────${NC}"
    echo ""
fi

if [ ! -f "$PS_SCRIPT" ]; then
    echo -e "${RED}Invoke-ZtDev.ps1 not found at: $PS_SCRIPT${NC}"
    exit 1
fi

"$PWSH" -NoLogo -NoProfile -File "$PS_SCRIPT" "$@"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 143 ]; then
    echo ""
    echo -e "${YELLOW}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}  ⚠ Process received SIGTERM (exit code 143)${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}Resume: ./invoke-ztdev.sh -Action Resume${NC}"
    echo ""
elif [ $EXIT_CODE -eq 130 ]; then
    echo ""
    echo -e "${YELLOW}  Interrupted (Ctrl+C). Use -Action Resume to continue.${NC}"
    echo ""
elif [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo -e "${RED}  Exited with code $EXIT_CODE${NC}"
    echo ""
fi

exit $EXIT_CODE
