#!/usr/bin/env bash
# ReconX - one-shot installer for Linux / macOS.
#
#   chmod +x install.sh && ./install.sh
#
# Installs Python deps and (if Go is present) the external recon binaries.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${YELLOW}[*]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Python ---------------------------------------------------------------
info "Checking Python..."
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found. Install Python 3.10+ first."
  exit 1
fi
PY_VERSION=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
ok "Python $PY_VERSION"

info "Creating virtual environment (.venv)..."
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

info "Installing Python dependencies..."
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt
ok "Python dependencies installed."

# --- External tools -------------------------------------------------------
GO_BIN="${GOPATH:-$HOME/go}/bin"

# nmap is a system package, not a Go tool.
if command -v nmap >/dev/null 2>&1; then
  ok "nmap already installed ($(nmap --version | head -n1))."
else
  info "Installing nmap (needs sudo)..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y nmap && ok "nmap installed." || fail "nmap install failed."
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y nmap && ok "nmap installed." || fail "nmap install failed."
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm nmap && ok "nmap installed." || fail "nmap install failed."
  else
    fail "No known package manager found. Install nmap manually for Deep Scan."
  fi
fi

if command -v go >/dev/null 2>&1; then
  ok "Go found: $(go version)"
  info "Installing recon binaries (this can take a few minutes)..."

  install_go() {
    # install_go <name> <module>
    if command -v "$1" >/dev/null 2>&1; then
      ok "$1 already installed, skipping."
    else
      info "  -> $1"
      go install "$2" >/dev/null 2>&1 && ok "$1 installed." || fail "$1 failed (check network / Go version)."
    fi
  }

  install_go subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go assetfinder "github.com/tomnomnom/assetfinder@latest"
  install_go amass       "github.com/owasp-amass/amass/v4/...@master"
  install_go dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  install_go httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_go waybackurls "github.com/tomnomnom/waybackurls@latest"
  install_go gau         "github.com/lc/gau/v2/cmd/gau@latest"
  install_go ffuf        "github.com/ffuf/ffuf/v2@latest"
  install_go dalfox      "github.com/hahwul/dalfox/v2@latest"

  case ":$PATH:" in
    *":$GO_BIN:"*) ;;
    *) info "Add this to your ~/.bashrc or ~/.zshrc:";
       echo "    export PATH=\"\$PATH:$GO_BIN\"" ;;
  esac
else
  fail "Go not found. Install Go 1.21+ then re-run, or install the tools manually."
  info "See README section 3."
fi

# --- dnsrecon + arjun (pip) ----------------------------------------------
if command -v dnsrecon >/dev/null 2>&1; then
  ok "dnsrecon already installed, skipping."
else
  info "Installing dnsrecon via pip..."
  python -m pip install dnsrecon >/dev/null 2>&1 && ok "dnsrecon installed." || fail "dnsrecon install failed."
fi

if command -v arjun >/dev/null 2>&1; then
  ok "arjun already installed, skipping."
else
  info "Installing arjun via pip..."
  python -m pip install arjun >/dev/null 2>&1 && ok "arjun installed." || fail "arjun install failed."
fi

# sqlmap ships as a system package on most distros; fall back to pip.
if command -v sqlmap >/dev/null 2>&1; then
  ok "sqlmap already installed, skipping."
else
  info "Installing sqlmap..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y sqlmap >/dev/null 2>&1 && ok "sqlmap installed." || python -m pip install sqlmap >/dev/null 2>&1 && ok "sqlmap installed (pip)." || fail "sqlmap install failed."
  else
    python -m pip install sqlmap >/dev/null 2>&1 && ok "sqlmap installed (pip)." || fail "sqlmap install failed."
  fi
fi

# cloud_enum (pip)
if command -v cloud_enum >/dev/null 2>&1 || command -v cloud-enum >/dev/null 2>&1; then
  ok "cloud_enum already installed, skipping."
else
  info "Installing cloud_enum via pip..."
  python -m pip install cloud-enum >/dev/null 2>&1 && ok "cloud_enum installed." || fail "cloud_enum install failed (optional)."
fi

# --- curated wordlists ----------------------------------------------------
info "Downloading curated wordlists (a few MB)..."
python - <<'PYEOF'
try:
    from reconx.core.wordlists import download_wordlists
    download_wordlists()
except Exception as exc:
    print(f"[-] wordlist download skipped: {exc}")
PYEOF
ok "Wordlists ready in ./wordlists/"

# --- Xray (prebuilt binary from GitHub releases) --------------------------
if command -v xray >/dev/null 2>&1; then
  ok "xray already installed, skipping."
else
  info "Installing xray (best-effort, from GitHub releases)..."
  LOCAL_BIN="$HOME/.local/bin"
  mkdir -p "$LOCAL_BIN"
  XRAY_TMP="$(mktemp -d)"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) XRAY_ARCH="amd64" ;;
    aarch64|arm64) XRAY_ARCH="arm64" ;;
    *) XRAY_ARCH="" ;;
  esac

  if [ -n "$XRAY_ARCH" ] && command -v curl >/dev/null 2>&1; then
    if curl -fsSL "https://github.com/chaitin/xray/releases/latest/download/xray_linux_${XRAY_ARCH}.zip" \
        -o "$XRAY_TMP/xray.zip" 2>/dev/null; then
      if command -v unzip >/dev/null 2>&1; then
        unzip -oq "$XRAY_TMP/xray.zip" -d "$LOCAL_BIN" && chmod +x "$LOCAL_BIN/xray" \
          && ok "xray installed to $LOCAL_BIN/xray." \
          || fail "xray unzip failed."
      else
        fail "unzip missing; install unzip then re-run."
      fi
    else
      fail "xray download failed - install manually from github.com/chaitin/xray/releases."
    fi
  else
    fail "xray not installed automatically - grab it from github.com/chaitin/xray/releases."
  fi
  rm -rf "$XRAY_TMP"

  case ":$PATH:" in
    *":$LOCAL_BIN:"*) ;;
    *) info "Add this to your shell rc:";
       echo "    export PATH=\"\$PATH:$LOCAL_BIN\"" ;;
  esac
fi

# --- Config ---------------------------------------------------------------
if [ ! -f ".env" ]; then
  cp .env.example .env
  ok "Created .env from template - edit it before scanning."
fi

echo
ok "Setup complete."
echo "  Activate env : source .venv/bin/activate"
[ -d "$GO_BIN" ] && echo "  Add tools    : export PATH=\"\$PATH:$GO_BIN\""
echo "  Run          : python reconx.py"
