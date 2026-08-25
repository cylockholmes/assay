#!/usr/bin/env bash
# assay bootstrap for Kali / Debian, tuned for WSL2 on Windows 11.
#
#   ./install.sh            # everything
#   ./install.sh --minimal  # assay + nmap only (small VMs)
#   ./install.sh --no-go    # skip the Go toolchain and ProjectDiscovery suite
set -euo pipefail

MINIMAL=0; NO_GO=0
for arg in "$@"; do
  case "$arg" in
    --minimal) MINIMAL=1 ;;
    --no-go)   NO_GO=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- checks ---
say "Environment"
IS_WSL=0
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then IS_WSL=1; ok "WSL detected"; fi
CPUS="$(nproc 2>/dev/null || echo 2)"
MEM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 2048)"
ok "${CPUS} CPU(s), ${MEM_MB} MB RAM"
if [ "$MEM_MB" -lt 3000 ]; then
  warn "Under 3 GB of RAM. assay auto-tunes its own pacing, but consider --minimal"
  warn "and running nuclei separately rather than as part of a full scan."
fi

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ------------------------------------------------------------------ apt ----
say "Base system packages"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq python3 python3-venv python3-pip jq curl git ca-certificates
ok "base packages installed"

# ----------------------------------------------------------------- assay ----
say "assay"
python3 -m venv "$HERE/.venv"
"$HERE/.venv/bin/pip" install -q --upgrade pip
"$HERE/.venv/bin/pip" install -q -e "$HERE"
ok "installed into $HERE/.venv"

read -r -p "Install the optional 'anthropic' SDK for AI triage? [y/N] " ans || ans=n
case "$ans" in
  [yY]*) "$HERE/.venv/bin/pip" install -q anthropic && ok "anthropic SDK installed" ;;
  *) ok "skipped (AI triage stays unavailable until you install it)" ;;
esac

mkdir -p "$HOME/.local/bin"
ln -sf "$HERE/.venv/bin/assay" "$HOME/.local/bin/assay"
ok "linked to ~/.local/bin/assay"

# ---------------------------------------------------------------- tools ----
# Delegated to `assay install` so the tool list has exactly one definition.
if [ "$MINIMAL" -eq 1 ]; then
  say "External tools (required only)"
  "$HERE/.venv/bin/assay" install --required-only -y || \
    warn "some tools failed; 'assay doctor' shows what is missing"
elif [ "$NO_GO" -eq 1 ]; then
  say "External tools (apt only)"
  "$HERE/.venv/bin/assay" install -y --only nmap,ffuf,seclists,testssl.sh || true
else
  say "External tools"
  "$HERE/.venv/bin/assay" install -y || \
    warn "some tools failed; 'assay doctor' shows what is missing"
fi

# ----------------------------------------------------------------- burp ----
if [ "$IS_WSL" -eq 1 ]; then
  say "Burp on the Windows host"
  HOST_IP="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
  cat <<TXT
Burp runs on Windows; WSL cannot reach a listener bound to Windows' 127.0.0.1.
Pick one:

  A) Mirrored networking (simplest). In C:\\Users\\<you>\\.wslconfig add:
         [wsl2]
         networkingMode=mirrored
     Then run 'wsl --shutdown' in PowerShell and reopen. Burp on
     127.0.0.1:8080 then works from WSL directly.

  B) Bind Burp to all interfaces: Burp > Proxy > Proxy settings > edit the
     listener > Bind to address: All interfaces. Allow it through Windows
     Defender Firewall, then use:
         assay scan --burp http://${HOST_IP:-<windows-ip>}:8080 ...

To let assay's tools trust Burp's CA (removes TLS errors in Burp's history):
  curl -s --proxy http://${HOST_IP:-127.0.0.1}:8080 http://burp/cert -o /tmp/burp.der \\
    && openssl x509 -inform DER -in /tmp/burp.der -out /tmp/burp.crt \\
    && $SUDO cp /tmp/burp.crt /usr/local/share/ca-certificates/burp.crt \\
    && $SUDO update-ca-certificates
TXT
fi

say "Done"
echo "  assay doctor                 # verify tools, Burp and resources"
echo "  assay scan <target> --scope scope.txt"
echo
warn "Open a new shell (or 'source ~/.bashrc') so PATH changes take effect."
