#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if command -v pkg >/dev/null 2>&1; then
    echo "[*] Termux detected."
    pkg update -y
    pkg install -y python git
    PYTHON_BIN="python"
elif command -v apt-get >/dev/null 2>&1; then
    echo "[*] Debian/Kali detected."
    if [[ "${EUID}" -eq 0 ]]; then
        apt-get update
        apt-get install -y python3 python3-venv python3-pip git
    else
        sudo apt-get update
        sudo apt-get install -y python3 python3-venv python3-pip git
    fi
    PYTHON_BIN="python3"
else
    echo "Error: unsupported package manager. Install Python 3, pip, and git manually." >&2
    exit 1
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit("Python 3.10+ is required.") if sys.version_info < (3, 10) else None'
if [[ ! -x ".venv/bin/python" ]]; then
    "$PYTHON_BIN" -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

cat <<'EOF'

Installation complete.

Run:
   .venv/bin/python cyberrecon.py --target example.com
   .venv/bin/python cyberrecon.py --target example.com --export

No API key or external AI service is required.
Only scan systems you own or are explicitly authorized to assess.
EOF
