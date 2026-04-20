#!/bin/bash
# MacGuard Analyzer — Launcher (double-click to run)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$HOME/.macguard_venv"
VENV_PYTHON="$VENV_DIR/bin/python3"

# Check if venv exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Ambiente virtuale non trovato. Esecuzione installer..."
    echo ""
    bash "$SCRIPT_DIR/install.sh"
    if [ $? -ne 0 ]; then
        echo "Installazione fallita. Premi Invio per chiudere."
        read
        exit 1
    fi
fi

# Activate venv and run
source "$VENV_DIR/bin/activate"

echo "Avvio MacGuard Analyzer..."
cd "$SCRIPT_DIR"
exec "$VENV_PYTHON" macguard/main.py
