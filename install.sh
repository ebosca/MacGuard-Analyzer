#!/bin/bash
# MacGuard Analyzer — Installer
# Installs dependencies in a virtual environment at ~/.macguard_venv

set -e

echo "========================================"
echo "  MacGuard Analyzer — Installazione"
echo "========================================"
echo ""

VENV_DIR="$HOME/.macguard_venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Find Python with tkinter support ─────────────────────────────────────────

find_python() {
    # Priority order: Homebrew Python 3.14/3.13/3.12, then system python3
    local candidates=(
        "/opt/homebrew/opt/python@3.14/bin/python3.14"
        "/opt/homebrew/opt/python@3.13/bin/python3.13"
        "/opt/homebrew/opt/python@3.12/bin/python3.12"
        "/opt/homebrew/bin/python3"
        "/usr/local/bin/python3"
        "$(which python3 2>/dev/null)"
    )

    for py in "${candidates[@]}"; do
        if [ -x "$py" ]; then
            # Test tkinter availability
            if "$py" -c "import tkinter" 2>/dev/null; then
                echo "$py"
                return 0
            fi
        fi
    done

    return 1
}

echo "→ Ricerca Python con supporto tkinter..."
PYTHON=$(find_python)

if [ -z "$PYTHON" ]; then
    echo ""
    echo "ERRORE: Python con tkinter non trovato."
    echo ""
    echo "Soluzioni:"
    echo "  1. Installa Homebrew: https://brew.sh"
    echo "  2. Installa Python + tkinter:"
    echo "     brew install python-tk"
    echo "     oppure: brew install python@3.14 python-tk@3.14"
    echo ""
    exit 1
fi

echo "✓ Python trovato: $PYTHON ($($PYTHON --version))"
echo ""

# ── Create virtual environment ────────────────────────────────────────────────

if [ -d "$VENV_DIR" ]; then
    echo "→ Ambiente virtuale esistente trovato in $VENV_DIR"
    echo "→ Aggiornamento dipendenze..."
else
    echo "→ Creazione ambiente virtuale in $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR"
    echo "✓ Ambiente virtuale creato"
fi

# Activate venv
source "$VENV_DIR/bin/activate"
echo ""

# ── Install/upgrade pip ───────────────────────────────────────────────────────

echo "→ Aggiornamento pip..."
pip install --upgrade pip --quiet
echo ""

# ── Install required packages ─────────────────────────────────────────────────

echo "→ Installazione dipendenze necessarie..."
pip install customtkinter darkdetect psutil --quiet
echo "✓ customtkinter, darkdetect, psutil installati"

echo ""
echo "→ Installazione dipendenze opzionali (PDF export)..."
pip install reportlab Pillow --quiet && echo "✓ reportlab, Pillow installati" || echo "  (opzionali non installati — il report PDF sarà in formato TXT)"

# ── Make scripts executable ───────────────────────────────────────────────────

echo ""
chmod +x "$SCRIPT_DIR/MacGuard.command" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/macguard/main.py" 2>/dev/null || true

# ── Create log directory ──────────────────────────────────────────────────────

mkdir -p "$HOME/Library/Logs/MacGuard"
echo "✓ Cartella log creata: ~/Library/Logs/MacGuard/"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "========================================"
echo "  ✅ Installazione completata!"
echo "========================================"
echo ""
echo "Per avviare MacGuard Analyzer:"
echo "  • Doppio click su MacGuard.command"
echo "  • oppure: $VENV_DIR/bin/python $SCRIPT_DIR/macguard/main.py"
echo ""

deactivate 2>/dev/null || true
