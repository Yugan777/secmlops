#!/usr/bin/env bash
# ==============================================================================
# SecMLOps — Demo Shutdown Script
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}Stopping SecMLOps demo processes...${NC}"

STOPPED=0

if [ -f "$ROOT_DIR/.detector.pid" ]; then
    PID=$(cat "$ROOT_DIR/.detector.pid")
    if kill "$PID" 2>/dev/null; then
        echo -e "  Stopped Live Detector (PID: $PID)"
        STOPPED=1
    fi
    rm -f "$ROOT_DIR/.detector.pid"
fi

if [ -f "$ROOT_DIR/.dashboard.pid" ]; then
    PID=$(cat "$ROOT_DIR/.dashboard.pid")
    if kill "$PID" 2>/dev/null; then
        echo -e "  Stopped Dashboard Backend (PID: $PID)"
        STOPPED=1
    fi
    rm -f "$ROOT_DIR/.dashboard.pid"
fi

# Fallback cleanup
pkill -f "python.*live_detection.py" 2>/dev/null || true
pkill -f "uvicorn.*dashboard.app:app" 2>/dev/null || true

echo -e "${GREEN}SecMLOps demo stopped cleanly.${NC}"
