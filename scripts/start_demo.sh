#!/usr/bin/env bash
# ==============================================================================
# SecMLOps — Demo Startup Script
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}       Starting SecMLOps Cyber-Defense Demo           ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"

# 1. Enforce Dry-Run Safety
export SEC_MLOPS_DRY_RUN=1
echo -e "\n${BOLD}[1] Safety Configuration:${NC}"
echo -e "  SEC_MLOPS_DRY_RUN = ${GREEN}1${NC} (Strict dry-run mode; no cluster workloads will be disrupted)"

# 2. Select Python executable
PYTHON="$ROOT_DIR/.venv/bin/python"
UVICORN="$ROOT_DIR/.venv/bin/uvicorn"
if [ ! -f "$PYTHON" ]; then
    PYTHON="python3"
    UVICORN="uvicorn"
fi
echo -e "  Python binary     = $PYTHON"

# 3. Create logs directory
mkdir -p "$ROOT_DIR/logs"

# 4. Prerequisites check: K3s and Tetragon
echo -e "\n${BOLD}[2] Checking Prerequisites:${NC}"
if ! kubectl get nodes >/dev/null 2>&1; then
    echo -e "  ${RED}ERROR:${NC} K3s cluster is not responding. Please ensure k3s is running."
    echo -e "  Start command: sudo systemctl start k3s"
    exit 1
fi
echo -e "  K3s Cluster       : ${GREEN}READY${NC}"

TET_POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null || true)
if [ -z "$TET_POD" ]; then
    echo -e "  ${YELLOW}WARNING:${NC} Tetragon pod not found in kube-system. eBPF live telemetry may be unavailable."
else
    echo -e "  Tetragon Sensor   : ${GREEN}READY${NC}"
fi

# 5. Stop any existing background demo instances
echo -e "\n${BOLD}[3] Cleaning Up Old Processes:${NC}"
if [ -f "$ROOT_DIR/.dashboard.pid" ]; then
    kill "$(cat "$ROOT_DIR/.dashboard.pid")" 2>/dev/null || true
    rm -f "$ROOT_DIR/.dashboard.pid"
fi
if [ -f "$ROOT_DIR/.detector.pid" ]; then
    kill "$(cat "$ROOT_DIR/.detector.pid")" 2>/dev/null || true
    rm -f "$ROOT_DIR/.detector.pid"
fi
pkill -f "uvicorn.*dashboard.app:app" 2>/dev/null || true
pkill -f "python.*live_detection.py" 2>/dev/null || true
echo -e "  Cleaned up stale PIDs and processes."

# 6. Start Dashboard Backend (FastAPI + Uvicorn)
echo -e "\n${BOLD}[4] Starting Dashboard Backend:${NC}"
"$UVICORN" dashboard.app:app --host 0.0.0.0 --port 8000 > "$ROOT_DIR/logs/dashboard.log" 2>&1 &
DASH_PID=$!
echo "$DASH_PID" > "$ROOT_DIR/.dashboard.pid"
echo -e "  Dashboard process launched (PID: $DASH_PID, logs: logs/dashboard.log)"

# Wait for Dashboard API readiness
echo -n "  Waiting for dashboard API to be ready..."
READY=0
for _ in {1..20}; do
    if curl -s -m 2 http://localhost:8000/api/state >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
    echo -n "."
done

if [ "$READY" -eq 1 ]; then
    echo -e " ${GREEN}READY!${NC}"
else
    echo -e " ${RED}TIMED OUT!${NC} Check logs/dashboard.log for details."
fi

# 7. Start Live Detector
echo -e "\n${BOLD}[5] Starting Live Detection Pipeline:${NC}"
"$PYTHON" "$ROOT_DIR/live_detection.py" > "$ROOT_DIR/logs/detector.log" 2>&1 &
DET_PID=$!
echo "$DET_PID" > "$ROOT_DIR/.detector.pid"
echo -e "  Detector process launched (PID: $DET_PID, logs: logs/detector.log)"

# 8. Ready Banner
echo -e "\n${BOLD}${GREEN}======================================================${NC}"
echo -e "${BOLD}${GREEN}          SecMLOps Demo Successfully Started         ${NC}"
echo -e "${BOLD}${GREEN}======================================================${NC}"
echo -e "  Dashboard URL     : ${BOLD}${CYAN}http://localhost:8000${NC}"
echo -e "  Status Script     : ${BOLD}./scripts/status_demo.sh${NC}"
echo -e "  Stop Script       : ${BOLD}./scripts/stop_demo.sh${NC}"
echo -e "  Simulation Runner : ${BOLD}./scripts/simulate_scenario.sh <SCENARIO>${NC}"
echo -e "  Logs Directory    : ${BOLD}logs/${NC} (detector.log, dashboard.log)"
echo -e "\n${YELLOW}NOTE:${NC} No attacks are run automatically. Use the Simulation Lab"
echo -e "      on the dashboard or ./scripts/simulate_scenario.sh to trigger scenarios.\n"
