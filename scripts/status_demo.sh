#!/usr/bin/env bash
# ==============================================================================
# SecMLOps — Demo & System Status Check
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}      SecMLOps — Antigravity System Status            ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"

# 1. Environment & Safety Checks
echo -e "\n${BOLD}[1] Environment & Safety${NC}"
DRY_RUN="${SEC_MLOPS_DRY_RUN:-1}"
if [ "$DRY_RUN" = "1" ]; then
    echo -e "  Dry-Run Mode      : ${GREEN}ENABLED${NC} (SEC_MLOPS_DRY_RUN=1 - safe, no real isolation)"
else
    echo -e "  Dry-Run Mode      : ${RED}DISABLED${NC} (SEC_MLOPS_DRY_RUN=$DRY_RUN - ENFORCEMENT)"
fi

# 2. Kubernetes (K3s) Status
echo -e "\n${BOLD}[2] Kubernetes (K3s) Cluster${NC}"
if command -v kubectl >/dev/null 2>&1 && kubectl get nodes >/dev/null 2>&1; then
    NODE_STATUS=$(kubectl get nodes --no-headers 2>/dev/null | awk '{print $2}')
    if [ "$NODE_STATUS" = "Ready" ]; then
        echo -e "  K3s Node Status   : ${GREEN}ONLINE${NC} (Node: Ready)"
    else
        echo -e "  K3s Node Status   : ${YELLOW}DEGRADED${NC} (Node: $NODE_STATUS)"
    fi
else
    echo -e "  K3s Node Status   : ${RED}OFFLINE${NC} (kubectl unreachable or cluster stopped)"
fi

# 3. Tetragon (eBPF Sensor) Status
echo -e "\n${BOLD}[3] Tetragon eBPF Sensor${NC}"
if command -v kubectl >/dev/null 2>&1; then
    TET_POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null || true)
    if [ -n "$TET_POD" ]; then
        TET_READY=$(echo "$TET_POD" | awk '{print $2}')
        TET_STATE=$(echo "$TET_POD" | awk '{print $3}')
        if [[ "$TET_READY" =~ ^2/2$ ]] && [ "$TET_STATE" = "Running" ]; then
            echo -e "  Tetragon Pod      : ${GREEN}ONLINE${NC} ($TET_READY $TET_STATE)"
        else
            echo -e "  Tetragon Pod      : ${YELLOW}DEGRADED${NC} ($TET_READY $TET_STATE)"
        fi
    else
        echo -e "  Tetragon Pod      : ${RED}NOT FOUND${NC} (in namespace kube-system)"
    fi

    # Check TracingPolicies
    POLICIES=$(kubectl get tracingpolicies --no-headers 2>/dev/null | awk '{print $1}' | tr '\n' ' ' || true)
    if [ -n "$POLICIES" ]; then
        echo -e "  Tracing Policies  : ${GREEN}ACTIVE${NC} ($POLICIES)"
    else
        echo -e "  Tracing Policies  : ${YELLOW}NONE${NC}"
    fi
else
    echo -e "  Tetragon Pod      : ${RED}UNKNOWN${NC} (kubectl not available)"
fi

# 4. Optional Infrastructure (Kafka / Neo4j)
echo -e "\n${BOLD}[4] Optional Services${NC}"
KAFKA_POD=$(kubectl get pods -n secmlops kafka-controller-0 --no-headers 2>/dev/null || true)
if [ -n "$KAFKA_POD" ] && echo "$KAFKA_POD" | grep -q "Running"; then
    echo -e "  Kafka Broker      : ${GREEN}ONLINE${NC}"
else
    echo -e "  Kafka Broker      : ${CYAN}NOT CONFIGURED${NC} (optional; detector tails Tetragon directly)"
fi

NEO4J_POD=$(kubectl get pods -n graph neo4j-0 --no-headers 2>/dev/null || true)
if [ -n "$NEO4J_POD" ] && echo "$NEO4J_POD" | grep -q "Running"; then
    echo -e "  Neo4j Database    : ${GREEN}ONLINE${NC}"
else
    echo -e "  Neo4j Database    : ${CYAN}NOT CONFIGURED${NC} (optional; in-memory NetworkX active)"
fi

# 5. Core Pipeline Processes
echo -e "\n${BOLD}[5] Core SecMLOps Processes${NC}"

# Detector process
DET_PID=$(pgrep -f "python.*live_detection.py" || true)
if [ -n "$DET_PID" ]; then
    echo -e "  Live Detector     : ${GREEN}RUNNING${NC} (PID: $DET_PID)"
else
    echo -e "  Live Detector     : ${RED}STOPPED${NC} (start with: scripts/start_demo.sh)"
fi

# Dashboard backend process
DASH_PID=$(pgrep -f "uvicorn.*dashboard.app:app" || true)
if [ -n "$DASH_PID" ]; then
    echo -e "  Dashboard Backend : ${GREEN}RUNNING${NC} (PID: $DASH_PID)"
else
    echo -e "  Dashboard Backend : ${RED}STOPPED${NC} (start with: scripts/start_demo.sh)"
fi

# 6. HTTP API & State Verification
echo -e "\n${BOLD}[6] HTTP API & Dashboard State${NC}"
if curl -s -m 2 http://localhost:8000/api/health >/dev/null 2>&1; then
    HEALTH_JSON=$(curl -s http://localhost:8000/api/health)
    echo -e "  API /api/health   : ${GREEN}ONLINE${NC} ($HEALTH_JSON)"
    DASH_URL="http://localhost:8000"
    echo -e "  Dashboard UI      : ${GREEN}$DASH_URL${NC}"

    # Threat state check
    THREAT_STATUS=$(curl -s http://localhost:8000/api/threat | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"' || echo "UNKNOWN")
    echo -e "  Current State     : ${BLUE}$THREAT_STATUS${NC}"
else
    echo -e "  Dashboard API     : ${RED}UNREACHABLE${NC} (port 8000 not responding)"
fi

# 7. Log Files
echo -e "\n${BOLD}[7] Log File Paths${NC}"
for logf in "logs/detector.log" "logs/dashboard.log"; do
    if [ -f "$logf" ]; then
        LINES=$(wc -l < "$logf")
        echo -e "  $logf : exists ($LINES lines)"
    else
        echo -e "  $logf : not found (no logs recorded yet)"
    fi
done

echo -e "\n${BOLD}${CYAN}======================================================${NC}\n"
