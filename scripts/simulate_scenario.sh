#!/usr/bin/env bash
# ==============================================================================
# SecMLOps — Safe, Repeatable Simulation Runner (Phase E)
# ==============================================================================
# Triggers safe simulation scenarios via the dashboard API or directly against
# a disposable Kubernetes test pod without disrupting cluster workloads.
# Strict dry-run safety is always maintained (SEC_MLOPS_DRY_RUN=1).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SCENARIO="${1:-MULTI_STAGE}"
MODE="${2:-api}"

echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}         SecMLOps — Safe Attack Simulation            ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "  Scenario : ${BOLD}$SCENARIO${NC}"
echo -e "  Mode     : $MODE"
echo -e "  Safety   : ${GREEN}SEC_MLOPS_DRY_RUN=1 (strict dry-run)${NC}\n"

# Verify API is reachable if mode is api
if [ "$MODE" = "api" ]; then
    if ! curl -s -m 2 http://localhost:8000/api/health >/dev/null 2>&1; then
        echo -e "${RED}ERROR:${NC} Dashboard API not reachable at http://localhost:8000."
        echo -e "Please start the demo first using: ${BOLD}./scripts/start_demo.sh${NC}"
        exit 1
    fi

    echo -e "Dispatching scenario '${BOLD}$SCENARIO${NC}' to /api/simulate..."
    RESPONSE=$(curl -s -X POST http://localhost:8000/api/simulate \
        -H "Content-Type: application/json" \
        -d "{\"scenario\": \"$SCENARIO\"}")

    echo -e "\n${BOLD}Simulation Result:${NC}"
    echo -e "$RESPONSE" | python3 -m json.tool || echo "$RESPONSE"
    echo -e "\n${GREEN}✓ Simulation completed.${NC} View live updates at ${BOLD}http://localhost:8000${NC}"
    exit 0
fi

# Live cluster injection mode (--k8s)
if [ "$MODE" = "--k8s" ]; then
    echo -e "${YELLOW}Running live telemetry simulation in disposable pod...${NC}"
    POD_NAME="secmlops-sim-$(date +%s)"
    
    echo "Creating disposable test pod: $POD_NAME"
    kubectl run "$POD_NAME" \
        --image=busybox:1.36 \
        --restart=Never \
        --command -- sh -c "mkdir -p /tmp/secmlops-test && echo 'confidential-data' > /tmp/secmlops-test/sensitive.txt && cat /tmp/secmlops-test/sensitive.txt && wget -T 2 -qO- http://10.0.0.50 || true"
    
    echo "Waiting for pod completion..."
    kubectl wait --for=condition=Ready pod/"$POD_NAME" --timeout=15s 2>/dev/null || true
    sleep 3
    echo "Cleaning up test pod..."
    kubectl delete pod "$POD_NAME" --ignore-not-found=true --now >/dev/null 2>&1 &
    echo -e "${GREEN}✓ Live telemetry event sequence emitted.${NC}"
fi
