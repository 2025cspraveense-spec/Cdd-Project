#!/usr/bin/env bash
# =============================================================================
# Secret Leak Guard v2.0 - Live Project Expo Verification & Health Script
# Verifies: Docker images, 5 services, slg-network, volumes, Nginx reverse proxy
# routing, HTTP security headers, and JSON 413/502 error responses.
# =============================================================================

set -e

# ANSI Color Codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PASSED_COUNT=0
TOTAL_CHECKS=0

print_header() {
    echo -e "\n${BLUE}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}   🛡️  SECRET LEAK GUARD v2.0 - INFRASTRUCTURE EXPO VERIFIER         ${NC}"
    echo -e "${BLUE}${BOLD}======================================================================${NC}"
}

check_result() {
    local test_name="$1"
    local status="$2"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$status" -eq 0 ]; then
        echo -e "  [${GREEN}PASS${NC}] $test_name"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "  [${RED}FAIL${NC}] $test_name"
    fi
}

# -----------------------------------------------------------------------------
# 1. Check CLI Prerequisites
# -----------------------------------------------------------------------------
verify_prerequisites() {
    echo -e "\n${BOLD}[1/7] Checking CLI Prerequisites...${NC}"
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "  Docker CLI: $(docker --version)"
    else
        echo -e "  ${RED}Docker CLI not found!${NC}"
        exit 1
    fi

    if docker compose version >/dev/null 2>&1; then
        echo -e "  Docker Compose: $(docker compose version)"
    else
        echo -e "  ${RED}Docker Compose not found!${NC}"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# 2. Inspect Docker Images Footprint
# -----------------------------------------------------------------------------
verify_images() {
    echo -e "\n${BOLD}[2/7] Inspecting Secret Leak Guard Container Images...${NC}"
    images=$(docker compose images -q 2>/dev/null | sort -u)
    if [ -n "$images" ]; then
        docker compose images
        check_result "Compose service images are present" 0
    else
        echo -e "  ${RED}No Compose service images are available.${NC}"
        check_result "Compose service images are present" 1
    fi
}

# -----------------------------------------------------------------------------
# 3. Inspect Running Containers & Health Status
# -----------------------------------------------------------------------------
verify_containers() {
    echo -e "\n${BOLD}[3/7] Verifying 5 Core Microservices Status...${NC}"
    docker compose ps

    services=("slg-gateway" "slg-frontend" "slg-backend" "slg-mongodb" "slg-vault")
    for svc in "${services[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${svc}$"; then
            status=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}missing-healthcheck{{end}}' "$svc" 2>/dev/null || echo "inspect-failed")
            echo -e "  Container ${CYAN}${svc}${NC}: Status = ${status}"
            if [ "$status" = "healthy" ]; then
                check_result "Container $svc health" 0
            else
                check_result "Container $svc health" 1
            fi
        else
            echo -e "  Container ${CYAN}${svc}${NC}: ${YELLOW}Not currently running in this shell${NC}"
            check_result "Container $svc presence check" 1
        fi
    done
}

# -----------------------------------------------------------------------------
# 4. Inspect Custom Bridge Network (slg-network)
# -----------------------------------------------------------------------------
verify_network() {
    echo -e "\n${BOLD}[4/7] Inspecting Custom Bridge Network (slg-network)...${NC}"
    if docker network inspect slg-network >/dev/null 2>&1; then
        subnet=$(docker network inspect slg-network --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || echo "172.28.0.0/16")
        driver=$(docker network inspect slg-network --format '{{.Driver}}' 2>/dev/null || echo "bridge")
        echo -e "  Network: ${CYAN}slg-network${NC} | Driver: ${driver} | Subnet: ${subnet}"
        check_result "Custom bridge network 'slg-network' active" 0
        for svc in "slg-gateway" "slg-frontend" "slg-backend" "slg-mongodb" "slg-vault"; do
            attached=$(docker inspect --format='{{range $name, $network := .NetworkSettings.Networks}}{{$name}} {{end}}' "$svc" 2>/dev/null || echo "")
            if echo "$attached" | grep -qw "slg-network"; then
                check_result "Container $svc attached to slg-network" 0
            else
                check_result "Container $svc attached to slg-network" 1
            fi
        done
    else
        echo -e "  ${YELLOW}Notice: slg-network will be created upon 'docker compose up'${NC}"
        check_result "Custom bridge network 'slg-network' active" 1
    fi
}

# -----------------------------------------------------------------------------
# 5. Inspect Persistent Volumes
# -----------------------------------------------------------------------------
verify_volumes() {
    echo -e "\n${BOLD}[5/7] Verifying Named Persistent Volumes...${NC}"
    volumes=("slg_mongodb_data" "slg_vault_data" "slg_workspace_data")
    for vol in "${volumes[@]}"; do
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            mountpoint=$(docker volume inspect "$vol" --format '{{.Mountpoint}}' 2>/dev/null)
            echo -e "  Volume ${CYAN}${vol}${NC}: Mount = ${mountpoint}"
            check_result "Persistent volume $vol" 0
        else
            echo -e "  Volume ${CYAN}${vol}${NC}: Ready in docker-compose.yml"
            check_result "Persistent volume $vol exists" 1
        fi
    done
}

# -----------------------------------------------------------------------------
# 6. Test Nginx Gateway Routing & Security Headers (Ports 80 & 8080)
# -----------------------------------------------------------------------------
verify_gateway_routing_and_headers() {
    echo -e "\n${BOLD}[6/7] Testing Gateway Upstream Routing & HTTP Security Headers...${NC}"

    BASE_URL="http://localhost:80"
    ALT_URL="http://localhost:8080"

    echo -e "\n  [A] Probing Gateway Health Check (/health)..."
    if curl -s -f "${BASE_URL}/health" >/dev/null 2>&1; then
        resp=$(curl -s "${BASE_URL}/health")
        echo -e "      Response: ${GREEN}${resp}${NC}"
        check_result "Gateway /health endpoint on Port 80" 0
    else
        echo -e "      ${RED}Gateway health endpoint is unavailable.${NC}"
        check_result "Gateway /health endpoint on Port 80" 1
    fi

    echo -e "\n  [B] Probing Dual Port Binding (Port 8080)..."
    if curl -s -f "${ALT_URL}/health" >/dev/null 2>&1; then
        check_result "Gateway listening on Port 8080" 0
    else
        echo -e "      ${RED}Gateway is unavailable on port 8080.${NC}"
        check_result "Gateway listening on Port 8080" 1
    fi

    for port in 80 8080; do
        for route in "/" "/app/" "/api/v1/health" "/vault/"; do
            status=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "http://localhost:${port}${route}" 2>/dev/null || true)
            if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 400 ] 2>/dev/null; then
                check_result "Route ${route} on port ${port} (HTTP ${status})" 0
            else
                echo -e "      ${RED}Route ${route} on port ${port} returned HTTP ${status}.${NC}"
                check_result "Route ${route} on port ${port}" 1
            fi
        done
    done

    echo -e "\n  [C] Testing Strict HTTP Security Headers via curl -I..."
    # Headers check against simulated or live gateway response
    headers=$(curl -s -I "${BASE_URL}/health" 2>/dev/null || true)

    echo "$headers" | grep -i "Content-Security-Policy" && check_result "Header: Content-Security-Policy" 0 || check_result "Header: Content-Security-Policy" 1
    echo "$headers" | grep -i "X-Frame-Options" && check_result "Header: X-Frame-Options" 0 || check_result "Header: X-Frame-Options" 1
    echo "$headers" | grep -i "X-Content-Type-Options" && check_result "Header: X-Content-Type-Options" 0 || check_result "Header: X-Content-Type-Options" 1
    echo "$headers" | grep -i "Referrer-Policy" && check_result "Header: Referrer-Policy" 0 || check_result "Header: Referrer-Policy" 1
    echo "$headers" | grep -i "X-XSS-Protection" && check_result "Header: X-XSS-Protection" 0 || check_result "Header: X-XSS-Protection" 1
}

# -----------------------------------------------------------------------------
# 7. Test Custom JSON Error Responses (413 & 502)
# -----------------------------------------------------------------------------
verify_json_error_responses() {
    echo -e "\n${BOLD}[7/7] Validating Custom JSON Error Handling (413 & 502)...${NC}"

    echo -e "  [A] Exercising the live HTTP 413 handler:"
    response_file=$(mktemp)
    status=$(curl -sS --max-time 10 -X POST \
        -H 'Content-Length: 1048576001' \
        -o "$response_file" -w '%{http_code}' \
        http://localhost:80/api/v1/scans 2>/dev/null || true)
    if [ "$status" = "413" ] && grep -q '"code":413' "$response_file"; then
        check_result "Live HTTP 413 JSON response" 0
    else
        echo -e "      ${RED}Expected HTTP 413 JSON, received status ${status}.${NC}"
        check_result "Live HTTP 413 JSON response" 1
    fi
    rm -f "$response_file"

    echo -e "  [B] Checking the configured JSON 502 handler (requires upstream outage to exercise live):"
    if grep -Fq 'error_page 502 = @json_502;' docker/gateway/nginx.conf \
        && grep -Fq '"code":502' docker/gateway/nginx.conf; then
        check_result "HTTP 502 JSON handler configuration" 0
    else
        check_result "HTTP 502 JSON handler configuration" 1
    fi
}

# -----------------------------------------------------------------------------
# Summary Report
# -----------------------------------------------------------------------------
print_summary() {
    echo -e "\n${BLUE}${BOLD}======================================================================${NC}"
    echo -e "${GREEN}${BOLD}   PROJECT EXPO INFRASTRUCTURE VERIFICATION SUMMARY                 ${NC}"
    echo -e "${BLUE}${BOLD}======================================================================${NC}"
    echo -e "  Passed Checks : ${GREEN}${PASSED_COUNT} / ${TOTAL_CHECKS}${NC}"
    echo -e "  Gateway       : Nginx 1.27.5 on ports 80 & 8080 (1000MB upload limit)"
    echo -e "  Frontend      : React 18.2 Dashboard on :3000 (Non-root UID 10001)"
    echo -e "  Backend       : Flask 3.1 + Gunicorn on :5000 (Non-root UID 10001)"
    echo -e "  Database      : MongoDB 7.0 (Persistent volume & TTL index)"
    echo -e "  Secrets Mgmt  : HashiCorp Vault 1.15.6 (KV-v2 & IPC_LOCK enabled)"
    echo -e "  CI/CD         : GitHub Actions (Gitleaks, Pytest, Trivy, GHCR, Auto-Rollback)"
    echo -e "${BLUE}${BOLD}======================================================================${NC}\n"
}

# Execution
print_header
verify_prerequisites
verify_images
verify_containers
verify_network
verify_volumes
verify_gateway_routing_and_headers
verify_json_error_responses
print_summary
if [ "$PASSED_COUNT" -ne "$TOTAL_CHECKS" ]; then
    exit 1
fi
exit 0
