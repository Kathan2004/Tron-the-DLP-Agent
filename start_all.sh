#!/bin/bash
# TRON THE DLP AGENT — Start All Components
# Starts the API server + all agents as background daemons

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv (created by setup.sh)
if [ -d ".venv" ]; then
    source .venv/bin/activate
elif [ -d "venv" ]; then
    source venv/bin/activate
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║   TRON THE DLP AGENT v2.0 — Starting All Components    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Kill existing on ports
echo -e "${YELLOW}Cleaning up old processes...${NC}"
lsof -ti :5001 | xargs kill -9 2>/dev/null
sleep 1

# Create log dir
mkdir -p /tmp/tron_logs

# 1) Start API Server
echo -e "${GREEN}Starting DLP API Server...${NC}"
python main.py > /tmp/tron_logs/server.log 2>&1 &
SERVER_PID=$!
echo "  PID: $SERVER_PID"
sleep 4

# Verify server
if curl -s http://localhost:5001/api/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}API Server is running${NC}"
else
    echo -e "  ${RED}API Server failed to start. Check /tmp/tron_logs/server.log${NC}"
    exit 1
fi

# 2) Start Endpoint Agent
echo -e "${GREEN}Starting Endpoint Agent...${NC}"
python agents/endpoint_agent.py --interval 20 > /tmp/tron_logs/endpoint.log 2>&1 &
ENDPOINT_PID=$!
echo "  PID: $ENDPOINT_PID"

# 3) Start Network Agent
echo -e "${GREEN}Starting Network Agent...${NC}"
python agents/network_agent.py --interval 30 > /tmp/tron_logs/network.log 2>&1 &
NETWORK_PID=$!
echo "  PID: $NETWORK_PID"

# 4) Start Web Agent
echo -e "${GREEN}Starting Web Agent...${NC}"
python agents/web_agent.py --interval 30 > /tmp/tron_logs/web.log 2>&1 &
WEB_PID=$!
echo "  PID: $WEB_PID"

# Save PIDs for stop script
echo "$SERVER_PID" > /tmp/tron_logs/server.pid
echo "$ENDPOINT_PID" > /tmp/tron_logs/endpoint.pid
echo "$NETWORK_PID" > /tmp/tron_logs/network.pid
echo "$WEB_PID" > /tmp/tron_logs/web.pid

sleep 3

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║   ALL COMPONENTS RUNNING                               ║"
echo "╠════════════════════════════════════════════════════════╣"
echo "║   API Server:     PID $SERVER_PID  (port 5001)          "
echo "║   Endpoint Agent: PID $ENDPOINT_PID                      "
echo "║   Network Agent:  PID $NETWORK_PID                       "
echo "║   Web Agent:      PID $WEB_PID                           "
echo "╠════════════════════════════════════════════════════════╣"
echo "║   Logs:                                                ║"
echo "║     tail -f /tmp/tron_logs/server.log              ║"
echo "║     tail -f /tmp/tron_logs/endpoint.log            ║"
echo "║     tail -f /tmp/tron_logs/network.log             ║"
echo "║     tail -f /tmp/tron_logs/web.log                 ║"
echo "╠════════════════════════════════════════════════════════╣"
echo "║   To stop: bash stop_all.sh                            ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Wait for all children — keeps this script alive so agents stay alive
wait
