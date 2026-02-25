#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Auto-VAPT — Start Script
# Launches both the backend (FastAPI on :8888) and the
# frontend dev server (Vite on :5173) simultaneously.
# ─────────────────────────────────────────────────────────────

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8888}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "   ___         __           _   _____    ___  ______"
  echo "  / _ | __ __ / /_ ___  ___| | / / _ |  / _ \/_ __/"
  echo " / __ |/ // // __// _ \/___/ |/ / __ | / ___/ / /   "
  echo "/_/ |_|\\_,_/ \\__/ \\___/    |___/_/ |_|/_/    /_/    "
  echo ""
  echo -e "  CI/CD Integrated Vulnerability Assessment Scanner${RESET}"
  echo ""
}

cleanup() {
  echo ""
  echo -e "${CYAN}Shutting down...${RESET}"
  kill "$BACKEND_PID" 2>/dev/null || true
  kill "$FRONTEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
  wait "$FRONTEND_PID" 2>/dev/null || true
  echo -e "${GREEN}✓ All services stopped.${RESET}"
}

trap cleanup EXIT INT TERM

banner

# ─── Check prerequisites ────────────────────────────────────

echo -e "${BOLD}Checking prerequisites...${RESET}"

if ! command -v python3 &>/dev/null; then
  echo -e "${RED}✗ python3 not found. Please install Python 3.11+.${RESET}"
  exit 1
fi

if ! command -v node &>/dev/null; then
  echo -e "${RED}✗ node not found. Please install Node.js 18+.${RESET}"
  exit 1
fi

echo -e "${GREEN}✓ python3 $(python3 --version 2>&1 | awk '{print $2}')${RESET}"
echo -e "${GREEN}✓ node $(node --version)${RESET}"

# ─── Activate virtual environment if available ───────────────

if [ -d "$ROOT_DIR/.venv" ]; then
  echo -e "${GREEN}✓ Activating virtual environment${RESET}"
  source "$ROOT_DIR/.venv/bin/activate"
elif [ -n "$VIRTUAL_ENV" ]; then
  echo -e "${GREEN}✓ Using active virtual environment: $VIRTUAL_ENV${RESET}"
else
  echo -e "${RED}⚠ No virtual environment found. Running with system Python.${RESET}"
fi

# ─── Install frontend dependencies if needed ────────────────

FRONTEND_DIR="$ROOT_DIR/dashboard/frontend"

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  echo -e "${CYAN}Installing frontend dependencies...${RESET}"
  (cd "$FRONTEND_DIR" && npm install)
fi

# ─── Start backend ──────────────────────────────────────────

echo ""
echo -e "${BOLD}Starting services...${RESET}"
echo -e "${GREEN}▶ Backend${RESET}  → http://localhost:${BACKEND_PORT}"

python3 -m uvicorn dashboard.app:app \
  --host 0.0.0.0 \
  --port "$BACKEND_PORT" \
  --reload \
  --reload-dir "$ROOT_DIR/auto_vapt" \
  --reload-dir "$ROOT_DIR/dashboard" &
BACKEND_PID=$!

# ─── Start frontend ─────────────────────────────────────────

echo -e "${GREEN}▶ Frontend${RESET} → http://localhost:${FRONTEND_PORT}"

(cd "$FRONTEND_DIR" && npx vite --port "$FRONTEND_PORT" --host) &
FRONTEND_PID=$!

echo ""
echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Dashboard: ${GREEN}http://localhost:${FRONTEND_PORT}${RESET}"
echo -e "${BOLD}  API:       ${GREEN}http://localhost:${BACKEND_PORT}/api/health${RESET}"
echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Press Ctrl+C to stop all services${RESET}"
echo ""

# ─── Wait for either to exit ────────────────────────────────

wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
