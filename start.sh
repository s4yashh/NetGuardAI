#!/usr/bin/env bash
# NetGuard AI launcher: starts the FastAPI backend and the Vite frontend,
# waits until both respond, then opens the dashboard.
#
# Usage:
#   ./start.sh            start everything (default)
#   ./start.sh status     show what is running
#   ./start.sh stop       stop both servers
#   ./start.sh restart    restart both servers
#
# Set NO_OPEN=1 to skip opening the browser.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RUN_DIR="$ROOT/.run"
BACKEND_PORT=8000
FRONTEND_PORT=5173
BACKEND_URL="http://127.0.0.1:$BACKEND_PORT"
FRONTEND_URL="http://localhost:$FRONTEND_PORT"
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"

mkdir -p "$RUN_DIR"

info() { printf '  %s\n' "$*"; }
ok()   { printf '✓ %s\n' "$*"; }
warn() { printf '! %s\n' "$*" >&2; }
die()  { printf '✗ %s\n' "$*" >&2; exit 1; }

port_pid() {
  lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | head -n 1 || true
}

pid_cwd() {
  lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1 || true
}

is_backend_up() {
  curl -fsS "$BACKEND_URL/api/health" >/dev/null 2>&1
}

is_frontend_up() {
  curl -fsS "$FRONTEND_URL/" >/dev/null 2>&1
}

wait_for() {
  local url="$1" name="$2" pid="$3"
  local i
  for i in $(seq 1 80); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      ok "$name is ready"
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      warn "$name exited during startup"
      return 1
    fi
    sleep 0.25
  done
  warn "$name did not become ready in time"
  return 1
}

ensure_dependencies() {
  if [ ! -x "$ROOT/.venv/bin/python" ]; then
    info "Creating Python virtual environment..."
    python3 -m venv "$ROOT/.venv"
  fi

  if ! "$ROOT/.venv/bin/python" -c "import fastapi, uvicorn, sklearn, pandas, scipy" >/dev/null 2>&1; then
    info "Installing Python dependencies (first run only)..."
    "$ROOT/.venv/bin/pip" install -r "$ROOT/requirements.txt"
  fi

  if [ ! -x "$ROOT/frontend/node_modules/.bin/vite" ]; then
    command -v npm >/dev/null 2>&1 || die "npm is not installed. Install Node.js 20+ first."
    info "Installing frontend dependencies (first run only)..."
    ( cd "$ROOT/frontend" && npm install )
  fi

  if [ ! -f "$ROOT/models/netguard_model.joblib" ]; then
    warn "models/netguard_model.joblib is missing."
    warn "The site will start, but predictions will return HTTP 503 until you run: python -m ml.train"
  fi
}

start_backend() {
  if is_backend_up; then
    ok "Backend already running on port $BACKEND_PORT"
    return 0
  fi

  local occupant
  occupant="$(port_pid "$BACKEND_PORT")"
  if [ -n "$occupant" ]; then
    die "Port $BACKEND_PORT is already in use by PID $occupant. Stop it first or run ./stop.sh."
  fi

  info "Starting backend..."
  nohup "$ROOT/.venv/bin/python" -m uvicorn backend.app.main:app \
    --host 127.0.0.1 --port "$BACKEND_PORT" \
    >"$BACKEND_LOG" 2>&1 &
  echo $! >"$RUN_DIR/backend.pid"

  if ! wait_for "$BACKEND_URL/api/health" "Backend" "$(cat "$RUN_DIR/backend.pid")"; then
    printf '\n--- backend.log (last 20 lines) ---\n' >&2
    tail -n 20 "$BACKEND_LOG" >&2 || true
    die "Backend failed to start. Full log: $BACKEND_LOG"
  fi
}

start_frontend() {
  if is_frontend_up; then
    ok "Frontend already running on port $FRONTEND_PORT"
    return 0
  fi

  local occupant
  occupant="$(port_pid "$FRONTEND_PORT")"
  if [ -n "$occupant" ]; then
    die "Port $FRONTEND_PORT is already in use by PID $occupant. Stop it first or run ./stop.sh."
  fi

  info "Starting frontend..."
  (
    cd "$ROOT/frontend"
    nohup "$ROOT/frontend/node_modules/.bin/vite" \
      --host 127.0.0.1 --port "$FRONTEND_PORT" --strictPort \
      >"$FRONTEND_LOG" 2>&1 &
    echo $! >"$RUN_DIR/frontend.pid"
  )

  if ! wait_for "$FRONTEND_URL/" "Frontend" "$(cat "$RUN_DIR/frontend.pid")"; then
    printf '\n--- frontend.log (last 20 lines) ---\n' >&2
    tail -n 20 "$FRONTEND_LOG" >&2 || true
    die "Frontend failed to start. Full log: $FRONTEND_LOG"
  fi
}

start_all() {
  ensure_dependencies
  start_backend
  start_frontend

  printf '\n'
  ok "NetGuard AI is running"
  info "Dashboard: $FRONTEND_URL"
  info "API docs:  $BACKEND_URL/docs"
  info "Logs:      $BACKEND_LOG"
  info "           $FRONTEND_LOG"
  info "Stop:      ./stop.sh   (or ./start.sh stop)"
  printf '\n'

  if [ "${NO_OPEN:-0}" != "1" ] && command -v open >/dev/null 2>&1; then
    open "$FRONTEND_URL"
  fi
}

stop_one() {
  local name="$1" pidfile="$2" port="$3"
  local pid="" stopped=0

  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile" 2>/dev/null || true)"
  fi

  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 25); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    ok "Stopped $name (PID $pid)"
    stopped=1
  fi

  # Fallback: find the listener on the port, but only stop it when its working
  # directory is this project. This avoids killing an unrelated Vite/uvicorn.
  if [ "$stopped" -eq 0 ]; then
    local occupant cwd
    occupant="$(port_pid "$port")"
    if [ -n "$occupant" ]; then
      cwd="$(pid_cwd "$occupant")"
      if [ "$cwd" = "$ROOT" ] || [ "$cwd" = "$ROOT/frontend" ]; then
        kill "$occupant" 2>/dev/null || true
        sleep 0.5
        kill -9 "$occupant" 2>/dev/null || true
        ok "Stopped $name (PID $occupant)"
        stopped=1
      else
        warn "Port $port is used by PID $occupant ($cwd), which is not this project; leaving it alone"
      fi
    fi
  fi

  if [ "$stopped" -eq 0 ] && [ -z "${occupant:-}" ]; then
    info "$name is not running"
  fi

  rm -f "$pidfile"
}

stop_all() {
  stop_one "backend" "$RUN_DIR/backend.pid" "$BACKEND_PORT"
  stop_one "frontend" "$RUN_DIR/frontend.pid" "$FRONTEND_PORT"
}

status_all() {
  printf 'NetGuard AI status\n'

  if is_backend_up; then
    ok "Backend running at $BACKEND_URL"
    curl -fsS "$BACKEND_URL/api/health" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("   model:", d.get("model_name", "-"),
      "| loaded:", d.get("model_loaded"),
      "| reliability:", d.get("reliability_active"),
      "| shift gate:", d.get("shift_gate_active"))
' 2>/dev/null || true
  else
    warn "Backend not running"
  fi

  if is_frontend_up; then
    ok "Frontend running at $FRONTEND_URL"
  else
    warn "Frontend not running"
  fi
}

case "${1:-start}" in
  start)   start_all ;;
  stop)    stop_all ;;
  restart) stop_all; printf '\n'; start_all ;;
  status)  status_all ;;
  *)
    printf 'Usage: ./start.sh [start|stop|restart|status]\n' >&2
    exit 1
    ;;
esac
