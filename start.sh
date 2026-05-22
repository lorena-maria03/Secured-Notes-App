#!/usr/bin/env bash
# Usage: ./start.sh [start|stop|restart|status|logs [backend|mailpit]]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
PID_DIR="$SCRIPT_DIR/.run"
LOG_DIR="$SCRIPT_DIR/.logs"
MAILPIT_PID="$PID_DIR/mailpit.pid"
BACKEND_PID="$PID_DIR/backend.pid"
MAILPIT_LOG="$LOG_DIR/mailpit.log"
BACKEND_LOG="$LOG_DIR/backend.log"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

say()  { printf "${1}%s${NC}\n" "${*:2}"; }
info() { printf "  %-10s %s\n" "$1" "$2"; }

mkdir -p "$PID_DIR" "$LOG_DIR"

# ── helpers ──────────────────────────────────────────────────────────────────

is_running() {
    local pid_file="$1"
    local pid
    [[ -f "$pid_file" ]] || return 1
    pid=$(cat "$pid_file")
    kill -0 "$pid" 2>/dev/null
}

kill_port() {
    local port="$1"
    local pids
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs kill 2>/dev/null || true
    fi
}

stop_process() {
    local name="$1" pid_file="$2"
    if is_running "$pid_file"; then
        local pid
        pid=$(cat "$pid_file")
        local pgid
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        if [[ -n "$pgid" && "$pgid" != "0" ]]; then
            kill -- -"$pgid" 2>/dev/null || kill "$pid" 2>/dev/null || true
        else
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
        printf "${RED}[%s]${NC} stopped\n" "$name"
    else
        # also sweep the port in case a stray process is there
        case "$name" in
            backend) kill_port 8000 ;;
            mailpit) kill_port 1025; kill_port 8025 ;;
        esac
        printf "${YELLOW}[%s]${NC} not running\n" "$name"
        rm -f "$pid_file"
    fi
}

# ── mailpit ──────────────────────────────────────────────────────────────────

start_mailpit() {
    if is_running "$MAILPIT_PID"; then
        printf "${YELLOW}[mailpit]${NC} already running (PID %s)\n" "$(cat "$MAILPIT_PID")"
        return 0
    fi
    local bin
    bin=$(command -v mailpit 2>/dev/null || true)
    if [[ -z "$bin" ]]; then
        printf "${RED}[mailpit]${NC} not found — install with: brew install mailpit\n"
        return 1
    fi
    "$bin" --smtp 0.0.0.0:1025 --listen 0.0.0.0:8025 >> "$MAILPIT_LOG" 2>&1 &
    echo $! > "$MAILPIT_PID"
    printf "${GREEN}[mailpit]${NC} started (PID %s)\n" "$!"
    printf "           SMTP → localhost:1025\n"
    printf "           Web  → http://localhost:8025\n"
}

# ── backend ──────────────────────────────────────────────────────────────────

start_backend() {
    if is_running "$BACKEND_PID"; then
        printf "${YELLOW}[backend]${NC} already running (PID %s)\n" "$(cat "$BACKEND_PID")"
        return 0
    fi
    # kill anything already sitting on port 8000
    kill_port 8000
    # activate venv if present
    if [[ -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "$SCRIPT_DIR/.venv/bin/activate"
    elif [[ -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "$SCRIPT_DIR/venv/bin/activate"
    fi
    (
        cd "$BACKEND_DIR"
        exec uvicorn main:app --reload >> "$BACKEND_LOG" 2>&1
    ) &
    echo $! > "$BACKEND_PID"
    printf "${GREEN}[backend]${NC} started (PID %s)\n" "$!"
    printf "           App  → http://localhost:8000\n"
}

# ── status ───────────────────────────────────────────────────────────────────

status() {
    printf "${BOLD}=== Secured NotesApp ===${NC}\n"
    if is_running "$MAILPIT_PID"; then
        printf "  mailpit  ${GREEN}running${NC}  PID=%s  web=http://localhost:8025\n" "$(cat "$MAILPIT_PID")"
    else
        printf "  mailpit  ${RED}stopped${NC}\n"
    fi
    if is_running "$BACKEND_PID"; then
        printf "  backend  ${GREEN}running${NC}  PID=%s  app=http://localhost:8000\n" "$(cat "$BACKEND_PID")"
    else
        printf "  backend  ${RED}stopped${NC}\n"
    fi
}

# ── dispatch ─────────────────────────────────────────────────────────────────

CMD="${1:-start}"

case "$CMD" in
    start)
        start_mailpit
        start_backend
        printf "\n"
        status
        ;;
    stop)
        stop_process mailpit "$MAILPIT_PID"
        stop_process backend "$BACKEND_PID"
        ;;
    restart)
        stop_process mailpit "$MAILPIT_PID"
        stop_process backend "$BACKEND_PID"
        sleep 1
        start_mailpit
        start_backend
        printf "\n"
        status
        ;;
    status)
        status
        ;;
    logs)
        TARGET="${2:-backend}"
        case "$TARGET" in
            backend) tail -f "$BACKEND_LOG" ;;
            mailpit) tail -f "$MAILPIT_LOG" ;;
            *) printf "Usage: %s logs [backend|mailpit]\n" "$0"; exit 1 ;;
        esac
        ;;
    *)
        printf "Usage: %s {start|stop|restart|status|logs [backend|mailpit]}\n" "$0"
        exit 1
        ;;
esac
