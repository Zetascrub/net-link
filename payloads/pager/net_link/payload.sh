#!/bin/sh
# Title: Net-Link
# Description: Peer link and segmentation validation
# Author: Net-Link
# Version: 0.2.0
# Category: General

PAYLOAD_DIR="/mmc/root/payloads/user/general/net_link"
RUNS_DIR="$PAYLOAD_DIR/runs"
BIN="$PAYLOAD_DIR/net-link"
LOG_FILE="$PAYLOAD_DIR/net-link.log"
PID_FILE="$PAYLOAD_DIR/net-link.pid"
RUN_PID=""
FIFO_FILE=""

mkdir -p "$PAYLOAD_DIR" "$RUNS_DIR" 2>/dev/null

say() {
    color="$1"; shift
    msg="$*"
    echo "[$(date '+%H:%M:%S')] $msg" >>"$LOG_FILE" 2>/dev/null
    LOG "$color" "$msg" 2>/dev/null || echo "$msg"
}

wait_button() {
    WAIT_FOR_INPUT 2>/dev/null || { read -r b; echo "$b"; }
}

show_ips() {
    ip -4 addr show 2>/dev/null | awk '
        /inet / { split($2,a,"/"); if (a[1] != "127.0.0.1") print a[1] }
    ' | while read -r addr; do
        say cyan "IP: $addr"
    done
}

stop_child() {
    if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then
        say yellow "Stopping $RUN_PID"
        kill "$RUN_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$RUN_PID" 2>/dev/null || true
    fi
    RUN_PID=""
    rm -f "$PID_FILE" 2>/dev/null || true
}

stop_stale() {
    if [ -f "$PID_FILE" ]; then
        old="$(cat "$PID_FILE" 2>/dev/null)"
        if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
            say yellow "Stopping previous pid $old"
            kill "$old" 2>/dev/null || true
            sleep 1
            kill -9 "$old" 2>/dev/null || true
        fi
        rm -f "$PID_FILE" 2>/dev/null || true
    fi
}

cleanup() {
    stop_child
    [ -n "$FIFO_FILE" ] && rm -f "$FIFO_FILE" 2>/dev/null || true
    LED OFF
    DPADLED off
    say yellow "Net-Link stopped"
}

run_stream() {
    stop_child
    FIFO_FILE="/tmp/nl-$$.fifo"
    rm -f "$FIFO_FILE" 2>/dev/null || true
    mkfifo "$FIFO_FILE" || { say red "pipe failed"; return 1; }

    "$@" >"$FIFO_FILE" 2>&1 &
    RUN_PID="$!"
    echo "$RUN_PID" >"$PID_FILE" 2>/dev/null || true

    while IFS= read -r line; do
        case "$line" in
            *"linked_both_ways"*|*"Reachable:"*|*"Link verified"*) say green  "$line" ;;
            *"linked_one_way"*|*"Discovery probe"*|*"warning:"*)    say yellow "$line" ;;
            *"error"*|*"Error"*|*"failed"*|*"Failed"*)              say red    "$line" ;;
            *) say white "$line" ;;
        esac
    done <"$FIFO_FILE"

    wait "$RUN_PID" 2>/dev/null
    exit_code=$?
    RUN_PID=""
    rm -f "$PID_FILE" "$FIFO_FILE" 2>/dev/null || true
    FIFO_FILE=""
    return $exit_code
}

# Parse a one-line summary from a JSON evidence file.
# The filename prefix indicates which JSON schema applies.
show_run_summary() {
    file="$1"
    [ -s "$file" ] || return
    name="$(basename "$file")"
    case "$name" in
        discover-*)
            peers=$(grep -o '"peers":[0-9]*'  "$file" | head -1 | grep -o '[0-9]*')
            linked=$(grep -o '"linked":[0-9]*' "$file" | head -1 | grep -o '[0-9]*')
            say cyan "Peers: ${peers:-0}  Linked: ${linked:-0}"
            ;;
        matrix-*)
            l2p=$(grep -o '"local_to_peer_reachable":[0-9]*' "$file" | head -1 | grep -o '[0-9]*')
            p2l=$(grep -o '"peer_to_local_reachable":[0-9]*' "$file" | head -1 | grep -o '[0-9]*')
            say cyan "Local->Peer: ${l2p:-0}  Peer->Local: ${p2l:-0}"
            ;;
        lan-*)
            targets=$(grep -o '"targets":[0-9]*'   "$file" | head -1 | grep -o '[0-9]*')
            reach=$(grep -o '"reachable":[0-9]*'   "$file" | head -1 | grep -o '[0-9]*')
            say cyan "Targets: ${targets:-0}  Reachable: ${reach:-0}"
            ;;
    esac
}

# Called after every scanning operation; shows summary, sets LEDs, waits for button.
finish_op() {
    file="$1"
    if [ -s "$file" ]; then
        show_run_summary "$file"
        LED FINISH
        DPADLED green
    else
        LED FAIL2
        DPADLED red
    fi
    say white "Press any button"
    wait_button >/dev/null 2>&1
}

show_status() {
    count=$(ls "$RUNS_DIR"/*.nljson 2>/dev/null | wc -l | tr -d ' ')
    say cyan "Saved runs: ${count:-0}"
    if [ "${count:-0}" -gt 0 ]; then
        last="$(ls -t "$RUNS_DIR"/*.nljson 2>/dev/null | head -1)"
        say white "Last: $(basename "$last")"
        show_run_summary "$last"
    fi
    say white "Press any button"
    wait_button >/dev/null 2>&1
}

matrix_port_menu() {
    say white "Matrix port profile:"
    say white "GREEN/A: Common"
    say white "UP: Web"
    say white "DOWN: Windows"
    say white "RED/B: Cancel"
    b="$(wait_button)"
    case "$b" in
        GREEN|A)  echo "22,80,443,47889" ;;
        UP)       echo "80,443,8080,8443" ;;
        DOWN)     echo "135,139,445,3389" ;;
        *)        echo "" ;;
    esac
}

main_menu() {
    LED SETUP
    DPADLED white
    say green "Net-Link"
    show_ips
    say white "GREEN/A: Listen"
    say white "UP: Find peers"
    say white "DOWN: Matrix"
    say white "LEFT: Status"
    say white "RIGHT: LAN scan"
    say white "RED/B: Exit"
}

# ---

cd "$PAYLOAD_DIR" || exit 1
echo "=== Net-Link $(date) ===" >"$LOG_FILE"
ENABLE_DISPLAY >/dev/null 2>&1 || true
trap cleanup INT TERM HUP EXIT
stop_stale

if [ ! -x "$BIN" ]; then
    LED FAIL
    ERROR_DIALOG "Missing binary: $BIN"
    exit 1
fi

while true; do
    main_menu
    button="$(wait_button)"
    case "$button" in

        GREEN|A|"")
            say cyan "Listening for peers"
            say yellow "UDP 47888 / TCP 47889"
            LED SPECIAL
            DPADLED cyan
            run_stream "$BIN" link listen --name pager
            # Returns only when killed/interrupted; LED reset on next menu iteration.
            ;;

        UP)
            say cyan "Finding Net-Link peers"
            LED STAGE1
            DPADLED yellow
            out="$RUNS_DIR/discover-$(date '+%Y%m%d-%H%M%S').nljson"
            run_stream "$BIN" link discover --name pager --out "$out"
            finish_op "$out"
            ;;

        DOWN)
            ports="$(matrix_port_menu)"
            [ -z "$ports" ] && continue
            say cyan "Matrix: $ports"
            LED STAGE2
            DPADLED yellow
            out="$RUNS_DIR/matrix-$(date '+%Y%m%d-%H%M%S').nljson"
            run_stream "$BIN" link matrix --name pager --ports "$ports" --out "$out"
            finish_op "$out"
            ;;

        LEFT)
            show_status
            ;;

        BLUE|RIGHT)
            if CONFIRMATION_DIALOG "Scan local networks?"; then
                say cyan "Discovering LAN services"
                LED STAGE3
                DPADLED yellow
                out="$RUNS_DIR/lan-$(date '+%Y%m%d-%H%M%S').nljson"
                run_stream "$BIN" discover --ports 22,80,443,8080,8443 --out "$out"
                finish_op "$out"
            fi
            ;;

        RED|B)
            say yellow "Exiting"
            cleanup
            trap - INT TERM HUP EXIT
            exit 0
            ;;

        *)
            say yellow "Button: $button"
            ;;

    esac
done
