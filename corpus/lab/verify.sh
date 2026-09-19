#!/usr/bin/env bash
# Verification for the container-escape lab. Applies nothing.
#
# 1. Runs `admission-review --pod <file> --json` over every pod manifest in
#    this directory and asserts risk_level is CRITICAL or HIGH.
# 2. Performs a runtime-baseline baseline/verify round trip against the kind
#    control-plane container (runtime docker) and expects "No drift detected".
#
# Exits non-zero if any manifest is under-detected or the runtime check fails.
# The runtime check is reported as SKIP (not FAIL) when docker/kind are
# unavailable in the current shell.
#
# FOR ISOLATED LAB USE ONLY.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="${LAB_CLUSTER_NAME:-escape-lab}"

log() { printf '[lab-verify] %s\n' "$*"; }
die() { printf '[lab-verify] ERROR: %s\n' "$*" >&2; exit 2; }

failures=0

# --- 1. admission review gate ------------------------------------------------
command -v admission-review >/dev/null 2>&1 || die "admission-review not found on PATH"

shopt -s nullglob
manifests=("$LAB_DIR"/*-pod.yaml)
shopt -u nullglob

((${#manifests[@]} > 0)) || die "no pod manifests found in $LAB_DIR"

log "admission-review over ${#manifests[@]} manifest(s)"
for manifest in "${manifests[@]}"; do
    name="$(basename "$manifest")"
    report=""
    if ! report="$(admission-review --pod "$manifest" --json 2>/dev/null)" || [[ -z "$report" ]]; then
        printf 'FAIL  %-34s admission-review produced no report\n' "$name"
        failures=$((failures + 1))
        continue
    fi

    verdict="$(printf '%s' "$report" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("PARSE_ERROR 0 0")
else:
    print(d.get("risk_level", "UNKNOWN"), d.get("risk_score", 0), d.get("total_findings", 0))
' 2>/dev/null)" || verdict="PARSE_ERROR 0 0"

    [[ -n "$verdict" ]] || verdict="PARSE_ERROR 0 0"

    level="${verdict%% *}"
    rest="${verdict#* }"
    score="${rest%% *}"
    findings="${rest#* }"

    case "$level" in
        CRITICAL | HIGH)
            printf 'PASS  %-34s risk_level=%-8s score=%-4s findings=%s\n' \
                "$name" "$level" "$score" "$findings"
            ;;
        *)
            printf 'FAIL  %-34s risk_level=%-8s score=%-4s (expected CRITICAL or HIGH)\n' \
                "$name" "$level" "$score"
            failures=$((failures + 1))
            ;;
    esac
done

# --- 2. runtime-baseline round trip ------------------------------------------
log "runtime-baseline round trip against '$CLUSTER_NAME' control-plane"
runtime_ok=1

if ! command -v runtime-baseline >/dev/null 2>&1; then
    printf 'SKIP  runtime-baseline        not installed on PATH\n'
elif ! docker info >/dev/null 2>&1; then
    printf 'SKIP  runtime-baseline        docker not accessible in this shell (run: newgrp docker)\n'
elif ! command -v kind >/dev/null 2>&1 || ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    printf 'SKIP  runtime-baseline        kind cluster %s not found (run: ./corpus/lab/up.sh)\n' "$CLUSTER_NAME"
else
    node_container=""
    if docker inspect "$CLUSTER_NAME-control-plane" >/dev/null 2>&1; then
        node_container="$CLUSTER_NAME-control-plane"
    else
        node_container="$(docker ps --format '{{.Names}}' | grep -m1 "^${CLUSTER_NAME}-control-plane$" || true)"
    fi

    if [[ -z "$node_container" ]]; then
        printf 'SKIP  runtime-baseline        no running %s control-plane container\n' "$CLUSTER_NAME"
    else
        baseline_file="$(mktemp)"
        verify_log="$(mktemp)"
        trap 'rm -f "$baseline_file" "$verify_log"' EXIT

        if runtime-baseline baseline --container "$node_container" --runtime docker \
            --output "$baseline_file" >"$verify_log" 2>&1 \
            && runtime-baseline verify --container "$node_container" --baseline "$baseline_file" \
                --runtime docker >>"$verify_log" 2>&1 \
            && grep -q "No drift detected" "$verify_log"; then
            printf 'PASS  runtime-baseline        container=%s  No drift detected\n' "$node_container"
        else
            printf 'FAIL  runtime-baseline        container=%s  (expected "No drift detected")\n' "$node_container"
            sed 's/^/      | /' "$verify_log"
            runtime_ok=0
        fi
        rm -f "$baseline_file" "$verify_log"
        trap - EXIT
    fi
fi

if ((runtime_ok == 0)); then
    failures=$((failures + 1))
fi

# --- summary -----------------------------------------------------------------
if ((failures > 0)); then
    log "FAILED: $failures check(s) failed"
    exit 1
fi

log "OK: all manifests detected and runtime baseline clean"
