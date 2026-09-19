#!/usr/bin/env bash
# Reproduce every verification claim in VERIFICATION.md.
#
#   ./scripts/verify.sh            # offline checks only (fast, no docker/registry)
#   ./scripts/verify.sh --live     # also pull images and read a live container
#
# Exit code is non-zero if any check fails, so this is CI-usable.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LIVE=0
[[ "${1:-}" == "--live" ]] && LIVE=1

PASS=0
FAIL=0

check() {
    local name="$1"; shift
    if "$@" >/tmp/verify-step.log 2>&1; then
        printf '  \033[32mPASS\033[0m  %s\n' "$name"
        PASS=$((PASS + 1))
    else
        printf '  \033[31mFAIL\033[0m  %s\n' "$name"
        sed 's/^/        /' /tmp/verify-step.log | tail -15
        FAIL=$((FAIL + 1))
    fi
}

section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

section "1. Unit and integration tests"
check "pytest (all tests, 80% coverage floor)" python3 -m pytest tests/ -q --cov=escape_corpus --cov-report=term-missing

section "2. Lint"
check "ruff check" ruff check .

section "3. Corpus internal consistency"
check "escape-corpus validate" escape-corpus validate
check "taxonomy.json is valid JSON" python3 -c \
    "import json;d=json.load(open('corpus/taxonomy/taxonomy.json'));assert d['techniques']"
check "taxonomy matches its schema" python3 -c "
import json, jsonschema
jsonschema.validate(json.load(open('corpus/taxonomy/taxonomy.json')),
                    json.load(open('schemas/taxonomy.schema.json')))
print('taxonomy schema-valid')"

section "4. Detection rules"
if command -v sigma >/dev/null 2>&1; then
    check "sigma check (engine validation)" bash -c \
        "out=\$(sigma check corpus/detection/sigma/ 2>&1); echo \"\$out\"; ! grep -qE 'Found [1-9][0-9]* errors' <<<\"\$out\""
else
    printf '  \033[33mSKIP\033[0m  sigma check (sigma-cli not installed: pip install sigma-cli)\n'
fi
check "Falco rules + detection index (schema + cross-refs)" python3 -m pytest tests/test_detection_rules.py -q

section "5. MCP server"
if python3 -c "import fastmcp" 2>/dev/null; then
    check "MCP tool/resource round-trip" python3 -m pytest tests/test_mcp_server.py -q
else
    printf '  \033[33mSKIP\033[0m  MCP tests (pip install "escape-corpus[mcp]")\n'
fi

section "6. Published benchmark fixtures"
check "shipped image-diff sample is schema-valid" python3 -c "
import json, jsonschema
jsonschema.validate(json.load(open('corpus/benchmarks/image-diff-nginx-sample.json')),
                    json.load(open('schemas/image-diff.schema.json')))
print('sample schema-valid')"

if [[ $LIVE -eq 1 ]]; then
    section "7. Live: image delta + package inventory (pulls from a registry)"
    check "image-diff busybox:1.35 -> busybox:1.36" bash -c \
        "escape-corpus image-diff busybox:1.35 busybox:1.36 -o /tmp/verify-busybox.json >/dev/null && \
         python3 -c \"import json;d=json.load(open('/tmp/verify-busybox.json'));print(d['risk_level'], d['packages'].get('counts'))\""

    section "8. Live: runtime baseline + drift (needs docker/podman)"
    if command -v docker >/dev/null 2>&1; then
        check "baseline -> verify round trip is clean" bash -c '
            docker rm -f verify-drift >/dev/null 2>&1 || true
            docker run -d --name verify-drift alpine:3.19 sleep 300 >/dev/null
            escape-corpus runtime-baseline baseline --container verify-drift -o /tmp/verify-base.json
            escape-corpus runtime-baseline verify --container verify-drift --baseline /tmp/verify-base.json
            docker rm -f verify-drift >/dev/null'
    else
        printf '  \033[33mSKIP\033[0m  docker not available\n'
    fi
else
    section "7-8. Live checks"
    printf '  \033[33mSKIP\033[0m  run with --live (needs registry network access and docker)\n'
fi

printf '\n\033[1mSummary:\033[0m %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]] || exit 1
