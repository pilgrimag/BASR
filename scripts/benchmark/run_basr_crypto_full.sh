#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_ROOT="/home/pilgrimage/basr/experiment-results"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="${1:-${RESULTS_ROOT}/basr-crypto-full-${TIMESTAMP}}"

PROFILE="full"
WARMUP_RUNS="5"
MEASUREMENT_RUNS="30"
REPORT_SIZE_BYTES="1024"
MIN_AVAILABLE_KB=$((3 * 1024 * 1024))
MAX_SWAP_USED_KB=$((256 * 1024))
FORMAL_MAVEN_OPTS="-Xms1g -Xmx1g -XX:+AlwaysPreTouch -Dfile.encoding=UTF-8"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

section() {
    printf '\n===== %s =====\n' "$*"
}

cd "${PROJECT_ROOT}"

section "Preflight"

[[ -f pom.xml ]] \
    || fail "pom.xml not found in ${PROJECT_ROOT}"

[[ -f src/main/java/com/basr/benchmark/CryptoBenchmarkMain.java ]] \
    || fail "CryptoBenchmarkMain.java is missing"

[[ -f scripts/benchmark/validate_basr_crypto_csv.py ]] \
    || fail "CSV validator is missing"

CURRENT_BRANCH="$(git branch --show-current)"
[[ "${CURRENT_BRANCH}" == "experiment/benchmark-baseline" ]] \
    || fail "Expected branch experiment/benchmark-baseline, found ${CURRENT_BRANCH}"

if [[ -n "$(git status --porcelain)" ]]; then
    git status --short >&2
    fail "Git worktree is not clean"
fi

MEM_AVAILABLE_KB="$(
    awk '/^MemAvailable:/ {print $2}' /proc/meminfo
)"
SWAP_TOTAL_KB="$(
    awk '/^SwapTotal:/ {print $2}' /proc/meminfo
)"
SWAP_FREE_KB="$(
    awk '/^SwapFree:/ {print $2}' /proc/meminfo
)"
SWAP_USED_KB=$((SWAP_TOTAL_KB - SWAP_FREE_KB))

if (( MEM_AVAILABLE_KB < MIN_AVAILABLE_KB )); then
    fail "Available memory is below 3 GiB: ${MEM_AVAILABLE_KB} KiB"
fi

if (( SWAP_USED_KB > MAX_SWAP_USED_KB )); then
    fail "Swap usage exceeds 256 MiB: ${SWAP_USED_KB} KiB"
fi

if docker info >/dev/null 2>&1; then
    ACTIVE_BASR_CONTAINERS="$(
        docker ps --format '{{.Names}}' \
            | grep -E \
              '^(ipfs|peer0\.org1\.example\.com|peer0\.org2\.example\.com|orderer\.example\.com|ca_org1|ca_org2|ca_orderer|dev-peer.*)$' \
            || true
    )"

    if [[ -n "${ACTIVE_BASR_CONTAINERS}" ]]; then
        printf '%s\n' "${ACTIVE_BASR_CONTAINERS}" >&2
        fail "BASR/IPFS/Fabric containers are still running"
    fi
fi

mkdir -p "${RESULT_DIR}"

if [[ -n "${MAVEN_OPTS:-}" ]] \
    && [[ "${MAVEN_OPTS}" != "${FORMAL_MAVEN_OPTS}" ]]; then

    printf 'NOTICE: replacing existing MAVEN_OPTS for the formal run.\n'
fi

export MAVEN_OPTS="${FORMAL_MAVEN_OPTS}"

section "Record environment before run"

{
    printf 'benchmark_name=BASR pure cryptography\n'
    printf 'started_local=%s\n' "$(date --iso-8601=seconds)"
    printf 'result_directory=%s\n' "${RESULT_DIR}"
    printf 'profile=%s\n' "${PROFILE}"
    printf 'warmup_runs=%s\n' "${WARMUP_RUNS}"
    printf 'measurement_runs=%s\n' "${MEASUREMENT_RUNS}"
    printf 'report_size_bytes=%s\n' "${REPORT_SIZE_BYTES}"
    printf 'maven_opts=%s\n' "${MAVEN_OPTS}"
    printf 'git_branch=%s\n' "${CURRENT_BRANCH}"
    printf 'git_commit=%s\n' "$(git rev-parse HEAD)"
    printf 'git_commit_describe=%s\n' "$(git describe --always --dirty)"
    printf '\n--- uname ---\n'
    uname -a
    printf '\n--- os-release ---\n'
    cat /etc/os-release
    printf '\n--- lscpu ---\n'
    lscpu
    printf '\n--- memory ---\n'
    free -h
    printf '\n--- load ---\n'
    uptime
    printf '\n--- Java ---\n'
    java -version 2>&1
    printf '\n--- Maven ---\n'
    mvn -version
    printf '\n--- Docker ---\n'
    docker --version 2>&1 || true
    docker compose version 2>&1 || true
} > "${RESULT_DIR}/environment-before.txt"

cat "${RESULT_DIR}/environment-before.txt"

section "Compile"

mvn clean compile \
    2>&1 \
    | tee "${RESULT_DIR}/compile.log"

sync
sleep 10

section "Run full BASR cryptographic benchmark"

mvn \
    -DskipTests \
    -Dexec.mainClass=com.basr.benchmark.CryptoBenchmarkMain \
    -Dexec.args="${PROFILE} ${RESULT_DIR} ${WARMUP_RUNS} ${MEASUREMENT_RUNS} ${REPORT_SIZE_BYTES}" \
    -Dexec.classpathScope=runtime \
    org.codehaus.mojo:exec-maven-plugin:3.1.0:java \
    2>&1 \
    | tee "${RESULT_DIR}/benchmark.log"

section "Validate raw CSV"

python3 \
    scripts/benchmark/validate_basr_crypto_csv.py \
    "${RESULT_DIR}" \
    2>&1 \
    | tee "${RESULT_DIR}/validation.log"

CSV_PATH="${RESULT_DIR}/basr-crypto-raw.csv"
METADATA_PATH="${RESULT_DIR}/basr-crypto-metadata.txt"

[[ -f "${CSV_PATH}" ]] \
    || fail "Raw CSV was not generated"

[[ -f "${METADATA_PATH}" ]] \
    || fail "Metadata file was not generated"

LINE_COUNT="$(wc -l < "${CSV_PATH}")"
[[ "${LINE_COUNT}" == "571" ]] \
    || fail "Expected 571 CSV lines, found ${LINE_COUNT}"

section "Record environment after run"

{
    printf 'finished_local=%s\n' "$(date --iso-8601=seconds)"
    printf '\n--- memory ---\n'
    free -h
    printf '\n--- load ---\n'
    uptime
} > "${RESULT_DIR}/environment-after.txt"

section "Create checksums"

(
    cd "${RESULT_DIR}"
    sha256sum \
        basr-crypto-raw.csv \
        basr-crypto-metadata.txt \
        environment-before.txt \
        environment-after.txt \
        compile.log \
        benchmark.log \
        validation.log \
        > checksums.sha256
)

section "Completed"

printf 'Formal BASR crypto benchmark completed successfully.\n'
printf 'Result directory: %s\n' "${RESULT_DIR}"
printf 'CSV lines: %s\n' "${LINE_COUNT}"
printf 'Git commit: %s\n' "$(git rev-parse HEAD)"
printf '\nValidation output:\n'
cat "${RESULT_DIR}/validation.log"
printf '\nChecksums:\n'
cat "${RESULT_DIR}/checksums.sha256"