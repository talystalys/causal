#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${REPO_ROOT}/tests/bin"
FIXTURES_DIR="${REPO_ROOT}/tests/fixtures"

mkdir -p "${BIN_DIR}"

CC="${CC:-cc}"
CFLAGS="-std=c17 -Wall -Wextra -Werror -O0 -g"

echo "Compiling fixtures using ${CC} ${CFLAGS}..."

"${CC}" ${CFLAGS} "${FIXTURES_DIR}/exit_42.c" -o "${BIN_DIR}/exit_42"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_term.c" -o "${BIN_DIR}/signal_term"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/write_hello.c" -o "${BIN_DIR}/write_hello"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/getpid_test.c" -o "${BIN_DIR}/getpid_test"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/getpid_replay.c" -o "${BIN_DIR}/getpid_replay"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/read_replay.c" -o "${BIN_DIR}/read_replay"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/mixed_replay.c" -o "${BIN_DIR}/mixed_replay"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/read_eof.c" -o "${BIN_DIR}/read_eof"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/read_zero_count.c" -o "${BIN_DIR}/read_zero_count"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/read_failed.c" -o "${BIN_DIR}/read_failed"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/raise_sigtrap.c" -o "${BIN_DIR}/raise_sigtrap"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/map_model.c" -o "${BIN_DIR}/map_model"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/brk_model.c" -o "${BIN_DIR}/brk_model"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/map_fail.c" -o "${BIN_DIR}/map_fail"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_external_usr1.c" -o "${BIN_DIR}/signal_external_usr1"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_external_term.c" -o "${BIN_DIR}/signal_external_term"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_stop_unsupported.c" -o "${BIN_DIR}/signal_stop_unsupported"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_segv_unsupported.c" -o "${BIN_DIR}/signal_segv_unsupported"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_multi_usr.c" -o "${BIN_DIR}/signal_multi_usr"
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/signal_during_read_unsupported.c" -o "${BIN_DIR}/signal_during_read_unsupported"

echo "Fixtures built successfully in ${BIN_DIR}."
