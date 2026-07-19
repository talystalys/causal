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
"${CC}" ${CFLAGS} "${FIXTURES_DIR}/raise_sigtrap.c" -o "${BIN_DIR}/raise_sigtrap"

echo "Fixtures built successfully in ${BIN_DIR}."
