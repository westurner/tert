#!/usr/bin/env bash
set -euo pipefail

shellwrap_usage() {
  cat <<EOF
Usage: $0 [--help] [--self-test] [-c cmdstr ... [name [arg ...]]] | [cmdstr]

Run commands and display streaming terminal output with colors
and also write to a log file with ANSI-escape-characters removed

Modes:
  $0 "cmdstr"
      Run a single command string like 'sh -c'.

  $0 -c "cmdstr" [name [arg ...]]
      Run a single command string with positional parameters like 'sh -c'.

  $0 -c "cmd1" -c "cmd2"
    Run multiple command strings sequentially.

  $0 -- "cmdstr" [name [arg ...]]
    Run a single command string and pass trailing args explicitly after --.

  $0 -c "cmdstr" -- [name [arg ...]]
    Pass positional parameters to a single -c command explicitly after --.

Environment:
  LOG_FILE        Plain log path. Default: build.log
  ANSI_LOG_FILE   ANSI log path. Default: build.log.ansi
  KEEP_ANSI_LOG   Keep ANSI log when set to 1. Default: 0
  TRACE           Enable shell tracing when set to 1. Default: 1
EOF
}

shellwrap_set_color_args() {
  export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
  export FORCE_COLOR="${FORCE_COLOR:-1}"
  export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:---color=yes}"
}

shellwrap_defaults() {
  LOG_FILE="${LOG_FILE:-build.log}"
  ANSI_LOG_FILE="${ANSI_LOG_FILE:-build.log.ansi}"
  KEEP_ANSI_LOG="${KEEP_ANSI_LOG:-0}"
  TRACE="${TRACE:-1}"
}

shellwrap_parse_args() {
  SW_CMDS=()
  SW_SINGLE_ARGV=()
  SW_ALLOW_ARGV="0"
  SW_EXPLICIT_ARGV="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c)
        shift
        if [[ $# -lt 1 ]]; then
          shellwrap_usage
          return 2
        fi
        SW_CMDS+=("$1")
        SW_ALLOW_ARGV="1"
        shift
        ;;
      --)
        SW_EXPLICIT_ARGV="1"
        shift
        break
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ ${#SW_CMDS[@]} -eq 0 ]]; then
    if [[ $# -eq 0 ]]; then
      shellwrap_usage
      return 2
    fi
    if [[ $# -eq 1 ]]; then
      SW_CMDS=("$1")
      return 0
    fi
    if [[ "$SW_EXPLICIT_ARGV" == "1" && $# -gt 1 ]]; then
      SW_CMDS=("$1")
      shift
      SW_SINGLE_ARGV=("$@")
      return 0
    fi
    shellwrap_usage
    return 2
  fi

  if [[ ${#SW_CMDS[@]} -gt 1 && $# -gt 0 ]]; then
    echo "shellwrap: trailing args are only supported with a single -c cmdstr" >&2
    return 2
  fi

  if [[ "$SW_ALLOW_ARGV" == "1" && ${#SW_CMDS[@]} -eq 1 && $# -gt 0 ]]; then
    SW_SINGLE_ARGV=("$@")
  fi
}

shellwrap_execute() {
  {
    local cmd
    for cmd in "${SW_CMDS[@]}"; do
      if [[ ${#SW_SINGLE_ARGV[@]} -gt 0 ]]; then
        bash -c "$cmd" "${SW_SINGLE_ARGV[@]}"
        SW_SINGLE_ARGV=()
      else
        bash -c "$cmd"
      fi
    done
  } 2>&1 | tee "$ANSI_LOG_FILE"

  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$ANSI_LOG_FILE" > "$LOG_FILE"

  if [[ "$KEEP_ANSI_LOG" != "1" ]]; then
    rm -f "$ANSI_LOG_FILE"
  fi
}

shellwrap_main() {
  shellwrap_defaults
  shellwrap_set_color_args
  shellwrap_parse_args "$@"

  if [[ "$TRACE" == "1" ]]; then
    set -x
  fi

  shellwrap_execute
}


## ## Test assertion functions

asserteq() {
  local expected="$1"
  local actual="$2"
  local label="${3:-values differ}"
  if [[ "$expected" != "$actual" ]]; then
    echo "ASSERT EQ FAILED: $label" >&2
    echo "  expected: [$expected]" >&2
    echo "    actual: [$actual]" >&2
    return 1
  fi
}

## ## Tests

test_parse_c_mode() {
  shellwrap_defaults
  shellwrap_parse_args -c 'echo "$0:$1"' name arg1
  asserteq "1" "${#SW_CMDS[@]}" "single -c cmd count"
  asserteq 'echo "$0:$1"' "${SW_CMDS[0]}" "cmd string captured"
  asserteq "2" "${#SW_SINGLE_ARGV[@]}" "single mode argv length"
  asserteq "name" "${SW_SINGLE_ARGV[0]}" "single mode argv[0]"
  asserteq "arg1" "${SW_SINGLE_ARGV[1]}" "single mode argv[1]"
}

test_parse_multiple_c_mode() {
  shellwrap_defaults
  shellwrap_parse_args -c 'printf "one\n"' -c 'printf "two\n"'
  asserteq "2" "${#SW_CMDS[@]}" "multiple -c cmd count"
  asserteq 'printf "one\n"' "${SW_CMDS[0]}" "first -c cmd"
  asserteq 'printf "two\n"' "${SW_CMDS[1]}" "second -c cmd"
  asserteq "0" "${#SW_SINGLE_ARGV[@]}" "multiple -c has no argv"
}

test_parse_double_dash_argv_mode() {
  shellwrap_defaults
  shellwrap_parse_args -- 'echo "$0:$1:$2"' name arg1
  asserteq "1" "${#SW_CMDS[@]}" "double dash single cmd count"
  asserteq 'echo "$0:$1:$2"' "${SW_CMDS[0]}" "double dash cmd string"
  asserteq "2" "${#SW_SINGLE_ARGV[@]}" "double dash argv length"
  asserteq "name" "${SW_SINGLE_ARGV[0]}" "double dash argv[0]"
  asserteq "arg1" "${SW_SINGLE_ARGV[1]}" "double dash argv[1]"
}

test_parse_no_args_errors() {
  shellwrap_defaults
  if shellwrap_parse_args >/dev/null 2>&1; then
    echo "ASSERT EQ FAILED: no-arg parse should fail" >&2
    return 1
  fi
}

test_single_cmd_writes_stripped_log() {
  local d
  d="$(mktemp -d)"
  (
    cd "$d"
    TRACE=0 KEEP_ANSI_LOG=0 shellwrap_main 'printf "\033[31mred\033[0m\n"; printf "plain\n"'
    local content
    content="$(cat build.log)"
    asserteq $'red\nplain' "$content" "single cmd log stripped"
    if [[ -e build.log.ansi ]]; then
      echo "ASSERT EQ FAILED: ansi log should be removed" >&2
      return 1
    fi
  )
}

test_multiple_c_mode_overrides() {
  local d
  d="$(mktemp -d)"
  (
    cd "$d"
    TRACE=0 KEEP_ANSI_LOG=1 shellwrap_main -c 'printf "one\n"' -c 'printf "two\n"'
    local content
    content="$(cat build.log)"
    asserteq $'one\ntwo' "$content" "multiple -c mode combines logs"
    if [[ ! -e build.log.ansi ]]; then
      echo "ASSERT EQ FAILED: ansi log should be kept" >&2
      return 1
    fi
  )
}

test_usage_contains_help() {
  local usage
  usage="$(shellwrap_usage)"
  [[ "$usage" == *"Usage:"* ]]
  [[ "$usage" == *"--help"* ]]
  [[ "$usage" == *"--self-test"* ]]
}

## ## main()

shelltest_main() {
  local failed=0
  local t
  for t in \
    test_usage_contains_help \
    test_parse_no_args_errors \
    test_parse_c_mode \
    test_parse_multiple_c_mode \
    test_parse_double_dash_argv_mode \
    test_single_cmd_writes_stripped_log \
    test_multiple_c_mode_overrides
  do
    if "$t"; then
      echo "ok: $t"
    else
      echo "not ok: $t" >&2
      failed=$((failed + 1))
    fi
  done

  if [[ $failed -ne 0 ]]; then
    echo "shell tests failed: $failed" >&2
    return 1
  fi
  echo "shell tests passed"
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  shellwrap_usage
elif [[ "${1:-}" == "--self-test" ]]; then
  shift
  shelltest_main "$@"
else
  shellwrap_main "$@"
fi
