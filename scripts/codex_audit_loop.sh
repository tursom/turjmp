#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/codex_audit_loop.sh -n <count> (-p <prompt> | -f <prompt-file>) [options]

Options:
  -n <count>              Number of audit/fix rounds. Must be a positive integer.
  -p <prompt>             Audit prompt text.
  -f <prompt-file>        Read audit prompt text from file.
  --fix-session same|new  Use the audit session for fixes, or start a new fix session. Default: same.
  -C, --cd <dir>          Codex working directory. Default: current directory.
  --model, -m <model>     Model to pass through to Codex.
  --enable-memories       Keep Codex memories enabled for child audit/fix runs. Default: disabled.
  --preserve-api-env      Preserve OPENAI_API_KEY/CODEX_API_KEY for child Codex runs. Default: unset them.
  -o, --output-dir <dir>  Output directory. Default: .codex-audit-loop under the working directory.
  -h, --help              Show this help.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_value() {
  local option=$1
  local value=${2-}
  [[ -n "$value" ]] || die "$option requires a value"
}

extract_thread_id() {
  local jsonl=$1

  if command -v jq >/dev/null 2>&1; then
    local ids
    ids=$(jq -r 'select(.type == "thread.started") | .thread_id // empty' "$jsonl")
    printf '%s\n' "$ids" | sed -n '1p'
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$jsonl" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "thread.started":
            print(event.get("thread_id", ""))
            break
PY
    return
  fi

  die "jq or python3 is required to parse Codex JSONL output"
}

print_jsonl_errors() {
  local jsonl=$1
  local printed=0

  [[ -s "$jsonl" ]] || return

  if command -v jq >/dev/null 2>&1; then
    while IFS= read -r message; do
      if [[ $printed -eq 0 ]]; then
        printf 'recent Codex errors from %s:\n' "$jsonl" >&2
        printed=1
      fi
      printf '  - %s\n' "$message" >&2
    done < <(jq -r 'select(.type == "error") | .message // empty' "$jsonl" | tail -n 10)
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$jsonl" <<'PY' >&2
import json
import sys

messages = []
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "error" and event.get("message"):
            messages.append(event["message"])

if messages:
    print(f"recent Codex errors from {sys.argv[1]}:")
    for message in messages[-10:]:
        print(f"  - {message}")
PY
  fi
}

run_codex_json() {
  local label=$1
  local jsonl=$2
  local final_message=$3
  shift 3

  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$label"
  if [[ "${preserve_api_env:-0}" -eq 1 ]]; then
    if ! "$@" >"$jsonl"; then
      print_jsonl_errors "$jsonl"
      die "$label failed; JSONL output is in $jsonl"
    fi
  elif ! env -u OPENAI_API_KEY -u CODEX_API_KEY "$@" >"$jsonl"; then
    print_jsonl_errors "$jsonl"
    die "$label failed; JSONL output is in $jsonl"
  fi

  if [[ ! -s "$final_message" ]]; then
    print_jsonl_errors "$jsonl"
    die "$label did not produce a final message at $final_message"
  fi
}

rounds=''
audit_prompt=''
audit_prompt_file=''
fix_session='same'
workdir=$(pwd)
output_dir='.codex-audit-loop'
model=''
memories_enabled=0
preserve_api_env=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n)
      need_value "$1" "${2-}"
      rounds=$2
      shift 2
      ;;
    -p)
      need_value "$1" "${2-}"
      audit_prompt=$2
      shift 2
      ;;
    -f)
      need_value "$1" "${2-}"
      audit_prompt_file=$2
      shift 2
      ;;
    --fix-session)
      need_value "$1" "${2-}"
      fix_session=$2
      shift 2
      ;;
    -C|--cd)
      need_value "$1" "${2-}"
      workdir=$2
      shift 2
      ;;
    --model|-m)
      need_value "$1" "${2-}"
      model=$2
      shift 2
      ;;
    --enable-memories)
      memories_enabled=1
      shift
      ;;
    --preserve-api-env)
      preserve_api_env=1
      shift
      ;;
    -o|--output-dir)
      need_value "$1" "${2-}"
      output_dir=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ $# -eq 0 ]] || die "unexpected positional arguments: $*"
[[ -n "$rounds" ]] || die "-n <count> is required"
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || die "-n must be a positive integer"

if [[ -n "$audit_prompt" && -n "$audit_prompt_file" ]]; then
  die "use only one of -p or -f"
fi

if [[ -z "$audit_prompt" && -z "$audit_prompt_file" ]]; then
  die "one of -p or -f is required"
fi

case "$fix_session" in
  same|new) ;;
  *) die "--fix-session must be either same or new" ;;
esac

[[ -d "$workdir" ]] || die "working directory does not exist: $workdir"
workdir=$(cd "$workdir" && pwd)

if [[ -n "$audit_prompt_file" ]]; then
  [[ -f "$audit_prompt_file" ]] || die "prompt file does not exist: $audit_prompt_file"
  audit_prompt=$(<"$audit_prompt_file")
fi

[[ -n "$audit_prompt" ]] || die "audit prompt must not be empty"

if [[ "$output_dir" != /* ]]; then
  output_dir="$workdir/$output_dir"
fi
mkdir -p "$output_dir"

printf 'Codex audit loop\n'
printf '  workdir: %s\n' "$workdir"
printf '  rounds: %s\n' "$rounds"
printf '  fix-session: %s\n' "$fix_session"
if [[ "$memories_enabled" -eq 1 ]]; then
  printf '  memories: enabled\n'
else
  printf '  memories: disabled\n'
fi
if [[ "$preserve_api_env" -eq 1 ]]; then
  printf '  api env: preserved\n'
else
  printf '  api env: stripped\n'
fi
printf '  output-dir: %s\n' "$output_dir"

for ((round = 1; round <= rounds; round++)); do
  audit_jsonl="$output_dir/round-${round}-audit.jsonl"
  audit_md="$output_dir/round-${round}-audit.md"
  fix_jsonl="$output_dir/round-${round}-fix.jsonl"
  fix_md="$output_dir/round-${round}-fix.md"
  threads_file="$output_dir/round-${round}-threads.txt"

  audit_cmd=(codex exec --json --sandbox read-only -C "$workdir" -o "$audit_md")
  if [[ "$memories_enabled" -eq 0 ]]; then
    audit_cmd+=(--disable memories)
  fi
  if [[ -n "$model" ]]; then
    audit_cmd+=(--model "$model")
  fi
  audit_cmd+=(-- "$audit_prompt")

  run_codex_json "round $round audit" "$audit_jsonl" "$audit_md" "${audit_cmd[@]}"

  audit_thread_id=$(extract_thread_id "$audit_jsonl")
  [[ -n "$audit_thread_id" ]] || die "round $round audit did not emit thread.started.thread_id"

  if [[ "$fix_session" == 'same' ]]; then
    fix_cmd=(
      codex exec resume
      --json
      -c 'sandbox_mode="workspace-write"'
      -c 'approval_policy="never"'
      -o "$fix_md"
    )
    if [[ "$memories_enabled" -eq 0 ]]; then
      fix_cmd+=(--disable memories)
    fi
    if [[ -n "$model" ]]; then
      fix_cmd+=(--model "$model")
    fi
    fix_cmd+=("$audit_thread_id" "修复这些问题")

    run_codex_json "round $round fix in audit session" "$fix_jsonl" "$fix_md" "${fix_cmd[@]}"
    fix_thread_id=$audit_thread_id
  else
    fix_cmd=(codex exec --json --sandbox workspace-write --ask-for-approval never -C "$workdir" -o "$fix_md")
    if [[ "$memories_enabled" -eq 0 ]]; then
      fix_cmd+=(--disable memories)
    fi
    if [[ -n "$model" ]]; then
      fix_cmd+=(--model "$model")
    fi
    fix_cmd+=(-- "修复这些问题")

    run_codex_json "round $round fix in new session" "$fix_jsonl" "$fix_md" "${fix_cmd[@]}" <"$audit_md"

    fix_thread_id=$(extract_thread_id "$fix_jsonl")
    [[ -n "$fix_thread_id" ]] || die "round $round fix did not emit thread.started.thread_id"
  fi

  {
    printf 'round=%s\n' "$round"
    printf 'fix_session=%s\n' "$fix_session"
    printf 'audit_thread_id=%s\n' "$audit_thread_id"
    printf 'fix_thread_id=%s\n' "$fix_thread_id"
  } >"$threads_file"

  printf '[%s] round %s complete: audit_thread_id=%s fix_thread_id=%s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$round" "$audit_thread_id" "$fix_thread_id"
done
