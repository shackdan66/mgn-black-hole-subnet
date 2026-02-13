#!/usr/bin/env bash
set -euo pipefail

PROFILE=""
REGION=""

usage() {
  cat <<'USAGE'
naclmaker.sh - standalone AWS NACL helper (Bash + AWS CLI)

Usage:
  naclmaker.sh create --vpc-id VPC_ID [--name NAME] [--profile PROFILE] [--region REGION]
  naclmaker.sh rule add --acl-id ACL_ID --direction ingress|egress --rule-number N --action allow|deny --protocol P (--cidr CIDR | --ipv6-cidr CIDR6) [--port-from N --port-to N] [--icmp-type N --icmp-code N] [--profile PROFILE] [--region REGION]
  naclmaker.sh rule change --acl-id ACL_ID --direction ingress|egress --rule-number N --action allow|deny --protocol P (--cidr CIDR | --ipv6-cidr CIDR6) [--port-from N --port-to N] [--icmp-type N --icmp-code N] [--profile PROFILE] [--region REGION]
  naclmaker.sh rule delete --acl-id ACL_ID --direction ingress|egress --rule-number N [--profile PROFILE] [--region REGION]
  naclmaker.sh rule bulk-add --acl-id ACL_ID (-f FILE | --file FILE | --csv FILE) [--profile PROFILE] [--region REGION]

Notes:
  - This script intentionally does NOT perform subnet association changes.
  - Use AWS CLI auth/SSO separately (example: aws sso login --profile my-profile).
USAGE
}

die() {
  echo "ERROR: $*" >&2
  exit 2
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_int() {
  [[ "$1" =~ ^-?[0-9]+$ ]]
}

validate_int_range() {
  local value="$1"
  local min="$2"
  local max="$3"
  local label="$4"

  is_int "$value" || die "$label must be an integer."
  (( value >= min && value <= max )) || die "$label must be between $min and $max."
}

validate_acl_id() {
  local acl_id="$1"
  [[ "$acl_id" =~ ^acl-[0-9a-fA-F]+$ ]] || die "Invalid ACL ID: $acl_id"
}

aws_ec2() {
  local -a cmd=(aws ec2)
  if [[ -n "$PROFILE" ]]; then
    cmd+=(--profile "$PROFILE")
  fi
  if [[ -n "$REGION" ]]; then
    cmd+=(--region "$REGION")
  fi
  cmd+=("$@")
  "${cmd[@]}"
}

protocol_to_number() {
  local p
  p="$(lower "$(trim "$1")")"

  case "$p" in
    all|-1) echo "-1" ;;
    tcp|6) echo "6" ;;
    udp|17) echo "17" ;;
    icmp|1) echo "1" ;;
    icmpv6|58) echo "58" ;;
    *)
      if [[ "$p" =~ ^-?[0-9]+$ ]]; then
        echo "$p"
      else
        die "Invalid protocol '$1'. Use all|tcp|udp|icmp|icmpv6 or protocol number."
      fi
      ;;
  esac
}

direction_to_egress_flag() {
  local dir
  dir="$(lower "$1")"

  case "$dir" in
    ingress) echo "--no-egress" ;;
    egress) echo "--egress" ;;
    *) die "Invalid direction '$1'. Use ingress or egress." ;;
  esac
}

apply_rule_entry() {
  local mode="$1"
  local acl_id="$2"
  local direction="$3"
  local rule_number="$4"
  local action="$5"
  local protocol="$6"
  local cidr="$7"
  local ipv6_cidr="$8"
  local port_from="$9"
  local port_to="${10}"
  local icmp_type="${11}"
  local icmp_code="${12}"

  local egress_flag proto_num normalized_action

  validate_acl_id "$acl_id"
  validate_int_range "$rule_number" 1 32766 "Rule number"

  normalized_action="$(lower "$action")"
  case "$normalized_action" in
    allow|deny) ;;
    *) die "Invalid action '$action'. Use allow or deny." ;;
  esac

  if [[ -n "$cidr" && -n "$ipv6_cidr" ]]; then
    die "Provide only one of --cidr or --ipv6-cidr."
  fi
  if [[ -z "$cidr" && -z "$ipv6_cidr" ]]; then
    die "Provide either --cidr or --ipv6-cidr."
  fi

  if [[ -n "$port_from" || -n "$port_to" ]]; then
    [[ -n "$port_from" && -n "$port_to" ]] || die "Provide both --port-from and --port-to."
    validate_int_range "$port_from" 0 65535 "Port from"
    validate_int_range "$port_to" 0 65535 "Port to"
    (( port_to >= port_from )) || die "--port-to must be >= --port-from."
  fi

  if [[ -n "$icmp_type" || -n "$icmp_code" ]]; then
    [[ -n "$icmp_type" && -n "$icmp_code" ]] || die "Provide both --icmp-type and --icmp-code."
    validate_int_range "$icmp_type" 0 255 "ICMP type"
    validate_int_range "$icmp_code" 0 255 "ICMP code"
  fi

  egress_flag="$(direction_to_egress_flag "$direction")"
  proto_num="$(protocol_to_number "$protocol")"

  local -a args=(
    --network-acl-id "$acl_id"
    --rule-number "$rule_number"
    --protocol "$proto_num"
    --rule-action "$normalized_action"
    "$egress_flag"
  )

  if [[ -n "$cidr" ]]; then
    args+=(--cidr-block "$cidr")
  else
    args+=(--ipv6-cidr-block "$ipv6_cidr")
  fi

  if [[ -n "$port_from" ]]; then
    args+=(--port-range "From=${port_from},To=${port_to}")
  fi

  if [[ -n "$icmp_type" ]]; then
    args+=(--icmp-type-code "Type=${icmp_type},Code=${icmp_code}")
  fi

  case "$mode" in
    add)
      aws_ec2 create-network-acl-entry "${args[@]}" >/dev/null
      ;;
    change)
      aws_ec2 replace-network-acl-entry "${args[@]}" >/dev/null
      ;;
    *)
      die "Internal error: unsupported rule mode '$mode'."
      ;;
  esac
}

cmd_create() {
  local vpc_id=""
  local name=""

  PROFILE=""
  REGION=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vpc-id)
        [[ $# -ge 2 ]] || die "--vpc-id requires a value."
        vpc_id="$2"
        shift 2
        ;;
      --name)
        [[ $# -ge 2 ]] || die "--name requires a value."
        name="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a value."
        PROFILE="$2"
        shift 2
        ;;
      --region)
        [[ $# -ge 2 ]] || die "--region requires a value."
        REGION="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option for create: $1"
        ;;
    esac
  done

  [[ -n "$vpc_id" ]] || die "create requires --vpc-id."

  local acl_id
  acl_id="$(aws_ec2 create-network-acl --vpc-id "$vpc_id" --query 'NetworkAcl.NetworkAclId' --output text)"

  if [[ -n "$name" ]]; then
    aws_ec2 create-tags --resources "$acl_id" --tags "Key=Name,Value=$name" >/dev/null
  fi

  # Required output.
  echo "$acl_id"

  cat >&2 <<MSG
Created ACL: $acl_id
Association is intentionally NOT automated.
Please review rules and perform subnet association manually after review/approval.
MSG
}

cmd_rule_add_or_change() {
  local mode="$1"
  shift

  local acl_id=""
  local direction=""
  local rule_number=""
  local action=""
  local protocol=""
  local cidr=""
  local ipv6_cidr=""
  local port_from=""
  local port_to=""
  local icmp_type=""
  local icmp_code=""

  PROFILE=""
  REGION=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --acl-id)
        [[ $# -ge 2 ]] || die "--acl-id requires a value."
        acl_id="$2"
        shift 2
        ;;
      --direction)
        [[ $# -ge 2 ]] || die "--direction requires a value."
        direction="$2"
        shift 2
        ;;
      --rule-number)
        [[ $# -ge 2 ]] || die "--rule-number requires a value."
        rule_number="$2"
        shift 2
        ;;
      --action)
        [[ $# -ge 2 ]] || die "--action requires a value."
        action="$2"
        shift 2
        ;;
      --protocol)
        [[ $# -ge 2 ]] || die "--protocol requires a value."
        protocol="$2"
        shift 2
        ;;
      --cidr)
        [[ $# -ge 2 ]] || die "--cidr requires a value."
        cidr="$2"
        shift 2
        ;;
      --ipv6-cidr)
        [[ $# -ge 2 ]] || die "--ipv6-cidr requires a value."
        ipv6_cidr="$2"
        shift 2
        ;;
      --port-from)
        [[ $# -ge 2 ]] || die "--port-from requires a value."
        port_from="$2"
        shift 2
        ;;
      --port-to)
        [[ $# -ge 2 ]] || die "--port-to requires a value."
        port_to="$2"
        shift 2
        ;;
      --icmp-type)
        [[ $# -ge 2 ]] || die "--icmp-type requires a value."
        icmp_type="$2"
        shift 2
        ;;
      --icmp-code)
        [[ $# -ge 2 ]] || die "--icmp-code requires a value."
        icmp_code="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a value."
        PROFILE="$2"
        shift 2
        ;;
      --region)
        [[ $# -ge 2 ]] || die "--region requires a value."
        REGION="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option for rule $mode: $1"
        ;;
    esac
  done

  [[ -n "$acl_id" ]] || die "rule $mode requires --acl-id."
  [[ -n "$direction" ]] || die "rule $mode requires --direction."
  [[ -n "$rule_number" ]] || die "rule $mode requires --rule-number."
  [[ -n "$action" ]] || die "rule $mode requires --action."
  [[ -n "$protocol" ]] || die "rule $mode requires --protocol."

  apply_rule_entry "$mode" "$acl_id" "$direction" "$rule_number" "$action" "$protocol" "$cidr" "$ipv6_cidr" "$port_from" "$port_to" "$icmp_type" "$icmp_code"

  echo "Rule ${mode}d: acl=$acl_id direction=$direction rule_number=$rule_number"
}

cmd_rule_delete() {
  local acl_id=""
  local direction=""
  local rule_number=""
  local egress_flag=""

  PROFILE=""
  REGION=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --acl-id)
        [[ $# -ge 2 ]] || die "--acl-id requires a value."
        acl_id="$2"
        shift 2
        ;;
      --direction)
        [[ $# -ge 2 ]] || die "--direction requires a value."
        direction="$2"
        shift 2
        ;;
      --rule-number)
        [[ $# -ge 2 ]] || die "--rule-number requires a value."
        rule_number="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a value."
        PROFILE="$2"
        shift 2
        ;;
      --region)
        [[ $# -ge 2 ]] || die "--region requires a value."
        REGION="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option for rule delete: $1"
        ;;
    esac
  done

  [[ -n "$acl_id" ]] || die "rule delete requires --acl-id."
  [[ -n "$direction" ]] || die "rule delete requires --direction."
  [[ -n "$rule_number" ]] || die "rule delete requires --rule-number."

  validate_acl_id "$acl_id"
  validate_int_range "$rule_number" 1 32766 "Rule number"

  egress_flag="$(direction_to_egress_flag "$direction")"

  aws_ec2 delete-network-acl-entry --network-acl-id "$acl_id" --rule-number "$rule_number" "$egress_flag" >/dev/null

  echo "Rule deleted: acl=$acl_id direction=$direction rule_number=$rule_number"
}

cmd_rule_bulk_add() {
  local acl_id=""
  local csv_path=""

  PROFILE=""
  REGION=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --acl-id)
        [[ $# -ge 2 ]] || die "--acl-id requires a value."
        acl_id="$2"
        shift 2
        ;;
      -f|--file|--csv)
        [[ $# -ge 2 ]] || die "$1 requires a value."
        csv_path="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a value."
        PROFILE="$2"
        shift 2
        ;;
      --region)
        [[ $# -ge 2 ]] || die "--region requires a value."
        REGION="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option for rule bulk-add: $1"
        ;;
    esac
  done

  [[ -n "$acl_id" ]] || die "rule bulk-add requires --acl-id."
  [[ -n "$csv_path" ]] || die "rule bulk-add requires -f/--file (or --csv)."
  [[ -f "$csv_path" ]] || die "CSV file not found: $csv_path"
  validate_acl_id "$acl_id"

  local line line_no
  line_no=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    line="$(trim "$line")"

    if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
      continue
    fi

    local direction rule_number action protocol cidr ipv6_cidr port_from port_to icmp_type icmp_code extra
    IFS=',' read -r direction rule_number action protocol cidr ipv6_cidr port_from port_to icmp_type icmp_code extra <<<"$line"

    if [[ -n "${extra:-}" ]]; then
      die "CSV line $line_no has too many columns."
    fi

    direction="$(trim "$direction")"
    rule_number="$(trim "$rule_number")"
    action="$(trim "$action")"
    protocol="$(trim "$protocol")"
    cidr="$(trim "${cidr:-}")"
    ipv6_cidr="$(trim "${ipv6_cidr:-}")"
    port_from="$(trim "${port_from:-}")"
    port_to="$(trim "${port_to:-}")"
    icmp_type="$(trim "${icmp_type:-}")"
    icmp_code="$(trim "${icmp_code:-}")"

    # Optional header row support.
    if [[ "$(lower "$direction")" == "direction" && "$(lower "$rule_number")" == "rule_number" ]]; then
      continue
    fi

    if ! apply_rule_entry "add" "$acl_id" "$direction" "$rule_number" "$action" "$protocol" "$cidr" "$ipv6_cidr" "$port_from" "$port_to" "$icmp_type" "$icmp_code"; then
      die "Failed to add CSV rule at line $line_no."
    fi

    echo "CSV rule added (line $line_no): direction=$direction rule_number=$rule_number"
  done < "$csv_path"
}

cmd_rule() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die "Missing rule subcommand. Use add|change|delete|bulk-add."
  shift || true

  case "$subcommand" in
    add)
      cmd_rule_add_or_change "add" "$@"
      ;;
    change)
      cmd_rule_add_or_change "change" "$@"
      ;;
    delete)
      cmd_rule_delete "$@"
      ;;
    bulk-add)
      cmd_rule_bulk_add "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      die "Unknown rule subcommand: $subcommand"
      ;;
  esac
}

main() {
  local command="${1:-}"
  [[ -n "$command" ]] || {
    usage
    exit 2
  }
  shift || true

  case "$command" in
    create)
      cmd_create "$@"
      ;;
    rule)
      cmd_rule "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      die "Unknown command: $command"
      ;;
  esac
}

main "$@"
