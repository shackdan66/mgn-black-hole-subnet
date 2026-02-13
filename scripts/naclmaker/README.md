# naclmaker.sh (Bash)

Standalone Bash utility for AWS Network ACL creation and rule management.
This script is intentionally independent of the Python CLI.

## Prerequisites

- AWS CLI v2
- Auth/session already established (for example SSO)
- Region available via `--region`, env vars, or profile config

Example auth step:

```bash
aws sso login --profile my-profile
```

## File

- `scripts/naclmaker/naclmaker.sh`

## Capabilities

- Create a new NACL in a VPC (required: `--vpc-id`)
  - Outputs the new ACL ID on stdout
  - Prints a kind-but-firm reminder that subnet association is manual
- Add/change/delete single ACL rules (required: `--acl-id`)
- Bulk-add rules from CSV (required: `--acl-id`, and one of `-f`, `--file`, or `--csv`)
- No subnet association commands by design

## Usage

```bash
scripts/naclmaker/naclmaker.sh --help
```

Create ACL:

```bash
scripts/naclmaker/naclmaker.sh create \
  --vpc-id vpc-0123456789abcdef0 \
  --name app-private \
  --profile my-profile \
  --region us-east-1
```

Add rule:

```bash
scripts/naclmaker/naclmaker.sh rule add \
  --acl-id acl-0123456789abcdef0 \
  --direction ingress \
  --rule-number 100 \
  --action allow \
  --protocol tcp \
  --cidr 10.0.0.0/8 \
  --port-from 443 \
  --port-to 443
```

Change rule:

```bash
scripts/naclmaker/naclmaker.sh rule change \
  --acl-id acl-0123456789abcdef0 \
  --direction egress \
  --rule-number 110 \
  --action deny \
  --protocol all \
  --cidr 0.0.0.0/0
```

Delete rule:

```bash
scripts/naclmaker/naclmaker.sh rule delete \
  --acl-id acl-0123456789abcdef0 \
  --direction ingress \
  --rule-number 100
```

Bulk add from CSV:

```bash
scripts/naclmaker/naclmaker.sh rule bulk-add \
  --acl-id acl-0123456789abcdef0 \
  -f scripts/naclmaker/example-rules.csv
```

## CSV Format

Columns (10 total):

1. `direction` (`ingress` or `egress`)
2. `rule_number` (`1..32766`)
3. `action` (`allow` or `deny`)
4. `protocol` (`all|tcp|udp|icmp|icmpv6` or numeric)
5. `cidr` (optional if using IPv6)
6. `ipv6_cidr` (optional if using IPv4)
7. `port_from` (optional, must pair with `port_to`)
8. `port_to` (optional, must pair with `port_from`)
9. `icmp_type` (optional, must pair with `icmp_code`)
10. `icmp_code` (optional, must pair with `icmp_type`)

Notes:

- Header row is optional and supported.
- Blank lines and `#` comment lines are ignored.
- If one CSV row fails validation/API call, the script stops immediately.
