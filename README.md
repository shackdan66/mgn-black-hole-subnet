# naclmaker

`naclmaker` is a Typer-based CLI for managing AWS VPC Network ACLs (NACLs).

## Prerequisites

- Python 3.11+
- AWS CLI configured for your account(s)
- SSO/auth already established, for example:

```bash
aws sso login --profile my-sso-profile
```

Also ensure a region is available via one of:
- `--region us-east-1`
- `AWS_REGION` / `AWS_DEFAULT_REGION`
- profile config (for example `aws configure set region us-east-1 --profile my-sso-profile`)

## Install

```bash
uv sync --extra dev
```

## Pre-commit

Install hooks locally (commit + push):

```bash
uv run pre-commit install --hook-type pre-commit --hook-type pre-push
```

Run all hooks manually:

```bash
uv run pre-commit run --all-files
```

Hook behavior:

- `pre-commit`: file hygiene checks, `ruff --fix`, `ruff format`, `black`
- `pre-push`: `pytest -q`

## Build (Local)

Build source and wheel distributions into `dist/`:

```bash
uv build
```

Artifacts will look like:

- `dist/naclmaker-<version>.tar.gz`
- `dist/naclmaker-<version>-py3-none-any.whl`

## Install Package (Local)

Install from a built wheel into your current environment:

```bash
uv pip install dist/naclmaker-*.whl
```

Reinstall after rebuilding:

```bash
uv pip install --force-reinstall dist/naclmaker-*.whl
```

Quick verification:

```bash
naclmaker --help
```

## Usage

```bash
uv run naclmaker --help
uv run naclmaker nacl --help
uv run naclmaker rule --help
uv run naclmaker assoc --help
```

Shell-style workflow (similar to `poetry shell`):

```bash
./scripts/dev-shell
```

This opens an interactive shell with `.venv` activated. You can also activate manually:

```bash
source .venv/bin/activate
```

Global flags:

- `--profile`: optional AWS profile
- `--region`: optional region override
- `--output [table|json]`: output format (default `table`)
- `--no-input`: fail instead of prompting for missing selectors

Note: global flags must be placed before the subcommand, for example:

```bash
uv run naclmaker --profile my-sso-profile --region us-east-1 nacl list
```

## Quick Cookbook

List NACLs in a VPC:

```bash
uv run naclmaker --profile my-sso-profile nacl list --vpc-id vpc-0123456789abcdef0
```

Create NACL and clone rules from another NACL (collision overwrite enabled):

```bash
uv run naclmaker --profile my-sso-profile nacl create \
  --vpc-id vpc-0123456789abcdef0 \
  --name app-private \
  --clone-from acl-0abc1234def567890
```

Associate a subnet with a NACL:

```bash
uv run naclmaker --profile my-sso-profile assoc set acl-0abc1234def567890 \
  --vpc-id vpc-0123456789abcdef0 \
  --subnet-id subnet-0123456789abcdef0
```

Add an ingress TCP rule:

```bash
uv run naclmaker --profile my-sso-profile rule create acl-0abc1234def567890 \
  --direction ingress \
  --rule-number 100 \
  --action allow \
  --protocol tcp \
  --cidr 10.0.0.0/8 \
  --port-from 443 \
  --port-to 443
```

Update (upsert) a rule:

```bash
uv run naclmaker --profile my-sso-profile rule update acl-0abc1234def567890 \
  --direction egress \
  --rule-number 100 \
  --action allow \
  --protocol tcp \
  --cidr 0.0.0.0/0 \
  --port-from 443 \
  --port-to 443
```

Delete a NACL (prompts unless `--force`):

```bash
uv run naclmaker --profile my-sso-profile nacl delete acl-0abc1234def567890 --force
```

JSON output example:

```bash
uv run naclmaker --profile my-sso-profile --output json nacl list --vpc-id vpc-0123456789abcdef0
```

## Notes

This CLI keeps built-in NACL guidance intentionally minimal and assumes basic AWS networking familiarity.
