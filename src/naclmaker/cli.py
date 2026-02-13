from __future__ import annotations

from typing import Any, Optional

import click
import typer
from botocore.exceptions import BotoCoreError, ClientError

from .aws import (
    associate_subnet,
    clone_entries,
    default_nacl_id,
    get_nacl,
    is_error_code,
    list_nacls,
    list_subnets,
    list_vpcs,
    make_ec2,
    resolve_nacl_ref,
)
from .models import (
    Ctx,
    NaclMakerError,
    build_rule_params,
    direction_to_egress,
    is_nacl_id,
    name_from_tags,
)
from .render import emit, make_nacl_table, make_rule_table, payload

app = typer.Typer(
    name="naclmaker", help="Manage AWS VPC Network ACLs.", no_args_is_help=True
)
nacl_app = typer.Typer(help="CRUD Network ACLs", no_args_is_help=True)
rule_app = typer.Typer(help="CRUD NACL ingress/egress rules", no_args_is_help=True)
assoc_app = typer.Typer(
    help="Associate/disassociate NACLs with subnets", no_args_is_help=True
)

app.add_typer(nacl_app, name="nacl")
app.add_typer(rule_app, name="rule")
app.add_typer(assoc_app, name="assoc")


def _die(message: str, code: int = 2) -> None:
    typer.secho(f"ERROR: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _ctx_obj(ctx: typer.Context) -> Ctx:
    obj = ctx.obj
    if not isinstance(obj, Ctx):
        raise NaclMakerError("CLI context not initialized.")
    if obj.ec2 is None:
        try:
            ec2, resolved_region = make_ec2(obj.profile, obj.region)
        except (BotoCoreError, ClientError) as exc:
            raise NaclMakerError(f"Failed to create boto3 EC2 client: {exc}") from exc
        obj.ec2 = ec2
        obj.region = resolved_region
    return obj


def _emit(
    c: Ctx,
    *,
    action: str,
    resource_type: str,
    table_lines: list[str],
    table: Any | None = None,
    item: dict[str, Any] | None = None,
    items: list[dict[str, Any]] | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    out = payload(
        action=action, resource_type=resource_type, item=item, items=items, meta=meta
    )
    emit(c.output, out, table_lines, table=table)


def _prompt_indexed_choice(kind: str, choices: list[tuple[str, str]]) -> str:
    if len(choices) == 1:
        selected_id, selected_label = choices[0]
        typer.echo(f"Using {kind}: {selected_label}")
        return selected_id

    typer.echo(f"Available {kind}s:")
    for idx, (_, label) in enumerate(choices, start=1):
        typer.echo(f"  {idx}. {label}")

    selected_idx = typer.prompt(
        f"Select {kind} number",
        type=click.IntRange(1, len(choices)),
        default=1,
        show_default=True,
    )
    return choices[selected_idx - 1][0]


def _pick_vpc(c: Ctx, vpc_id: Optional[str]) -> str:
    if vpc_id:
        return vpc_id
    if c.no_input:
        raise NaclMakerError(
            "Missing --vpc-id and prompting is disabled by --no-input."
        )

    vpcs = list_vpcs(c.ec2)
    if not vpcs:
        raise NaclMakerError("No VPCs found.")

    choices: list[tuple[str, str]] = []
    for vpc in vpcs:
        vid = vpc["VpcId"]
        choices.append(
            (
                vid,
                f"{name_from_tags(vpc.get('Tags')) or '(no Name tag)'}  {vid}  {vpc.get('CidrBlock', '?')}",
            )
        )

    return _prompt_indexed_choice("VPC", choices)


def _pick_subnet(c: Ctx, vpc_id: str, subnet_id: Optional[str]) -> str:
    if subnet_id:
        return subnet_id
    if c.no_input:
        raise NaclMakerError(
            "Missing --subnet-id and prompting is disabled by --no-input."
        )

    subnets = list_subnets(c.ec2, vpc_id)
    if not subnets:
        raise NaclMakerError(f"No subnets found in VPC {vpc_id}.")

    choices: list[tuple[str, str]] = []
    for subnet in subnets:
        sid = subnet["SubnetId"]
        choices.append(
            (
                sid,
                (
                    f"{name_from_tags(subnet.get('Tags')) or '(no Name tag)'}  {sid}  "
                    f"{subnet.get('AvailabilityZone', '?')}  {subnet.get('CidrBlock', '?')}"
                ),
            )
        )

    return _prompt_indexed_choice("Subnet", choices)


def _pick_nacl(c: Ctx, vpc_id: str, nacl_ref: Optional[str]) -> str:
    if nacl_ref:
        return resolve_nacl_ref(c.ec2, vpc_id, nacl_ref)
    if c.no_input:
        raise NaclMakerError(
            "Missing NACL reference and prompting is disabled by --no-input."
        )

    nacls = list_nacls(c.ec2, vpc_id)
    if not nacls:
        raise NaclMakerError(f"No NACLs found in VPC {vpc_id}.")

    choices: list[tuple[str, str]] = []
    for nacl in nacls:
        nid = nacl["NetworkAclId"]
        label = f"{name_from_tags(nacl.get('Tags')) or 'None'}  {nid}"
        if nacl.get("IsDefault"):
            label += "  DEFAULT"
        choices.append((nid, label))

    return _prompt_indexed_choice("NACL", choices)


def _resolve_nacl_with_vpc(
    c: Ctx, nacl_ref: str, vpc_id: str | None
) -> tuple[str, str]:
    if vpc_id:
        return vpc_id, resolve_nacl_ref(c.ec2, vpc_id, nacl_ref)
    if not is_nacl_id(nacl_ref):
        raise NaclMakerError("When using a Name tag reference, provide --vpc-id.")

    nacl = get_nacl(c.ec2, nacl_ref)
    resolved_vpc_id = str(nacl["VpcId"])
    return resolved_vpc_id, resolve_nacl_ref(c.ec2, resolved_vpc_id, nacl_ref)


@app.callback()
def main(
    ctx: typer.Context,
    profile: Optional[str] = typer.Option(
        None, "--profile", help="AWS profile (SSO is supported)"
    ),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region override"),
    output: str = typer.Option(
        "table", "--output", help="Output format: table or json"
    ),
    no_input: bool = typer.Option(
        False,
        "--no-input",
        help="Disable prompts; fail if required selectors are missing",
    ),
) -> None:
    out = output.strip().lower()
    if out not in {"table", "json"}:
        _die("--output must be table or json.")
    ctx.obj = Ctx(
        profile=profile, region=region, ec2=None, output=out, no_input=no_input
    )


@nacl_app.command("list")
def nacl_list(
    ctx: typer.Context,
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; prompted when omitted"
    ),
) -> None:
    c = _ctx_obj(ctx)
    resolved_vpc_id = _pick_vpc(c, vpc_id)
    nacls = list_nacls(c.ec2, resolved_vpc_id)

    items = []
    lines: list[str] = []
    table = None
    if not nacls:
        lines = ["No NACLs found."]
    else:
        table_rows: list[list[str]] = []
        for nacl in nacls:
            subnet_ids = [
                assoc.get("SubnetId")
                for assoc in (nacl.get("Associations") or [])
                if assoc.get("SubnetId")
            ]
            item = {
                "nacl_id": nacl["NetworkAclId"],
                "name": name_from_tags(nacl.get("Tags")) or "",
                "is_default": bool(nacl.get("IsDefault", False)),
                "subnet_ids": subnet_ids,
            }
            items.append(item)
            table_rows.append(
                [
                    item["name"] or "None",
                    item["nacl_id"],
                    "TRUE" if item["is_default"] else "FALSE",
                    ",".join(subnet_ids) if subnet_ids else "-",
                ]
            )
        table = make_nacl_table(table_rows)

    _emit(
        c,
        action="list",
        resource_type="nacl",
        items=items,
        meta={"vpc_id": resolved_vpc_id, "count": len(items)},
        table_lines=lines,
        table=table,
    )


@nacl_app.command("create")
def nacl_create(
    ctx: typer.Context,
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; prompted when omitted"
    ),
    name: Optional[str] = typer.Option(
        None, "--name", help="Name tag for the new NACL"
    ),
    clone_from: Optional[str] = typer.Option(
        None,
        "--clone-from",
        help="Source NACL (ID acl-... or Name tag) to clone rules from in the same VPC",
    ),
    associate_subnet_id: Optional[str] = typer.Option(
        None,
        "--associate-subnet-id",
        help="Subnet to associate to the new NACL",
    ),
) -> None:
    c = _ctx_obj(ctx)
    resolved_vpc_id = _pick_vpc(c, vpc_id)

    response = c.ec2.create_network_acl(VpcId=resolved_vpc_id)
    nacl_id = str(response["NetworkAcl"]["NetworkAclId"])
    if name:
        c.ec2.create_tags(Resources=[nacl_id], Tags=[{"Key": "Name", "Value": name}])

    clone_summary: dict[str, Any] | None = None
    if clone_from:
        src_id = resolve_nacl_ref(c.ec2, resolved_vpc_id, clone_from)
        clone_summary = clone_entries(c.ec2, src_id, nacl_id, overwrite=True)

    associated_subnet_id: str | None = None
    if associate_subnet_id:
        subnet_id = _pick_subnet(c, resolved_vpc_id, associate_subnet_id)
        associate_subnet(c.ec2, subnet_id, nacl_id)
        associated_subnet_id = subnet_id

    item = {
        "nacl_id": nacl_id,
        "vpc_id": resolved_vpc_id,
        "name": name or "",
        "clone": clone_summary,
        "associated_subnet_id": associated_subnet_id,
    }

    lines = [f"Created NACL: {nacl_id}"]
    if clone_summary:
        lines.append(
            "Clone summary: "
            f"created={clone_summary['created']} overwritten={clone_summary['overwritten']} skipped={clone_summary['skipped']}"
        )
    if associated_subnet_id:
        lines.append(f"Associated {nacl_id} -> {associated_subnet_id}")

    _emit(c, action="create", resource_type="nacl", item=item, table_lines=lines)


@nacl_app.command("rename")
def nacl_rename(
    ctx: typer.Context,
    nacl_id: str = typer.Argument(..., help="Target NACL ID (acl-...)"),
    name: str = typer.Option(..., "--name", help="New Name tag value"),
) -> None:
    c = _ctx_obj(ctx)
    c.ec2.create_tags(Resources=[nacl_id], Tags=[{"Key": "Name", "Value": name}])

    _emit(
        c,
        action="rename",
        resource_type="nacl",
        item={"nacl_id": nacl_id, "name": name},
        table_lines=[f"Renamed {nacl_id} -> Name={name}"],
    )


@nacl_app.command("delete")
def nacl_delete(
    ctx: typer.Context,
    nacl_ref: str = typer.Argument(..., help="NACL ID (acl-...) or Name tag"),
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; required for Name tag references"
    ),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
) -> None:
    c = _ctx_obj(ctx)

    if not is_nacl_id(nacl_ref) and not vpc_id:
        raise NaclMakerError("When deleting by Name tag, you must provide --vpc-id.")

    resolved_vpc_id, nacl_id = _resolve_nacl_with_vpc(c, nacl_ref, vpc_id)
    nacl = get_nacl(c.ec2, nacl_id)
    if nacl.get("IsDefault"):
        raise NaclMakerError(f"Refusing to delete default NACL: {nacl_id}")

    if not force:
        confirmed = typer.confirm(
            f"Delete NACL {name_from_tags(nacl.get('Tags')) or ''} {nacl_id}?"
        )
        if not confirmed:
            raise typer.Exit(1)

    default_id = default_nacl_id(c.ec2, resolved_vpc_id)
    moved_subnets: list[str] = []

    for assoc in nacl.get("Associations") or []:
        subnet_id = assoc.get("SubnetId")
        assoc_id = assoc.get("NetworkAclAssociationId")
        if subnet_id and assoc_id:
            c.ec2.replace_network_acl_association(
                AssociationId=assoc_id, NetworkAclId=default_id
            )
            moved_subnets.append(str(subnet_id))

    c.ec2.delete_network_acl(NetworkAclId=nacl_id)

    _emit(
        c,
        action="delete",
        resource_type="nacl",
        item={
            "nacl_id": nacl_id,
            "vpc_id": resolved_vpc_id,
            "default_nacl_id": default_id,
            "moved_subnet_ids": moved_subnets,
        },
        table_lines=[
            f"Deleted NACL {nacl_id}",
            f"Moved subnets to default {default_id}: {','.join(moved_subnets) if moved_subnets else '-'}",
        ],
    )


@assoc_app.command("set")
def assoc_set(
    ctx: typer.Context,
    nacl_ref: str = typer.Argument(
        ..., help="NACL ID (acl-...) or Name tag (within VPC)"
    ),
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; prompted when omitted"
    ),
    subnet_id: Optional[str] = typer.Option(
        None, "--subnet-id", help="Subnet ID; prompted when omitted"
    ),
) -> None:
    c = _ctx_obj(ctx)
    resolved_vpc_id = _pick_vpc(c, vpc_id)
    resolved_subnet_id = _pick_subnet(c, resolved_vpc_id, subnet_id)
    nacl_id = resolve_nacl_ref(c.ec2, resolved_vpc_id, nacl_ref)

    associate_subnet(c.ec2, resolved_subnet_id, nacl_id)
    _emit(
        c,
        action="set",
        resource_type="association",
        item={
            "nacl_id": nacl_id,
            "subnet_id": resolved_subnet_id,
            "vpc_id": resolved_vpc_id,
        },
        table_lines=[f"Associated {nacl_id} -> {resolved_subnet_id}"],
    )


@assoc_app.command("default")
def assoc_default(
    ctx: typer.Context,
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; prompted when omitted"
    ),
    subnet_id: Optional[str] = typer.Option(
        None, "--subnet-id", help="Subnet ID; prompted when omitted"
    ),
) -> None:
    c = _ctx_obj(ctx)
    resolved_vpc_id = _pick_vpc(c, vpc_id)
    resolved_subnet_id = _pick_subnet(c, resolved_vpc_id, subnet_id)
    nacl_id = default_nacl_id(c.ec2, resolved_vpc_id)

    associate_subnet(c.ec2, resolved_subnet_id, nacl_id)
    _emit(
        c,
        action="set-default",
        resource_type="association",
        item={
            "nacl_id": nacl_id,
            "subnet_id": resolved_subnet_id,
            "vpc_id": resolved_vpc_id,
        },
        table_lines=[f"Associated default {nacl_id} -> {resolved_subnet_id}"],
    )


@rule_app.command("list")
def rule_list(
    ctx: typer.Context,
    nacl_ref: Optional[str] = typer.Argument(
        None, help="NACL ID (acl-...) or Name tag"
    ),
    vpc_id: Optional[str] = typer.Option(
        None, "--vpc-id", help="VPC ID; prompted when omitted"
    ),
) -> None:
    c = _ctx_obj(ctx)

    if vpc_id:
        resolved_vpc_id = vpc_id
    elif nacl_ref and is_nacl_id(nacl_ref):
        resolved_vpc_id = str(get_nacl(c.ec2, nacl_ref)["VpcId"])
    else:
        resolved_vpc_id = _pick_vpc(c, None)

    nacl_id = _pick_nacl(c, resolved_vpc_id, nacl_ref)
    nacl = get_nacl(c.ec2, nacl_id)

    entries = sorted(
        nacl.get("Entries", []) or [],
        key=lambda entry: (
            int(entry.get("RuleNumber", 0)),
            bool(entry.get("Egress", False)),
        ),
    )

    items = []
    lines: list[str] = []
    table_rows: list[list[str]] = []
    for entry in entries:
        rule_number = entry.get("RuleNumber")
        if rule_number is None:
            continue

        direction = "egress" if entry.get("Egress") else "ingress"
        cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock") or ""
        port_range = entry.get("PortRange")
        ports = (
            f"{int(port_range['From'])}-{int(port_range['To'])}"
            if isinstance(port_range, dict)
            else ""
        )
        item = {
            "direction": direction,
            "rule_number": int(rule_number),
            "action": str(entry.get("RuleAction")),
            "protocol": str(entry.get("Protocol")),
            "cidr": cidr,
            "ports": ports,
        }
        items.append(item)
        table_rows.append(
            [
                direction,
                str(item["rule_number"]),
                item["action"],
                item["protocol"],
                cidr or "-",
                ports or "-",
            ]
        )

    table = make_rule_table(name_from_tags(nacl.get("Tags")), nacl_id, table_rows)

    _emit(
        c,
        action="list",
        resource_type="rule",
        items=items,
        meta={"nacl_id": nacl_id, "vpc_id": resolved_vpc_id, "count": len(items)},
        table_lines=lines,
        table=table,
    )


@rule_app.command("create")
def rule_create(
    ctx: typer.Context,
    nacl_id: str = typer.Argument(..., help="Target NACL ID (acl-...)"),
    direction: str = typer.Option(..., "--direction", help="ingress or egress"),
    rule_number: int = typer.Option(..., "--rule-number", min=1, max=32766),
    action: str = typer.Option(..., "--action", help="allow or deny"),
    protocol: str = typer.Option(
        "tcp", "--protocol", help="all|tcp|udp|icmp|icmpv6 or a number"
    ),
    cidr: Optional[str] = typer.Option(
        None, "--cidr", help="IPv4 CIDR, e.g. 10.0.0.0/8"
    ),
    ipv6_cidr: Optional[str] = typer.Option(
        None, "--ipv6-cidr", help="IPv6 CIDR, e.g. 2001:db8::/32"
    ),
    port_from: Optional[int] = typer.Option(None, "--port-from", min=0, max=65535),
    port_to: Optional[int] = typer.Option(None, "--port-to", min=0, max=65535),
    icmp_type: Optional[int] = typer.Option(None, "--icmp-type", min=0, max=255),
    icmp_code: Optional[int] = typer.Option(None, "--icmp-code", min=0, max=255),
) -> None:
    c = _ctx_obj(ctx)
    egress = direction_to_egress(direction)
    params = build_rule_params(
        nacl_id=nacl_id,
        egress=egress,
        rule_number=rule_number,
        action=action,
        protocol=protocol,
        cidr=cidr,
        ipv6_cidr=ipv6_cidr,
        port_from=port_from,
        port_to=port_to,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )

    c.ec2.create_network_acl_entry(**params)

    _emit(
        c,
        action="create",
        resource_type="rule",
        item={
            "nacl_id": nacl_id,
            "direction": "egress" if egress else "ingress",
            "rule_number": rule_number,
        },
        table_lines=["Rule created."],
    )


@rule_app.command("delete")
def rule_delete(
    ctx: typer.Context,
    nacl_id: str = typer.Argument(..., help="Target NACL ID (acl-...)"),
    direction: str = typer.Option(..., "--direction", help="ingress or egress"),
    rule_number: int = typer.Option(..., "--rule-number", min=1, max=32766),
) -> None:
    c = _ctx_obj(ctx)
    egress = direction_to_egress(direction)

    c.ec2.delete_network_acl_entry(
        NetworkAclId=nacl_id, RuleNumber=rule_number, Egress=egress
    )

    _emit(
        c,
        action="delete",
        resource_type="rule",
        item={
            "nacl_id": nacl_id,
            "direction": "egress" if egress else "ingress",
            "rule_number": rule_number,
        },
        table_lines=["Rule deleted."],
    )


@rule_app.command("update")
def rule_update(
    ctx: typer.Context,
    nacl_id: str = typer.Argument(..., help="Target NACL ID (acl-...)"),
    direction: str = typer.Option(..., "--direction", help="ingress or egress"),
    rule_number: int = typer.Option(..., "--rule-number", min=1, max=32766),
    action: str = typer.Option(..., "--action", help="allow or deny"),
    protocol: str = typer.Option(
        "tcp", "--protocol", help="all|tcp|udp|icmp|icmpv6 or a number"
    ),
    cidr: Optional[str] = typer.Option(
        None, "--cidr", help="IPv4 CIDR, e.g. 10.0.0.0/8"
    ),
    ipv6_cidr: Optional[str] = typer.Option(
        None, "--ipv6-cidr", help="IPv6 CIDR, e.g. 2001:db8::/32"
    ),
    port_from: Optional[int] = typer.Option(None, "--port-from", min=0, max=65535),
    port_to: Optional[int] = typer.Option(None, "--port-to", min=0, max=65535),
    icmp_type: Optional[int] = typer.Option(None, "--icmp-type", min=0, max=255),
    icmp_code: Optional[int] = typer.Option(None, "--icmp-code", min=0, max=255),
) -> None:
    c = _ctx_obj(ctx)
    egress = direction_to_egress(direction)

    try:
        c.ec2.delete_network_acl_entry(
            NetworkAclId=nacl_id, RuleNumber=rule_number, Egress=egress
        )
        existed = True
    except ClientError as exc:
        if not is_error_code(exc, "InvalidNetworkAclEntry.NotFound"):
            raise
        existed = False

    params = build_rule_params(
        nacl_id=nacl_id,
        egress=egress,
        rule_number=rule_number,
        action=action,
        protocol=protocol,
        cidr=cidr,
        ipv6_cidr=ipv6_cidr,
        port_from=port_from,
        port_to=port_to,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )

    c.ec2.create_network_acl_entry(**params)

    _emit(
        c,
        action="update",
        resource_type="rule",
        item={
            "nacl_id": nacl_id,
            "direction": "egress" if egress else "ingress",
            "rule_number": rule_number,
            "previously_existed": existed,
        },
        table_lines=["Rule updated."],
    )


def run() -> int:
    try:
        app()
        return 0
    except NaclMakerError as exc:
        typer.secho(f"ERROR: {exc.message}", fg=typer.colors.RED, err=True)
        return exc.code
    except ClientError as exc:
        typer.secho(f"ERROR: AWS API error: {exc}", fg=typer.colors.RED, err=True)
        return 2
    except BotoCoreError as exc:
        typer.secho(f"ERROR: AWS SDK error: {exc}", fg=typer.colors.RED, err=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
