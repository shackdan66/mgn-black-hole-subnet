from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from .models import NaclMakerError, is_nacl_id, name_from_tags


def make_ec2(profile: str | None, region: str | None) -> tuple[BaseClient, str]:
    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    resolved_region = session.region_name
    if not resolved_region:
        raise NaclMakerError(
            "No region resolved. Set --region or configure a default region for your AWS profile."
        )
    return session.client("ec2"), resolved_region


def is_error_code(err: ClientError, *codes: str) -> bool:
    error_code = err.response.get("Error", {}).get("Code")
    return error_code in set(codes)


def list_vpcs(ec2: BaseClient) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_vpcs")
    for page in paginator.paginate():
        output.extend(page.get("Vpcs", []))
    output.sort(
        key=lambda item: (name_from_tags(item.get("Tags")), item.get("VpcId", ""))
    )
    return output


def list_subnets(ec2: BaseClient, vpc_id: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_subnets")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        output.extend(page.get("Subnets", []))
    output.sort(
        key=lambda item: (name_from_tags(item.get("Tags")), item.get("SubnetId", ""))
    )
    return output


def list_nacls(ec2: BaseClient, vpc_id: str | None = None) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_network_acls")
    args: Dict[str, Any] = {}
    if vpc_id:
        args["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    for page in paginator.paginate(**args):
        output.extend(page.get("NetworkAcls", []))
    output.sort(
        key=lambda item: (
            name_from_tags(item.get("Tags")),
            item.get("NetworkAclId", ""),
        )
    )
    return output


def get_nacl(ec2: BaseClient, nacl_id: str) -> dict[str, Any]:
    response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    nacls = response.get("NetworkAcls", [])
    if not nacls:
        raise NaclMakerError(f"NACL not found: {nacl_id}")
    return nacls[0]


def default_nacl_id(ec2: BaseClient, vpc_id: str) -> str:
    response = ec2.describe_network_acls(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "default", "Values": ["true"]},
        ]
    )
    nacls = response.get("NetworkAcls", [])
    if not nacls:
        raise NaclMakerError(f"Default NACL not found for VPC {vpc_id}")
    return str(nacls[0]["NetworkAclId"])


def resolve_nacl_ref(ec2: BaseClient, vpc_id: str, ref: str) -> str:
    if is_nacl_id(ref):
        nacl = get_nacl(ec2, ref)
        if nacl.get("VpcId") != vpc_id:
            raise NaclMakerError(
                f"NACL {ref} is in VPC {nacl.get('VpcId')} not {vpc_id}"
            )
        return ref

    matches: list[str] = []
    for nacl in list_nacls(ec2, vpc_id):
        if (name_from_tags(nacl.get("Tags")) or "") == ref:
            matches.append(str(nacl["NetworkAclId"]))

    if not matches:
        raise NaclMakerError(f"No NACL with Name '{ref}' found in VPC {vpc_id}")
    if len(matches) > 1:
        raise NaclMakerError(
            f"Name '{ref}' is not unique in VPC {vpc_id}. Use NACL ID instead."
        )
    return matches[0]


def subnet_assoc(ec2: BaseClient, subnet_id: str) -> tuple[str, str]:
    response = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )
    nacls = response.get("NetworkAcls", [])
    if not nacls:
        raise NaclMakerError(f"No NACL association found for subnet {subnet_id}")

    for nacl in nacls:
        for assoc in nacl.get("Associations", []) or []:
            if assoc.get("SubnetId") == subnet_id:
                return str(nacl["NetworkAclId"]), str(assoc["NetworkAclAssociationId"])

    raise NaclMakerError(f"Association id not found for subnet {subnet_id}")


def associate_subnet(ec2: BaseClient, subnet_id: str, nacl_id: str) -> dict[str, Any]:
    _, association_id = subnet_assoc(ec2, subnet_id)
    return ec2.replace_network_acl_association(
        AssociationId=association_id,
        NetworkAclId=nacl_id,
    )


def _entry_to_params(dst_nacl_id: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    rule_number = entry.get("RuleNumber")
    if rule_number is None:
        return None
    if int(rule_number) == 32767:
        return None

    params: dict[str, Any] = {
        "NetworkAclId": dst_nacl_id,
        "RuleNumber": int(rule_number),
        "Protocol": str(entry.get("Protocol")),
        "RuleAction": entry.get("RuleAction"),
        "Egress": bool(entry.get("Egress", False)),
    }

    if entry.get("CidrBlock"):
        params["CidrBlock"] = entry["CidrBlock"]
    elif entry.get("Ipv6CidrBlock"):
        params["Ipv6CidrBlock"] = entry["Ipv6CidrBlock"]
    else:
        return None

    if entry.get("PortRange"):
        params["PortRange"] = {
            "From": int(entry["PortRange"]["From"]),
            "To": int(entry["PortRange"]["To"]),
        }
    if entry.get("IcmpTypeCode"):
        params["IcmpTypeCode"] = {
            "Type": int(entry["IcmpTypeCode"]["Type"]),
            "Code": int(entry["IcmpTypeCode"]["Code"]),
        }

    return params


def clone_entries(
    ec2: BaseClient,
    src_nacl_id: str,
    dst_nacl_id: str,
    overwrite: bool = True,
) -> dict[str, Any]:
    src = get_nacl(ec2, src_nacl_id)
    dst = get_nacl(ec2, dst_nacl_id)
    if src.get("VpcId") != dst.get("VpcId"):
        raise NaclMakerError("Refusing to clone rules across VPCs.")

    summary: dict[str, Any] = {
        "source_nacl_id": src_nacl_id,
        "destination_nacl_id": dst_nacl_id,
        "created": 0,
        "overwritten": 0,
        "skipped": 0,
    }

    destination_keys = {
        (bool(entry.get("Egress", False)), int(entry["RuleNumber"]))
        for entry in (dst.get("Entries", []) or [])
        if entry.get("RuleNumber") is not None and int(entry.get("RuleNumber")) != 32767
    }

    entries = sorted(
        src.get("Entries", []) or [],
        key=lambda item: (
            bool(item.get("Egress", False)),
            int(item.get("RuleNumber", 0)),
        ),
    )

    for entry in entries:
        params = _entry_to_params(dst_nacl_id, entry)
        if not params:
            summary["skipped"] += 1
            continue

        key = (params["Egress"], params["RuleNumber"])
        if key in destination_keys:
            if not overwrite:
                summary["skipped"] += 1
                continue
            ec2.delete_network_acl_entry(
                NetworkAclId=dst_nacl_id,
                RuleNumber=params["RuleNumber"],
                Egress=params["Egress"],
            )
            ec2.create_network_acl_entry(**params)
            summary["overwritten"] += 1
        else:
            ec2.create_network_acl_entry(**params)
            summary["created"] += 1
            destination_keys.add(key)

    return summary
