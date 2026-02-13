from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from botocore.client import BaseClient

OutputMode = Literal["table", "json"]
NACL_ID_RE = re.compile(r"^acl-[0-9a-fA-F]+$")


@dataclass
class Ctx:
    profile: str | None
    region: str | None
    ec2: BaseClient | None
    output: OutputMode
    no_input: bool


class NaclMakerError(Exception):
    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def name_from_tags(tags: Optional[list[dict[str, Any]]]) -> str:
    if not tags:
        return ""
    for tag in tags:
        if tag.get("Key") == "Name":
            return str(tag.get("Value") or "")
    return ""


def is_nacl_id(value: str) -> bool:
    return bool(NACL_ID_RE.match(value))


def protocol_to_number(proto: str) -> int:
    normalized = proto.strip().lower()
    if normalized in {"all", "-1"}:
        return -1
    if normalized in {"tcp", "6"}:
        return 6
    if normalized in {"udp", "17"}:
        return 17
    if normalized in {"icmp", "1"}:
        return 1
    if normalized in {"icmpv6", "58"}:
        return 58
    if re.fullmatch(r"-?\d+", normalized):
        return int(normalized)
    raise NaclMakerError(
        "Invalid protocol. Use one of: all, tcp, udp, icmp, icmpv6, or a number (e.g. 6)."
    )


def direction_to_egress(direction: str) -> bool:
    normalized = direction.strip().lower()
    if normalized == "ingress":
        return False
    if normalized == "egress":
        return True
    raise NaclMakerError("--direction must be ingress or egress.")


def _validate_cidr_pair(cidr: str | None, ipv6_cidr: str | None) -> tuple[str, str]:
    if cidr and ipv6_cidr:
        raise NaclMakerError("Provide only one of --cidr or --ipv6-cidr.")
    if not cidr and not ipv6_cidr:
        raise NaclMakerError("You must provide --cidr (IPv4) or --ipv6-cidr (IPv6).")

    if cidr:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as exc:
            raise NaclMakerError(f"Invalid IPv4 CIDR '{cidr}': {exc}") from exc
        return "CidrBlock", str(network)

    assert ipv6_cidr is not None
    try:
        network6 = ipaddress.IPv6Network(ipv6_cidr, strict=False)
    except ValueError as exc:
        raise NaclMakerError(f"Invalid IPv6 CIDR '{ipv6_cidr}': {exc}") from exc
    return "Ipv6CidrBlock", str(network6)


def build_rule_params(
    nacl_id: str,
    egress: bool,
    rule_number: int,
    action: str,
    protocol: str,
    cidr: str | None,
    ipv6_cidr: str | None,
    port_from: int | None,
    port_to: int | None,
    icmp_type: int | None,
    icmp_code: int | None,
) -> Dict[str, Any]:
    normalized_action = action.strip().lower()
    if normalized_action not in {"allow", "deny"}:
        raise NaclMakerError("--action must be allow or deny.")

    cidr_key, cidr_value = _validate_cidr_pair(cidr, ipv6_cidr)
    proto_num = protocol_to_number(protocol)

    params: Dict[str, Any] = {
        "NetworkAclId": nacl_id,
        "RuleNumber": rule_number,
        "Protocol": str(proto_num),
        "RuleAction": normalized_action,
        "Egress": egress,
        cidr_key: cidr_value,
    }

    if port_from is not None or port_to is not None:
        if port_from is None or port_to is None:
            raise NaclMakerError(
                "If using ports, provide both --port-from and --port-to."
            )
        if port_from < 0 or port_to < 0 or port_to < port_from:
            raise NaclMakerError("Invalid port range.")
        params["PortRange"] = {"From": port_from, "To": port_to}

    if icmp_type is not None or icmp_code is not None:
        if icmp_type is None or icmp_code is None:
            raise NaclMakerError(
                "If using ICMP, provide both --icmp-type and --icmp-code."
            )
        params["IcmpTypeCode"] = {"Type": icmp_type, "Code": icmp_code}

    return params
