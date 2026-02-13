from __future__ import annotations

import pytest

from naclmaker.models import (
    NaclMakerError,
    build_rule_params,
    direction_to_egress,
    protocol_to_number,
)


def test_protocol_to_number_mappings() -> None:
    assert protocol_to_number("all") == -1
    assert protocol_to_number("tcp") == 6
    assert protocol_to_number("udp") == 17
    assert protocol_to_number("icmp") == 1
    assert protocol_to_number("icmpv6") == 58
    assert protocol_to_number("132") == 132


def test_protocol_to_number_rejects_invalid() -> None:
    with pytest.raises(NaclMakerError, match="Invalid protocol"):
        protocol_to_number("bogus")


def test_direction_to_egress() -> None:
    assert direction_to_egress("ingress") is False
    assert direction_to_egress("egress") is True
    with pytest.raises(NaclMakerError, match="--direction"):
        direction_to_egress("sideways")


def test_build_rule_params_validates_cidr_and_ports() -> None:
    with pytest.raises(NaclMakerError, match="only one of --cidr"):
        build_rule_params(
            nacl_id="acl-1234",
            egress=False,
            rule_number=100,
            action="allow",
            protocol="tcp",
            cidr="10.0.0.0/24",
            ipv6_cidr="2001:db8::/64",
            port_from=443,
            port_to=443,
            icmp_type=None,
            icmp_code=None,
        )

    with pytest.raises(NaclMakerError, match="both --port-from and --port-to"):
        build_rule_params(
            nacl_id="acl-1234",
            egress=False,
            rule_number=100,
            action="allow",
            protocol="tcp",
            cidr="10.0.0.0/24",
            ipv6_cidr=None,
            port_from=443,
            port_to=None,
            icmp_type=None,
            icmp_code=None,
        )


def test_build_rule_params_normalizes_ipv4() -> None:
    params = build_rule_params(
        nacl_id="acl-1234",
        egress=False,
        rule_number=100,
        action="allow",
        protocol="tcp",
        cidr="10.0.0.5/24",
        ipv6_cidr=None,
        port_from=80,
        port_to=80,
        icmp_type=None,
        icmp_code=None,
    )

    assert params["CidrBlock"] == "10.0.0.0/24"
    assert params["PortRange"] == {"From": 80, "To": 80}
