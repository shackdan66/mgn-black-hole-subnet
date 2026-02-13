from __future__ import annotations

import pytest
from botocore.stub import Stubber

from naclmaker.aws import clone_entries, resolve_nacl_ref
from naclmaker.models import NaclMakerError


def test_resolve_nacl_ref_rejects_non_unique_name(ec2_client) -> None:
    stubber = Stubber(ec2_client)
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-11111111111111111",
                    "VpcId": "vpc-1",
                    "Entries": [],
                    "Associations": [],
                    "IsDefault": False,
                    "Tags": [{"Key": "Name", "Value": "shared-name"}],
                },
                {
                    "NetworkAclId": "acl-22222222222222222",
                    "VpcId": "vpc-1",
                    "Entries": [],
                    "Associations": [],
                    "IsDefault": False,
                    "Tags": [{"Key": "Name", "Value": "shared-name"}],
                },
            ]
        },
        {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]},
    )

    with stubber:
        with pytest.raises(NaclMakerError, match="not unique"):
            resolve_nacl_ref(ec2_client, "vpc-1", "shared-name")


def test_clone_entries_overwrites_collisions(ec2_client) -> None:
    stubber = Stubber(ec2_client)
    source_entry = {
        "RuleNumber": 100,
        "Protocol": "6",
        "RuleAction": "allow",
        "Egress": False,
        "CidrBlock": "10.0.0.0/24",
        "PortRange": {"From": 443, "To": 443},
    }

    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-source",
                    "VpcId": "vpc-1",
                    "Entries": [source_entry],
                    "Associations": [],
                    "IsDefault": False,
                    "Tags": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-source"]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-dest",
                    "VpcId": "vpc-1",
                    "Entries": [
                        {
                            "RuleNumber": 100,
                            "Protocol": "6",
                            "RuleAction": "deny",
                            "Egress": False,
                            "CidrBlock": "10.0.1.0/24",
                        }
                    ],
                    "Associations": [],
                    "IsDefault": False,
                    "Tags": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-dest"]},
    )
    stubber.add_response(
        "delete_network_acl_entry",
        {},
        {"NetworkAclId": "acl-dest", "RuleNumber": 100, "Egress": False},
    )
    stubber.add_response(
        "create_network_acl_entry",
        {},
        {
            "NetworkAclId": "acl-dest",
            "RuleNumber": 100,
            "Protocol": "6",
            "RuleAction": "allow",
            "Egress": False,
            "CidrBlock": "10.0.0.0/24",
            "PortRange": {"From": 443, "To": 443},
        },
    )

    with stubber:
        summary = clone_entries(ec2_client, "acl-source", "acl-dest", overwrite=True)

    assert summary["created"] == 0
    assert summary["overwritten"] == 1
    assert summary["skipped"] == 0
