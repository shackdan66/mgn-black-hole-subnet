from __future__ import annotations

import json

from botocore.stub import Stubber
from typer.testing import CliRunner

from naclmaker import cli

runner = CliRunner()


def _patch_make_ec2(monkeypatch, ec2_client) -> None:
    monkeypatch.setattr(
        cli, "make_ec2", lambda profile, region: (ec2_client, "us-east-1")
    )


def test_prompt_indexed_choice_auto_selects_single(monkeypatch) -> None:
    echoed: list[str] = []
    prompt_called = {"value": False}

    monkeypatch.setattr(cli.typer, "echo", lambda msg: echoed.append(msg))

    def fake_prompt(*args, **kwargs):
        prompt_called["value"] = True
        return 1

    monkeypatch.setattr(cli.typer, "prompt", fake_prompt)

    selected = cli._prompt_indexed_choice(
        "VPC",
        [("vpc-1234", "primary-vpc  vpc-1234  10.0.0.0/16")],
    )

    assert selected == "vpc-1234"
    assert prompt_called["value"] is False
    assert any(line.startswith("Using VPC:") for line in echoed)


def test_prompt_indexed_choice_uses_numeric_selection(monkeypatch) -> None:
    echoed: list[str] = []
    monkeypatch.setattr(cli.typer, "echo", lambda msg: echoed.append(msg))
    monkeypatch.setattr(cli.typer, "prompt", lambda *args, **kwargs: 2)

    selected = cli._prompt_indexed_choice(
        "VPC",
        [
            ("vpc-1111", "vpc-one  vpc-1111  10.0.0.0/16"),
            ("vpc-2222", "vpc-two  vpc-2222  10.1.0.0/16"),
        ],
    )

    assert selected == "vpc-2222"
    assert any(line == "Available VPCs:" for line in echoed)
    assert any(line.strip().startswith("1.") for line in echoed)
    assert any(line.strip().startswith("2.") for line in echoed)


def test_nacl_group_help_does_not_require_region() -> None:
    result = runner.invoke(cli.app, ["nacl"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "Usage: naclmaker nacl" in result.stdout
    assert "CRUD Network ACLs" in result.stdout


def test_no_input_fails_when_vpc_missing(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)

    result = runner.invoke(
        cli.app, ["--no-input", "nacl", "list"], catch_exceptions=True
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, Exception)
    assert "Missing --vpc-id" in str(result.exception)


def test_rule_list_selects_nacl_when_missing(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)

    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-1111",
                    "VpcId": "vpc-1",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
        {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-1111",
                    "VpcId": "vpc-1",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-1111"]},
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            ["rule", "list", "--vpc-id", "vpc-1"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    assert "Using NACL:" in result.stdout
    assert "NACL Rules:" in result.stdout
    assert "Direction" in result.stdout


def test_rule_list_selects_vpc_then_nacl_when_missing(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)

    stubber.add_response(
        "describe_vpcs",
        {
            "Vpcs": [
                {
                    "VpcId": "vpc-1",
                    "CidrBlock": "10.0.0.0/16",
                    "Tags": [{"Key": "Name", "Value": "main"}],
                }
            ]
        },
        {},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-1111",
                    "VpcId": "vpc-1",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
        {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-1111",
                    "VpcId": "vpc-1",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-1111"]},
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            ["rule", "list"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    assert "Using VPC:" in result.stdout
    assert "Using NACL:" in result.stdout
    assert "NACL Rules:" in result.stdout


def test_rule_update_upsert_outputs_json(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)
    stubber.add_client_error(
        "delete_network_acl_entry",
        service_error_code="InvalidNetworkAclEntry.NotFound",
        service_message="not found",
        http_status_code=400,
        expected_params={
            "NetworkAclId": "acl-1234567890abcdef0",
            "RuleNumber": 100,
            "Egress": False,
        },
    )
    stubber.add_response(
        "create_network_acl_entry",
        {},
        {
            "NetworkAclId": "acl-1234567890abcdef0",
            "RuleNumber": 100,
            "Protocol": "6",
            "RuleAction": "allow",
            "Egress": False,
            "CidrBlock": "10.0.0.0/24",
            "PortRange": {"From": 443, "To": 443},
        },
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            [
                "--output",
                "json",
                "rule",
                "update",
                "acl-1234567890abcdef0",
                "--direction",
                "ingress",
                "--rule-number",
                "100",
                "--action",
                "allow",
                "--protocol",
                "tcp",
                "--cidr",
                "10.0.0.0/24",
                "--port-from",
                "443",
                "--port-to",
                "443",
            ],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["status"] == "ok"
    assert body["action"] == "update"
    assert body["resource_type"] == "rule"
    assert body["item"]["previously_existed"] is False


def test_nacl_delete_reassociates_to_default(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)

    nacl_obj = {
        "NetworkAclId": "acl-1234567890abcdef0",
        "VpcId": "vpc-1234",
        "IsDefault": False,
        "Entries": [],
        "Tags": [{"Key": "Name", "Value": "to-delete"}],
        "Associations": [
            {
                "NetworkAclAssociationId": "aclassoc-abc",
                "NetworkAclId": "acl-1234567890abcdef0",
                "SubnetId": "subnet-1234",
            }
        ],
    }

    stubber.add_response(
        "describe_network_acls",
        {"NetworkAcls": [nacl_obj]},
        {"NetworkAclIds": ["acl-1234567890abcdef0"]},
    )
    stubber.add_response(
        "describe_network_acls",
        {"NetworkAcls": [nacl_obj]},
        {"NetworkAclIds": ["acl-1234567890abcdef0"]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-default",
                    "VpcId": "vpc-1234",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [],
                }
            ]
        },
        {
            "Filters": [
                {"Name": "vpc-id", "Values": ["vpc-1234"]},
                {"Name": "default", "Values": ["true"]},
            ]
        },
    )
    stubber.add_response(
        "replace_network_acl_association",
        {"NewAssociationId": "aclassoc-new"},
        {"AssociationId": "aclassoc-abc", "NetworkAclId": "acl-default"},
    )
    stubber.add_response(
        "delete_network_acl",
        {},
        {"NetworkAclId": "acl-1234567890abcdef0"},
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            [
                "--output",
                "json",
                "nacl",
                "delete",
                "acl-1234567890abcdef0",
                "--vpc-id",
                "vpc-1234",
                "--force",
            ],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["action"] == "delete"
    assert body["resource_type"] == "nacl"
    assert body["item"]["default_nacl_id"] == "acl-default"
    assert body["item"]["moved_subnet_ids"] == ["subnet-1234"]


def test_nacl_list_json_shape(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-abc",
                    "VpcId": "vpc-1",
                    "IsDefault": True,
                    "Entries": [],
                    "Associations": [],
                    "Tags": [{"Key": "Name", "Value": "default"}],
                }
            ]
        },
        {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]},
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            ["--output", "json", "nacl", "list", "--vpc-id", "vpc-1"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body == {
        "action": "list",
        "items": [
            {
                "is_default": True,
                "name": "default",
                "nacl_id": "acl-abc",
                "subnet_ids": [],
            }
        ],
        "meta": {"count": 1, "vpc_id": "vpc-1"},
        "resource_type": "nacl",
        "status": "ok",
    }


def test_rule_list_orders_by_rule_number(monkeypatch, ec2_client) -> None:
    _patch_make_ec2(monkeypatch, ec2_client)
    stubber = Stubber(ec2_client)
    base_acl = {
        "NetworkAclId": "acl-abc",
        "VpcId": "vpc-1",
        "IsDefault": True,
        "Associations": [],
        "Tags": [],
    }
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    **base_acl,
                    "Entries": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-abc"]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    **base_acl,
                    "Entries": [],
                }
            ]
        },
        {"NetworkAclIds": ["acl-abc"]},
    )
    stubber.add_response(
        "describe_network_acls",
        {
            "NetworkAcls": [
                {
                    **base_acl,
                    "Entries": [
                        {
                            "RuleNumber": 200,
                            "Egress": True,
                            "RuleAction": "allow",
                            "Protocol": "6",
                            "CidrBlock": "0.0.0.0/0",
                        },
                        {
                            "RuleNumber": 100,
                            "Egress": False,
                            "RuleAction": "allow",
                            "Protocol": "6",
                            "CidrBlock": "10.0.0.0/24",
                        },
                        {
                            "RuleNumber": 150,
                            "Egress": False,
                            "RuleAction": "deny",
                            "Protocol": "17",
                            "CidrBlock": "10.0.1.0/24",
                        },
                    ],
                }
            ]
        },
        {"NetworkAclIds": ["acl-abc"]},
    )

    with stubber:
        result = runner.invoke(
            cli.app,
            ["--output", "json", "rule", "list", "acl-abc"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert [item["rule_number"] for item in body["items"]] == [100, 150, 200]
