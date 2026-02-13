from __future__ import annotations

import json
from typing import Any, Sequence

import typer
from rich.console import Console
from rich.table import Table


def payload(
    *,
    action: str,
    resource_type: str,
    status: str = "ok",
    item: dict[str, Any] | None = None,
    items: list[dict[str, Any]] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": status,
        "action": action,
        "resource_type": resource_type,
    }
    if item is not None:
        out["item"] = item
    if items is not None:
        out["items"] = items
    if meta is not None:
        out["meta"] = meta
    return out


def emit(
    output: str,
    out: dict[str, Any],
    table_lines: Sequence[str] | None = None,
    table: Table | None = None,
) -> None:
    if output == "json":
        typer.echo(json.dumps(out, sort_keys=True))
        return

    if table is not None:
        Console().print(table)
        return

    for line in table_lines or []:
        typer.echo(line)


def make_nacl_table(rows: Sequence[Sequence[str]]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("ID")
    table.add_column("Default")
    table.add_column("Subnets")

    for row in rows:
        table.add_row(*(str(col) for col in row))
    return table


def make_rule_table(
    nacl_name: str, nacl_id: str, rows: Sequence[Sequence[str]]
) -> Table:
    title_name = nacl_name or "None"
    table = Table(
        show_header=True,
        header_style="bold",
        title=f"NACL Rules: {title_name} ({nacl_id})",
    )
    table.add_column("Direction")
    table.add_column("Rule #", justify="right")
    table.add_column("Action")
    table.add_column("Protocol")
    table.add_column("CIDR")
    table.add_column("Ports")

    for row in rows:
        table.add_row(*(str(col) for col in row))
    return table
