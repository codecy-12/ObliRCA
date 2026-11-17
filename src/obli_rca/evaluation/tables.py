"""Markdown table helpers for the paper's evaluation tables."""

from __future__ import annotations

from typing import Any, Iterable


def markdown_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def format_main_results(rows: list[dict[str, Any]]) -> str:
    headers = ["Group", "Method", "N/N_L", "F@1/3/5", "L@1/3/5", "MRR@10"]
    body = [
        [
            row["group"],
            row["method"],
            f"{row['n']}/{row['n_l']}",
            "/".join(f"{row[f'f_at_{k}']:.2f}" for k in (1, 3, 5)),
            "/".join(f"{row[f'l_at_{k}']:.2f}" for k in (1, 3, 5)),
            f"{row['mrr_at_10']:.4f}",
        ]
        for row in rows
    ]
    return markdown_table(headers, body)


def format_ablation(rows: list[dict[str, Any]]) -> str:
    headers = ["Group", "Configuration", "F@5", "L@5", "MRR@10"]
    body = [
        [row["group"], row["configuration"], f"{row['f_at_5']:.2f}", f"{row['l_at_5']:.2f}", f"{row['mrr_at_10']:.4f}"]
        for row in rows
    ]
    return markdown_table(headers, body)


def format_cost(rows: list[dict[str, Any]]) -> str:
    headers = ["Stage", "Component", "Time (min)", "Tokens (k/case)"]
    body = [
        [row["stage"], row["component"], f"{row['minutes']:.2f}", f"{row['tokens_k']:.2f}"]
        for row in rows
    ]
    return markdown_table(headers, body)
