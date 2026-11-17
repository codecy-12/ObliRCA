"""Prompt loading and output schemas."""

from __future__ import annotations

from pathlib import Path


def load_prompt(name: str, prompts_dir: str | Path = "prompts") -> str:
    path = Path(prompts_dir) / name
    if not path.suffix:
        path = path.with_suffix(".md")
    if not path.exists():
        alt = Path(__file__).resolve().parents[3] / "prompts" / path.name
        if alt.exists():
            path = alt
    if not path.exists():
        raise FileNotFoundError(f"prompt not found: {path}")
    return path.read_text(encoding="utf-8")


EXTRACTION_SCHEMA = {
    "type": "object",
    "required": ["entry"],
    "properties": {
        "entry": {
            "type": "object",
            "required": [
                "id",
                "category",
                "summary",
                "roles",
                "graphs",
                "conditions",
                "query_manual",
            ],
        }
    },
}

SOI_SCHEMA = {
    "type": "object",
    "required": ["hypotheses"],
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["obligation_id", "location", "mechanism", "gap_type"],
            },
        },
        "unresolved_questions": {"type": "array", "items": {"type": "string"}},
    },
}

VERIFICATION_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {
        "status": {"enum": ["verified", "refuted", "needs_revision"]},
        "conditions": {"type": "array", "items": {"type": "string"}},
        "counterexample": {"type": "object"},
        "questions": {"type": "array", "items": {"type": "string"}},
    },
}

RANK_SCHEMA = {
    "type": "object",
    "required": ["ranked"],
    "properties": {
        "ranked": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["hypothesis_id", "rank", "score", "explanation", "fix_suggestion"],
            },
        }
    },
}
