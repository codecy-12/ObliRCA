"""Obligation-library persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.obligation import ObligationEntry
from .database import Database


class ObligationStore:
    def __init__(self, db: Database):
        self.db = db
        self.db.init_schema()

    def save(self, entry: ObligationEntry, status: str = "accepted") -> None:
        entry.validate()
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(entry.to_dict(), ensure_ascii=False)
        self.db.execute(
            """
            INSERT INTO obl_entries
                (id, category, category_id, version, semantic_hash, status, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                category=excluded.category,
                category_id=excluded.category_id,
                version=excluded.version,
                semantic_hash=excluded.semantic_hash,
                status=excluded.status,
                payload=excluded.payload,
                updated_at=excluded.updated_at
            """,
            (
                entry.id,
                entry.category,
                entry.category_id,
                entry.version,
                entry.semantic_hash(),
                status,
                payload,
                now,
                now,
            ),
        )
        for graph_id, graph_hash in entry.graph_hashes().items():
            graph = next(g for g in entry.graphs if g.id == graph_id)
            self.db.execute(
                """
                INSERT INTO obl_graphs (entry_id, graph_id, semantic_hash, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(entry_id, graph_id) DO UPDATE SET
                    semantic_hash=excluded.semantic_hash,
                    payload=excluded.payload
                """,
                (
                    entry.id,
                    graph_id,
                    graph_hash,
                    json.dumps(graph.to_dict(), ensure_ascii=False),
                ),
            )
        self.db.commit()

    def get(self, entry_id: str) -> ObligationEntry | None:
        row = self.db.query_one("SELECT payload FROM obl_entries WHERE id = ?", (entry_id,))
        if not row:
            return None
        return ObligationEntry.from_dict(json.loads(row["payload"]))

    def list(self, status: str | None = None) -> list[ObligationEntry]:
        if status:
            rows = self.db.query(
                "SELECT payload FROM obl_entries WHERE status = ? ORDER BY category_id, id",
                (status,),
            )
        else:
            rows = self.db.query("SELECT payload FROM obl_entries ORDER BY category_id, id")
        return [ObligationEntry.from_dict(json.loads(r["payload"])) for r in rows]

    def find_semantic(self, semantic_hash: str) -> ObligationEntry | None:
        row = self.db.query_one(
            "SELECT payload FROM obl_entries WHERE semantic_hash = ? LIMIT 1", (semantic_hash,)
        )
        return ObligationEntry.from_dict(json.loads(row["payload"])) if row else None

    def find_by_category(self, category: str) -> list[ObligationEntry]:
        rows = self.db.query(
            "SELECT payload FROM obl_entries WHERE lower(category) = lower(?) ORDER BY id",
            (category,),
        )
        return [ObligationEntry.from_dict(json.loads(r["payload"])) for r in rows]

    def stats(self) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT category, COUNT(*) AS entries FROM obl_entries GROUP BY category ORDER BY category"
        )
        total = sum(int(r["entries"]) for r in rows)
        return {"total_entries": total, "by_category": {r["category"]: int(r["entries"]) for r in rows}}

    def export_yaml(self, directory: str | Path) -> list[Path]:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for entry in self.list():
            path = target / f"{entry.category_id:02d}_{entry.category.lower().replace(' ', '_')}.yaml"
            entry.save(path)
            written.append(path)
        return written

    def add_case(self, entry_id: str, case_ref: str, role: str = "source", source: str = "") -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO obl_cases (entry_id, case_ref, role, source) VALUES (?, ?, ?, ?)",
            (entry_id, case_ref, role, source),
        )
        self.db.commit()
