"""Investigation workspace persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..models.code import CodeFramework, FrameworkNode
from ..models.hypothesis import FeedbackRequest, Hypothesis, RankedHypothesis
from ..models.log import LogEvent
from .database import Database


class InvestigationStore:
    def __init__(self, db: Database):
        self.db = db
        self.db.init_schema()

    def create(self, investigation_id: str, scenario_id: str, source_version: str = "") -> None:
        self.db.execute(
            """
            INSERT INTO inv_investigations (id, scenario_id, source_version, status, created_at, metadata)
            VALUES (?, ?, ?, 'running', ?, '{}')
            ON CONFLICT(id) DO NOTHING
            """,
            (investigation_id, scenario_id, source_version, datetime.now(timezone.utc).isoformat()),
        )
        self.db.commit()

    def finish(self, investigation_id: str, status: str = "completed") -> None:
        self.db.execute(
            "UPDATE inv_investigations SET status = ? WHERE id = ?", (status, investigation_id)
        )
        self.db.commit()

    def add_framework_node(self, investigation_id: str, node: FrameworkNode) -> None:
        self.db.execute(
            """
            INSERT INTO inv_framework
                (investigation_id, node_id, app, source_version, file, function, start_line,
                 end_line, kind, snippet, event_ids, parent_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, node_id) DO NOTHING
            """,
            (
                investigation_id,
                node.id,
                node.application,
                node.source_version,
                node.file,
                node.function,
                node.start_line,
                node.end_line,
                node.kind,
                node.snippet,
                json.dumps(node.event_ids),
                node.parent_id,
                json.dumps(node.metadata, ensure_ascii=False),
            ),
        )
        self.db.commit()

    def load_framework(self, investigation_id: str) -> CodeFramework:
        rows = self.db.query(
            "SELECT * FROM inv_framework WHERE investigation_id = ? ORDER BY rowid",
            (investigation_id,),
        )
        framework = CodeFramework(investigation_id)
        for row in rows:
            framework.add_node(
                FrameworkNode(
                    id=row["node_id"],
                    application=row["app"],
                    source_version=row["source_version"],
                    file=row["file"],
                    function=row["function"],
                    start_line=int(row["start_line"]),
                    end_line=int(row["end_line"]),
                    kind=row["kind"],
                    snippet=row["snippet"],
                    event_ids=json.loads(row["event_ids"] or "[]"),
                    parent_id=row["parent_id"],
                    metadata=json.loads(row["metadata"] or "{}"),
                )
            )
        return framework

    def add_log_ref(self, investigation_id: str, event: LogEvent) -> None:
        self.db.execute(
            """
            INSERT INTO inv_log_refs (investigation_id, event_id, app, tid, syscall, object, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, event_id) DO NOTHING
            """,
            (
                investigation_id,
                event.event_id,
                event.process,
                event.tid,
                event.syscall,
                event.object_key,
                json.dumps(event.to_dict(), ensure_ascii=False),
            ),
        )
        self.db.commit()

    def save_hypothesis(self, investigation_id: str, hypothesis: Hypothesis) -> None:
        self.db.execute(
            """
            INSERT INTO inv_hypotheses
                (investigation_id, hypothesis_id, obligation_id, location, mechanism, gap_type,
                 status, confidence, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, hypothesis_id) DO UPDATE SET
                status=excluded.status,
                confidence=excluded.confidence,
                payload=excluded.payload
            """,
            (
                investigation_id,
                hypothesis.id,
                hypothesis.obligation_id,
                hypothesis.location.key,
                hypothesis.mechanism,
                hypothesis.gap_type.value,
                hypothesis.status.value,
                hypothesis.confidence,
                json.dumps(hypothesis.to_dict(), ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.db.commit()

    def hypotheses(self, investigation_id: str) -> list[Hypothesis]:
        rows = self.db.query(
            "SELECT payload FROM inv_hypotheses WHERE investigation_id = ? ORDER BY created_at",
            (investigation_id,),
        )
        return [Hypothesis.from_dict(json.loads(r["payload"])) for r in rows]

    def save_feedback(
        self,
        investigation_id: str,
        request: FeedbackRequest,
        response: dict[str, Any] | None = None,
    ) -> None:
        self.db.execute(
            """
            INSERT INTO inv_feedback
                (investigation_id, hypothesis_id, round, request, response, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, hypothesis_id, round) DO UPDATE SET
                request=excluded.request,
                response=excluded.response
            """,
            (
                investigation_id,
                request.hypothesis_id,
                request.round,
                json.dumps(request.to_dict(), ensure_ascii=False),
                json.dumps(response or {}, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.db.commit()

    def save_ranking(self, investigation_id: str, ranked: RankedHypothesis) -> None:
        self.db.execute(
            """
            INSERT INTO inv_rankings
                (investigation_id, hypothesis_id, rank, score, explanation, fix)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, hypothesis_id) DO UPDATE SET
                rank=excluded.rank,
                score=excluded.score,
                explanation=excluded.explanation,
                fix=excluded.fix
            """,
            (
                investigation_id,
                ranked.hypothesis.id,
                ranked.rank,
                ranked.score,
                ranked.explanation,
                ranked.fix_suggestion,
            ),
        )
        self.db.commit()

    def rankings(self, investigation_id: str) -> list[dict[str, Any]]:
        return self.db.query(
            "SELECT * FROM inv_rankings WHERE investigation_id = ? ORDER BY rank",
            (investigation_id,),
        )
