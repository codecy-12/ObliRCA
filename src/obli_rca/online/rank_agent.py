"""Rank Agent: verification, feedback, and evidence-based ranking."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..llm.client import LLMClient
from ..models.code import CodeFramework
from ..models.evidence import Evidence, EvidenceKind
from ..models.hypothesis import (
    FeedbackRequest,
    GapType,
    Hypothesis,
    HypothesisStatus,
    RankedHypothesis,
    VerificationResult,
)
from ..models.obligation import ObligationEntry
from ..storage.investigation_store import InvestigationStore
from ..tools.base import ToolContext, ToolRegistry
from .explanation import ExplanationBuilder


@dataclass
class RankResult:
    verified: list[RankedHypothesis] = field(default_factory=list)
    refuted: list[Hypothesis] = field(default_factory=list)
    unresolved: list[Hypothesis] = field(default_factory=list)
    feedback: list[FeedbackRequest] = field(default_factory=list)


class RankAgent:
    def __init__(
        self,
        config: Config,
        tools: ToolRegistry,
        store: InvestigationStore,
        investigation_id: str,
        obligations: dict[str, ObligationEntry],
        *,
        workspace: str | Path | None = None,
        llm: LLMClient | None = None,
        use_llm: bool = False,
        feedback_handler: Callable[[FeedbackRequest], Hypothesis | None] | None = None,
    ):
        self.config = config
        self.tools = tools
        self.store = store
        self.investigation_id = investigation_id
        self.obligations = obligations
        self.workspace = Path(workspace or Path("data") / "investigations" / investigation_id)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.llm = llm or LLMClient(config, mock=not use_llm)
        self.feedback_handler = feedback_handler
        self.max_feedback = int(config.get("online.rank.feedback_rounds", 2))
        self.explainer = ExplanationBuilder()
        self.ctx = ToolContext(
            config=config,
            investigation_id=investigation_id,
            workspace=self.workspace,
            framework=CodeFramework(investigation_id),
            budget=int(config.get("online.rank.rerank_top_n", 20)),
        )

    # ------------------------------------------------------------------
    def run(self, hypotheses: list[Hypothesis], binary: str | None = None) -> RankResult:
        merged = self._merge(hypotheses)
        result = RankResult()
        for hypothesis in merged:
            verification = self.verify(hypothesis, binary=binary)
            if verification.status == HypothesisStatus.VERIFIED:
                hypothesis.status = HypothesisStatus.VERIFIED
                hypothesis.confidence = max(hypothesis.confidence, 0.7)
            elif verification.status == HypothesisStatus.REFUTED:
                hypothesis.status = HypothesisStatus.REFUTED
                result.refuted.append(hypothesis)
            elif verification.status == HypothesisStatus.NEEDS_REVISION:
                if hypothesis.revision_round >= self.max_feedback:
                    hypothesis.status = HypothesisStatus.UNRESOLVED
                    result.unresolved.append(hypothesis)
                    continue
                hypothesis.status = HypothesisStatus.NEEDS_REVISION
                request = FeedbackRequest(
                    hypothesis_id=hypothesis.id,
                    conditions_to_check=verification.constraints,
                    tool_evidence=[e.summary for e in hypothesis.evidence[-2:]],
                    questions=verification.notes.split("; ") if verification.notes else [],
                    round=hypothesis.revision_round + 1,
                )
                result.feedback.append(request)
                if self.feedback_handler:
                    revised = self.feedback_handler(request)
                    if revised and revised.status == HypothesisStatus.VERIFIED:
                        hypothesis = revised
                result.unresolved.append(hypothesis)
            else:
                hypothesis.status = HypothesisStatus.UNRESOLVED
                result.unresolved.append(hypothesis)
            self.store.save_hypothesis(self.investigation_id, hypothesis)
        result.verified = self.rank(
            [h for h in merged if h.status == HypothesisStatus.VERIFIED]
        )
        for ranked in result.verified:
            self.store.save_ranking(self.investigation_id, ranked)
        return result

    # ------------------------------------------------------------------
    def _merge(self, hypotheses: list[Hypothesis]) -> list[Hypothesis]:
        merged: dict[tuple[str, str], Hypothesis] = {}
        for hypothesis in hypotheses:
            key = (hypothesis.location.key, hypothesis.mechanism)
            if key in merged:
                existing = merged[key]
                existing.evidence.extend(hypothesis.evidence)
                existing.bindings.update(hypothesis.bindings)
                existing.confidence = max(existing.confidence, hypothesis.confidence)
            else:
                merged[key] = hypothesis
        return list(merged.values())

    def verify(self, hypothesis: Hypothesis, binary: str | None = None) -> VerificationResult:
        obligation = self.obligations.get(hypothesis.obligation_id)
        constraints = list(obligation.conditions.must) if obligation else []
        if binary:
            result = self.tools.run(
                "angr",
                self.ctx,
                binary=binary,
                gap_type=hypothesis.gap_type.value,
                constraints=constraints,
            )
            if result.ok and result.data:
                payload = result.data
                return VerificationResult(
                    hypothesis_id=hypothesis.id,
                    status=HypothesisStatus(payload.get("status", "unresolved")),
                    gap_type=hypothesis.gap_type,
                    constraints=payload.get("constraints", constraints),
                    counterexample=payload.get("counterexample", {}),
                    tool="angr",
                    notes=payload.get("notes", ""),
                )
        # Deterministic fallback: a source-backed gap with at least one
        # location and one evidence record is treated as verified; a hypothesis
        # without source evidence is sent back for revision.
        source_evidence = [e for e in hypothesis.evidence if e.kind == EvidenceKind.SOURCE]
        if not source_evidence:
            return VerificationResult(
                hypothesis_id=hypothesis.id,
                status=HypothesisStatus.NEEDS_REVISION,
                gap_type=hypothesis.gap_type,
                constraints=constraints,
                tool="evidence-check",
                notes="no source evidence; ask the SOI to locate the guard or sink",
            )
        if hypothesis.location.file and hypothesis.location.function:
            return VerificationResult(
                hypothesis_id=hypothesis.id,
                status=HypothesisStatus.VERIFIED,
                gap_type=hypothesis.gap_type,
                constraints=constraints,
                tool="evidence-check",
                notes="source-backed obligation gap",
            )
        return VerificationResult(
            hypothesis_id=hypothesis.id,
            status=HypothesisStatus.UNRESOLVED,
            gap_type=hypothesis.gap_type,
            constraints=constraints,
            tool="evidence-check",
        )

    # ------------------------------------------------------------------
    def rank(self, hypotheses: list[Hypothesis]) -> list[RankedHypothesis]:
        scored: list[tuple[float, Hypothesis]] = []
        for hypothesis in hypotheses:
            evidence_factor = min(1.0, len(hypothesis.evidence) / 4.0)
            clarity = 1.0 if hypothesis.location.file and hypothesis.location.function else 0.4
            compatibility = 1.0 if hypothesis.source_app else 0.6
            score = (
                0.35 * hypothesis.confidence
                + 0.25 * evidence_factor
                + 0.2 * clarity
                + 0.2 * compatibility
            )
            scored.append((round(score, 4), hypothesis))
        scored.sort(key=lambda item: item[0], reverse=True)
        ranked: list[RankedHypothesis] = []
        for index, (score, hypothesis) in enumerate(scored, start=1):
            obligation = self.obligations.get(hypothesis.obligation_id)
            explanation = self.explainer.build(hypothesis, obligation)
            ranked.append(
                RankedHypothesis(
                    rank=index,
                    hypothesis=hypothesis,
                    score=score,
                    explanation=explanation.text,
                    fix_suggestion=explanation.fix,
                    obligation_name=obligation.category if obligation else "",
                )
            )
        return ranked

    def _explain(self, hypothesis: Hypothesis, obligation: ObligationEntry | None) -> str:
        must = "; ".join(obligation.conditions.must) if obligation else "the registered obligation"
        return (
            f"The candidate at {hypothesis.location.file}:{hypothesis.location.line} "
            f"({hypothesis.location.function}) is responsible for the condition '{must}'. "
            f"The observed defect is {hypothesis.mechanism}."
        )

    def _fix(self, hypothesis: Hypothesis, obligation: ObligationEntry | None) -> str:
        if hypothesis.gap_type == GapType.MISSING_NECESSARY:
            region = hypothesis.missing_region or hypothesis.location.function
            return (
                f"Add the missing check in {region} before the protected operation; "
                f"the check must establish: {obligation.conditions.must[0] if obligation else 'the obligation'}."
            )
        return (
            f"Strengthen the existing check at {hypothesis.location.function} so that it covers "
            f"all required conditions and survives subsequent processing."
        )
