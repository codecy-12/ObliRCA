"""Rule-based primary-category assignment for offline cases.

The LLM extraction path can choose a category itself; this module provides a
deterministic fallback and a consistency check.  It is intentionally coarse:
the review step decides the final category.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CATEGORY_KEYWORDS: dict[str, dict[str, float]] = {
    "Path Constraints": {
        "path": 2.0,
        "traversal": 3.0,
        "canonical": 2.0,
        "symlink": 2.0,
        "directory": 1.0,
        "filename": 1.0,
        "root": 1.5,
        "chroot": 2.0,
    },
    "Authorization Checks": {
        "authorization": 3.0,
        "authentication": 2.0,
        "permission": 3.0,
        "policy": 2.0,
        "credential": 2.0,
        "role": 1.5,
        "capability": 2.0,
        "host": 1.5,
        "tenant": 1.5,
    },
    "Resource Bounds": {
        "quota": 3.0,
        "limit": 2.0,
        "rate": 2.0,
        "exhaust": 2.0,
        "allocation": 1.5,
        "count": 1.0,
        "capacity": 2.0,
        "memory exhaustion": 3.0,
    },
    "Protocol State Constraints": {
        "protocol": 3.0,
        "handshake": 3.0,
        "state": 2.0,
        "frame": 2.0,
        "session": 2.0,
        "version": 1.5,
        "resumption": 2.0,
        "sequence": 1.5,
    },
    "Memory Bounds": {
        "buffer": 2.0,
        "overflow": 3.0,
        "over-read": 3.0,
        "out-of-bounds": 3.0,
        "heap": 1.5,
        "stack": 1.5,
        "length": 2.0,
        "offset": 2.0,
        "integer overflow": 2.5,
        "memcpy": 2.0,
    },
    "Input Sanitization": {
        "injection": 3.0,
        "sanitize": 3.0,
        "escape": 2.0,
        "encoding": 2.0,
        "parse": 1.5,
        "deserialization": 3.0,
        "command": 1.5,
        "template": 2.0,
        "xss": 3.0,
    },
    "Secure Defaults": {
        "default": 3.0,
        "configuration": 2.0,
        "option": 2.0,
        "strict": 2.0,
        "disabled": 2.0,
        "enabled": 1.5,
        "insecure default": 3.0,
    },
    "Concurrency Ordering": {
        "race": 3.0,
        "concurrent": 2.0,
        "lock": 2.0,
        "atomic": 2.0,
        "toctou": 3.0,
        "use-after-free": 1.0,
        "refcount": 2.0,
        "ordering": 2.0,
    },
    "Resource Lifecycles": {
        "file descriptor": 3.0,
        "socket": 2.0,
        "close": 2.0,
        "release": 2.0,
        "leak": 3.0,
        "handle": 2.0,
        "cleanup": 2.0,
        "resource": 1.5,
    },
    "Object Lifecycles": {
        "use-after-free": 3.0,
        "lifetime": 3.0,
        "reference": 2.0,
        "destroy": 2.0,
        "initialization": 2.0,
        "stale": 2.0,
        "double free": 3.0,
        "object": 1.0,
    },
}


@dataclass
class CategoryDecision:
    category: str
    confidence: float
    scores: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "scores": self.scores,
        }


class CategoryAssigner:
    def assign(self, text: str) -> CategoryDecision:
        lowered = (text or "").lower()
        scores: dict[str, float] = {}
        for category, keywords in CATEGORY_KEYWORDS.items():
            score = 0.0
            for keyword, weight in keywords.items():
                if keyword in lowered:
                    score += weight
            scores[category] = round(score, 3)
        best = max(scores, key=scores.get)
        total = sum(scores.values())
        confidence = round(scores[best] / total, 3) if total else 0.0
        return CategoryDecision(best, confidence, scores)

    def assign_case(self, case: Any) -> CategoryDecision:
        text = " ".join(
            [
                str(getattr(case, "project", "")),
                str(getattr(case, "category", "")),
                str(getattr(case, "metadata", {}).get("defect", "")),
                str(getattr(case, "metadata", {}).get("vulnerability_type", "")),
            ]
        )
        return self.assign(text)
