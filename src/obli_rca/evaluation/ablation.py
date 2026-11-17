"""Ablation settings described in the paper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import Config


@dataclass
class AblationSpec:
    name: str
    disable_library: bool = False
    disable_verification: bool = False
    disable_cross_app: bool = False
    description: str = ""

    def apply(self, config: Config) -> Config:
        data = config.as_dict()
        if self.disable_cross_app:
            data.setdefault("online", {}).setdefault("localization", {})["max_peer_queries"] = 100000
            data["online"]["localization"]["disable_cross_app"] = True
        if self.disable_verification:
            data.setdefault("online", {}).setdefault("rank", {})["disable_verification"] = True
        if self.disable_library:
            data.setdefault("online", {})["use_generic_instructions"] = True
        return Config(data, root=config.root)


ABLATIONS = [
    AblationSpec(
        "without_obligation_library",
        disable_library=True,
        description="replace obligation entries with generic investigation instructions",
    ),
    AblationSpec(
        "without_verification",
        disable_verification=True,
        description="disable Rank verification and hypothesis revision; merge in fixed order",
    ),
    AblationSpec(
        "without_cross_application_expansion",
        disable_cross_app=True,
        description="supply all logs and application source at once instead of hop-by-hop queries",
    ),
]


def get_ablation(name: str) -> AblationSpec:
    for spec in ABLATIONS:
        if spec.name == name:
            return spec
    raise KeyError(name)
