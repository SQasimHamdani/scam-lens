"""Rule packs: load and validate the JSON files that describe scam red flags."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import List, Tuple

_PACK_NAME = re.compile(r"^[a-z0-9_-]+$")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    weight: int  # 1 = weak signal, 2 = strong, 3 = very strong
    explanation: str
    patterns: Tuple["re.Pattern[str]", ...]
    skip_if_negated: bool = False


@dataclass(frozen=True)
class Brand:
    name: str
    domains: Tuple[str, ...]


@dataclass
class Pack:
    name: str
    description: str
    rules: List[Rule] = field(default_factory=list)
    brands: List[Brand] = field(default_factory=list)


def _parse_pack(data: dict, source: str) -> Pack:
    try:
        name = str(data["name"])
        description = str(data.get("description", ""))
        rules = []
        for raw in data.get("rules", []):
            weight = int(raw["weight"])
            if weight not in (1, 2, 3):
                raise ValueError(f"rule {raw.get('id')!r}: weight must be 1, 2 or 3")
            try:
                patterns = tuple(re.compile(p, re.IGNORECASE) for p in raw["patterns"])
            except re.error as exc:
                raise ValueError(f"rule {raw.get('id')!r}: bad regex ({exc})") from exc
            rules.append(
                Rule(
                    id=str(raw["id"]),
                    title=str(raw["title"]),
                    weight=weight,
                    explanation=str(raw["explanation"]),
                    patterns=patterns,
                    skip_if_negated=bool(raw.get("skip_if_negated", False)),
                )
            )
        brands = [
            Brand(name=str(b["name"]).lower(), domains=tuple(d.lower() for d in b["domains"]))
            for b in data.get("brands", [])
        ]
    except KeyError as exc:
        raise ValueError(f"{source}: missing required field {exc}") from exc
    return Pack(name=name, description=description, rules=rules, brands=brands)


def list_packs() -> List[str]:
    """Names of the rule packs bundled with the package."""
    folder = resources.files("scam_lens") / "packs"
    return sorted(p.name[:-5] for p in folder.iterdir() if p.name.endswith(".json"))


def load_pack(name: str) -> Pack:
    """Load a bundled pack by name (e.g. ``global`` or ``pk``)."""
    if not _PACK_NAME.match(name):
        raise ValueError(f"invalid pack name: {name!r}")
    path = resources.files("scam_lens") / "packs" / f"{name}.json"
    if not path.is_file():
        raise ValueError(f"unknown pack {name!r}; available: {', '.join(list_packs())}")
    return _parse_pack(json.loads(path.read_text(encoding="utf-8")), source=f"pack {name}")


def load_pack_file(path: str) -> Pack:
    """Load a pack from a JSON file on disk (for custom or in-development packs)."""
    p = Path(path)
    return _parse_pack(json.loads(p.read_text(encoding="utf-8")), source=str(p))
