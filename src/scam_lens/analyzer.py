"""Core analysis: turn a message into a list of explained red flags and a cautious verdict."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import Pack, load_pack
from .urls import belongs_to, find_urls, host_of, link_signals

NO_KNOWN_RED_FLAGS = "NO_KNOWN_RED_FLAGS"
SUSPICIOUS = "SUSPICIOUS"
LIKELY_SCAM = "LIKELY_SCAM"

# There is deliberately no "SAFE" verdict: this tool only knows about patterns it has been taught.
DISCLAIMER = (
    "This tool only looks for known patterns. 'No known red flags' does NOT mean a message is "
    "genuine or safe. If you are unsure, contact the organisation using a phone number or website "
    "you already trust, never the ones inside the message."
)

_NEGATION = re.compile(r"(?:\bnot\b|\bnever\b|n't\b|\bno ?one\b|\bnobody\b)[^.!?\n]{0,30}$", re.IGNORECASE)


@dataclass
class Finding:
    rule_id: str
    title: str
    weight: int
    explanation: str
    evidence: str = ""

    @property
    def severity(self) -> str:
        return {1: "low", 2: "medium", 3: "high"}[self.weight]


@dataclass
class Report:
    verdict: str
    score: int
    findings: List[Finding] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    packs: List[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> Dict[str, object]:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "findings": [
                {
                    "id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "explanation": f.explanation,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "links": self.links,
            "packs": self.packs,
            "disclaimer": self.disclaimer,
        }


def _snippet(text: str, start: int, end: int, limit: int = 80) -> str:
    snippet = " ".join(text[start:end].split())
    return snippet if len(snippet) <= limit else snippet[: limit - 1] + "…"


def _verdict_for(score: int) -> str:
    if score <= 0:
        return NO_KNOWN_RED_FLAGS
    if score <= 2:
        return SUSPICIOUS
    return LIKELY_SCAM


def analyze(text: str, packs: Optional[Sequence[Pack]] = None) -> Report:
    """Analyse ``text`` against the given packs (default: the bundled ``global`` pack)."""
    if packs is None:
        packs = [load_pack("global")]

    findings: Dict[str, Finding] = {}

    # 1. Wording rules from the packs. Each rule counts once, however often it matches.
    # group -> (weight, matched length, rule id) of the rule that currently represents it.
    groups: Dict[str, Tuple[int, int, str]] = {}
    for pack in packs:
        for rule in pack.rules:
            if rule.id in findings:
                continue
            for pattern in rule.patterns:
                hit = None
                for match in pattern.finditer(text):
                    if rule.skip_if_negated and _NEGATION.search(text[max(0, match.start() - 40): match.start()]):
                        continue
                    hit = match
                    break
                if hit:
                    if rule.group:
                        # Keep the heavier rule, then the one that matched more text.
                        rank = (rule.weight, hit.end() - hit.start())
                        best = groups.get(rule.group)
                        if best:
                            if rank < best[:2]:
                                break
                            del findings[best[2]]
                        groups[rule.group] = (*rank, rule.id)
                    findings[rule.id] = Finding(
                        rule.id, rule.title, rule.weight, rule.explanation, _snippet(text, hit.start(), hit.end())
                    )
                    break

    # 2. Link checks.
    links = find_urls(text)
    lowered = text.lower()
    brands = [b for pack in packs for b in pack.brands]
    for url in links:
        for rule_id, title, weight, explanation in link_signals(url):
            findings.setdefault(rule_id, Finding(rule_id, title, weight, explanation, url))
        host = host_of(url)
        if not host:
            continue
        for brand in brands:
            legit = any(belongs_to(host, d) for d in brand.domains)
            if legit:
                continue
            mentioned = re.search(rf"\b{re.escape(brand.name)}\b", lowered) is not None
            in_host = brand.name in host
            if in_host:
                findings.setdefault(
                    f"lookalike-{brand.name}",
                    Finding(
                        f"lookalike-{brand.name}",
                        f"Link imitates the {brand.name.title()} name",
                        3,
                        f"The address contains '{brand.name}' but is not an official {brand.name.title()} domain "
                        f"({', '.join(brand.domains)}).",
                        url,
                    ),
                )
            elif mentioned:
                findings.setdefault(
                    f"brand-mismatch-{brand.name}",
                    Finding(
                        f"brand-mismatch-{brand.name}",
                        f"Mentions {brand.name.title()} but links somewhere else",
                        2,
                        f"The message talks about {brand.name.title()} but the link goes to {host}, "
                        f"which is not one of its official domains ({', '.join(brand.domains)}).",
                        url,
                    ),
                )

    ordered = sorted(findings.values(), key=lambda f: (-f.weight, f.rule_id))
    score = sum(f.weight for f in ordered)
    return Report(
        verdict=_verdict_for(score),
        score=score,
        findings=ordered,
        links=links,
        packs=[p.name for p in packs],
    )
