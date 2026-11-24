"""Link extraction and link-based red-flag checks. Pure string analysis; no network access."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
        "rb.gy", "ow.ly", "shorturl.at", "tiny.cc", "buff.ly", "t.ly",
    }
)

# Top-level domains that are cheap and heavily abused. Not proof of anything on their own.
ABUSED_TLDS = frozenset({"top", "xyz", "click", "icu", "cfd", "sbs", "rest", "buzz", "cyou", "monster"})

_SHORTENER_ALT = "|".join(re.escape(s) for s in sorted(SHORTENERS))
_URL = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\)\]]+"
    rf"|\b(?:{_SHORTENER_ALT})/[^\s<>\"'\)\]]*"
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"'\)\]]*",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?"


def find_urls(text: str) -> List[str]:
    """Return the links in ``text`` in order of appearance, without duplicates."""
    seen, out = set(), []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(_TRAILING)
        if url and url.lower() not in seen:
            seen.add(url.lower())
            out.append(url)
    return out


def host_of(url: str) -> Optional[str]:
    """Lower-case host name of a link, or ``None`` if it cannot be parsed."""
    candidate = url if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.IGNORECASE) else "http://" + url
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def belongs_to(host: str, domain: str) -> bool:
    """True if ``host`` is ``domain`` or one of its sub-domains."""
    return host == domain or host.endswith("." + domain)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def link_signals(url: str) -> List[tuple]:
    """Structural red flags for one link as ``(rule_id, title, weight, explanation)`` tuples."""
    signals = []
    host = host_of(url)
    if not host:
        return signals
    candidate = url if "://" in url else "http://" + url
    try:
        netloc = urlsplit(candidate).netloc
    except ValueError:
        netloc = ""

    if host in SHORTENERS:
        signals.append((
            "link-shortener", "Uses a link shortener", 1,
            "Shortened links hide the real destination, so you cannot tell where they lead before clicking.",
        ))
    if _is_ip(host):
        signals.append((
            "link-ip-address", "Link points to a raw IP address", 2,
            "Real organisations almost always use a normal domain name, not a bare IP address.",
        ))
    if any(label.startswith("xn--") for label in host.split(".")):
        signals.append((
            "link-punycode", "Link uses look-alike (punycode) characters", 2,
            "Domains starting with 'xn--' can display foreign letters that imitate a familiar brand.",
        ))
    if "@" in netloc:
        signals.append((
            "link-userinfo", "Link contains an '@' before the real host", 2,
            "In 'http://trusted.com@evil.example' the part before '@' is ignored and only what follows is visited.",
        ))
    if host.rsplit(".", 1)[-1] in ABUSED_TLDS:
        signals.append((
            "link-abused-tld", "Link ends in a frequently abused domain suffix", 1,
            "Some cheap domain endings are common in scam campaigns. This is a weak signal, not proof.",
        ))
    return signals


def hosts(urls: Iterable[str]) -> List[str]:
    return [h for h in (host_of(u) for u in urls) if h]
