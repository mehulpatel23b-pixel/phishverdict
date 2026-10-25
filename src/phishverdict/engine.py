"""Signal detection engine for phishverdict.

Every check is a pure function of the URL string; no network access, no
state, no telemetry. The engine's job is to answer one question fast:
"does this URL deserve a closer look?"
"""
from __future__ import annotations

import codecs
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import reference as ref

# verdict thresholds
CRITICAL_AT = 50
SUSPICIOUS_AT = 20


@dataclass
class Hit:
    signal_id: str
    weight: int
    title: str
    detail: str


@dataclass
class Result:
    url: str
    host: str = ""
    registrable: str = ""
    scheme: str = ""
    hits: list = field(default_factory=list)
    score: int = 0
    verdict: str = "CLEAN"

    @property
    def exit_code(self) -> int:
        return 1 if self.score >= SUSPICIOUS_AT else 0


def _levenshtein_near(label: str, brand: str) -> bool:
    if len(brand) < 5:
        return False  # short names distort distances
    return ref.levenshtein(label, brand, cap=2) <= 1


def _numeric_ip(host: str) -> bool:
    """Raw dotted IPs, hex (0x...) and long decimal/octal encodings."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    s = host.replace(".", "")
    if not s:
        return False
    if s.lower().startswith("0x"):
        try:
            n = int(s, 16)
        except ValueError:
            return False
        return 0x1000000 <= n <= 0xFFFFFFFF
    if all(c in "01234567" for c in s):
        try:
            n = int(s, 8)
        except ValueError:
            return False
        return 0x1000000 <= n <= 0xFFFFFFFF
    if s.isdigit():
        return 0x1000000 <= int(s) <= 0xFFFFFFFF
    return False


def _host_tokens(host: str) -> set:
    """Whole words appearing as host labels or hyphen-chunks."""
    tokens = set()
    for label in host.split("."):
        for chunk in label.split("-"):
            if chunk:
                tokens.add(chunk.lower())
    return tokens


def _decode_idna(host: str, labels) -> str:
    if all(not l.startswith("xn--") for l in labels):
        return host
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        try:
            out = []
            for l in labels:
                out.append(codecs.decode(l[4:], "punycode")
                            if l.startswith("xn--") else l)
            return ".".join(out)
        except Exception:
            return host


def analyze(url: str) -> Result:
    r = Result(url=url)
    lowered = url.strip().lower()

    # 0. scheme that executes in a browser -- short-circuit everything
    for bad_scheme in ("javascript:", "data:", "vbscript:"):
        if lowered.startswith(bad_scheme):
            r.scheme = bad_scheme[:-1]
            r.hits.append(Hit("dangerous_scheme", 60, "Dangerous scheme",
                              f"scheme '{r.scheme}:' can execute in a browser"))
            _finalize(r)
            return r

    parsed = urlparse(url if "://" in url else "http://" + url)
    r.scheme = parsed.scheme or "http"
    host = (parsed.hostname or "").lower().rstrip(".")
    r.host = host
    if not host:
        r.hits.append(Hit("unparseable_url", 25, "No host",
                           "URL has no parsable hostname"))
        _finalize(r)
        return r
    r.registrable = ref.registrable_domain(host)
    is_ip = _numeric_ip(host)
    if is_ip:
        r.registrable = host  # an IP has no meaningful registrable domain

    labels = host.split(".")
    tokens = _host_tokens(host)
    subdomain_part = host[: -(len(r.registrable) + 1)] if host != r.registrable else ""
    reg_labels = r.registrable.split(".")
    reg_label = reg_labels[0]
    reg_tld = reg_labels[-1]
    norm_reg = ref.de_leet(reg_label)
    norm_reg_digits_stripped = norm_reg.rstrip("0123456789")
    norm_hyphenless = ref.de_leet(reg_label.replace("-", ""))

    # 1. raw / obfuscated IP host
    if is_ip:
        r.hits.append(Hit("ip_literal_host", 35, "Raw IP host",
                          f"host is an IP literal family: {host}"))

    # 2. punycode / IDN homoglyph
    if any(l.startswith("xn--") for l in labels):
        decoded = _decode_idna(host, labels)
        r.hits.append(Hit("idn_homoglyph", 40, "Punycode/IDN host",
                          f"decodes to '{decoded}'"))

    # 3. brand impersonation (token in subdomains) and lookalike/leetsquat
    official_domains = set(ref.BRANDS.values())
    trusted_registrable = r.registrable in official_domains
    for brand, official in () if trusted_registrable else ref.BRANDS.items():
        same_site = host == official or host.endswith("." + official)
        in_sub = brand in tokens and not same_site
        imitates = False
        if r.registrable != official:
            if (norm_reg == brand or norm_hyphenless == brand
                    or norm_reg_digits_stripped == brand
                    or _levenshtein_near(norm_reg, brand)):
                imitates = True
            else:
                for chunk in reg_label.split("-"):
                    c = ref.de_leet(chunk).rstrip("0123456789")
                    if c == brand or _levenshtein_near(c, brand):
                        imitates = True
                        break
        if in_sub:
            r.hits.append(Hit(
                "brand_impersonation", 30, f"Brand token '{brand}'",
                f"'{brand}' appears in the subdomain chain, but the "
                f"registrable domain is '{r.registrable}' (official: {official})"))
        if imitates:
            r.hits.append(Hit(
                "brand_lookalike", 35, f"Lookalike of '{brand}'",
                f"registrable domain '{r.registrable}' imitates a leet/typosquat of {official}"))
        if in_sub or imitates:
            break  # one brand finding is enough for triage

    # 4. risky TLD on the registrable domain
    if reg_tld in ref.RISKY_TLDS:
        r.hits.append(Hit("risky_tld", 12, f"High-risk TLD .{reg_tld}",
                          f"registrable domain is '{r.registrable}'"))

    # 5. known URL shortener
    if host in ref.SHORTENERS:
        r.hits.append(Hit("url_shortener", 15, "URL shortener",
                          f"'{host}' hides the real destination"))

    # 6. login-ish tokens in the host
    login_hits = sorted(tokens & ref.LOGIN_TOKENS)
    if login_hits:
        r.hits.append(Hit("login_keyword", 10, "Login-themed hostname",
                          "tokens: " + ", ".join(login_hits)))

    # 7. deep subdomain chains (>= 4 labels before the registrable domain)
    if subdomain_part:
        depth = len([l for l in subdomain_part.split(".") if l])
        if depth >= 4:
            r.hits.append(Hit("excessive_depth", 8, "Very deep subdomain chain",
                              f"'{subdomain_part}' stacks {depth} labels"))

    # 8. hyphen stuffing
    if host.count("-") >= 4:
        r.hits.append(Hit("hyphen_stuffing", 8, "Hyphen-stuffed host",
                          f"'{host}' contains {host.count('-')} hyphens"))

    # 9. userinfo credential trick (http://paypal@evil.tld/)
    if "@" in url:
        head = url.split("@", 1)[0]
        if "://" in head:
            fake = head.split("://", 1)[1]
            if not any(c in fake for c in "/?#"):
                r.hits.append(Hit("userinfo_trick", 40, "Userinfo credential trick",
                                  f"'{fake}@' prefix makes the real host look like '{fake}'"))

    # 10. second URL hiding inside the path (open-redirect / cloaking shape)
    if "://" in url.split("://", 1)[1]:
        r.hits.append(Hit("nested_url", 25, "URL inside the URL",
                          "a second '://' hides in the path: credential- or redirect-shaped"))

    # 11. extremes of length
    if len(url) > 200:
        r.hits.append(Hit("extreme_length", 5, "Extreme length",
                          f"{len(url)} characters"))

    _finalize(r)
    return r


def _finalize(r: Result) -> None:
    r.score = min(100, sum(h.weight for h in r.hits))
    if r.score >= CRITICAL_AT:
        r.verdict = "CRITICAL"
    elif r.score >= SUSPICIOUS_AT:
        r.verdict = "SUSPICIOUS"
    elif r.score > 0:
        r.verdict = "LOW"
    else:
        r.verdict = "CLEAN"


def triage(urls, json_mode=False):
    """Analyze a sequence of URL strings; returns (results, summary)."""
    results = [analyze(u) for u in urls]
    summary = {}
    for v in ("CLEAN", "LOW", "SUSPICIOUS", "CRITICAL"):
        summary[v] = sum(1 for r in results if r.verdict == v)
    return results, summary
