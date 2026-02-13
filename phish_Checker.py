#!/usr/bin/env python3
"""
Simple phishing-risk URL checker for quick triage (heuristics-based).

What it does:
- Parses one or more URLs
- Applies common phishing red-flag checks
- Outputs a risk score (0–100) + human-readable findings

Note:
This is NOT a perfect detector. It is a lightweight, explainable triage tool.
"""

from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "club",
    "cam",
    "work",
    "lol",
    "gq",
    "tk",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "rb.gy",
}

BRAND_KEYWORDS = {
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "instagram",
    "facebook",
    "whatsapp",
    "telegram",
    "bank",
    "visa",
    "mastercard",
}

REDIRECT_QUERY_KEYS = {
    "redirect",
    "redir",
    "url",
    "next",
    "target",
    "dest",
    "destination",
    "continue",
    "return",
    "return_url",
}


class RiskLabel(str, Enum):
    LOW = "LOW RISK"
    MEDIUM = "MEDIUM RISK"
    HIGH = "HIGH RISK"


@dataclass(frozen=True)
class Finding:
    points: int
    reason: str


@dataclass(frozen=True)
class AnalysisResult:
    original: str
    normalized: str
    host: str
    score: int
    label: RiskLabel
    findings: list[Finding]


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if "://" not in raw_url:
        # If user pastes "example.com", make it parseable.
        return f"http://{raw_url}"
    return raw_url


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def count_subdomains(host: str) -> int:
    parts = [part for part in host.split(".") if part]
    # crude: "a.b.example.com" => 2 subdomains (a, b)
    return max(0, len(parts) - 2)


def get_tld(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    return parts[-1].lower() if parts else ""


def approx_registered_domain(host: str) -> str:
    """
    Approximation without external libs:
    - "paypal-login.verify-account.xyz" => "verify-account.xyz"
    - "a.b.example.co.uk" => "co.uk" (not perfect)
    Good enough for a simple heuristic checker.
    """
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def classify(score: int) -> RiskLabel:
    if score >= 60:
        return RiskLabel.HIGH
    if score >= 30:
        return RiskLabel.MEDIUM
    return RiskLabel.LOW


def analyze_url(raw_url: str) -> AnalysisResult:
    findings: list[Finding] = []
    normalized = normalize_url(raw_url)

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    if not host:
        findings.append(Finding(100, "Invalid URL or missing hostname"))
        return AnalysisResult(
            original=raw_url,
            normalized=normalized,
            host=host,
            score=100,
            label=RiskLabel.HIGH,
            findings=findings,
        )

    # 1) Scheme / HTTPS
    if parsed.scheme != "https":
        findings.append(Finding(15, "Not using HTTPS"))

    # 2) Known shortener
    if host in URL_SHORTENERS:
        findings.append(Finding(25, "URL shortener domain (hides real destination)"))

    # 3) IP address in host
    if is_ip_address(host):
        findings.append(Finding(25, "Uses an IP address instead of a domain"))

    # 4) Many subdomains
    subdomain_count = count_subdomains(host)
    if subdomain_count >= 3:
        findings.append(Finding(20, f"Many subdomains ({subdomain_count})"))

    # 5) Punycode
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding(20, "Punycode domain (possible lookalike characters)"))

    # 6) '@' confusion trick
    if "@" in normalized:
        findings.append(Finding(25, "Contains '@' (can obscure real hostname)"))

    # 7) Suspicious TLD
    tld = get_tld(host)
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(10, f"Suspicious TLD: .{tld}"))

    # 8) Excessive length
    if len(normalized) > 100:
        findings.append(Finding(10, "Very long URL"))

    # 9) Many hyphens in hostname
    if host.count("-") >= 3:
        findings.append(Finding(10, "Many hyphens in hostname"))

    # 10) Brand impersonation heuristic (improved)
    lower_all = f"{host}{path}{query}".lower()
    brand_hits = sorted(brand for brand in BRAND_KEYWORDS if brand in lower_all)
    if brand_hits:
        reg_domain = approx_registered_domain(host)
        # If a brand appears anywhere in the URL but the "registered domain" does NOT include it,
        # it's often a brand-in-subdomain / prefix trick.
        if not any(brand in reg_domain for brand in brand_hits):
            findings.append(
                Finding(
                    25,
                    f"Brand impersonation likely: {', '.join(brand_hits)} "
                    f"but registered domain is '{reg_domain}'",
                )
            )

    # 11) Redirect parameters
    qs = parse_qs(query)
    if any(key in qs for key in REDIRECT_QUERY_KEYS):
        findings.append(Finding(15, "Contains redirect-style query parameter"))

    score = min(100, sum(item.points for item in findings))
    label = classify(score)

    return AnalysisResult(
        original=raw_url,
        normalized=normalized,
        host=host,
        score=score,
        label=label,
        findings=findings,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phish_checker",
        description="Heuristic phishing-risk analyzer for URLs.",
    )
    parser.add_argument("urls", nargs="+", help="One or more URLs to analyze.")
    return parser.parse_args()


def print_result(result: AnalysisResult) -> None:
    print("=" * 64)
    print(f"Input:      {result.original}")
    print(f"Normalized: {result.normalized}")
    print(f"Host:       {result.host or '(none)'}")
    print(f"Risk:       {result.label.value} (score={result.score}/100)")
    if result.findings:
        print("Findings:")
        for item in result.findings:
            print(f"  - (+{item.points}) {item.reason}")
    else:
        print("Findings:   none (basic checks passed)")


def main() -> int:
    args = parse_args()
    for raw in args.urls:
        print_result(analyze_url(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
