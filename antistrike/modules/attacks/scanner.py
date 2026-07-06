"""Built-in HTTP vulnerability scanner — no external tools required."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

from antistrike.payloads.library import get_payloads


class BuiltinScanner:
    """Built-in web vulnerability scanner with payload injection."""

    TIMEOUT = 15
    USER_AGENT = "Antistrike/7.0 (Authorized Security Assessment)"

    def __init__(self, target: str) -> None:
        self.target = target.rstrip("/")
        self.findings: list[dict[str, Any]] = []
        self.client = httpx.Client(
            timeout=self.TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": self.USER_AGENT},
            verify=False,
        )

    def scan(self, attack_types: list[str] | None = None) -> dict[str, Any]:
        types = attack_types or ["sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect", "cors"]
        for attack_type in types:
            method = getattr(self, f"_test_{attack_type}", None)
            if method:
                method()
        return {
            "target": self.target,
            "findings": self.findings,
            "total": len(self.findings),
            "scanned_types": types,
        }

    def _add_finding(
        self,
        title: str,
        severity: str,
        attack_type: str,
        location: str,
        evidence: str = "",
        payload: str = "",
    ) -> None:
        self.findings.append({
            "title": title,
            "severity": severity,
            "attack_type": attack_type,
            "location": location,
            "evidence": evidence[:500],
            "payload": payload,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    def _get_params(self) -> list[tuple[str, str, str]]:
        """Extract testable URL parameters."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        results = []
        if params:
            for key in params:
                results.append((base, key, params[key][0]))
        else:
            common = ["id", "q", "search", "page", "url", "redirect", "file", "path", "name", "email"]
            for key in common:
                results.append((base, key, "test"))
        return results

    def _inject_param(self, base_url: str, param: str, value: str) -> httpx.Response | None:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        try:
            return self.client.get(url)
        except Exception:
            return None

    def _test_sqli(self) -> None:
        for base, param, _ in self._get_params():
            for p in get_payloads("sqli")[:5]:
                resp = self._inject_param(base, param, p["payload"])
                if resp and self._detect_sqli(resp, p):
                    self._add_finding(
                        "SQL Injection",
                        "high",
                        "sqli",
                        f"{base}?{param}=",
                        resp.text[:200],
                        p["payload"],
                    )
                    return

    def _detect_sqli(self, resp: httpx.Response, payload: dict) -> bool:
        errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
            "unclosed quotation", "quoted string not properly terminated",
            "syntax error", "odbc", "jdbc", "sql server",
        ]
        text = resp.text.lower()
        return any(e in text for e in errors)

    def _test_xss(self) -> None:
        marker = "antistrike7xss"
        for base, param, _ in self._get_params():
            for p in get_payloads("xss")[:4]:
                test_payload = p["payload"].replace("alert(1)", f"alert('{marker}')")
                resp = self._inject_param(base, param, test_payload)
                if resp and marker in resp.text:
                    self._add_finding(
                        "Cross-Site Scripting (XSS)",
                        "high",
                        "xss",
                        f"{base}?{param}=",
                        "Payload reflected unescaped",
                        test_payload,
                    )
                    return

    def _test_ssrf(self) -> None:
        for base, param, _ in self._get_params():
            if param in ("url", "redirect", "next", "return", "callback", "fetch", "proxy"):
                for p in get_payloads("ssrf")[:3]:
                    resp = self._inject_param(base, param, p["payload"])
                    if resp and resp.status_code in (200, 301, 302):
                        indicators = ["root:", "ami-id", "computeMetadata", "localhost"]
                        if any(i in resp.text for i in indicators):
                            self._add_finding(
                                "Server-Side Request Forgery (SSRF)",
                                "critical",
                                "ssrf",
                                f"{base}?{param}=",
                                resp.text[:200],
                                p["payload"],
                            )
                            return

    def _test_lfi(self) -> None:
        for base, param, _ in self._get_params():
            if param in ("file", "path", "page", "include", "template", "doc"):
                for p in get_payloads("lfi")[:4]:
                    resp = self._inject_param(base, param, p["payload"])
                    if resp and ("root:" in resp.text or "[extensions]" in resp.text):
                        self._add_finding(
                            "Local File Inclusion (LFI)",
                            "high",
                            "lfi",
                            f"{base}?{param}=",
                            resp.text[:200],
                            p["payload"],
                        )
                        return

    def _test_ssti(self) -> None:
        for base, param, _ in self._get_params():
            for p in get_payloads("ssti")[:3]:
                resp = self._inject_param(base, param, p["payload"])
                if resp and "49" in resp.text and "7*7" in p["payload"]:
                    self._add_finding(
                        "Server-Side Template Injection (SSTI)",
                        "critical",
                        "ssti",
                        f"{base}?{param}=",
                        "Template expression evaluated",
                        p["payload"],
                    )
                    return

    def _test_open_redirect(self) -> None:
        for base, param, _ in self._get_params():
            if param in ("url", "redirect", "next", "return", "goto", "dest"):
                for p in get_payloads("open_redirect")[:3]:
                    resp = self._inject_param(base, param, p["payload"])
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if "evil.com" in location:
                            self._add_finding(
                                "Open Redirect",
                                "medium",
                                "open_redirect",
                                f"{base}?{param}=",
                                f"Redirects to: {location}",
                                p["payload"],
                            )
                            return

    def _test_cors(self) -> None:
        try:
            resp = self.client.get(
                self.target,
                headers={"Origin": "https://evil-antistrike-test.com"},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acao == "https://evil-antistrike-test.com" or acao == "*":
                severity = "high" if acac.lower() == "true" else "medium"
                self._add_finding(
                    "CORS Misconfiguration",
                    severity,
                    "cors",
                    self.target,
                    f"ACAO: {acao}, ACAC: {acac}",
                )
        except Exception:
            pass

    def _test_cmdi(self) -> None:
        for base, param, _ in self._get_params():
            for p in get_payloads("cmdi")[:3]:
                resp = self._inject_param(base, param, p["payload"])
                if resp and re.search(r"uid=\d+.*gid=\d+", resp.text):
                    self._add_finding(
                        "Command Injection",
                        "critical",
                        "cmdi",
                        f"{base}?{param}=",
                        resp.text[:200],
                        p["payload"],
                    )
                    return

    def _test_nosql(self) -> None:
        for base, param, _ in self._get_params():
            for p in get_payloads("nosql")[:2]:
                resp = self._inject_param(base, param, p["payload"])
                if resp and resp.status_code == 200 and len(resp.text) > 100:
                    self._add_finding(
                        "Potential NoSQL Injection",
                        "high",
                        "nosql",
                        f"{base}?{param}=",
                        "NoSQL operator accepted",
                        p["payload"],
                    )

    def close(self) -> None:
        self.client.close()