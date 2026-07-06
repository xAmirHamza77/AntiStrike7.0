"""Tool registry — maps modules to external CLI tools and built-in scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from antistrike.core.engine import engine


@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    binary: str | None = None
    builtin: bool = False
    attack_types: list[str] = field(default_factory=list)
    depth_levels: list[str] = field(default_factory=lambda: ["quick", "standard", "deep", "exhaustive"])

    def is_available(self) -> bool:
        if self.builtin:
            return True
        return self.binary is not None and engine.tool_available(self.binary)


# Comprehensive tool registry — expanded beyond both reference projects
TOOL_REGISTRY: list[ToolSpec] = [
    # Reconnaissance
    ToolSpec("subdomain_enum", "recon", "Subdomain enumeration", "subfinder", attack_types=["recon"]),
    ToolSpec("dns_brute", "recon", "DNS brute force", "dnsx", attack_types=["recon"]),
    ToolSpec("amass_recon", "recon", "Deep subdomain mapping", "amass", attack_types=["recon"]),
    ToolSpec("whois_lookup", "recon", "WHOIS information", "whois", attack_types=["recon"]),
    ToolSpec("osint_harvest", "recon", "Email and metadata harvest", "theHarvester", attack_types=["recon", "osint"]),
    ToolSpec("tech_detect", "recon", "Technology fingerprinting", "whatweb", attack_types=["recon"]),
    ToolSpec("asn_map", "recon", "ASN and network mapping", "asnmap", attack_types=["recon"]),

    # Network scanning
    ToolSpec("port_scan", "network", "Comprehensive port scan", "nmap", attack_types=["network", "recon"]),
    ToolSpec("fast_port_scan", "network", "High-speed port discovery", "rustscan", attack_types=["network"]),
    ToolSpec("mass_scan", "network", "Internet-scale port scan", "masscan", attack_types=["network"]),
    ToolSpec("service_enum", "network", "Service enumeration", "nmap", attack_types=["network"]),
    ToolSpec("smb_enum", "network", "SMB share enumeration", "enum4linux-ng", attack_types=["network", "credential"]),
    ToolSpec("snmp_enum", "network", "SNMP community strings", "onesixtyone", attack_types=["network"]),
    ToolSpec("ldap_enum", "network", "LDAP directory enumeration", "ldapsearch", attack_types=["network"]),
    ToolSpec("netbios_scan", "network", "NetBIOS name resolution", "nbtscan", attack_types=["network"]),

    # Web discovery
    ToolSpec("dir_brute", "web", "Directory brute force", "ffuf", attack_types=["web", "recon"]),
    ToolSpec("dir_gobuster", "web", "Path enumeration", "gobuster", attack_types=["web", "recon"]),
    ToolSpec("web_crawl", "web", "Deep web crawling", "katana", attack_types=["web", "recon"]),
    ToolSpec("param_discover", "web", "Hidden parameter discovery", "arjun", attack_types=["web", "api"]),
    ToolSpec("js_analyze", "web", "JavaScript endpoint extraction", "linkfinder", attack_types=["web"]),
    ToolSpec("wayback_enum", "web", "Historical URL enumeration", "gau", attack_types=["web", "recon"]),

    # Vulnerability scanning
    ToolSpec("vuln_scan", "web", "Template-based vuln scan", "nuclei", attack_types=["web", "api", "network", "cloud"]),
    ToolSpec("nikto_scan", "web", "Web server vulnerability scan", "nikto", attack_types=["web"]),
    ToolSpec("wapiti_scan", "web", "Web application scanner", "wapiti", attack_types=["web"]),
    ToolSpec("zap_scan", "web", "OWASP ZAP automated scan", "zap-cli", attack_types=["web"]),

    # Injection attacks
    ToolSpec("sqli_scan", "injection", "SQL injection detection", "sqlmap", attack_types=["sqli", "injection"]),
    ToolSpec("sqli_builtin", "injection", "Built-in SQLi fuzzer", builtin=True, attack_types=["sqli", "injection"]),
    ToolSpec("xss_scan", "injection", "XSS vulnerability scan", "dalfox", attack_types=["xss", "injection"]),
    ToolSpec("xss_builtin", "injection", "Built-in XSS fuzzer", builtin=True, attack_types=["xss", "injection"]),
    ToolSpec("ssti_scan", "injection", "Server-side template injection", builtin=True, attack_types=["ssti", "injection"]),
    ToolSpec("cmdi_scan", "injection", "Command injection testing", builtin=True, attack_types=["rce", "injection"]),
    ToolSpec("nosql_scan", "injection", "NoSQL injection testing", builtin=True, attack_types=["nosql", "injection"]),
    ToolSpec("ldap_inject", "injection", "LDAP injection testing", builtin=True, attack_types=["ldap", "injection"]),
    ToolSpec("xpath_inject", "injection", "XPath injection testing", builtin=True, attack_types=["xpath", "injection"]),
    ToolSpec("crlf_scan", "injection", "CRLF injection testing", builtin=True, attack_types=["crlf", "injection"]),
    ToolSpec("header_inject", "injection", "HTTP header injection", builtin=True, attack_types=["header_injection"]),
    ToolSpec("llm_inject", "injection", "LLM prompt injection testing", builtin=True, attack_types=["llm_injection", "ai"]),

    # Server-side attacks
    ToolSpec("ssrf_scan", "server", "Server-side request forgery", builtin=True, attack_types=["ssrf"]),
    ToolSpec("xxe_scan", "server", "XML external entity injection", builtin=True, attack_types=["xxe"]),
    ToolSpec("lfi_scan", "server", "Local file inclusion", builtin=True, attack_types=["lfi", "path_traversal"]),
    ToolSpec("rfi_scan", "server", "Remote file inclusion", builtin=True, attack_types=["rfi", "path_traversal"]),
    ToolSpec("deserial_scan", "server", "Insecure deserialization", builtin=True, attack_types=["deserialization"]),
    ToolSpec("smuggle_scan", "server", "HTTP request smuggling", builtin=True, attack_types=["http_smuggling"]),
    ToolSpec("host_header", "server", "Host header injection", builtin=True, attack_types=["host_header"]),
    ToolSpec("cache_poison", "server", "Web cache poisoning", builtin=True, attack_types=["cache_poisoning"]),
    ToolSpec("proto_pollution", "server", "Prototype pollution", builtin=True, attack_types=["prototype_pollution"]),

    # Access control
    ToolSpec("idor_scan", "access", "Insecure direct object reference", builtin=True, attack_types=["idor"]),
    ToolSpec("auth_bypass", "access", "Authentication bypass testing", builtin=True, attack_types=["auth_bypass"]),
    ToolSpec("priv_escalation", "access", "Privilege escalation testing", builtin=True, attack_types=["privilege_escalation"]),
    ToolSpec("bfla_scan", "access", "Broken function-level authorization", builtin=True, attack_types=["bfla"]),
    ToolSpec("mass_assign", "access", "Mass assignment testing", builtin=True, attack_types=["mass_assignment"]),
    ToolSpec("race_scan", "access", "Race condition testing", builtin=True, attack_types=["race_condition"]),
    ToolSpec("biz_logic", "access", "Business logic flaw testing", builtin=True, attack_types=["business_logic"]),

    # Client-side
    ToolSpec("csrf_scan", "client", "Cross-site request forgery", builtin=True, attack_types=["csrf"]),
    ToolSpec("open_redirect", "client", "Open redirect testing", builtin=True, attack_types=["open_redirect"]),
    ToolSpec("cors_scan", "client", "CORS misconfiguration", builtin=True, attack_types=["cors"]),
    ToolSpec("clickjack", "client", "Clickjacking detection", builtin=True, attack_types=["clickjacking"]),
    ToolSpec("dom_xss", "client", "DOM-based XSS testing", builtin=True, attack_types=["xss", "dom"]),

    # API security
    ToolSpec("api_fuzz", "api", "REST API fuzzing", "ffuf", attack_types=["api"]),
    ToolSpec("graphql_scan", "api", "GraphQL security testing", builtin=True, attack_types=["graphql", "api"]),
    ToolSpec("grpc_scan", "api", "gRPC endpoint testing", builtin=True, attack_types=["grpc", "api"]),
    ToolSpec("jwt_analyze", "api", "JWT token analysis", "jwt_tool", attack_types=["jwt", "auth"]),
    ToolSpec("oauth_scan", "api", "OAuth flow testing", builtin=True, attack_types=["oauth", "auth"]),
    ToolSpec("websocket_scan", "api", "WebSocket security testing", builtin=True, attack_types=["websocket"]),
    ToolSpec("soap_scan", "api", "SOAP/XML API testing", builtin=True, attack_types=["soap", "api"]),

    # Authentication
    ToolSpec("brute_force", "auth", "Credential brute force", "hydra", attack_types=["brute_force", "credential"]),
    ToolSpec("hash_crack", "auth", "Hash cracking", "hashcat", attack_types=["credential"]),
    ToolSpec("password_spray", "auth", "Password spraying", builtin=True, attack_types=["brute_force"]),
    ToolSpec("session_test", "auth", "Session management testing", builtin=True, attack_types=["session"]),
    ToolSpec("mfa_bypass", "auth", "MFA bypass testing", builtin=True, attack_types=["mfa_bypass"]),
    ToolSpec("kerberos_attack", "auth", "Kerberos attack suite", "impacket", attack_types=["kerberos", "ad"]),
    ToolSpec("ntlm_relay", "auth", "NTLM relay attacks", "ntlmrelayx", attack_types=["ntlm", "ad"]),

    # Cloud security
    ToolSpec("aws_audit", "cloud", "AWS security audit", "prowler", attack_types=["cloud", "aws"]),
    ToolSpec("azure_audit", "cloud", "Azure security assessment", "scout-suite", attack_types=["cloud", "azure"]),
    ToolSpec("gcp_audit", "cloud", "GCP security review", "scout-suite", attack_types=["cloud", "gcp"]),
    ToolSpec("k8s_hunt", "cloud", "Kubernetes penetration testing", "kube-hunter", attack_types=["cloud", "kubernetes"]),
    ToolSpec("k8s_bench", "cloud", "Kubernetes CIS benchmark", "kube-bench", attack_types=["cloud", "kubernetes"]),
    ToolSpec("container_scan", "cloud", "Container vulnerability scan", "trivy", attack_types=["cloud", "container"]),
    ToolSpec("iac_scan", "cloud", "Infrastructure-as-code scan", "checkov", attack_types=["cloud", "iac"]),
    ToolSpec("terraform_scan", "cloud", "Terraform security scan", "terrascan", attack_types=["cloud", "iac"]),
    ToolSpec("serverless_scan", "cloud", "Serverless function testing", builtin=True, attack_types=["cloud", "serverless"]),
    ToolSpec("s3_enum", "cloud", "S3 bucket enumeration", builtin=True, attack_types=["cloud", "aws"]),

    # Mobile
    ToolSpec("apk_analyze", "mobile", "Android APK analysis", "apktool", attack_types=["mobile", "android"]),
    ToolSpec("ios_analyze", "mobile", "iOS IPA analysis", builtin=True, attack_types=["mobile", "ios"]),
    ToolSpec("mobile_api", "mobile", "Mobile API backend testing", builtin=True, attack_types=["mobile", "api"]),

    # Binary / exploitation
    ToolSpec("binary_analyze", "binary", "Binary reverse engineering", "radare2", attack_types=["binary"]),
    ToolSpec("ghidra_analyze", "binary", "Ghidra decompilation", "ghidra", attack_types=["binary"]),
    ToolSpec("rop_chain", "binary", "ROP gadget finder", "ropper", attack_types=["binary", "exploit"]),
    ToolSpec("symbolic_exec", "binary", "Symbolic execution", "angr", attack_types=["binary"]),
    ToolSpec("firmware_scan", "binary", "Firmware analysis", "binwalk", attack_types=["binary", "iot"]),

    # Wireless
    ToolSpec("wifi_scan", "wireless", "WiFi network scanning", "airodump-ng", attack_types=["wireless"]),
    ToolSpec("bluetooth_scan", "wireless", "Bluetooth enumeration", builtin=True, attack_types=["wireless", "bluetooth"]),

    # Credential / secrets
    ToolSpec("secret_scan", "secrets", "Secret and credential scanning", "gitleaks", attack_types=["secrets"]),
    ToolSpec("truffle_scan", "secrets", "Entropy-based secret detection", "trufflehog", attack_types=["secrets"]),
    ToolSpec("responder", "secrets", "LLMNR/NBT-NS poisoning", "responder", attack_types=["credential", "network"]),

    # Code analysis
    ToolSpec("sast_scan", "code", "Static application security testing", "semgrep", attack_types=["code", "sast"]),
    ToolSpec("bandit_scan", "code", "Python security linter", "bandit", attack_types=["code", "sast"]),

    # Reporting
    ToolSpec("report_gen", "report", "Generate assessment report", builtin=True, attack_types=["report"]),
    ToolSpec("sarif_export", "report", "SARIF format export", builtin=True, attack_types=["report"]),
]

ATTACK_TYPES = sorted({t for spec in TOOL_REGISTRY for t in spec.attack_types})


def get_tool(name: str) -> ToolSpec | None:
    for spec in TOOL_REGISTRY:
        if spec.name == name:
            return spec
    return None


def list_tools(category: str | None = None, attack_type: str | None = None) -> list[dict[str, Any]]:
    results = []
    for spec in TOOL_REGISTRY:
        if category and spec.category != category:
            continue
        if attack_type and attack_type not in spec.attack_types:
            continue
        results.append({
            "name": spec.name,
            "category": spec.category,
            "description": spec.description,
            "available": spec.is_available(),
            "builtin": spec.builtin,
            "attack_types": spec.attack_types,
            "depth_levels": spec.depth_levels,
        })
    return results


def list_categories() -> list[str]:
    return sorted({spec.category for spec in TOOL_REGISTRY})