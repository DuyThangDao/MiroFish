"""
MITRE ATT&CK TTP Reference Library cho Multi-Expert Panel (Direction B)

Top-20 TTP phổ biến theo DBIR 2024, phân nhóm theo domain và persona.
Dùng để inject context phù hợp vào prompt của từng expert agent.
"""

from typing import Dict, List, Optional


# ─── TTP data ─────────────────────────────────────────────────────────────────
# Mỗi TTP entry có:
#   name, tactic, description, detection_tools, common_indicators

TTP_CATALOG: Dict[str, Dict] = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Attackers scan ports, services, and vulnerabilities before launching an attack.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["High port scan rate from single IP", "SYN flood pattern"],
        "offensive_notes": "Identify open ports, service versions, and OS fingerprints.",
        "defensive_notes": "Detect via anomaly detection on traffic patterns.",
        "auditor_notes": "Broad attack surface = more exposed services = easier successful scans.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploit vulnerabilities in public-facing web apps, APIs, and VPN gateways.",
        "detection_tools": ["waf", "siem"],
        "common_indicators": ["Anomalous HTTP payload", "SQL injection pattern", "Path traversal"],
        "offensive_notes": "Find unpatched CVEs on service versions. SQL injection and RCE are most common.",
        "defensive_notes": "WAF + patch management + input validation are the 3 primary layers of defense.",
        "auditor_notes": "Check API authentication: is there JWT expiry? Rate limiting?",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Use VPN, RDP, SSH, or Citrix to access the network with valid or stolen credentials.",
        "detection_tools": ["siem", "mfa"],
        "common_indicators": ["Login from unusual geo", "Off-hours access", "Failed MFA"],
        "offensive_notes": "Once credentials are obtained, this is the lowest-noise path into the network.",
        "defensive_notes": "Enforce MFA on all remote access. Geo-blocking where possible.",
        "auditor_notes": "Audit the VPN user list — are there stale accounts no longer in use?",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Use RDP for lateral movement between hosts in the internal network.",
        "detection_tools": ["ndr", "siem", "edr"],
        "common_indicators": ["RDP from non-admin host", "RDP to multiple hosts in short time"],
        "offensive_notes": "RDP with admin credentials = full access. No privilege escalation needed.",
        "defensive_notes": "Restrict RDP to jump server only. Disable if not needed.",
        "auditor_notes": "Check network segmentation — can RDP reach from DMZ into the internal zone?",
    },
    "T1021.002": {
        "name": "SMB / Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Use SMB shares (C$, ADMIN$) to copy files and execute on remote hosts.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["Admin share access from non-admin host", "PsExec pattern"],
        "offensive_notes": "PsExec + SMB = remote code execution on any host in the subnet.",
        "defensive_notes": "Disable admin shares if not needed. Monitor SMB traffic.",
        "auditor_notes": "SMB v1 should be fully disabled. Check firewall rules within the internal network.",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Emails with malicious attachments targeting specific users.",
        "detection_tools": ["siem", "edr"],
        "common_indicators": ["Macro-enabled Office file", "PDF with embedded script", "Zip with EXE"],
        "offensive_notes": "Target HR, finance, C-level employees. Higher click rate than generic spam.",
        "defensive_notes": "Email gateway + attachment sandboxing + user training.",
        "auditor_notes": "Is there an incident reporting process when users receive suspicious emails?",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
        "description": "Use stolen valid credentials to maintain access and evade detection.",
        "detection_tools": ["siem", "mfa"],
        "common_indicators": ["Login time anomaly", "Access from new device", "Credential spray"],
        "offensive_notes": "Valid account = no alerts from AV/EDR. Best way to blend into normal activity.",
        "defensive_notes": "UEBA (User Entity Behavior Analytics) in SIEM. MFA reduces the blast radius.",
        "auditor_notes": "Password policy: complexity requirements, rotation schedule, no reuse across systems.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Use PowerShell to execute payloads, download stagers, or live off the land.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["Encoded command", "Download cradle", "Invoke-Expression"],
        "offensive_notes": "PowerShell is present on every Windows machine. Script block logging is rarely enabled.",
        "defensive_notes": "PowerShell Constrained Language Mode + script block logging + AMSI.",
        "auditor_notes": "Check PowerShell execution policy — is it set to Unrestricted anywhere?",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Use cmd.exe to execute commands. Less sophisticated than PowerShell.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["cmd spawned from Office", "Unusual parent-child process chain"],
        "offensive_notes": "Used for basic recon and execution when PowerShell is blocked.",
        "defensive_notes": "Process creation logging + parent-child process monitoring.",
        "auditor_notes": "Are there any scripts using cmd.exe that could be vulnerable to injection?",
    },
    "T1053.005": {
        "name": "Scheduled Task / Job",
        "tactic": "Persistence",
        "description": "Create scheduled tasks to maintain persistence across reboots.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["New task created by non-admin", "Task running from temp dir"],
        "offensive_notes": "Simplest persistence mechanism on Windows. Task XML is rarely scanned by AV.",
        "defensive_notes": "Audit scheduled tasks regularly. Alert on new task creation.",
        "auditor_notes": "Who has permission to create scheduled tasks? Are there too many users with local admin?",
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "tactic": "Credential Access",
        "description": "Dump LSASS memory to extract credential hashes and NTLM tokens.",
        "detection_tools": ["edr"],
        "common_indicators": ["Access to lsass.exe memory", "Mimikatz signature", "ProcDump on lsass"],
        "offensive_notes": "Dumping LSASS yields credentials of every user who has logged into that host.",
        "defensive_notes": "Credential Guard + EDR with LSASS protection. No local admin for regular users.",
        "auditor_notes": "How many accounts have Domain Admin? Is the principle of least privilege enforced?",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Encode or encrypt payloads to bypass AV signature detection.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["High entropy binary", "Base64 encoded script", "Packed executable"],
        "offensive_notes": "Encode payload + certutil decode = bypass many AVs. Combine with T1059.001.",
        "defensive_notes": "Behavior-based EDR instead of signature-based AV. Sandbox files before execution.",
        "auditor_notes": "Does the scan policy cover obfuscated scripts, or only executables?",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Exfiltrate data over an established C2 channel (HTTP/S, DNS).",
        "detection_tools": ["ndr", "siem", "dlp"],
        "common_indicators": ["Large outbound data over HTTPS", "DNS query spike", "Unusual destination"],
        "offensive_notes": "HTTPS C2 blends into normal traffic. DNS exfiltration via recursive queries.",
        "defensive_notes": "DLP + egress filtering + anomaly detection on outbound traffic.",
        "auditor_notes": "Is there a data classification policy? Is PII encrypted at rest?",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Use FTP, SCP, cloud storage, or email to exfiltrate data.",
        "detection_tools": ["ndr", "dlp"],
        "common_indicators": ["FTP/SFTP to external IP", "Upload to Dropbox/Drive", "Large email attachment"],
        "offensive_notes": "Uploading to legitimate cloud storage (Drive, OneDrive) bypasses many proxies.",
        "defensive_notes": "Whitelist cloud providers. DLP monitoring on uploads. Block outbound FTP.",
        "auditor_notes": "Check egress rules — is outbound FTP to the internet blocked?",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Collect OS, hardware, and domain membership information after gaining access to a host.",
        "detection_tools": ["edr"],
        "common_indicators": ["Rapid systeminfo/whoami/net commands", "WMI query spike"],
        "offensive_notes": "First step after initial access. Determine position in the network and current privileges.",
        "defensive_notes": "Monitor for excessive enumeration commands. Deploy honeypot accounts.",
        "auditor_notes": "Is system information exposed through unauthenticated API endpoints?",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Enumerate other hosts in the internal network to plan lateral movement.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["ICMP sweep", "NetBIOS enumeration", "ARP scan pattern"],
        "offensive_notes": "After gaining a foothold, discover what else exists in the network. net view / arp -a / nmap.",
        "defensive_notes": "Micro-segmentation prevents hosts from freely communicating. NDR detects sweeps.",
        "auditor_notes": "Does the current network diagram reflect reality? Is there shadow IT?",
    },
    "T1071.001": {
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "description": "Use HTTP/S to communicate with a C2 server — hidden within normal traffic.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["Beaconing interval", "Domain fronting", "JA3 fingerprint anomaly"],
        "offensive_notes": "HTTPS C2 over port 443 blends into SSL traffic. Domain fronting bypasses proxies.",
        "defensive_notes": "SSL inspection + domain reputation check + JA3 fingerprinting.",
        "auditor_notes": "Is SSL inspection enabled in the proxy? Is certificate pinning in use?",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Collect files, databases, and credentials from the local filesystem after compromise.",
        "detection_tools": ["edr", "dlp"],
        "common_indicators": ["Mass file read", "DB dump command", "Credential file access"],
        "offensive_notes": "Find config files containing DB passwords, SSH keys, and API keys before exfiltrating.",
        "defensive_notes": "File integrity monitoring on sensitive directories. DLP agent on endpoints.",
        "auditor_notes": "Secret management: are credentials hardcoded in config files?",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Encrypt files to demand ransom or cause service disruption.",
        "detection_tools": ["edr"],
        "common_indicators": ["Mass file rename/extension change", "Shadow copy deletion", "High I/O spike"],
        "offensive_notes": "Delete shadow copies first, then encrypt. Domain Admin is required to encrypt the entire network.",
        "defensive_notes": "Immutable offline backups. EDR behavioral detection on mass rename activity.",
        "auditor_notes": "Are backups offline / air-gapped? What is the Recovery Time Objective (RTO)?",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "User executes a malicious file themselves (attachment, download) — initial execution vector.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["Office macro execution", "Script file from browser download"],
        "offensive_notes": "Phishing attachment → user clicks → macro runs PowerShell stager.",
        "defensive_notes": "Disable macros from internet-sourced files. Mark of the Web (MOTW) protection.",
        "auditor_notes": "Is user awareness training conducted regularly? Are phishing simulations run?",
    },
}

# ─── Domain → TTP mapping ──────────────────────────────────────────────────────

TTP_BY_DOMAIN: Dict[str, List[str]] = {
    "network_security":  ["T1595", "T1190", "T1133", "T1021.001", "T1021.002",
                          "T1018", "T1071.001"],
    "appsec":            ["T1190", "T1059.001", "T1059.003", "T1566.001",
                          "T1204.002", "T1027"],
    "endpoint_security": ["T1059.001", "T1059.003", "T1053.005", "T1003.001",
                          "T1027", "T1005", "T1486"],
    "threat_intel":      ["T1566.001", "T1078", "T1041", "T1048", "T1071.001"],
    "risk":              [],  # Risk/compliance focus on impact, not technique
}

# ─── Attacker profile → TTP affinity ──────────────────────────────────────────
# Mỗi attacker profile ưu tiên tìm loại TTP nào

TTP_BY_ATTACKER: Dict[str, List[str]] = {
    "opportunistic":   ["T1595", "T1190", "T1133", "T1204.002"],
    "apt":             ["T1078", "T1021.001", "T1003.001", "T1041", "T1071.001",
                        "T1027", "T1082"],
    "insider_threat":  ["T1078", "T1005", "T1041", "T1048", "T1082"],
    "ransomware":      ["T1003.001", "T1021.001", "T1021.002", "T1486", "T1018"],
    "supply_chain":    ["T1195", "T1078", "T1027", "T1071.001", "T1041"],
}


class MitreReference:
    """TTP reference library. Inject TTP context vào expert agent prompt."""

    def get_ttp_context_for_agent(self, domain: str, persona: str) -> str:
        """
        Trả về mô tả TTP phù hợp với domain × persona.
          offensive  → nhấn mạnh cách exploit
          defensive  → nhấn mạnh cách detect
          auditor/architect/admin/ciso/compliance → nhấn mạnh gap và compliance
        """
        ttp_ids = TTP_BY_DOMAIN.get(domain, [])
        if not ttp_ids:
            return "Focus on business impact and compliance implications of any identified vulnerabilities."

        persona_key = self._persona_key(persona)
        lines = [f"Relevant MITRE ATT&CK techniques for your role ({domain} / {persona}):"]

        for tid in ttp_ids:
            ttp = TTP_CATALOG.get(tid)
            if not ttp:
                continue
            lines.append(f"\n[{tid}] {ttp['name']} ({ttp['tactic']})")
            lines.append(f"  Overview: {ttp['description']}")
            if persona_key == "offensive":
                lines.append(f"  Attack angle: {ttp['offensive_notes']}")
            elif persona_key == "defensive":
                lines.append(f"  Defense focus: {ttp['defensive_notes']}")
            else:
                lines.append(f"  Audit/Design lens: {ttp['auditor_notes']}")

        return "\n".join(lines)

    def get_ttp_context_for_attacker(self, attacker_profile: str) -> str:
        """Trả về TTP context cho attacker profile agent."""
        ttp_ids = TTP_BY_ATTACKER.get(attacker_profile, [])
        if not ttp_ids:
            return ""

        lines = [f"Common attack techniques used by '{attacker_profile}' type attackers:"]
        for tid in ttp_ids:
            ttp = TTP_CATALOG.get(tid)
            if not ttp:
                continue
            lines.append(f"  [{tid}] {ttp['name']}: {ttp['offensive_notes']}")
        return "\n".join(lines)

    def get_relevant_ttps(self, service_or_asset_desc: str, domain: str) -> List[str]:
        """
        TTP nào có thể áp dụng cho asset/service này + domain.
        Simple keyword match — không cần LLM.
        """
        desc_lower = service_or_asset_desc.lower()
        domain_ttps = TTP_BY_DOMAIN.get(domain, [])
        relevant = []

        keyword_map = {
            "T1190":    ["apache", "nginx", "web", "http", "api", "wordpress", "drupal"],
            "T1595":    ["port", "scan", "exposed", "public"],
            "T1133":    ["rdp", "vpn", "ssh", "citrix", "remote"],
            "T1021.001":["rdp", "remote desktop", "3389"],
            "T1021.002":["smb", "samba", "445", "share", "cifs"],
            "T1059.001":["powershell", "windows", "ps1"],
            "T1059.003":["cmd", "batch", "windows"],
            "T1053.005":["task scheduler", "windows", "cronjob", "cron"],
            "T1003.001":["lsass", "credentials", "active directory", "windows server"],
            "T1566.001":["email", "smtp", "phishing", "outlook"],
            "T1486":    ["backup", "storage", "file server", "smb", "nas"],
            "T1041":    ["firewall", "egress", "outbound"],
            "T1048":    ["ftp", "cloud", "s3", "dropbox", "upload"],
        }

        for tid in domain_ttps:
            keywords = keyword_map.get(tid, [])
            if any(kw in desc_lower for kw in keywords):
                relevant.append(tid)

        # Nếu không match gì thì trả về top-3 của domain
        return relevant if relevant else domain_ttps[:3]

    def get_detection_requirements(self, technique_id: str) -> List[str]:
        """Cần tool gì để detect technique này."""
        ttp = TTP_CATALOG.get(technique_id)
        return ttp["detection_tools"] if ttp else []

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Trả về full TTP entry."""
        return TTP_CATALOG.get(technique_id)

    def list_all_technique_ids(self) -> List[str]:
        return list(TTP_CATALOG.keys())

    # ─── Private ──────────────────────────────────────────────────────────────

    def _persona_key(self, persona: str) -> str:
        """Normalize persona vào offensive / defensive / auditor."""
        offensive_personas = {"offensive", "apt_analyst", "red"}
        defensive_personas = {"defensive", "ir_analyst", "blue"}
        if persona in offensive_personas:
            return "offensive"
        if persona in defensive_personas:
            return "defensive"
        return "auditor"  # architect, auditor, admin, ciso, compliance, ...
