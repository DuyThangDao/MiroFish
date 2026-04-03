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
        "description": "Kẻ tấn công scan ports, services, vulnerabilities trước khi tấn công.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["High port scan rate from single IP", "SYN flood pattern"],
        "offensive_notes": "Xác định open port, service version, và OS fingerprint.",
        "defensive_notes": "Phát hiện qua anomaly detection trên traffic pattern.",
        "auditor_notes": "Attack surface rộng = nhiều service exposed = scan dễ thành công hơn.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Khai thác lỗ hổng trong web app, API, VPN gateway đối ngoại.",
        "detection_tools": ["waf", "siem"],
        "common_indicators": ["Anomalous HTTP payload", "SQL injection pattern", "Path traversal"],
        "offensive_notes": "Tìm CVE chưa patch trên service version. SQL injection, RCE là phổ biến nhất.",
        "defensive_notes": "WAF + patch management + input validation là 3 lớp bảo vệ chính.",
        "auditor_notes": "Kiểm tra API authentication: có JWT expiry không? Rate limiting không?",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Dùng VPN, RDP, SSH, Citrix để vào mạng với credential hợp lệ hoặc bị đánh cắp.",
        "detection_tools": ["siem", "mfa"],
        "common_indicators": ["Login from unusual geo", "Off-hours access", "Failed MFA"],
        "offensive_notes": "Sau khi có credential, đây là path vào mạng ít noise nhất.",
        "defensive_notes": "MFA bắt buộc trên tất cả remote access. Geo-blocking nếu có thể.",
        "auditor_notes": "Audit danh sách VPN user — có account cũ không dùng nữa không?",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Dùng RDP để lateral movement giữa các host trong mạng nội bộ.",
        "detection_tools": ["ndr", "siem", "edr"],
        "common_indicators": ["RDP from non-admin host", "RDP to multiple hosts in short time"],
        "offensive_notes": "RDP với admin credential = full access. Không cần escalation.",
        "defensive_notes": "Giới hạn RDP chỉ từ jump server. Disable nếu không cần.",
        "auditor_notes": "Kiểm tra network segmentation — RDP có thể đi từ DMZ vào Internal không?",
    },
    "T1021.002": {
        "name": "SMB / Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Dùng SMB shares (C$, ADMIN$) để copy file và execute trên remote host.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["Admin share access from non-admin host", "PsExec pattern"],
        "offensive_notes": "PsExec + SMB = remote code execution trên mọi host trong subnet.",
        "defensive_notes": "Disable admin shares nếu không cần. Monitor SMB traffic.",
        "auditor_notes": "SMB v1 nên bị disable hoàn toàn. Kiểm tra firewall rule trong nội bộ.",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Email có attachment độc hại nhắm vào người dùng cụ thể.",
        "detection_tools": ["siem", "edr"],
        "common_indicators": ["Macro-enabled Office file", "PDF with embedded script", "Zip with EXE"],
        "offensive_notes": "Nhắm vào HR, finance, C-level. Tỉ lệ click cao hơn spam thông thường.",
        "defensive_notes": "Email gateway + attachment sandboxing + user training.",
        "auditor_notes": "Có quy trình incident report khi user nhận email đáng ngờ không?",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
        "description": "Dùng credential hợp lệ bị đánh cắp để giữ access và evade detection.",
        "detection_tools": ["siem", "mfa"],
        "common_indicators": ["Login time anomaly", "Access from new device", "Credential spray"],
        "offensive_notes": "Valid account = không có alert từ AV/EDR. Best way to blend in.",
        "defensive_notes": "UEBA (User Entity Behavior Analytics) trong SIEM. MFA giảm thiểu thiệt hại.",
        "auditor_notes": "Password policy: độ phức tạp, rotation, không reuse giữa system.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Dùng PowerShell để execute payload, download stager, hoặc living-off-the-land.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["Encoded command", "Download cradle", "Invoke-Expression"],
        "offensive_notes": "PowerShell có trong mọi Windows. Script block logging ít bật.",
        "defensive_notes": "PowerShell Constrained Language Mode + script block logging + AMSI.",
        "auditor_notes": "Kiểm tra PowerShell execution policy — có Unrestricted không?",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Dùng cmd.exe để execute command. Ít sophisticated hơn PowerShell.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["cmd spawned from Office", "Unusual parent-child process chain"],
        "offensive_notes": "Dùng cho basic recon và execution khi PowerShell bị block.",
        "defensive_notes": "Process creation log + parent-child process monitoring.",
        "auditor_notes": "Có script nào dùng cmd.exe mà có thể bị injection không?",
    },
    "T1053.005": {
        "name": "Scheduled Task / Job",
        "tactic": "Persistence",
        "description": "Tạo scheduled task để maintain persistence sau khi reboot.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["New task created by non-admin", "Task running from temp dir"],
        "offensive_notes": "Persistence đơn giản nhất trên Windows. Task XML không bị AV scan.",
        "defensive_notes": "Audit scheduled tasks thường xuyên. Alert khi có task mới.",
        "auditor_notes": "Ai có quyền tạo scheduled task? Có quá nhiều user local admin không?",
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "tactic": "Credential Access",
        "description": "Dump LSASS để lấy credential hash và NTLM token.",
        "detection_tools": ["edr"],
        "common_indicators": ["Access to lsass.exe memory", "Mimikatz signature", "ProcDump on lsass"],
        "offensive_notes": "Sau khi dump LSASS có credential của tất cả user đã login vào host đó.",
        "defensive_notes": "Credential Guard + EDR với LSASS protection. No local admin cho user thường.",
        "auditor_notes": "Có bao nhiêu account có Domain Admin? Principle of least privilege không?",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Encode/encrypt payload để bypass AV signature detection.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["High entropy binary", "Base64 encoded script", "Packed executable"],
        "offensive_notes": "Encode payload + certutil decode = bypass nhiều AV. Kết hợp T1059.001.",
        "defensive_notes": "Behavior-based EDR thay vì signature-based AV. Sandbox file trước khi execute.",
        "auditor_notes": "Scan policy có cover obfuscated script không hay chỉ executable?",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Exfiltrate data qua kênh C2 đã thiết lập (HTTP/S, DNS).",
        "detection_tools": ["ndr", "siem", "dlp"],
        "common_indicators": ["Large outbound data over HTTPS", "DNS query spike", "Unusual destination"],
        "offensive_notes": "HTTPS C2 ẩn trong traffic bình thường. DNS exfiltration qua recursive query.",
        "defensive_notes": "DLP + egress filtering + anomaly detection trên outbound traffic.",
        "auditor_notes": "Có data classification policy không? PII có bị encrypt khi rest không?",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Dùng FTP, SCP, cloud storage, hoặc email để exfiltrate data.",
        "detection_tools": ["ndr", "dlp"],
        "common_indicators": ["FTP/SFTP to external IP", "Upload to Dropbox/Drive", "Large email attachment"],
        "offensive_notes": "Upload lên cloud storage hợp lệ (Drive, OneDrive) bypass nhiều proxy.",
        "defensive_notes": "Whitelist cloud provider. DLP monitor upload. Block FTP ra ngoài.",
        "auditor_notes": "Kiểm tra egress rule — FTP ra internet có bị block không?",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Thu thập thông tin về OS, hardware, domain membership sau khi vào host.",
        "detection_tools": ["edr"],
        "common_indicators": ["Rapid systeminfo/whoami/net commands", "WMI query spike"],
        "offensive_notes": "Bước đầu sau initial access. Xác định vị trí trong mạng và privilege hiện có.",
        "defensive_notes": "Giám sát excessive enumeration command. Honeypot account.",
        "auditor_notes": "Thông tin hệ thống có bị expose qua unauthenticated API endpoint không?",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Liệt kê các host khác trong mạng nội bộ để plan lateral movement.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["ICMP sweep", "NetBIOS enumeration", "ARP scan pattern"],
        "offensive_notes": "Sau khi có foothold, cần biết còn gì trong mạng. net view / arp -a / nmap.",
        "defensive_notes": "Micro-segmentation ngăn host tự do communicate. NDR detect sweep.",
        "auditor_notes": "Network diagram hiện tại có đúng thực tế không? Có shadow IT không?",
    },
    "T1071.001": {
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "description": "Dùng HTTP/S để giao tiếp với C2 server — ẩn trong traffic bình thường.",
        "detection_tools": ["ndr", "siem"],
        "common_indicators": ["Beaconing interval", "Domain fronting", "JA3 fingerprint anomaly"],
        "offensive_notes": "HTTPS C2 qua port 443 ẩn trong SSL traffic. Domain fronting bypass proxy.",
        "defensive_notes": "SSL inspection + domain reputation check + JA3 fingerprinting.",
        "auditor_notes": "Có SSL inspection trong proxy không? Certificate pinning có được dùng không?",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Thu thập file, database, credential từ local filesystem sau khi compromise.",
        "detection_tools": ["edr", "dlp"],
        "common_indicators": ["Mass file read", "DB dump command", "Credential file access"],
        "offensive_notes": "Tìm file config chứa DB password, SSH key, API key trước khi exfiltrate.",
        "defensive_notes": "File integrity monitoring trên sensitive directory. DLP agent trên endpoint.",
        "auditor_notes": "Secret management: credential có được hardcode trong config không?",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Encrypt file để đòi ransom hoặc gây gián đoạn dịch vụ.",
        "detection_tools": ["edr"],
        "common_indicators": ["Mass file rename/extension change", "Shadow copy deletion", "High I/O spike"],
        "offensive_notes": "Delete shadow copy trước, sau đó encrypt. Cần quyền Domain Admin để encrypt mạng.",
        "defensive_notes": "Immutable backup offline. EDR behavioral detection trên mass rename.",
        "auditor_notes": "Backup có offline / air-gapped không? Recovery time objective (RTO) là bao lâu?",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "User tự execute malicious file (attachment, download) — initial execution.",
        "detection_tools": ["edr", "siem"],
        "common_indicators": ["Office macro execution", "Script file from browser download"],
        "offensive_notes": "Phishing attachment → user click → macro chạy PowerShell stager.",
        "defensive_notes": "Disable macro từ internet. Mark Of The Web (MOTW) protection.",
        "auditor_notes": "User awareness training có regular không? Có phishing simulation không?",
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
