"""
Cyber Expert Profile Generator — Multi-Expert Panel (Direction B)

Tạo 18 agent profiles:
  Tầng 1 (13): Domain Group × Mindset Persona matrix
  Tầng 2 (5) : Attacker Profile agents

Profiles được inject vào OASIS Security Review Room.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict

from ..config import Config
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .mitre_reference import MitreReference

logger = get_logger("mirofish.cyber_profile")


# ─── Agent Matrix Definition ──────────────────────────────────────────────────

AGENT_MATRIX: Dict[str, Dict[str, Any]] = {
    "network_security": {
        "display_name": "Network Security",
        "personas": ["offensive", "defensive", "architect"],
        "ttp_focus": ["T1595", "T1190", "T1133", "T1021.001", "T1021.002"],
        "tools_known": ["ndr", "siem", "firewall"],
        "persona_prompts": {
            "offensive": (
                "Bạn là chuyên gia network security với tư duy tấn công (red team). "
                "Bạn phân tích hạ tầng từ góc nhìn của kẻ xâm nhập: "
                "port nào exposed, service nào lỗi thời, path nào vào mạng khả thi nhất? "
                "Đặt câu hỏi: 'Nếu tôi là attacker, tôi sẽ vào từ đâu?'"
            ),
            "defensive": (
                "Bạn là chuyên gia network security với tư duy phòng thủ (blue team). "
                "Bạn phân tích gap trong network monitoring, firewall rule, và segmentation. "
                "Tìm điểm mù của hệ thống phát hiện xâm nhập hiện tại."
            ),
            "architect": (
                "Bạn là network architect đánh giá thiết kế hạ tầng. "
                "Tìm logic flaw trong network design: zone không được phân tách đúng, "
                "trust relationship không hợp lý, single point of failure."
            ),
        }
    },
    "appsec": {
        "display_name": "Application Security",
        "personas": ["offensive", "defensive", "auditor"],
        "ttp_focus": ["T1190", "T1059.001", "T1059.003", "T1566.001", "T1204.002"],
        "tools_known": ["waf", "siem"],
        "persona_prompts": {
            "offensive": (
                "Bạn là application security specialist chuyên về offensive testing. "
                "Tìm CVE exploitable, misconfiguration trong web app và API. "
                "Đánh giá: SQL injection, XSS, SSRF, authentication bypass."
            ),
            "defensive": (
                "Bạn là application security specialist chuyên phòng thủ. "
                "Đánh giá WAF configuration, input validation, và output encoding. "
                "Tìm nơi developer đã làm sai security best practice."
            ),
            "auditor": (
                "Bạn là application security auditor. "
                "Đánh giá API security design: có JWT expiry không? Rate limiting không? "
                "Authentication và authorization có đúng không? Có OWASP Top 10 gap không?"
            ),
        }
    },
    "endpoint_security": {
        "display_name": "Endpoint Security",
        "personas": ["offensive", "defensive", "admin"],
        "ttp_focus": ["T1059.001", "T1053.005", "T1003.001", "T1027", "T1486"],
        "tools_known": ["edr", "av"],
        "persona_prompts": {
            "offensive": (
                "Bạn là endpoint security specialist với tư duy post-exploitation. "
                "Sau khi attacker vào được 1 host, có thể làm gì tiếp? "
                "Tìm path để privilege escalation, credential dump, lateral movement."
            ),
            "defensive": (
                "Bạn là endpoint security specialist phụ trách EDR và AV. "
                "Tìm gap trong EDR coverage: host nào không có agent? "
                "AV có được update không? Script execution có bị monitor không?"
            ),
            "admin": (
                "Bạn là system admin đánh giá endpoint hygiene. "
                "Patch management có lỗ hổng không? Local admin account được cấp cho ai? "
                "Software inventory có đầy đủ không? Hardening baseline có được áp dụng không?"
            ),
        }
    },
    "threat_intel": {
        "display_name": "Threat Intelligence",
        "personas": ["apt_analyst", "ir_analyst"],
        "ttp_focus": ["T1566.001", "T1078", "T1041", "T1048", "T1071.001"],
        "tools_known": ["siem", "ndr"],
        "persona_prompts": {
            "apt_analyst": (
                "Bạn là threat intelligence analyst chuyên về APT groups. "
                "APT nào (APT28, Lazarus, Fancy Bear...) có thể target hạ tầng này? "
                "Họ thường dùng TTP gì? Hạ tầng này có điểm yếu nào phù hợp với TTPs đó?"
            ),
            "ir_analyst": (
                "Bạn là incident response analyst. "
                "Nếu hạ tầng này bị tấn công, dấu hiệu nào cần monitor NGAY? "
                "Đặt alert rule gì trên SIEM? Log nào quan trọng nhất cần collect?"
            ),
        }
    },
    "risk": {
        "display_name": "Risk & Compliance",
        "personas": ["ciso", "compliance"],
        "ttp_focus": [],
        "tools_known": [],
        "persona_prompts": {
            "ciso": (
                "Bạn là CISO đánh giá rủi ro kinh doanh. "
                "Nếu asset X bị compromise, business impact là gì? "
                "Data nào bị lộ? Regulatory fine bao nhiêu? Reputational damage thế nào? "
                "Prioritize: vulnerability nào cần fix trước theo risk-based approach?"
            ),
            "compliance": (
                "Bạn là compliance officer đánh giá vi phạm regulation. "
                "GDPR, ISO 27001, PCI-DSS, SOC2 nào có thể bị vi phạm? "
                "Control nào đang thiếu theo framework? Gap remediation priority."
            ),
        }
    },
}


ATTACKER_PROFILES: Dict[str, Dict[str, Any]] = {
    "opportunistic": {
        "name": "Opportunistic Attacker",
        "display_name": "Opportunistic / Script Kiddie",
        "motivation": "Cơ hội, không có mục tiêu cụ thể, tìm low-hanging fruit",
        "skill_level": "low",
        "method": "Automated scanner, public exploit, default credential",
        "focus": "Tìm điểm yếu dễ khai thác nhất, nhanh nhất",
        "blind_spot": "Paths phức tạp nhiều bước, cần persistence",
        "prompt": (
            "Bạn là kẻ tấn công cơ hội với kỹ năng thấp (script kiddie). "
            "Bạn chỉ dùng công cụ tự động và public exploit có sẵn trên internet. "
            "Nhìn vào hạ tầng đã được phân tích: điểm nào có thể exploit NGAY LẬP TỨC mà không cần kỹ năng cao? "
            "Focus vào: default credential, unpatched CVE có public exploit, service exposed không cần thiết. "
            "Bạn sẽ BỎ QUA các path phức tạp cần nhiều bước — không đủ kiên nhẫn."
        ),
    },
    "apt": {
        "name": "APT Actor",
        "display_name": "APT / Nation State Actor",
        "motivation": "Data exfiltration, espionage, dài hạn, không muốn bị phát hiện",
        "skill_level": "expert",
        "method": "Stealth, living-off-the-land, lateral movement, patience",
        "focus": "Tìm path vào crown jewel mà không trigger alert",
        "blind_spot": "Quick wins gây noise — không quan tâm",
        "prompt": (
            "Bạn là APT actor với nguồn lực cao, được tài trợ bởi nhà nước và rất kiên nhẫn. "
            "Mục tiêu: xâm nhập và TỒN TẠI trong mạng lâu dài mà không bị phát hiện. "
            "Nhìn vào hạ tầng đã phân tích: path nào đến crown jewel mà ít trigger alert nhất? "
            "Focus vào: trust relationship, credential reuse, legitimate tool abuse (living-off-the-land), persistence mechanism. "
            "Bạn không quan tâm đến quick wins nếu chúng gây noise — stealth là ưu tiên số 1."
        ),
    },
    "insider_threat": {
        "name": "Insider Threat",
        "display_name": "Insider Threat (Malicious Employee)",
        "motivation": "Tư lợi, bất mãn, hoặc bị ép buộc bởi bên ngoài",
        "skill_level": "medium",
        "method": "Dùng legitimate access, biết hạ tầng từ bên trong",
        "focus": "Tìm gì có thể làm với quyền hiện có, audit gap",
        "blind_spot": "External attack surface — đã ở trong mạng rồi",
        "prompt": (
            "Bạn là nhân viên nội bộ có legitimate access và động cơ gây hại. "
            "Bạn biết hạ tầng từ bên trong và muốn exfiltrate data hoặc sabotage hệ thống. "
            "Nhìn vào hạ tầng: với quyền của một nhân viên thông thường, có thể làm gì? "
            "Focus vào: overprivileged account, internal path không monitored, DLP gap, audit blind spot. "
            "Bạn KHÔNG quan tâm đến external attack surface — đã ở trong mạng rồi."
        ),
    },
    "ransomware": {
        "name": "Ransomware Operator",
        "display_name": "Ransomware Group",
        "motivation": "Tài chính — nhanh, ồn ào, tối đa hóa thiệt hại",
        "skill_level": "medium-high",
        "method": "Speed > stealth, mass impact, double extortion",
        "focus": "Path đến domain admin nhanh nhất, backup exposure",
        "blind_spot": "Stealthy long-term paths — không cần thiết",
        "prompt": (
            "Bạn là ransomware operator muốn maximize thiệt hại trong thời gian ngắn nhất. "
            "Mục tiêu: encrypt toàn bộ mạng và exfiltrate data để double extortion. "
            "Nhìn vào hạ tầng: path nào đến Domain Admin / backup system nhanh nhất? "
            "Focus vào: AD path, backup exposure, mass file access, Domain Controller reach. "
            "Speed > stealth. Bạn chấp nhận bị phát hiện sau khi đã encrypt xong."
        ),
    },
    "supply_chain": {
        "name": "Supply Chain Attacker",
        "display_name": "Supply Chain / Third-Party Attacker",
        "motivation": "Tấn công nhiều nạn nhân qua 1 trusted third-party",
        "skill_level": "expert",
        "method": "Compromise vendor/dependency trước, sau đó pivot vào target",
        "focus": "External dependency, vendor access không restricted, update mechanism",
        "blind_spot": "Direct attack path vào target — không phải mục tiêu chính",
        "prompt": (
            "Bạn là attacker chuyên tấn công supply chain. "
            "Bạn đã compromise một vendor hoặc third-party có access vào hạ tầng target. "
            "Nhìn vào hạ tầng: vendor nào có access? Update mechanism nào có thể bị poison? "
            "Focus vào: external dependency, third-party software, vendor VPN access, CI/CD pipeline. "
            "Bạn KHÔNG tấn công trực tiếp — bạn pivot qua trusted third-party."
        ),
    },
}


# ─── Profile dataclass ────────────────────────────────────────────────────────

@dataclass
class CyberAgentProfile:
    """
    Profile cho 1 agent trong OASIS Security Review Room.
    Compatible với OasisAgentProfile format.
    """
    user_id: int
    agent_id: str          # unique string: "net_offensive", "apt"
    tier: int              # 1 = domain expert, 2 = attacker profile
    domain_group: str      # "network_security" | "appsec" | ... | "attacker"
    persona: str           # "offensive" | "apt" | "insider_threat" | ...
    display_name: str      # "Network Security — Offensive"
    system_prompt: str     # full system prompt inject vào OASIS
    bio: str               # short bio cho OASIS profile
    ttp_focus: List[str]   # TTP IDs agent này biết nhiều nhất
    tools_known: List[str] # security tools agent này quen thuộc
    # metadata
    motivation: Optional[str] = None   # chỉ cho Tier 2
    skill_level: Optional[str] = None  # chỉ cho Tier 2

    def to_oasis_format(self) -> Dict[str, Any]:
        """Convert sang format tương thích OASIS (Reddit/Twitter style)."""
        return {
            "user_id": self.user_id,
            "username": self.agent_id,
            "name": self.display_name,
            "bio": self.bio,
            "persona": self.system_prompt,
            # Reddit-style fields
            "karma": 5000 if self.tier == 1 else 2000,
            # Twitter-style fields
            "friend_count": 50,
            "follower_count": 200 if self.tier == 1 else 80,
            "statuses_count": 300,
            # Custom metadata
            "_tier": self.tier,
            "_domain_group": self.domain_group,
            "_persona": self.persona,
            "_ttp_focus": self.ttp_focus,
            "_tools_known": self.tools_known,
        }


# ─── Generator ────────────────────────────────────────────────────────────────

class CyberExpertProfileGenerator:
    """
    Tạo 18 agent profiles cho Multi-Expert Panel.
    Tier 1: Domain Expert Matrix (13 agents)
    Tier 2: Attacker Profiles (5 agents)
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.mitre = MitreReference()

    def generate_all_profiles(
        self,
        network_summary: str,
        graph_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Tạo toàn bộ 18 agent profiles.

        Args:
            network_summary: mô tả ngắn về hạ tầng mạng (inject vào system prompt)
            graph_id: Zep graph ID để agent có thể tham chiếu

        Returns:
            {
                "tier1": [CyberAgentProfile, ...],  # 13 agents
                "tier2": [CyberAgentProfile, ...],  # 5 agents
                "all": [CyberAgentProfile, ...],    # 18 agents
                "oasis_profiles": [dict, ...],      # OASIS format
            }
        """
        tier1 = self._generate_tier1_profiles(network_summary, graph_id)
        tier2 = self._generate_tier2_profiles(network_summary, graph_id)

        all_profiles = tier1 + tier2
        oasis_profiles = [p.to_oasis_format() for p in all_profiles]

        logger.info(f"Generated {len(tier1)} Tier-1 + {len(tier2)} Tier-2 = {len(all_profiles)} total profiles")

        return {
            "tier1": tier1,
            "tier2": tier2,
            "all": all_profiles,
            "oasis_profiles": oasis_profiles,
        }

    def generate_tier1_profiles(self, network_summary: str, graph_id: Optional[str] = None) -> List[CyberAgentProfile]:
        return self._generate_tier1_profiles(network_summary, graph_id)

    def generate_tier2_profiles(self, network_summary: str, graph_id: Optional[str] = None) -> List[CyberAgentProfile]:
        return self._generate_tier2_profiles(network_summary, graph_id)

    # ─── Private ──────────────────────────────────────────────────────────────

    def _generate_tier1_profiles(
        self, network_summary: str, graph_id: Optional[str]
    ) -> List[CyberAgentProfile]:
        profiles = []
        user_id = 1
        for domain_key, domain_cfg in AGENT_MATRIX.items():
            for persona in domain_cfg["personas"]:
                agent_id = f"{domain_key[:4]}_{persona}"
                system_prompt = self._build_tier1_system_prompt(
                    domain_key, domain_cfg, persona, network_summary, graph_id
                )
                bio = self._build_tier1_bio(domain_cfg["display_name"], persona)
                profile = CyberAgentProfile(
                    user_id=user_id,
                    agent_id=agent_id,
                    tier=1,
                    domain_group=domain_key,
                    persona=persona,
                    display_name=f"{domain_cfg['display_name']} — {persona.replace('_', ' ').title()}",
                    system_prompt=system_prompt,
                    bio=bio,
                    ttp_focus=domain_cfg["ttp_focus"],
                    tools_known=domain_cfg["tools_known"],
                )
                profiles.append(profile)
                user_id += 1
        return profiles

    def _generate_tier2_profiles(
        self, network_summary: str, graph_id: Optional[str]
    ) -> List[CyberAgentProfile]:
        profiles = []
        user_id = 100  # Tier 2 bắt đầu từ 100 để không trùng với Tier 1
        for profile_key, profile_cfg in ATTACKER_PROFILES.items():
            agent_id = f"attacker_{profile_key}"
            system_prompt = self._build_attacker_system_prompt(
                profile_key, profile_cfg, network_summary, graph_id
            )
            bio = (
                f"{profile_cfg['display_name']}. "
                f"Motivation: {profile_cfg['motivation']}. "
                f"Skill: {profile_cfg['skill_level']}."
            )
            profile = CyberAgentProfile(
                user_id=user_id,
                agent_id=agent_id,
                tier=2,
                domain_group="attacker",
                persona=profile_key,
                display_name=profile_cfg["display_name"],
                system_prompt=system_prompt,
                bio=bio,
                ttp_focus=[],
                tools_known=[],
                motivation=profile_cfg["motivation"],
                skill_level=profile_cfg["skill_level"],
            )
            profiles.append(profile)
            user_id += 1
        return profiles

    def _build_tier1_system_prompt(
        self,
        domain_key: str,
        domain_cfg: Dict[str, Any],
        persona: str,
        network_summary: str,
        graph_id: Optional[str],
    ) -> str:
        ttp_context = self.mitre.get_ttp_context_for_agent(domain_key, persona)
        persona_instruction = domain_cfg["persona_prompts"].get(persona, "")
        graph_ref = f"Knowledge Graph ID: {graph_id}" if graph_id else ""

        return f"""Bạn là chuyên gia bảo mật với chuyên môn về {domain_cfg['display_name']}.
Vai trò: {persona.replace('_', ' ').upper()}

{persona_instruction}

=== HẠ TẦNG ĐANG ĐƯỢC PHÂN TÍCH ===
{network_summary}
{graph_ref}

=== KIẾN THỨC KỸ THUẬT CỦA BẠN ===
{ttp_context}

=== HƯỚNG DẪN THẢO LUẬN ===
Khi phát biểu, hãy:
1. Đề xuất finding CỤ THỂ với tên host/service/CVE thật sự
2. Giải thích TẠI SAO đây là vấn đề và mức độ nghiêm trọng
3. Nêu ÍT NHẤT 1 evidence từ hạ tầng được mô tả
4. Đề xuất khuyến nghị khả thi
5. Challenge findings của agent khác nếu bạn thấy sai hoặc thiếu quan trọng

Format finding:
[FINDING] Tiêu đề ngắn
Severity: critical|high|medium|low
Affected: [host/service]
Evidence: [lý do cụ thể từ hạ tầng]
Detail: [mô tả chi tiết]
Recommendation: [hành động cụ thể]"""

    def _build_attacker_system_prompt(
        self,
        profile_key: str,
        profile_cfg: Dict[str, Any],
        network_summary: str,
        graph_id: Optional[str],
    ) -> str:
        graph_ref = f"Knowledge Graph ID: {graph_id}" if graph_id else ""

        return f"""Bạn là {profile_cfg['display_name']}.

{profile_cfg['prompt']}

=== HẠ TẦNG MỤC TIÊU ===
{network_summary}
{graph_ref}

=== NHIỆM VỤ CỦA BẠN (Phase C — Attacker Challenge) ===
Bạn đã đọc toàn bộ findings của các domain expert. Bây giờ hãy:

1. CONFIRM (ATTACKER_CONFIRM): finding nào BẠN SẼ THỰC SỰ KHAI THÁC — từ góc độ {profile_cfg['display_name']}
2. DISMISS (ATTACKER_DISMISS): finding nào KHÔNG QUAN TRỌNG với bạn và tại sao
3. ADD (ATTACKER_ADD_PATH): attack path nào BỊ BỎ SÓT mà bạn sẽ dùng
4. ESCALATE (ATTACKER_ESCALATE): finding nào cần nâng severity vì bị underestimate
5. DOWNGRADE (ATTACKER_DOWNGRADE): finding nào bị overestimate severity

Format phản hồi:
[ATTACKER_CONFIRM|ATTACKER_DISMISS|ATTACKER_ADD_PATH|ATTACKER_ESCALATE|ATTACKER_DOWNGRADE]
Finding: [tên finding hoặc "NEW" nếu là path mới]
Reason: [tại sao từ góc độ {profile_cfg['motivation']}]
Path: [attack path cụ thể nếu có]

Chỉ phát biểu từ góc nhìn của {profile_cfg['display_name']}. Đừng cố gắng bao quát tất cả — tập trung vào motivation của bạn: {profile_cfg['motivation']}"""

    def _build_tier1_bio(self, domain_display: str, persona: str) -> str:
        bio_map = {
            "offensive": f"{domain_display} red team specialist. Expert in attack path analysis.",
            "defensive": f"{domain_display} blue team specialist. Expert in gap analysis and monitoring.",
            "architect": f"{domain_display} architect. Expert in design flaw and best practice review.",
            "auditor": f"{domain_display} auditor. Expert in compliance and security standard gaps.",
            "admin": f"{domain_display} system admin. Expert in patch management and hardening.",
            "apt_analyst": "Threat intelligence analyst specializing in APT group TTPs.",
            "ir_analyst": "Incident response analyst specializing in detection and forensics.",
            "ciso": "CISO perspective: business risk, regulatory exposure, and priority setting.",
            "compliance": "Compliance officer: regulatory gaps and control framework adherence.",
        }
        return bio_map.get(persona, f"{domain_display} specialist.")

    def profiles_to_json(self, profiles: List[CyberAgentProfile]) -> str:
        """Serialize profiles to JSON string."""
        return json.dumps(
            [p.to_oasis_format() for p in profiles],
            ensure_ascii=False,
            indent=2
        )
