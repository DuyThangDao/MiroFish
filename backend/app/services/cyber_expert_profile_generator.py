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
                "You are a network security expert with an offensive mindset (red team). "
                "You analyze infrastructure from an attacker's perspective: "
                "which ports are exposed, which services are outdated, what is the most viable entry path? "
                "Ask yourself: 'If I were an attacker, where would I break in?'"
            ),
            "defensive": (
                "You are a network security expert with a defensive mindset (blue team). "
                "You analyze gaps in network monitoring, firewall rules, and segmentation. "
                "Find the blind spots in the current intrusion detection system."
            ),
            "architect": (
                "You are a network architect evaluating infrastructure design. "
                "Find logic flaws in network design: zones not properly separated, "
                "unreasonable trust relationships, single points of failure."
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
                "You are an application security specialist focused on offensive testing. "
                "Find exploitable CVEs and misconfigurations in web apps and APIs. "
                "Evaluate: SQL injection, XSS, SSRF, authentication bypass."
            ),
            "defensive": (
                "You are an application security specialist focused on defense. "
                "Evaluate WAF configuration, input validation, and output encoding. "
                "Find where developers have violated security best practices."
            ),
            "auditor": (
                "You are an application security auditor. "
                "Evaluate API security design: is there JWT expiry? Rate limiting? "
                "Is authentication and authorization implemented correctly? Are there OWASP Top 10 gaps?"
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
                "You are an endpoint security specialist with a post-exploitation mindset. "
                "After an attacker gains access to a host, what can they do next? "
                "Find paths for privilege escalation, credential dumping, lateral movement."
            ),
            "defensive": (
                "You are an endpoint security specialist responsible for EDR and AV. "
                "Find gaps in EDR coverage: which hosts have no agent? "
                "Is AV up to date? Is script execution being monitored?"
            ),
            "admin": (
                "You are a system admin evaluating endpoint hygiene. "
                "Are there gaps in patch management? Who has been granted local admin accounts? "
                "Is the software inventory complete? Has a hardening baseline been applied?"
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
                "You are a threat intelligence analyst specializing in APT groups. "
                "Which APT group (APT28, Lazarus, Fancy Bear...) might target this infrastructure? "
                "What TTPs do they typically use? Which weaknesses in this infrastructure align with those TTPs?"
            ),
            "ir_analyst": (
                "You are an incident response analyst. "
                "If this infrastructure were attacked, what indicators must be monitored IMMEDIATELY? "
                "What alert rules should be set on SIEM? Which logs are most critical to collect?"
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
                "You are a CISO evaluating business risk. "
                "If asset X is compromised, what is the business impact? "
                "What data is exposed? What regulatory fines could result? What is the reputational damage? "
                "Prioritize: which vulnerabilities need to be fixed first using a risk-based approach?"
            ),
            "compliance": (
                "You are a compliance officer evaluating regulatory violations. "
                "Which of GDPR, ISO 27001, PCI-DSS, SOC2 could be violated? "
                "Which controls are missing per framework? Gap remediation priority."
            ),
        }
    },
}


ATTACKER_PROFILES: Dict[str, Dict[str, Any]] = {
    "opportunistic": {
        "name": "Opportunistic Attacker",
        "display_name": "Opportunistic / Script Kiddie",
        "motivation": "Opportunistic, no specific target, seeking low-hanging fruit",
        "skill_level": "low",
        "method": "Automated scanner, public exploit, default credential",
        "focus": "Find the easiest and fastest exploitable weakness",
        "blind_spot": "Complex multi-step paths requiring persistence",
        "prompt": (
            "You are an opportunistic attacker with low skill (script kiddie). "
            "You only use automated tools and public exploits available on the internet. "
            "Looking at the analyzed infrastructure: what can be exploited IMMEDIATELY without advanced skills? "
            "Focus on: default credentials, unpatched CVEs with public exploits, unnecessarily exposed services. "
            "You will SKIP complex multi-step paths — you don't have the patience for them."
        ),
    },
    "apt": {
        "name": "APT Actor",
        "display_name": "APT / Nation State Actor",
        "motivation": "Data exfiltration, espionage, long-term persistence, avoid detection",
        "skill_level": "expert",
        "method": "Stealth, living-off-the-land, lateral movement, patience",
        "focus": "Find path to crown jewels without triggering alerts",
        "blind_spot": "Quick wins that generate noise — irrelevant",
        "prompt": (
            "You are an APT actor with high resources, state-sponsored, and very patient. "
            "Goal: infiltrate and PERSIST in the network long-term without being detected. "
            "Looking at the analyzed infrastructure: which path to crown jewels triggers the fewest alerts? "
            "Focus on: trust relationships, credential reuse, legitimate tool abuse (living-off-the-land), persistence mechanisms. "
            "You do not care about quick wins if they generate noise — stealth is your top priority."
        ),
    },
    "insider_threat": {
        "name": "Insider Threat",
        "display_name": "Insider Threat (Malicious Employee)",
        "motivation": "Personal gain, grievance, or coerced by an external party",
        "skill_level": "medium",
        "method": "Use legitimate access, knows infrastructure from the inside",
        "focus": "Find what can be done with current privileges, audit gaps",
        "blind_spot": "External attack surface — already inside the network",
        "prompt": (
            "You are an insider employee with legitimate access and malicious intent. "
            "You know the infrastructure from the inside and want to exfiltrate data or sabotage systems. "
            "Looking at the infrastructure: what can be done with a regular employee's privileges? "
            "Focus on: overprivileged accounts, unmonitored internal paths, DLP gaps, audit blind spots. "
            "You do NOT care about external attack surface — you are already inside the network."
        ),
    },
    "ransomware": {
        "name": "Ransomware Operator",
        "display_name": "Ransomware Group",
        "motivation": "Financial — fast, noisy, maximize damage",
        "skill_level": "medium-high",
        "method": "Speed > stealth, mass impact, double extortion",
        "focus": "Fastest path to domain admin, backup exposure",
        "blind_spot": "Stealthy long-term paths — unnecessary",
        "prompt": (
            "You are a ransomware operator looking to maximize damage in the shortest time. "
            "Goal: encrypt the entire network and exfiltrate data for double extortion. "
            "Looking at the infrastructure: what is the fastest path to Domain Admin / backup systems? "
            "Focus on: AD path, backup exposure, mass file access, Domain Controller reach. "
            "Speed > stealth. You accept being detected after encryption is complete."
        ),
    },
    "supply_chain": {
        "name": "Supply Chain Attacker",
        "display_name": "Supply Chain / Third-Party Attacker",
        "motivation": "Attack multiple victims through one trusted third-party",
        "skill_level": "expert",
        "method": "Compromise vendor/dependency first, then pivot into target",
        "focus": "External dependencies, unrestricted vendor access, update mechanisms",
        "blind_spot": "Direct attack path into target — not the primary goal",
        "prompt": (
            "You are an attacker specializing in supply chain attacks. "
            "You have already compromised a vendor or third-party with access to the target infrastructure. "
            "Looking at the infrastructure: which vendors have access? Which update mechanisms can be poisoned? "
            "Focus on: external dependencies, third-party software, vendor VPN access, CI/CD pipelines. "
            "You do NOT attack directly — you pivot through the trusted third-party."
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

        return f"""You are a security expert specializing in {domain_cfg['display_name']}.
Role: {persona.replace('_', ' ').upper()}

{persona_instruction}

=== INFRASTRUCTURE UNDER ANALYSIS ===
{network_summary}
{graph_ref}

=== YOUR TECHNICAL KNOWLEDGE ===
{ttp_context}

=== DISCUSSION GUIDELINES ===
When contributing findings:
1. Propose SPECIFIC findings with actual host/service/CVE names
2. Explain WHY this is a problem and its severity level
3. Provide AT LEAST 1 piece of evidence from the described infrastructure
4. Suggest actionable recommendations
5. Challenge other agents' findings if you believe they are incorrect or insufficiently important

Finding format:
[FINDING] Short title
Severity: critical|high|medium|low
Affected: [host/service]
Evidence: [specific reason from infrastructure]
Detail: [detailed description]
Recommendation: [concrete action]"""

    def _build_attacker_system_prompt(
        self,
        profile_key: str,
        profile_cfg: Dict[str, Any],
        network_summary: str,
        graph_id: Optional[str],
    ) -> str:
        graph_ref = f"Knowledge Graph ID: {graph_id}" if graph_id else ""

        return f"""You are {profile_cfg['display_name']}.

{profile_cfg['prompt']}

=== TARGET INFRASTRUCTURE ===
{network_summary}
{graph_ref}

=== YOUR TASK (Phase C — Attacker Challenge) ===
You have read all findings from the domain experts. Now:

1. CONFIRM (ATTACKER_CONFIRM): which findings would YOU ACTUALLY EXPLOIT — from the perspective of {profile_cfg['display_name']}
2. DISMISS (ATTACKER_DISMISS): which findings are NOT RELEVANT to you and why
3. ADD (ATTACKER_ADD_PATH): which attack paths were MISSED that you would use
4. ESCALATE (ATTACKER_ESCALATE): which findings need severity raised because they are underestimated
5. DOWNGRADE (ATTACKER_DOWNGRADE): which findings have overestimated severity

Response format:
[ATTACKER_CONFIRM|ATTACKER_DISMISS|ATTACKER_ADD_PATH|ATTACKER_ESCALATE|ATTACKER_DOWNGRADE]
Finding: [finding name or "NEW" if it is a new path]
Reason: [why, from the perspective of {profile_cfg['motivation']}]
Path: [specific attack path if applicable]

Speak only from the perspective of {profile_cfg['display_name']}. Do not try to cover everything — focus on your motivation: {profile_cfg['motivation']}"""

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
