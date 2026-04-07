"""
Network Topology Builder — Multi-Expert Panel (Direction B)

Parse mô tả hạ tầng mạng (text / IaC) → LLM extract → Zep KG.
Reuse GraphBuilderService patterns nhưng với Security ontology.
"""

import re
import json
import uuid
import threading
from typing import Dict, List, Any, Optional

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..models.cyber_models import NetworkAsset, SecurityControls, PatchStatus
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .graph_builder import GraphBuilderService

logger = get_logger("mirofish.network_topology")

# ─── Security ontology cố định cho Zep ────────────────────────────────────────
# Các entity type và edge type dùng cho network topology graph.

CYBER_ONTOLOGY: Dict[str, Any] = {
    "entity_types": [
        {
            "name": "NetworkHost",
            "description": "A host or server in the network infrastructure",
            "attributes": [
                {"name": "host_id",      "description": "Unique identifier e.g. WEB-01"},
                {"name": "ip_address",   "description": "IP address"},
                {"name": "zone",         "description": "Network zone: DMZ, Internal, Database, Management"},
                {"name": "os_version",   "description": "Operating system and version"},
                {"name": "patch_status", "description": "patched | unpatched | partially_patched"},
                {"name": "is_critical",  "description": "Whether this is a critical asset"},
                {"name": "controls",     "description": "Active security controls: edr, siem, av, ndr, waf, mfa, dlp"},
            ]
        },
        {
            "name": "NetworkService",
            "description": "A service or application running on a host",
            "attributes": [
                {"name": "service_name", "description": "Service name and version e.g. Apache 2.4.49"},
                {"name": "port",         "description": "Port number"},
                {"name": "protocol",     "description": "Protocol: TCP, UDP, HTTP, HTTPS"},
                {"name": "is_exposed",   "description": "Whether exposed to external network"},
            ]
        },
        {
            "name": "Vulnerability",
            "description": "A CVE or security vulnerability",
            "attributes": [
                {"name": "cve_id",       "description": "CVE identifier e.g. CVE-2021-41773"},
                {"name": "severity",     "description": "critical | high | medium | low"},
                {"name": "cvss_score",   "description": "CVSS score 0-10"},
                {"name": "description",  "description": "Vulnerability description"},
                {"name": "is_patched",   "description": "Whether the vulnerability is patched"},
            ]
        },
        {
            "name": "NetworkZone",
            "description": "A network zone or segment",
            "attributes": [
                {"name": "zone_name",    "description": "Zone name: DMZ, Internal, Database, Management"},
                {"name": "trust_level",  "description": "Trust level: untrusted, semi-trusted, trusted"},
                {"name": "firewall_rules","description": "Summary of firewall rules for this zone"},
            ]
        },
    ],
    "edge_types": [
        {"name": "runs_service",        "description": "Host runs a service"},
        {"name": "has_vulnerability",   "description": "Host or service has a vulnerability"},
        {"name": "belongs_to_zone",     "description": "Host belongs to a network zone"},
        {"name": "connects_to",         "description": "Host can connect to another host"},
        {"name": "trusts",              "description": "Network zone trusts another zone"},
        {"name": "is_protected_by",     "description": "Host is protected by a security control"},
    ]
}


# ─── IaC Parsers ───────────────────────────────────────────────────────────────

class IaCParser:
    """Parse Infrastructure-as-Code files thành text mô tả host."""

    @staticmethod
    def parse_terraform(content: str) -> str:
        """Extract resource blocks từ Terraform HCL."""
        lines = []
        # Match resource blocks: resource "aws_instance" "web" { ... }
        resource_pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]+)\}',
            re.DOTALL
        )
        for m in resource_pattern.finditer(content):
            rtype, rname, rbody = m.group(1), m.group(2), m.group(3)
            lines.append(f"Infrastructure resource: {rtype} named '{rname}'")
            # Extract key-value pairs
            for kv in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', rbody):
                lines.append(f"  {kv.group(1)}: {kv.group(2)}")
        return "\n".join(lines) if lines else content[:2000]

    @staticmethod
    def parse_docker_compose(content: str) -> str:
        """Extract services từ docker-compose YAML."""
        lines = []
        try:
            import yaml
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "services" in data:
                for svc_name, svc_cfg in data["services"].items():
                    lines.append(f"Container service: {svc_name}")
                    if isinstance(svc_cfg, dict):
                        if "image" in svc_cfg:
                            lines.append(f"  image: {svc_cfg['image']}")
                        if "ports" in svc_cfg:
                            lines.append(f"  ports: {svc_cfg['ports']}")
                        if "environment" in svc_cfg:
                            env = svc_cfg["environment"]
                            if isinstance(env, list):
                                for e in env[:5]:  # limit env vars
                                    lines.append(f"  env: {e}")
                        if "networks" in svc_cfg:
                            lines.append(f"  networks: {svc_cfg['networks']}")
            return "\n".join(lines) if lines else content[:2000]
        except Exception:
            # Regex fallback nếu yaml không có hoặc parse lỗi
            for m in re.finditer(r'^  (\w[\w-]*):', content, re.MULTILINE):
                lines.append(f"Service: {m.group(1)}")
            for m in re.finditer(r'image:\s*(.+)', content):
                lines.append(f"  image: {m.group(1).strip()}")
            for m in re.finditer(r'- "?(\d+:\d+)"?', content):
                lines.append(f"  port: {m.group(1)}")
            return "\n".join(lines) if lines else content[:2000]

    @staticmethod
    def parse_kubernetes(content: str) -> str:
        """Extract resource specs từ Kubernetes YAML."""
        lines = []
        try:
            import yaml
            # K8s files thường có nhiều docs separated by ---
            for doc in yaml.safe_load_all(content):
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind", "Unknown")
                meta = doc.get("metadata", {})
                name = meta.get("name", "unnamed") if isinstance(meta, dict) else "unnamed"
                lines.append(f"Kubernetes {kind}: {name}")
                spec = doc.get("spec", {})
                if isinstance(spec, dict):
                    if "containers" in spec:
                        for c in spec["containers"]:
                            if isinstance(c, dict):
                                lines.append(f"  container: {c.get('image', 'unknown')}")
                    elif "template" in spec:
                        tmpl = spec["template"]
                        if isinstance(tmpl, dict):
                            for c in tmpl.get("spec", {}).get("containers", []):
                                lines.append(f"  container: {c.get('image', 'unknown')}")
            return "\n".join(lines) if lines else content[:2000]
        except Exception:
            return content[:2000]


# ─── Main Builder ─────────────────────────────────────────────────────────────

class NetworkTopologyBuilder:
    """
    Parse hạ tầng mạng → LLM extract → Zep KG.
    Reuse GraphBuilderService cho Zep operations.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.graph_service = GraphBuilderService()
        self.task_manager = TaskManager()

    # ─── Public async API ─────────────────────────────────────────────────────

    def build_from_text_async(self, text: str, graph_name: str) -> str:
        """
        Async: LLM extract NetworkAsset từ text → Zep KG.
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="network_topology_build",
            metadata={"graph_name": graph_name, "mode": "text", "text_length": len(text)}
        )
        thread = threading.Thread(
            target=self._build_worker,
            args=(task_id, text, graph_name),
            daemon=True
        )
        thread.start()
        return task_id

    def build_from_iac_async(
        self,
        iac_files: Dict[str, str],   # {filename: content}
        extra_text: str,
        graph_name: str
    ) -> str:
        """
        Async: Parse IaC files + enrich bằng extra_text → LLM extract → Zep KG.
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="network_topology_build",
            metadata={"graph_name": graph_name, "mode": "iac", "file_count": len(iac_files)}
        )
        thread = threading.Thread(
            target=self._build_iac_worker,
            args=(task_id, iac_files, extra_text, graph_name),
            daemon=True
        )
        thread.start()
        return task_id

    # ─── Query helpers ────────────────────────────────────────────────────────

    def get_attack_surface(self, graph_id: str) -> List[Dict[str, Any]]:
        """
        Trả về các host dễ bị tấn công nhất.
        Lọc: có vulnerability hoặc thiếu security control.
        """
        from ..utils.zep_paging import fetch_all_nodes, fetch_all_edges
        zep = self.graph_service.client

        nodes = fetch_all_nodes(zep, graph_id)
        edges = fetch_all_edges(zep, graph_id)

        # Host nào có edge "has_vulnerability"
        vulnerable_host_uuids = {
            e.source_node_uuid
            for e in edges
            if hasattr(e, "relation_type") and e.relation_type == "has_vulnerability"
        }

        attack_surface = []
        for node in nodes:
            if not hasattr(node, "labels") or "NetworkHost" not in (node.labels or []):
                continue
            attrs = node.attributes or {}
            node_uuid = str(node.uuid) if hasattr(node, "uuid") else None
            is_vulnerable = node_uuid in vulnerable_host_uuids
            controls_str = attrs.get("controls") or ""
            missing_critical = "edr" not in controls_str and "siem" not in controls_str

            if is_vulnerable or missing_critical:
                attack_surface.append({
                    "host_id":     attrs.get("host_id", node.name),
                    "zone":        attrs.get("zone", "unknown"),
                    "patch_status": attrs.get("patch_status", "unknown"),
                    "is_critical":  attrs.get("is_critical", False),
                    "controls":    controls_str,
                    "risk_reason": "has_vulnerability" if is_vulnerable else "missing_edr_or_siem",
                })

        # Sort: critical asset trước, sau đó unpatched
        attack_surface.sort(
            key=lambda h: (
                h["is_critical"] != "True",
                h["patch_status"] != "unpatched"
            )
        )
        return attack_surface

    # ─── Workers ──────────────────────────────────────────────────────────────

    def _build_worker(self, task_id: str, text: str, graph_name: str):
        try:
            self.task_manager.update_task(task_id, status=TaskStatus.PROCESSING,
                                          progress=5, message="Extracting network assets with LLM...")
            assets = self._extract_assets_with_llm(text)
            self.task_manager.update_task(task_id, progress=30,
                                          message=f"Extracted {len(assets)} assets. Building Zep graph...")
            graph_id = self._store_to_zep(graph_name, assets, text)
            self.task_manager.complete_task(task_id, {
                "graph_id": graph_id,
                "asset_count": len(assets),
                "mode": "text",
            })
        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    def _build_iac_worker(
        self,
        task_id: str,
        iac_files: Dict[str, str],
        extra_text: str,
        graph_name: str
    ):
        try:
            self.task_manager.update_task(task_id, status=TaskStatus.PROCESSING,
                                          progress=5, message="Parsing IaC files...")
            combined_text = self._parse_iac_files(iac_files)
            if extra_text:
                combined_text = combined_text + "\n\n" + extra_text

            self.task_manager.update_task(task_id, progress=20,
                                          message="Extracting network assets with LLM...")
            assets = self._extract_assets_with_llm(combined_text)

            self.task_manager.update_task(task_id, progress=40,
                                          message=f"Extracted {len(assets)} assets. Building Zep graph...")
            graph_id = self._store_to_zep(graph_name, assets, combined_text)
            self.task_manager.complete_task(task_id, {
                "graph_id": graph_id,
                "asset_count": len(assets),
                "mode": "iac",
                "files_parsed": list(iac_files.keys()),
            })
        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    # ─── Core logic ───────────────────────────────────────────────────────────

    def _parse_iac_files(self, iac_files: Dict[str, str]) -> str:
        """Parse IaC files thành text. Chọn parser theo tên file."""
        parts = []
        for filename, content in iac_files.items():
            fn_lower = filename.lower()
            if fn_lower.endswith(".tf"):
                parsed = IaCParser.parse_terraform(content)
                parts.append(f"=== Terraform: {filename} ===\n{parsed}")
            elif "docker-compose" in fn_lower or fn_lower.endswith(".yml") or fn_lower.endswith(".yaml"):
                if "docker" in fn_lower or "compose" in fn_lower:
                    parsed = IaCParser.parse_docker_compose(content)
                    parts.append(f"=== Docker Compose: {filename} ===\n{parsed}")
                else:
                    parsed = IaCParser.parse_kubernetes(content)
                    parts.append(f"=== Kubernetes: {filename} ===\n{parsed}")
            else:
                parts.append(f"=== {filename} ===\n{content[:1500]}")
        return "\n\n".join(parts)

    def _extract_assets_with_llm(self, text: str) -> List[NetworkAsset]:
        """LLM extract host, CVE, service, zone → JSON strict → List[NetworkAsset]."""
        prompt = f"""You are a network security analyst. Analyze the following infrastructure description and extract all network assets.

Return a JSON object with key "assets" containing an array. Each asset must have:
- host_id: short unique ID (e.g. "WEB-01", "DB-01", "FW-01")
- hostname: full hostname or container name
- ip: IP address (use "unknown" if not specified)
- zone: one of "DMZ", "Internal", "Database", "Management", "Cloud", "External"
- os: OS and version (use "unknown" if not specified)
- services: array of service strings ["Apache 2.4.49", "OpenSSH 8.9"]
- vulnerabilities: array of CVE IDs if mentioned ["CVE-2021-41773"]
- patch_status: "patched" | "unpatched" | "partially_patched" | "unknown"
- is_critical: true if this is a DB server, Domain Controller, firewall, or payment system
- controls: object with boolean fields edr, siem, av, ndr, waf, mfa, dlp (true if present)
- notes: any additional security-relevant notes

Infrastructure description:
{text[:4000]}

Extract ALL hosts, servers, containers, and network devices. Be specific about zone placement."""

        try:
            result = self.llm.chat_json([{"role": "user", "content": prompt}], temperature=0.1)
            assets_raw = result.get("assets", [])
            return [self._dict_to_asset(a) for a in assets_raw if isinstance(a, dict)]
        except Exception as e:
            logger.warning(f"LLM asset extraction failed: {e}. Using empty asset list.")
            return []

    def _dict_to_asset(self, d: Dict[str, Any]) -> NetworkAsset:
        """Convert raw LLM dict → NetworkAsset dataclass."""
        controls_raw = d.get("controls", {})
        if isinstance(controls_raw, dict):
            controls = SecurityControls(
                edr=bool(controls_raw.get("edr", False)),
                siem=bool(controls_raw.get("siem", False)),
                av=bool(controls_raw.get("av", False)),
                ndr=bool(controls_raw.get("ndr", False)),
                waf=bool(controls_raw.get("waf", False)),
                mfa=bool(controls_raw.get("mfa", False)),
                dlp=bool(controls_raw.get("dlp", False)),
            )
        else:
            controls = SecurityControls()

        return NetworkAsset(
            host_id=str(d.get("host_id", f"HOST-{uuid.uuid4().hex[:4].upper()}")),
            hostname=str(d.get("hostname", d.get("host_id", "unknown"))),
            ip=str(d.get("ip", "unknown")),
            zone=str(d.get("zone", "Internal")),
            os=str(d.get("os", "unknown")),
            services=list(d.get("services", [])),
            vulnerabilities=list(d.get("vulnerabilities", [])),
            patch_status=str(d.get("patch_status", PatchStatus.UNKNOWN.value)),
            is_critical=bool(d.get("is_critical", False)),
            controls=controls,
            notes=str(d.get("notes", "")),
        )

    def _store_to_zep(self, graph_name: str, assets: List[NetworkAsset], raw_text: str) -> str:
        """
        Lưu assets vào Zep graph.
        1. Create graph
        2. Set CYBER_ONTOLOGY
        3. Add text batches (asset descriptions + raw text)
        """
        graph_id = self.graph_service.create_graph(graph_name)
        logger.info(f"Created Zep graph: {graph_id}")

        self.graph_service.set_ontology(graph_id, CYBER_ONTOLOGY)
        logger.info("Set cyber ontology on graph")

        # Build text chunks: 1 chunk per asset + raw text chunks
        from .text_processor import TextProcessor
        asset_texts = [a.to_zep_text() for a in assets]
        raw_chunks = TextProcessor.split_text(raw_text, chunk_size=600, overlap=50)

        all_chunks = asset_texts + raw_chunks
        logger.info(f"Sending {len(all_chunks)} chunks to Zep ({len(asset_texts)} asset + {len(raw_chunks)} raw)")

        episode_uuids = self.graph_service.add_text_batches(
            graph_id, all_chunks, batch_size=3,
            progress_callback=lambda msg, _: logger.debug(msg)
        )

        self.graph_service._wait_for_episodes(
            episode_uuids,
            progress_callback=lambda msg, _: logger.debug(msg)
        )
        return graph_id

    def _merge_assets(
        self,
        existing: List[NetworkAsset],
        new_assets: List[NetworkAsset]
    ) -> List[NetworkAsset]:
        """Dedup assets by hostname — keep existing, update if new has more info."""
        index = {a.hostname: a for a in existing}
        for asset in new_assets:
            if asset.hostname not in index:
                index[asset.hostname] = asset
            else:
                # Merge: fill in missing fields from new
                old = index[asset.hostname]
                if old.ip == "unknown" and asset.ip != "unknown":
                    old.ip = asset.ip
                if not old.vulnerabilities and asset.vulnerabilities:
                    old.vulnerabilities = asset.vulnerabilities
                if not old.services and asset.services:
                    old.services = asset.services
        return list(index.values())
