import asyncio
import json
import logging
from pathlib import Path
from typing import Iterable

from .httpx_runner import HttpxRunner
from .katana_runner import KatanaRunner
from .parser import EndpointParser
from .subfinder_runner import SubfinderRunner
from .wayback_runner import WaybackRunner

logger = logging.getLogger("rastro.recon")


class ReconRunner:
    def __init__(self, target_root: Path):
        self.target_root = target_root
        self.recon_dir = self.target_root / "recon"
        self.endpoints_dir = self.target_root / "endpoints"
        self.analysis_dir = self.target_root / "analysis"
        self.logs_dir = self.target_root / "logs"
        self.screenshots_dir = self.target_root / "screenshots"
        for folder in [self.recon_dir, self.endpoints_dir, self.analysis_dir, self.logs_dir, self.screenshots_dir]:
            folder.mkdir(parents=True, exist_ok=True)
        self.subfinder = SubfinderRunner(self.recon_dir)
        self.httpx = HttpxRunner(self.recon_dir)
        self.katana = KatanaRunner(self.recon_dir)
        self.wayback = WaybackRunner(self.recon_dir)
        self.parser = EndpointParser()

    async def run_pipeline(self, domain: str, mode: str = "FAST") -> dict[str, str]:
        domain = domain.strip()
        if not domain:
            raise ValueError("Domain is required for recon.")

        outputs: dict[str, str] = {}
        source_files = []

        subfinder_path = await self.subfinder.run_subfinder(domain, "subfinder.txt")
        outputs["subfinder"] = str(subfinder_path)

        wayback_task = asyncio.create_task(self.wayback.run_wayback(domain, "wayback.txt"))
        katana_task = asyncio.create_task(self.katana.run_katana(domain, "katana.json"))

        if mode.upper() in {"DEEP", "API"}:
            httpx_path = await self.httpx.run_httpx(subfinder_path, "httpx.json")
            outputs["httpx"] = str(httpx_path)
            source_files.append(httpx_path)

        wayback_path = await wayback_task
        outputs["wayback"] = str(wayback_path)
        source_files.append(wayback_path)

        katana_path = await katana_task
        outputs["katana"] = str(katana_path)
        source_files.append(katana_path)

        normalized_path = self.endpoints_dir / "normalized_endpoints.json"
        parser_output = self.parser.parse_files(source_files, normalized_path)
        outputs["normalized_endpoints"] = str(parser_output)

        endpoint_entries = []
        if parser_output.exists():
            with parser_output.open("r", encoding="utf-8", errors="ignore") as file:
                endpoint_entries = json.load(file)

        summary_path = self.analysis_dir / "summary.json"
        summary_data = {
            "domain": domain,
            "mode": mode.upper(),
            "outputs": outputs,
            "endpoint_count": len(endpoint_entries),
        }
        summary_path.write_text(json.dumps(summary_data, indent=2))
        outputs["summary"] = str(summary_path)

        logger.info("Recon pipeline completed for %s", domain)
        return outputs

    async def join_results(self, paths: Iterable[Path], out_file: str) -> Path:
        target = self.target_root / out_file
        with target.open("wb") as writer:
            for path in paths:
                if path.exists():
                    writer.write(path.read_bytes())
                    writer.write(b"\n")
        return target
