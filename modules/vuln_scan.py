from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def scan_vulnerabilities(domain, output_dir=None):
    output_dir = Path(output_dir) if output_dir else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return {
            "domain": domain,
            "status": "skipped",
            "message": "Nuclei CLI is not installed or not on PATH. Install it to enable vulnerability scanning.",
            "findings": [],
        }

    output_file = output_dir / f"{domain.replace('.', '_')}_nuclei.txt"

    try:
        command = [nuclei_path, "-u", f"https://{domain}", "-o", str(output_file)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)

        if result.returncode not in (0, 1):
            return {
                "domain": domain,
                "status": "failed",
                "message": result.stderr.strip() or result.stdout.strip() or "Nuclei execution failed.",
                "findings": [],
            }

        if output_file.exists() and output_file.stat().st_size > 0:
            with output_file.open("r", encoding="utf-8") as handle:
                findings = [line.strip() for line in handle if line.strip()]
            return {
                "domain": domain,
                "status": "ok",
                "message": "Nuclei scan completed.",
                "findings": findings,
            }

        return {
            "domain": domain,
            "status": "ok",
            "message": "No findings returned by Nuclei.",
            "findings": [],
        }
    except FileNotFoundError:
        return {
            "domain": domain,
            "status": "skipped",
            "message": "Nuclei binary is unavailable on this machine.",
            "findings": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "domain": domain,
            "status": "failed",
            "message": "Nuclei scan timed out.",
            "findings": [],
        }
    except Exception as exc:
        return {
            "domain": domain,
            "status": "failed",
            "message": str(exc),
            "findings": [],
        }
