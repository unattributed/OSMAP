#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM from locked Cargo metadata."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            text=True,
        )
    )
    packages = sorted(metadata["packages"], key=lambda item: item["id"])
    components = []
    for package in packages:
        component = {
            "type": "library",
            "bom-ref": package["id"],
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        if package.get("source"):
            component["externalReferences"] = [
                {"type": "distribution", "url": package["source"]}
            ]
        components.append(component)
    dependencies = [
        {
            "ref": node["id"],
            "dependsOn": sorted(dependency["pkg"] for dependency in node["deps"]),
        }
        for node in sorted(metadata["resolve"]["nodes"], key=lambda item: item["id"])
    ]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "osmap",
            }
        },
        "components": components,
        "dependencies": dependencies,
    }
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
