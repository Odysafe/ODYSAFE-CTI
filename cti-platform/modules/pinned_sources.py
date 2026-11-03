"""
Pinned external sources for reproducible installs and supply-chain control.
Update scripts/pinned_sources.json when bumping third-party snapshots.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

PINNED_SOURCES_FILE = Path(__file__).resolve().parent.parent.parent / "scripts" / "pinned_sources.json"


def load_pinned_sources() -> Dict[str, Any]:
    with open(PINNED_SOURCES_FILE, encoding="utf-8") as handle:
        return json.load(handle)


def get_mitre_enterprise_attack_url(use_latest: bool = False) -> str:
    data = load_pinned_sources()
    mitre = data["mitre_attack"]
    if use_latest:
        return mitre["latest_url"]
    commit = mitre["commit"]
    path = mitre["path"]
    return (
        f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        f"{commit}/{path}"
    )


def get_pinned_repo(name: str) -> Dict[str, str]:
    data = load_pinned_sources()
    if name not in data:
        raise KeyError(f"Unknown pinned repository: {name}")
    repo = data[name]
    return {"url": repo["url"], "commit": repo["commit"]}


def clone_repo_at_commit(
    url: str,
    target: Path,
    commit: str,
    timeout: int = 120,
) -> bool:
    """Shallow clone a Git repository at a pinned commit."""
    target = Path(target)
    if target.exists():
        import shutil
        shutil.rmtree(target, ignore_errors=True)

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "init", str(target)], capture_output=True, check=True, timeout=10)
        subprocess.run(
            ["git", "-C", str(target), "remote", "add", "origin", url],
            capture_output=True,
            check=True,
            timeout=10,
        )
        fetch = subprocess.run(
            ["git", "-C", str(target), "fetch", "--depth", "1", "origin", commit],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if fetch.returncode != 0:
            logger.error("Git fetch failed for %s@%s: %s", url, commit, fetch.stderr)
            return False

        checkout = subprocess.run(
            ["git", "-C", str(target), "checkout", "FETCH_HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if checkout.returncode != 0:
            logger.error("Git checkout failed for %s@%s: %s", url, commit, checkout.stderr)
            return False

        logger.info("Cloned %s at pinned commit %s", url, commit[:12])
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        logger.error("Pinned clone failed for %s: %s", url, exc)
        return False


def clone_pinned_repo(name: str, target: Path, timeout: int = 120) -> bool:
    repo = get_pinned_repo(name)
    return clone_repo_at_commit(repo["url"], target, repo["commit"], timeout=timeout)
