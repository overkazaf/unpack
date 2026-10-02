from __future__ import annotations

import hashlib
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def _quick_key(path: Path) -> str:
    size = path.stat().st_size
    head = path.read_bytes()[:32]
    return f"{size}:{hashlib.md5(head).hexdigest()}"


def dedup_dex_files(dex_dir: Path) -> list[Path]:
    dex_files = sorted(dex_dir.glob("*.dex"))
    if len(dex_files) <= 1:
        return dex_files

    quick_groups: dict[str, list[Path]] = {}
    for p in dex_files:
        try:
            key = _quick_key(p)
        except OSError:
            continue
        quick_groups.setdefault(key, []).append(p)

    unique: list[Path] = []
    removed: list[Path] = []
    seen_hashes: set[str] = set()

    for group in quick_groups.values():
        if len(group) == 1:
            unique.append(group[0])
            continue

        for p in group:
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            if h in seen_hashes:
                removed.append(p)
                p.unlink()
                log.info("removed duplicate: %s", p.name)
            else:
                seen_hashes.add(h)
                unique.append(p)

    for p in removed:
        log.debug("dedup removed: %s", p.name)

    return sorted(unique)
