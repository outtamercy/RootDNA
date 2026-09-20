"""On-demand RootDNA learning scan. It suggests; it never creates routes."""

from pathlib import Path
from typing import Dict, List


# Retained for RootDNA's explicit, user-invoked learning pass. FW itself must
# not consume these as automatic destinations or junction targets.
HOT_FOLDERS: List[str] = [
    "SKSE/Plugins/CommunityShaders",
    "UnifiedWaterCache",
    "ShaderCache",
    "CellOffsets",
    "SSEEdit Cache",
    "enbseries",
    "textures",
    "meshes",
    "interface",
    "MCM",
    "backup",
    "Plugins",
    "SKSE/Plugins",
]


def scan_active_mods(mods_path: Path, active_mods: List[str]) -> Dict[str, Path]:
    """Return candidate paths for a manual RootDNA review, deepest first.

    Callers must present the candidates to the user. This function does not
    claim ownership, move files, or create links. That's where old FW went off
    the rails, and we are not doing that sequel.
    """
    redirects: Dict[str, Path] = {}
    for mod_name in reversed(active_mods):
        mod_root = mods_path / mod_name
        if not mod_root.is_dir():
            continue
        for rel in HOT_FOLDERS:
            candidate = mod_root / rel
            if candidate.is_dir() and rel not in redirects:
                redirects[rel] = candidate.resolve()
    return redirects
