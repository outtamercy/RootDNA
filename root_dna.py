"""Optional RootDNA module. Exact declared links after explicit shallow discovery."""
from __future__ import annotations
import ctypes, hashlib, html, json, logging, os, re, shutil, subprocess, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QTextCursor
from PyQt6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSizePolicy,
                             QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

MODULE_API = 1
MODULE_MARKER = "root_dna.module.json"
logger = logging.getLogger("FileWatchdog")

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def _json(path, default):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError): return default
def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True); temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
def _inside(path, root):
    try: path.relative_to(root); return True
    except ValueError: return False
def _normal(path): return Path(os.path.normcase(os.path.abspath(path)))
def _is_reparse(path):
    try:
        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attributes != 0xFFFFFFFF and bool(attributes & 0x0400)
    except OSError: return False

class RootDNA:
    """Manifest-first root deployment. If it isn't declared, it isn't ours."""
    def __init__(self, paths, plugin_dir):
        self.paths, self.plugin_dir = paths, Path(plugin_dir)
        safe_profile = quote(paths.profile_name, safe="")
        self.state = self.plugin_dir.parent / "data" / "root_dna" / "profiles" / safe_profile
        self.definition_path = self.state / "rootdna_definition.json"
        self.manifest_path = self.state / "fw_manifest.json"
        self.audit_path = self.state / "fw_audit.log"
        self.status_path = self.state / "rootdna_status.log"
        self.lock_path = self.state / "rootdna.lock"
        self.cache_root = paths.mods / "FW-RootCache" / safe_profile
    def definition(self): return _json(self.definition_path, {})
    def manifest(self): return _json(self.manifest_path, {"schema_version": 1, "links": []})
    def game_identity(self):
        root = self.paths.game_root
        return {"name": self.paths.game_name or (root.name if root else "unknown"),
                "root": str(_normal(root)) if root else ""}
    def audit(self, event, detail):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as stream: stream.write(f"{_now()} {event} {detail}\n")
        logger.info("RootDNA %s: %s", event, detail)
    def append_status(self, detail, paths=()):
        """Human-facing running history for this open RootDNA session."""
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        with self.status_path.open("a", encoding="utf-8") as stream:
            stream.write(f"[{_now()}]\n{detail}\n")
            for path in dict.fromkeys(str(item) for item in paths): stream.write(f"Open: {path}\n")
            stream.write("\n")
    def reset_status(self):
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text("", encoding="utf-8")
    def foreign_deployments(self):
        """Read only RootDNA's own manifests. Never go snooping through game root."""
        game_root = self.paths.game_root
        if not game_root or not self.state.parent.is_dir(): return []
        found = []
        for candidate in self.state.parent.glob("*/fw_manifest.json"):
            if candidate == self.manifest_path: continue
            manifest = _json(candidate, {})
            if manifest.get("links") and _normal(manifest.get("game_root", "")) == _normal(game_root):
                found.append(manifest.get("profile", candidate.parent.name))
        return found
    def create_template(self):
        if self.definition_path.exists(): raise RuntimeError("RootDNA definition already exists. It won't trample your homework.")
        game = str(self.paths.game_root) if self.paths.game_root else ""
        _atomic_json(self.definition_path, {
            "schema_version": 1, "profile": self.paths.profile_name, "game_root": game, "game_identity": self.game_identity(),
            "protected_processes": list(self.paths.root_executables()), "payloads": [], "pending_adoptions": [], "learned_adoptions": [],
            "placement_rules": {}
        })
        self.audit("CREATED", "blank profile definition")
    def stock_game_candidates(self):
        """Small, declared-shape checks on enabled mods. No recursive rummaging."""
        found = []
        for mod_name, enabled in self.paths.listed_mods():
            mod_root = self.paths.mods / mod_name
            for source_name, source in ((".", mod_root), ("root", mod_root / "root")):
                for executable in self.paths.game_executables():
                    if (source / executable).is_file() and (source / "Data").is_dir():
                        found.append({"mod": mod_name, "source": source_name, "path": source, "game": executable, "enabled": enabled})
        return found
    def root_payload_candidates(self):
        """Shallow game-root inventory. The user adopts; RootDNA just points."""
        game_root = self.paths.game_root
        if not game_root or not game_root.is_dir(): return []
        managed = {str(_normal(Path(record.get("target", "")))).lower() for record in self.manifest().get("links", [])}
        def state_for(items):
            matches = [str(_normal(game_root / name)).lower() in managed for name, _kind in items]
            return "managed" if matches and all(matches) else ("partly managed — hands off" if any(matches) else "available")
        signatures = (
            ("creation-kit-ae", "Creation Kit AE root payload", "RootDNA - Creation Kit", (
                "CreationKit.exe", "CreationKit.ini", "CreationKitCustom.ini", "CreationKitPrefs.ini",
                "CreationKitPlatformExtended_SSE_Databases.pak", "CreationKitPlatformExtended_SSE_Dialogs.pak",
                "CreationKitPlatformExtended.toml", "CreationKitPlatformExtendedCustomTheme.toml",
                "CreationKitPlatformExtendedMessagesBlacklist.txt")),
            ("ck-platform-extended", "CK Platform Extended root payload", "RootDNA - CK Platform Extended", (
                "ckpe_loader.exe", "CKPE.Common.dll", "CKPE.dll", "CKPE.Installer.exe", "CKPE.PluginAPI.dll", "CKPE.SkyrimSE.dll")),
            ("skse-ae", "SKSE AE root payload", "RootDNA - SKSE", (
                "skse64_loader.exe", "skse64_loader_original.exe", "skse64_steam_loader.dll", "skse64_1_6_1170.dll")),
            ("enb", "ENB root payload", "RootDNA - ENB", (
                "d3d11.dll", "d3dcompiler_46e.dll", "enbseries", "enbseries.ini", "enblocal.ini", "enbhost.exe")),
            ("reshade", "ReShade root payload", "RootDNA - ReShade", (
                "dxgi.dll", "ReShade.ini", "reshade-shaders")),
            ("engine-fixes", "Engine Fixes Part 2 root payload", "RootDNA - Engine Fixes", (
                "d3dx9_42.dll", "tbb.dll", "tbbmalloc.dll")),
            ("opencomposite", "OpenComposite root payload", "RootDNA - OpenComposite", (
                "openvr_api.dll", "opencomposite.ini")),
            ("spatial-audio", "Spatial audio root payload", "RootDNA - Spatial Audio", (
                "x3daudio1_7.dll", "hrtf")),
        )
        found = []
        claimed = set()
        for ident, title, mod, names in signatures:
            present = tuple((name, "directory" if (game_root / name).is_dir() else "file") for name in names if (game_root / name).is_file() or (game_root / name).is_dir())
            # A payload needs its actual anchor. Don't offer an ENB because a
            # random ini exists, or SKSE because a stray old loader got left behind.
            # d3d11.dll alone is ambiguous: ENB and some ReShade installs use
            # it. An ENB config is the needed receipt; otherwise it stays
            # unclassified for the user to inspect.
            anchor = {"creation-kit-ae": "CreationKit.exe", "ck-platform-extended": "ckpe_loader.exe", "skse-ae": "skse64_loader.exe", "enb": "enbseries.ini", "reshade": "dxgi.dll", "engine-fixes": "d3dx9_42.dll", "opencomposite": "openvr_api.dll", "spatial-audio": "x3daudio1_7.dll"}[ident]
            if any(name == anchor for name, _kind in present):
                claimed.update(name.lower() for name, _kind in present)
                found.append({"kind": "game-root-payload", "id": ident, "title": title, "mod": mod,
                              "source": game_root, "status": state_for(present), "items": present, "count": len(present),
                              # Header Select All is for the boring, known stuff.
                              # Anything heuristic gets its own deliberate tick.
                              "auto_select": True})
        # Vanilla's root furniture stays out of the candidate pile. Everything
        # else is merely shown as an unclassified direct-root payload—never
        # grabbed until the user ticks it.
        stock = {"bink2w64.dll", "d3dcompiler_46.dll", "installscript.vdf", "skyrim_default.ini", "skyrim.ccc",
                 "skyrimreservedaddonindexes.txt", "skyrimse.exe", "skyrimselauncher.exe", "steam_api64.dll",
                 "high.ini", "medium.ini", "low.ini", "ultra.ini"}
        stock.update(name.lower() for name in self.paths.game_executables())
        ignored = stock | claimed | {"data", "_commonredist", "logs", "crashdumps", "modorganizer"}
        loose = []
        for item in game_root.iterdir():
            if item.name.lower() in ignored or item.name.startswith("."): continue
            if item.is_dir() or item.is_file(): loose.append((item.name, "directory" if item.is_dir() else "file"))
        if loose:
            digest = hashlib.sha1("|".join(name.lower() for name, _kind in loose).encode("utf-8")).hexdigest()[:10]
            loose_state = state_for(tuple(loose))
            found.append({"kind": "game-root-payload", "id": "unclassified-" + digest, "title": "Unclassified game-root payload", "mod": "RootDNA - Unclassified Root Payload",
                          "source": game_root, "status": "needs your eyeballs" if loose_state == "available" else loose_state, "items": tuple(loose), "count": len(loose), "auto_select": False})
        return found
    def mod_root_candidates(self):
        """Check only a mod's top level and explicit Root wrappers. No crawl."""
        wrappers = ("root", "game root", "gameroot", "game_root", "root files")
        skipped = {"data", "fomod", "optional files", "docs", "documentation", "screenshots", "meta.ini"}
        game_root = self.paths.game_root
        live_ck = game_root / "CreationKit.exe" if game_root else None
        # The selected physical game root wins for known payload groups. A
        # duplicate mod copy is an alternate source, not another thing that
        # gets to fight over CreationKit.exe or CKPE's shared support files.
        physical_names = {name.lower() for candidate in self.root_payload_candidates() for name, _kind in candidate["items"]}
        found = []
        learned = {item.get("candidate_id"): item for item in self.definition().get("learned_adoptions", [])}
        for mod, enabled in self.paths.listed_mods():
            if mod.lower().startswith("rootdna - "): continue
            lowered_mod = mod.lower()
            mod_root = self.paths.mods / mod
            if not mod_root.is_dir(): continue
            sources = [(".", mod_root)]
            sources.extend((child.name, child) for child in mod_root.iterdir() if child.is_dir() and child.name.lower() in wrappers)
            for source_name, source in sources:
                if source_name == "." and any(child.is_dir() and child.name.lower() in wrappers for child in mod_root.iterdir()): continue
                items = tuple((child.name, "directory" if child.is_dir() else "file") for child in source.iterdir() if child.name.lower() not in skipped and (child.is_file() or child.is_dir()))
                if not items: continue
                # Bare mod roots need an actual loader/proxy binary. Root-level
                # INIs are normal mod guts all the time, and treating those as
                # root payloads is how you summon a thousand rows.
                if source_name == "." and not any(kind == "file" and Path(name).suffix.lower() in {".exe", ".dll", ".asi"} for name, kind in items): continue
                source_ck = source / "CreationKit.exe"
                # When the selected game already has CK, RootDNA migrates that
                # exact copy. Extra CK mods are alternates, not additional
                # candidates for the same game-root filenames.
                if source_ck.is_file() and live_ck and live_ck.is_file(): continue
                if any(name.lower() in physical_names for name, _kind in items): continue
                digest = hashlib.sha1(f"{mod}|{source_name}".encode("utf-8")).hexdigest()[:10]
                candidate_id = "mod-root-" + digest
                learned_rule = learned.get(candidate_id)
                found.append({"kind": "mod-root-payload", "id": candidate_id, "title": f"{mod} — root payload", "mod": mod, "source_name": source_name,
                              "source": source, "status": "learned — managed" if learned_rule else ("enabled — available" if enabled else "disabled — available"), "items": items, "count": len(items),
                              "auto_select": False})
        return found
    def pending_adoptions(self):
        definition = self.definition(); pending = definition.get("pending_adoptions", [])
        if not pending and definition and not any(item.get("links") for item in definition.get("payloads", [])):
            return [item["id"] for item in self.root_payload_candidates()]
        return pending
    def adopt_stock_game(self, candidate):
        definition = self.definition()
        if not definition: raise RuntimeError("Create the RootDNA profile template first.")
        candidates = {(item["mod"], item["source"]): item for item in self.stock_game_candidates()}
        chosen = candidates.get((candidate["mod"], candidate["source"]))
        if not chosen: raise RuntimeError("That clean-copy candidate changed since the scan. RootDNA won't guess.")
        definition["stock_game"] = {"mod": chosen["mod"], "source": chosen["source"], "game": chosen["game"]}
        _atomic_json(self.definition_path, definition); self.audit("ADOPTED", f"clean game source {chosen['path']}")
    def _validate_stock_game(self, definition, game_root):
        stock = definition.get("stock_game")
        if not stock: return None
        mod, source_name, executable = stock.get("mod"), stock.get("source"), stock.get("game")
        if not isinstance(mod, str) or source_name not in {".", "root"} or executable not in self.paths.game_executables(): raise RuntimeError("Stock-game source definition is malformed.")
        source = (self.paths.mods / mod / source_name).resolve(); mod_root = (self.paths.mods / mod).resolve()
        if not _inside(source, mod_root) or not (source / executable).is_file() or not (source / "Data").is_dir(): raise RuntimeError("Declared clean game copy no longer has the expected game shape.")
        live_executable, live_data = game_root / executable, game_root / "Data"
        if not live_executable.is_file() or not live_data.is_dir(): raise RuntimeError("Clean copy game family does not match MO2's active game root.")
        if source.joinpath(executable).stat().st_size != live_executable.stat().st_size:
            raise RuntimeError("Clean-copy version does not match the active game. Refusing a mixed build.")
        return source
    def _validated_definition(self):
        definition = self.definition()
        if definition.get("schema_version") != 1: raise RuntimeError("RootDNA needs a schema_version 1 definition. No guessing games.")
        if definition.get("profile") != self.paths.profile_name: raise RuntimeError("This RootDNA definition belongs to another MO2 profile. Hands off.")
        game_root = self.paths.game_root
        if not game_root or not game_root.is_dir(): raise RuntimeError("MO2 did not hand RootDNA a usable game path.")
        declared_game = definition.get("game_root", "")
        # v1's first template build wrote Qt's object repr instead of its path.
        # Repair only that obviously broken, FW-generated value.
        if "<PyQt6.QtCore.QDir object" in declared_game:
            definition["game_root"] = str(game_root); _atomic_json(self.definition_path, definition)
            self.audit("VALIDATED", "repaired bad Qt game-path placeholder")
            declared_game = str(game_root)
        if declared_game and _normal(declared_game) != _normal(game_root): raise RuntimeError("Definition game root does not match MO2's active game. Nope.")
        identity = self.game_identity()
        if definition.get("game_identity") and definition["game_identity"] != identity: raise RuntimeError("Definition belongs to another managed game. Hands off.")
        if not definition.get("game_identity"):
            definition["game_identity"] = identity; _atomic_json(self.definition_path, definition)
        payloads = definition.get("payloads")
        if not isinstance(payloads, list): raise RuntimeError("RootDNA payload list is missing.")
        game_root = game_root.resolve(); self._validate_stock_game(definition, game_root)
        return definition, game_root
    def _plans(self):
        definition, game_root = self._validated_definition(); plans = []
        for payload in definition["payloads"]:
            for required in ("id", "mod", "source", "links"):
                if required not in payload: raise RuntimeError(f"Payload is missing {required}.")
            links = payload["links"]
            if not isinstance(links, list): raise RuntimeError(f"{payload['id']}: links must be a list.")
            # Empty template payloads are allowed. They are instructions, not
            # a half-deployed mod that should throw a bogus path tantrum.
            if not links: continue
            source_root = (self.paths.mods / payload["mod"] / payload["source"]).resolve()
            mod_root = (self.paths.mods / payload["mod"]).resolve()
            if not source_root.is_dir() or not _inside(source_root, mod_root): raise RuntimeError(f"{payload['id']}: make {self.paths.mods / payload['mod'] / payload['source']} first, then put its declared root payload there.")
            for item in links:
                source_rel, game_rel = item.get("source"), item.get("game")
                kind = item.get("kind")
                if kind not in {"directory", "file"} or not isinstance(source_rel, str) or not isinstance(game_rel, str): raise RuntimeError(f"{payload['id']}: every link needs source, game, and kind.")
                source = (source_root / source_rel).resolve(); target = _normal(game_root / game_rel)
                if not _inside(source, source_root) or not _inside(target, _normal(game_root)): raise RuntimeError(f"{payload['id']}: a path escaped its declared lane. Hard stop.")
                if not source.exists() or (kind == "directory" and not source.is_dir()) or (kind == "file" and not source.is_file()): raise RuntimeError(f"{payload['id']}: source missing or wrong type: {source}")
                plans.append({"id": payload["id"], "source": source, "target": target, "kind": kind, "return_to_game_on_remove": bool(payload.get("return_to_game_on_remove", False))})
        by_target = {}
        for plan in plans: by_target.setdefault(str(plan["target"]).lower(), []).append(plan)
        collisions = [(target, items) for target, items in by_target.items() if len(items) > 1]
        if collisions:
            receipts = []
            for target, items in collisions[:4]:
                owners = " vs ".join(f"{item['id']} [{item['source']}]" for item in items)
                receipts.append(f"{target}: {owners}")
            more = f" (+{len(collisions) - 4} more)" if len(collisions) > 4 else ""
            raise RuntimeError("RootDNA target collision — " + "; ".join(receipts) + more)
        return definition, game_root, plans
    def _running(self, names):
        try:
            output = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, creationflags=0x08000000)
        except OSError: return []
        lowered = output.lower(); return [name for name in names if f'"{name.lower()}"' in lowered]
    def _root_builder_present(self):
        """Root Builder is an MO2 plugin. A stale config is fine; a live plugin ain't."""
        def matches(name):
            return "rootbuilder" in "".join(char for char in name.lower() if char.isalnum())
        hits = []
        plugins_root = self.plugin_dir.parent
        try:
            hits.extend(f"MO2 plugin: {item.name}" for item in plugins_root.iterdir() if matches(item.name))
        except OSError:
            pass
        return hits
    @contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try: handle = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError: raise RuntimeError("RootDNA is already busy, or a previous run left a lock. Check its audit before touching it.")
        try:
            os.write(handle, str(os.getpid()).encode("ascii")); yield
        finally:
            os.close(handle)
            try: self.lock_path.unlink()
            except OSError: pass
    def _guard(self, definition):
        root_builder = self._root_builder_present()
        if root_builder:
            raise RuntimeError("Root Builder is present (" + "; ".join(root_builder) + "). RootDNA won't share root ownership. Remove/disable Root Builder first.")
        running = self._running(definition.get("protected_processes", []))
        if running: raise RuntimeError("RootDNA won't touch root files while this is running: " + ", ".join(running))
    def preview(self):
        definition, game_root, plans = self._plans(); self._guard(definition); manifest = self.manifest(); existing = {item["target"]: item for item in manifest.get("links", [])}
        result = []
        for plan in plans:
            target = plan["target"]; record = existing.get(str(target))
            if record: state = "managed"
            elif target.exists() or target.is_symlink(): state = "backup needed" if not _is_reparse(target) else "foreign reparse point — refused"
            else: state = "ready"
            result.append((plan, state))
        return result
    def _signature(self, plan):
        raw = f"rootdna-v1|{plan['id']}|{plan['kind']}|{_normal(plan['source'])}|{_normal(plan['target'])}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    def _save_manifest(self, game_root, records):
        _atomic_json(self.manifest_path, {"schema_version": 1, "profile": self.paths.profile_name, "game_root": str(game_root), "game_identity": self.game_identity(), "links": list(records.values())})
    def _marker_matches(self, marker, signature, target, source):
        data = _json(marker, {})
        return data.get("signature") == signature and data.get("target") == str(target) and data.get("source") == str(source)
    def _disk_matches(self, record, target, source):
        if record.get("link_mode") == "hardlink":
            try: return target.is_file() and os.path.samefile(target, source)
            except OSError: return False
        return _is_reparse(target) and target.resolve() == source.resolve()
    def deploy(self):
        definition = self.definition()
        definition, game_root, plans = self._plans()
        if not plans: raise RuntimeError("No RootDNA links are declared yet. Fill the payload definition first.")
        with self._locked():
            self._guard(definition); preview = self.preview()
            foreign = self.foreign_deployments()
            if foreign: raise RuntimeError("RootDNA is deployed for another profile: " + ", ".join(foreign) + ". Switch back and remove it there first.")
            bad = [state for _plan, state in preview if state == "foreign reparse point — refused"]
            if bad: raise RuntimeError("A declared game path is already somebody else's reparse point. RootDNA will not play landlord.")
            manifest = self.manifest(); records = {item["target"]: item for item in manifest.get("links", [])}; operation = uuid.uuid4().hex
            for plan, state in preview:
                target = plan["target"]; source = plan["source"]
                if state == "managed":
                    record = records[str(target)]
                    if (record.get("signature") != self._signature(plan) or not self._marker_matches(Path(record.get("marker", "")), self._signature(plan), target, source)
                            or not self._disk_matches(record, target, source)):
                        raise RuntimeError(f"Tampered RootDNA link: {target}. Refusing the lot.")
                    continue
                backup = ""
                if target.exists() or target.is_symlink():
                    backup_path = self.cache_root / "backups" / operation / target.relative_to(game_root)
                    backup_path.parent.mkdir(parents=True, exist_ok=True); shutil.move(str(target), str(backup_path)); backup = str(backup_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                if plan["kind"] == "directory":
                    completed = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(target), str(source)], capture_output=True, text=True, creationflags=0x08000000)
                    if completed.returncode: raise RuntimeError(f"Couldn't make junction {target}: {completed.stderr or completed.stdout}")
                    link_mode = "junction"
                else:
                    try: os.symlink(source, target, target_is_directory=False); link_mode = "symlink"
                    except OSError:
                        if source.drive.lower() != target.drive.lower(): raise RuntimeError(f"Couldn't make file link {target}; symlinks need permission and hardlinks cannot cross drives.")
                        os.link(source, target); link_mode = "hardlink"
                marker = self.cache_root / "markers" / (self._signature(plan) + ".json")
                _atomic_json(marker, {"signature": self._signature(plan), "target": str(target), "source": str(source), "created": _now()})
                records[str(target)] = {"id": plan["id"], "source": str(source), "target": str(target), "kind": plan["kind"], "link_mode": link_mode, "return_to_game_on_remove": plan["return_to_game_on_remove"], "signature": self._signature(plan), "backup": backup, "marker": str(marker)}
                # Persist every completed root link. A later failure is then
                # removable from the manifest instead of becoming an orphan.
                self._save_manifest(game_root, records)
                self.audit("CREATED", f"{source} -> {target}")
            self._save_manifest(game_root, records)
    @staticmethod
    def _mod_name(line):
        return line[1:].strip() if line[:1] in "+-" else ""
    @staticmethod
    def _payload_family(payload):
        haystack = (payload.get("id", "") + " " + payload.get("title", "")).lower()
        if "skse" in haystack or "script extender" in haystack: return "script-extender"
        if "creation kit" in haystack or "ckpe" in haystack or "platform extended" in haystack: return "creation-kit"
        if "opencomposite" in haystack or "openvr" in haystack: return "vr-runtime"
        if "enb" in haystack or "reshade" in haystack: return "visual-wrapper"
        if "engine" in haystack or "inject" in haystack: return "runtime-injector"
        return "root-payload"
    @staticmethod
    def _separator(name):
        return name.lower().endswith("_separator")
    def _write_payload_metadata(self, name, payload, rule):
        """Tiny self-describing hint for sorters. Unknown INI sections are harmless to MO2."""
        meta = self.paths.mods / name / "meta.ini"
        try: text = meta.read_text(encoding="utf-8")
        except OSError: text = ""
        if not text.strip():
            text = ("[General]\n" f"gameName={self.paths.game_name}\nmodid=0\nversion=RootDNA\n"
                    "category=\"-1,\"\ncomments=RootDNA-managed game-root payload.\n"
                    "notes=RootDNA owns this root payload; ordinary mod files do not belong here.\n")
        text = re.sub(r"(?ims)^\[RootDNA\]\s*.*?(?=^\[|\Z)", "", text).rstrip() + "\n\n"
        text += ("[RootDNA]\nmanaged=true\n"
                 f"payloadId={payload.get('id', '')}\nfamily={self._payload_family(payload)}\n"
                 "sortHint=keep with the matching root-payload family\n"
                 f"anchor={rule.get('anchor', '')}\nanchorSide={rule.get('side', '')}\n"
                 f"game={self.game_identity().get('name', '')}\n"
                 "notes=Placement is learned from this profile. ModSlut may use family; RootDNA never guesses separators.\n")
        meta.parent.mkdir(parents=True, exist_ok=True); meta.write_text(text, encoding="utf-8")
    def _place_payload_mod(self, name, payload, definition):
        """Keep a learned raw modlist position, never a made-up numeric priority."""
        path = self.paths.modlist_path
        if not path.is_file(): raise RuntimeError("MO2 profile modlist is missing.")
        lines = path.read_text(encoding="utf-8").splitlines()
        current = next((index for index, line in enumerate(lines) if self._mod_name(line) == name), None)
        rules = definition.setdefault("placement_rules", {}); rule = rules.setdefault(payload.get("id", name), {})
        if current is None:
            anchor, side = rule.get("anchor"), rule.get("side")
            insert_at = len(lines)
            if anchor:
                anchor_index = next((index for index, line in enumerate(lines) if self._mod_name(line) == anchor), None)
                if anchor_index is not None: insert_at = anchor_index + (1 if side == "after" else 0)
            lines.insert(insert_at, "+" + name)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            current = insert_at
        rule.setdefault("baseline_index", current)
        self._write_payload_metadata(name, payload, rule)
        _atomic_json(self.definition_path, definition)
    def learn_placement_rules(self):
        """Notice deliberate user/sorter moves. Separators help, but are never required."""
        definition = self.definition(); path = self.paths.modlist_path
        if not definition or not path.is_file(): return
        lines = path.read_text(encoding="utf-8").splitlines()
        payloads = definition.get("payloads", []); owned = {item.get("mod") for item in payloads}
        rules = definition.setdefault("placement_rules", {}); changed = False
        for payload in payloads:
            # Existing user mods adopted as link sources stay theirs. RootDNA
            # does not scribble metadata into those just to be helpful.
            if not payload.get("return_to_game_on_remove"): continue
            name = payload.get("mod", ""); current = next((i for i, line in enumerate(lines) if self._mod_name(line) == name), None)
            if current is None: continue
            rule = rules.setdefault(payload.get("id", name), {})
            baseline = rule.get("baseline_index")
            if baseline is None:
                rule["baseline_index"] = current; changed = True
            elif baseline != current:
                nearby = []
                for index, line in enumerate(lines):
                    candidate = self._mod_name(line)
                    if not candidate or candidate == name or candidate in owned: continue
                    nearby.append((abs(index - current), 0 if self._separator(candidate) else 1, index, candidate))
                if nearby:
                    _distance, _not_separator, index, anchor = min(nearby)
                    rule.update({"anchor": anchor, "side": "after" if current > index else "before", "baseline_index": current})
                    self.audit("LEARNED", f"{name} sits {rule['side']} {anchor}"); changed = True
            self._write_payload_metadata(name, payload, rule)
        if changed: _atomic_json(self.definition_path, definition)
    def _remove_mod_entry(self, name):
        path = self.paths.modlist_path
        if not path.is_file(): return
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(line for line in lines if not (line[:1] in "+-" and line[1:].strip() == name)) + "\n", encoding="utf-8")
    def _migration_payloads(self, definition):
        # The id fallback repairs the first CK adoption build, before this flag
        # existed. New adopters carry the explicit return flag.
        return [item for item in definition.get("payloads", []) if item.get("return_to_game_on_remove") or item.get("id") == "creation-kit-ae-root"]
    def _restore_migrated_payloads(self, definition):
        restored = 0; removed_mods = []
        for payload in self._migration_payloads(definition):
            source_root = self.paths.mods / payload["mod"] / payload["source"]
            for item in payload.get("links", []):
                source, target = source_root / item["source"], self.paths.game_root / item["game"]
                if not source.exists(): continue
                if target.exists() or target.is_symlink(): raise RuntimeError(f"Restore collision at {target}. Leaving {source} alone.")
                target.parent.mkdir(parents=True, exist_ok=True); shutil.move(str(source), str(target)); restored += 1; self.audit("RESTORED", str(target))
            mod_root = self.paths.mods / payload["mod"]
            try:
                for folder in sorted((item for item in mod_root.rglob("*") if item.is_dir()), key=lambda item: len(item.parts), reverse=True): folder.rmdir()
                mod_root.rmdir(); self._remove_mod_entry(payload["mod"]); removed_mods.append(payload["mod"])
            except OSError: pass
        if restored:
            definition["payloads"] = [item for item in definition.get("payloads", []) if item not in self._migration_payloads(definition)]
            _atomic_json(self.definition_path, definition)
        return restored, removed_mods
    def _reset_profile_definition(self):
        """Remove means a clean slate; the audit stays as the paper trail."""
        try: self.definition_path.unlink()
        except FileNotFoundError: pass
    def adopt_root_payload(self, candidate):
        """Move one scanned, named root payload into its own RootDNA source mod."""
        definition = self.definition(); game_root = self.paths.game_root
        if not definition: raise RuntimeError("Create the RootDNA profile template first.")
        if not game_root or not game_root.is_dir(): raise RuntimeError("MO2 did not hand RootDNA a usable game path.")
        if "<PyQt6.QtCore.QDir object" in definition.get("game_root", ""): definition["game_root"] = str(game_root)
        if definition.get("profile") != self.paths.profile_name: raise RuntimeError("Definition belongs to another profile. Hands off.")
        candidates = {item["id"]: item for item in self.root_payload_candidates() + self.mod_root_candidates()}
        chosen = candidates.get(candidate.get("id"))
        if not chosen or chosen.get("items") != candidate.get("items"):
            raise RuntimeError("That root payload changed since the scan. RootDNA won't wing it.")
        if chosen["kind"] == "mod-root-payload":
            source_root = chosen["source"].resolve(); mod_root = (self.paths.mods / chosen["mod"]).resolve()
            if not _inside(source_root, mod_root): raise RuntimeError("Mod root candidate escaped its own mod. Nope.")
            payloads = [item for item in definition.get("payloads", []) if item.get("id") != chosen["id"]]
            payloads.append({"id": chosen["id"], "title": chosen["title"], "mod": chosen["mod"], "source": chosen["source_name"],
                             "links": [{"source": name, "game": name, "kind": kind} for name, kind in chosen["items"]]})
            definition["payloads"] = payloads
            learned = [item for item in definition.get("learned_adoptions", []) if item.get("candidate_id") != chosen["id"]]
            learned.append({"candidate_id": chosen["id"], "title": chosen["title"], "source": str(source_root),
                            "items": [name for name, _kind in chosen["items"]], "reason": "user-selected mod root payload",
                            "game_identity": self.game_identity(), "adopted_at": _now()})
            definition["learned_adoptions"] = learned; _atomic_json(self.definition_path, definition)
            self.audit("ADOPTED", f"declared mod root payload {source_root}")
            return
        sources = [game_root / name for name, _kind in chosen["items"]]
        mod_name = chosen["mod"]; source_root = self.paths.mods / mod_name / "root"
        with self._locked():
            self._guard(definition)
            collisions = [source_root / item.name for item in sources if (source_root / item.name).exists()]
            if collisions: raise RuntimeError("RootDNA payload already has files. Won't overwrite: " + ", ".join(str(item) for item in collisions))
            source_root.mkdir(parents=True, exist_ok=True); moved = []
            try:
                for source in sources:
                    destination = source_root / source.name; shutil.move(str(source), str(destination)); moved.append((source, destination))
                payload_id = chosen["id"] + "-root"
                payloads = [item for item in definition.get("payloads", []) if item.get("id") != payload_id]
                payloads.append({"id": payload_id, "title": chosen["title"], "mod": mod_name, "source": "root", "return_to_game_on_remove": True,
                                 "links": [{"source": item.name, "game": item.name, "kind": kind} for (_source, item), (_name, kind) in zip(moved, chosen["items"])]})
                definition["payloads"] = payloads
                learned = [item for item in definition.get("learned_adoptions", []) if item.get("candidate_id") != chosen["id"]]
                learned.append({"candidate_id": chosen["id"], "title": chosen["title"], "source": str(game_root),
                                "items": [name for name, _kind in chosen["items"]], "reason": "user-selected game-root migration",
                                "game_identity": self.game_identity(), "adopted_at": _now()})
                definition["learned_adoptions"] = learned; _atomic_json(self.definition_path, definition)
                definition["pending_adoptions"] = [item for item in definition.get("pending_adoptions", []) if item != chosen["id"]]; _atomic_json(self.definition_path, definition)
                self._place_payload_mod(mod_name, payloads[-1], definition); self.audit("MIGRATED", f"moved {len(moved)} {chosen['title']} file(s) into {source_root}")
            except Exception:
                for original, staged in reversed(moved):
                    if staged.exists() and not original.exists(): shutil.move(str(staged), str(original))
                raise
    def adopt_ae_creation_kit(self):
        candidate = next((item for item in self.root_payload_candidates() if item["id"] == "creation-kit-ae"), None)
        if not candidate: raise RuntimeError("No declared AE Creation Kit root files are in this game folder.")
        self.adopt_root_payload(candidate)
    def remove(self):
        manifest = self.manifest()
        if not manifest.get("links"):
            definition = self.definition(); restored, removed = self._restore_migrated_payloads(definition) if definition else (0, [])
            self.audit("VALIDATED", "remove requested with no deployed links")
            self._reset_profile_definition()
            return f"Restored {restored} migrated file(s), removed {', '.join(removed)}, and reset this RootDNA profile." if restored else "Nothing is deployed for this profile. RootDNA profile reset."
        definition, game_root, plans = self._plans(); expected = {str(item["target"]): item for item in plans}
        if manifest.get("profile") not in {None, self.paths.profile_name} or _normal(manifest.get("game_root", game_root)) != _normal(game_root): raise RuntimeError("Manifest belongs to another profile or game root. Not touching it.")
        with self._locked():
            self._guard(definition)
            for record in manifest.get("links", []):
                plan = expected.get(record.get("target"))
                target = Path(record.get("target", "")); source = Path(record.get("source", "")); marker = Path(record.get("marker", ""))
                if (not plan or record.get("signature") != self._signature(plan)
                        or not self._marker_matches(marker, self._signature(plan), target, source)
                        or not self._disk_matches(record, target, source)):
                    raise RuntimeError(f"Orphan or tampered RootDNA record: {target}. Nothing was removed.")
            for record in manifest.get("links", []):
                target = Path(record["target"]); target.rmdir() if target.is_dir() else target.unlink()
                backup = Path(record["backup"]) if record.get("backup") else None
                if backup and backup.exists():
                    if target.exists(): raise RuntimeError(f"Restore collision at {target}. Leaving backup alone.")
                    target.parent.mkdir(parents=True, exist_ok=True); shutil.move(str(backup), str(target)); self.audit("RESTORED", str(target))
                Path(record["marker"]).unlink(missing_ok=True); self.audit("REMOVED", str(target))
            self._save_manifest(game_root, {})
        restored, removed = self._restore_migrated_payloads(definition)
        self._reset_profile_definition()
        return f"RootDNA links removed. Restored {restored} adopted file(s), removed {', '.join(removed)}, and reset this RootDNA profile."

class RootDNAPanel(QWidget):
    def __init__(self, paths, plugin_dir, parent=None, lazy=False):
        super().__init__(parent); self.rootdna = RootDNA(paths, plugin_dir); self.rootdna.reset_status()
        layout = QVBoxLayout(self); body = QHBoxLayout(); left = QVBoxLayout(); right = QVBoxLayout(); body.addLayout(left, 4); body.addLayout(right, 1); layout.addLayout(body)
        left.addWidget(QLabel("RootDNA — exact declared game-root links only. No Data crawl. No freestyle."))
        left.addWidget(QLabel("Candidates are detected read-only. Adoption is explicit; RootDNA never freelances."))
        self.candidates = QTableWidget(0, 5, self); self.candidates.setHorizontalHeaderLabels(("", "Candidate", "Kind", "Source", "Status")); self.candidates.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.candidates.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded); self.candidates.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel); left.addWidget(self.candidates)
        self.candidates.verticalHeader().setDefaultSectionSize(46)
        header = self.candidates.horizontalHeader(); header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive); header.setStretchLastSection(False)
        for column, width in enumerate((42, 270, 150, 360, 180)): self.candidates.setColumnWidth(column, width)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed); self.select_all = QCheckBox(header); self.select_all.toggled.connect(self._set_all); header.geometriesChanged.connect(self._position_select_all)
        self.selection_note = QLabel("Select candidates to preview Deploy.", self); self.selection_note.setWordWrap(True); self.selection_note.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred); left.addWidget(self.selection_note)
        self.table = QTableWidget(0, 4, self); self.table.setHorizontalHeaderLabels(("Payload", "Source", "Game-root link", "State")); self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded); self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive); self.table.horizontalHeader().setStretchLastSection(False)
        self.table.verticalHeader().setDefaultSectionSize(46)
        for column, width in enumerate((170, 390, 390, 120)): self.table.setColumnWidth(column, width)
        left.addWidget(self.table)
        buttons = QHBoxLayout()
        for text, callback in (("Create profile", self.template), ("Dry run", self.dry_run), ("Deploy selected", self.deploy), ("Remove RDNA", self.remove), ("Open definition", self.open_definition), ("Open audit", self.open_audit)):
            button = QPushButton(text, self); button.clicked.connect(callback); buttons.addWidget(button)
        left.addLayout(buttons); right.addWidget(QLabel("Activity log — click a path to open it.")); self.status = QTextBrowser(self); self.status.setOpenLinks(False); self.status.anchorClicked.connect(self._open_status_link); right.addWidget(self.status)
        clear = QPushButton("Clear status", self); clear.clicked.connect(self._clear_status); right.addWidget(clear)
        self._loaded = False
        if not lazy: self.activate()
    def activate(self):
        """Pay the broad mod-root scan only when somebody opens this tab."""
        if self._loaded: return
        self._loaded = True; self._load_status(); self.refresh()
    def say(self, text, paths=()):
        self.rootdna.append_status(text, paths); self._load_status()
    @staticmethod
    def _short(text, limit=52):
        def trim(line):
            if len(line) <= limit: return line
            left = max(12, limit // 2 - 3); right = max(10, limit - left - 3)
            return line[:left] + " … " + line[-right:]
        return "\n".join(trim(line) for line in str(text).splitlines())
    def _cell(self, table, row, column, value, limit=52):
        item = QTableWidgetItem(self._short(value, limit)); item.setToolTip(str(value)); table.setItem(row, column, item)
    def _load_status(self):
        try: lines = self.rootdna.status_path.read_text(encoding="utf-8").splitlines()
        except OSError: lines = []
        rendered = []
        for line in lines:
            if line.startswith("Open: "):
                path = line[6:]; url = html.escape(QUrl.fromLocalFile(path).toString(), quote=True)
                rendered.append(f'<a href="{url}">{html.escape(line)}</a>')
            else: rendered.append(html.escape(line) if line else "<br>")
        self.status.setHtml("<br>".join(rendered)); self.status.moveCursor(QTextCursor.MoveOperation.End)
    def _clear_status(self):
        try: self.rootdna.status_path.unlink()
        except FileNotFoundError: pass
        self.status.clear()
    def _open_status_link(self, url):
        if url.isLocalFile(): QDesktopServices.openUrl(url)
    def refresh(self):
        # This is read-mostly: it only remembers a placement after somebody has
        # moved it, and refreshes RootDNA's little sorter hint in meta.ini.
        self.rootdna.learn_placement_rules()
        previous = {candidate.get("id"): box.isChecked() for candidate, box in zip(getattr(self, "candidate_rows", []), getattr(self, "candidate_boxes", []))}
        self.table.setRowCount(0); self.candidates.setRowCount(0); self.candidate_rows = []; self.candidate_boxes = []
        for candidate in self.rootdna.stock_game_candidates():
            self.candidate_rows.append({"kind": "stock-game", **candidate})
        for candidate in self.rootdna.root_payload_candidates(): self.candidate_rows.append(candidate)
        for candidate in self.rootdna.mod_root_candidates(): self.candidate_rows.append(candidate)
        for candidate in self.candidate_rows:
            row = self.candidates.rowCount(); self.candidates.insertRow(row)
            box = QCheckBox(self.candidates); box.toggled.connect(self._selection_changed)
            if "managed" in candidate.get("status", "") or "hands off" in candidate.get("status", ""): box.setEnabled(False)
            if previous.get(candidate.get("id"), False): box.setChecked(True)
            self.candidates.setCellWidget(row, 0, box); self.candidate_boxes.append(box)
            if candidate["kind"] == "stock-game":
                status = "adopted" if self.rootdna.definition().get("stock_game", {}) == {"mod": candidate["mod"], "source": candidate["source"], "game": candidate["game"]} else ("enabled — available" if candidate["enabled"] else "disabled — available")
                values = (candidate["mod"] + "\nclean game copy", "clean game copy\nrecord only", str(candidate["path"]) + "\nData + executable match", status + "\nno files move")
            else:
                preview = ", ".join(name for name, _kind in candidate["items"][:3]) + (" …" if candidate["count"] > 3 else "")
                moving = "moves into a RootDNA mod" if candidate["kind"] == "game-root-payload" else "links straight from this mod"
                values = (candidate["title"] + "\n" + preview, ("game-root payload" if candidate["kind"] == "game-root-payload" else "mod root payload") + "\n" + moving, str(candidate["source"]) + ("\nphysical game root" if candidate["kind"] == "game-root-payload" else "\nMO2 mod source"), f"{candidate['count']} items — {candidate['status']}\nselect to adopt")
            for column, value in enumerate(values, 1): self._cell(self.candidates, row, column, value, (42, 38, 58, 34)[column - 1])
        self._position_select_all(); self._selection_changed()
        foreign = self.rootdna.foreign_deployments()
        if foreign:
            self.say("RootDNA is deployed for another profile: " + ", ".join(foreign) + ". This profile will not touch it."); return
        if not self.rootdna.definition_path.is_file(): self.say("No RootDNA profile for this setup yet. Create it, select what you want RootDNA to own, then deploy."); return
        try:
            for plan, state in self.rootdna.preview():
                row = self.table.rowCount(); self.table.insertRow(row)
                for column, value in enumerate((plan["id"] + "\n" + plan["kind"], str(plan["source"]) + "\nRootDNA source", str(plan["target"]) + "\ngame-root link", state + "\nRootDNA checked")): self._cell(self.table, row, column, value, (30, 56, 56, 24)[column])
        except Exception as exc: self.rootdna.audit("REFUSED", str(exc)); self.say(f"Refused: {exc}")
    def template(self):
        try:
            if self.rootdna.definition_path.exists():
                self.open_definition(); self.say("Definition already exists, so RootDNA opened it instead of stomping on it.")
            else: self.rootdna.create_template(); self.refresh(); self.say("Profile created. Select candidates, then deploy.", (self.rootdna.definition_path,))
        except Exception as exc: self.say(f"Nope: {exc}")
    def _position_select_all(self):
        header = self.candidates.horizontalHeader(); size = self.select_all.sizeHint()
        self.select_all.setGeometry(header.sectionViewportPosition(0) + max(0, (header.sectionSize(0) - size.width()) // 2), max(0, (header.height() - size.height()) // 2), size.width(), size.height())
    def _set_all(self, checked):
        for candidate, box in zip(self.candidate_rows, self.candidate_boxes):
            if not box.isEnabled() or not candidate.get("auto_select", False): continue
            box.blockSignals(True); box.setChecked(checked); box.blockSignals(False)
        self._selection_changed()
    def _selected_candidates(self): return [candidate for candidate, box in zip(self.candidate_rows, self.candidate_boxes) if box.isEnabled() and box.isChecked()]
    @staticmethod
    def _selection_collision(selected):
        claims = {}
        for candidate in selected:
            if candidate["kind"] not in {"game-root-payload", "mod-root-payload"}: continue
            for name, _kind in candidate["items"]: claims.setdefault(name.lower(), []).append(candidate)
        overlaps = [(name, owners) for name, owners in claims.items() if len(owners) > 1]
        if not overlaps: return None
        receipts = []
        for name, owners in overlaps[:4]: receipts.append(f"{name}: " + " vs ".join(item["title"] for item in owners))
        more = f" (+{len(overlaps) - 4} more)" if len(overlaps) > 4 else ""
        return "Selected candidates overlap — " + "; ".join(receipts) + more
    def _selection_changed(self):
        selected = self._selected_candidates() if hasattr(self, "candidate_boxes") else []
        if not selected: self.selection_note.setText("Select candidates to preview Deploy."); return
        moved = sum(item["count"] for item in selected if item["kind"] == "game-root-payload")
        linked = sum(item["count"] for item in selected if item["kind"] == "mod-root-payload")
        copied = sum(1 for item in selected if item["kind"] == "stock-game")
        bits = []
        if moved: bits.append(f"move/link {moved} game-root item(s)")
        if linked: bits.append(f"link {linked} item(s) from selected mods")
        if copied: bits.append(f"record {copied} clean-copy source(s)")
        manual = sum(1 for item in selected if not item.get("auto_select", False))
        suffix = " Manual picks stay deliberate." if manual else ""
        self.selection_note.setText(f"{len(selected)} selected — " + "; ".join(bits) + ". Dry run has the full receipts." + suffix)
    def dry_run(self):
        if not self.rootdna.definition_path.is_file(): self.say("Create the RootDNA profile first."); return
        selected = self._selected_candidates(); definition = self.rootdna.definition(); notes = []
        try:
            self.rootdna._guard(definition)
            collision = self._selection_collision(selected)
            if collision: raise RuntimeError(collision)
            for candidate in selected:
                if candidate["kind"] == "stock-game":
                    if candidate not in [{"kind": "stock-game", **item} for item in self.rootdna.stock_game_candidates()]: raise RuntimeError("Selected clean-copy candidate changed since the scan.")
                    notes.append(f"Would adopt clean-copy source only: {candidate['path']}")
                elif candidate["kind"] == "game-root-payload":
                    target = self.rootdna.paths.mods / candidate["mod"] / "root"
                    if any((target / name).exists() for name, _kind in candidate["items"]): raise RuntimeError(f"Would refuse: RootDNA payload already exists at {target}.")
                    notes.append(f"Would move {candidate['count']} {candidate['title']} items to {target}, keep any learned placement, then link them back.")
                elif candidate["kind"] == "mod-root-payload":
                    notes.append(f"Would declare {candidate['count']} items from {candidate['source']} and link them into the game root. Nothing gets moved out of that mod.")
            for plan, state in self.rootdna.preview(): notes.append(f"Would validate {plan['source']} -> {plan['target']} ({state}).")
            self.say("Dry run — zero writes.\n\n" + ("\n".join(notes) if notes else "No candidate selected and no declared links to deploy."), (self.rootdna.definition_path, self.rootdna.paths.game_root))
        except Exception as exc: self.say(f"Dry run refused: {exc}")
    def deploy(self):
        selected = self._selected_candidates()
        if not self.rootdna.definition_path.is_file(): self.say("Create the RootDNA profile first."); return
        try:
            collision = self._selection_collision(selected)
            if collision: raise RuntimeError(collision)
            for candidate in selected:
                if candidate["kind"] == "stock-game": self.rootdna.adopt_stock_game(candidate)
                elif candidate["kind"] in {"game-root-payload", "mod-root-payload"}: self.rootdna.adopt_root_payload(candidate)
            self.rootdna.deploy(); self.refresh(); self.say("Selected RootDNA payloads deployed. Check the audit if you want receipts.", (self.rootdna.paths.game_root, self.rootdna.audit_path))
        except Exception as exc: self.rootdna.audit("REFUSED", str(exc)); self.say(f"Refused: {exc}")
    def adopt_ae_ck(self):
        try: self.rootdna.adopt_ae_creation_kit(); self.refresh(); self.say("AE Creation Kit moved into RootDNA - Creation Kit, then linked back into the game root.")
        except Exception as exc: self.rootdna.audit("REFUSED", str(exc)); self.say(f"Refused: {exc}")
    def remove(self):
        try: message = self.rootdna.remove(); self.refresh(); self.say(message, (self.rootdna.paths.game_root, self.rootdna.audit_path))
        except Exception as exc: self.rootdna.audit("REFUSED", str(exc)); self.say(f"Refused: {exc}")
    def open_definition(self): QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.rootdna.definition_path)))
    def open_audit(self): QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.rootdna.audit_path)))
