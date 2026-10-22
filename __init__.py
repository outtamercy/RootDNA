"""RootDNA: explicit, manifest-owned game-root links for Mod Organizer 2."""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import sys
from pathlib import Path

import mobase
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QTabWidget, QVBoxLayout

PLUGIN_DIR = Path(__file__).parent
COUPLING_FILE = "rootdna_coupling.json"
logger = logging.getLogger("RootDNA")
if not logger.handlers:
    handler = logging.FileHandler(PLUGIN_DIR / "rootdna_debug.log", mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


def _load_panel():
    """Load our own core file without borrowing File Watchdog's loader."""
    spec = importlib.util.spec_from_file_location("rootdna_core", PLUGIN_DIR / "root_dna.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("RootDNA core could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RootDNAPanel


class OrganizerPaths:
    """Live MO2 API paths. No INI archaeology and no guessed folders."""
    def __init__(self, organizer):
        self.organizer = organizer
        self.mods = self._api_path("modsPath")
        self.overwrite = self._api_path("overwritePath")
        profile = self._api_path("profilePath")
        self._game_root = self._managed_game_root()
        missing = [name for name, value in (("mods", self.mods), ("active profile", profile), ("game root", self._game_root)) if value is None]
        if missing:
            raise RuntimeError("MO2 did not provide a live " + ", ".join(missing) + " path. Fix MO2 Settings > Paths; RootDNA will not guess.")
        invalid = [str(value) for value in (self.mods, profile, self._game_root) if not value.is_dir()]
        if invalid:
            raise RuntimeError("MO2 handed RootDNA a missing path: " + "; ".join(invalid))
        self.profiles = profile.parent
        self.profile_name = profile.name
        configured_game = self._managed_game_name() or "Unknown Game"
        self.game_name = "SkyrimSE" if configured_game == "Skyrim Special Edition" else configured_game

    def _api_path(self, method):
        try:
            value = getattr(self.organizer, method)()
            if hasattr(value, "absolutePath"):
                value = value.absolutePath()
            return Path(str(value).strip()).resolve() if str(value).strip() else None
        except Exception:
            return None

    def _managed_game_root(self):
        try:
            value = self.organizer.managedGame().gameDirectory()
            if hasattr(value, "absolutePath"):
                value = value.absolutePath()
            return Path(str(value).strip()).resolve() if str(value).strip() else None
        except Exception:
            return None

    def _managed_game_name(self):
        try:
            game = self.organizer.managedGame()
            for attribute in ("gameName", "name"):
                value = getattr(game, attribute, None)
                value = value() if callable(value) else value
                if value:
                    return str(value).strip()
        except Exception:
            pass
        return ""

    @property
    def profile_dir(self):
        return self.profiles / self.profile_name

    @property
    def modlist_path(self):
        return self.profile_dir / "modlist.txt"

    @property
    def game_root(self):
        return self._game_root

    def listed_mods(self):
        if not self.modlist_path.is_file():
            return []
        return [(line[1:].strip(), line.startswith("+")) for line in self.modlist_path.read_text(encoding="utf-8").splitlines() if line[:1] in "+-" and line[1:].strip()]

    def game_executables(self):
        compact = re.sub(r"[^a-z0-9]", "", self.game_name.lower())
        candidate = self.game_root / (compact + ".exe")
        return (candidate.name,) if compact and candidate.is_file() else ()

    def root_executables(self):
        try:
            return tuple(item.name for item in self.game_root.iterdir() if item.is_file() and item.suffix.lower() == ".exe")
        except OSError:
            return ()


class RootDNAWindow(QDialog):
    def __init__(self, paths, organizer):
        super().__init__()
        self._organizer = organizer
        self.file_watchdog_window = None
        self.setWindowTitle("RootDNA — Root Link Manager")
        self.resize(1450, 840)
        layout = QVBoxLayout(self)
        titlebar = QHBoxLayout()
        titlebar.addWidget(QLabel("RootDNA"))
        titlebar.addStretch(1)
        self.couple_file_watchdog = QPushButton("Couple with File Watchdog", self)
        self.couple_file_watchdog.setCheckable(True)
        self.couple_file_watchdog.setMinimumHeight(30)
        couple_font = QFont(self.couple_file_watchdog.font()); couple_font.setBold(True); self.couple_file_watchdog.setFont(couple_font)
        self._file_watchdog_dir = self._find_file_watchdog()
        self.couple_file_watchdog.setEnabled(self._file_watchdog_dir is not None)
        self.couple_file_watchdog.setToolTip("Show File Watchdog as an extra RootDNA tab. This is only a UI preference; neither tool becomes dependent on the other." if self._file_watchdog_dir else "File Watchdog is not installed beside RootDNA, so there is nothing to couple.")
        self.couple_file_watchdog.setChecked(self._is_coupled())
        self.couple_file_watchdog.toggled.connect(self._set_coupled)
        titlebar.addWidget(self.couple_file_watchdog)
        titlebar.addWidget(QLabel("Color"))
        self.color_scheme = QComboBox(self)
        self.color_scheme.addItems(("MO2 blue", "Ember", "Rainbow"))
        titlebar.addWidget(self.color_scheme)
        layout.addLayout(titlebar)
        self.tabs = QTabWidget(self)
        tab_font = QFont(self.tabs.tabBar().font()); tab_font.setBold(True); self.tabs.tabBar().setFont(tab_font)
        self.panel = _load_panel()(paths, PLUGIN_DIR, self.tabs)
        self.tabs.addTab(self.panel, "RootDNA")
        layout.addWidget(self.tabs)
        if self.couple_file_watchdog.isChecked(): self._mount_file_watchdog()
        close = QPushButton("Close", self)
        close.clicked.connect(self.accept)
        layout.addWidget(close)
        self.color_scheme.currentTextChanged.connect(self._apply_color_scheme)
        self.color_scheme.setCurrentText(self._saved_color_scheme())
        self._apply_color_scheme(self.color_scheme.currentText())

    def _find_file_watchdog(self):
        try:
            for folder in PLUGIN_DIR.parent.iterdir():
                manifest = folder / "package_daddy.package.json"
                if not manifest.is_file(): continue
                data = json.loads(manifest.read_text(encoding="utf-8"))
                if data.get("id") == "file-watchdog": return folder
        except (OSError, ValueError, TypeError):
            pass
        return None

    @property
    def _coupling_path(self):
        return PLUGIN_DIR / COUPLING_FILE

    def _is_coupled(self):
        try:
            data = json.loads(self._coupling_path.read_text(encoding="utf-8"))
            return data.get("format") == 1 and data.get("coupled_with_file_watchdog") is True
        except (OSError, ValueError, TypeError):
            return False

    def _set_coupled(self, coupled):
        if self._file_watchdog_dir is None: return
        try:
            temporary = self._coupling_path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"format": 1, "coupled_with_file_watchdog": bool(coupled)}, indent=2), encoding="utf-8")
            os.replace(temporary, self._coupling_path)
        except OSError as exc:
            logger.warning("Couldn't save RootDNA coupling preference: %s", exc)
            self.couple_file_watchdog.blockSignals(True); self.couple_file_watchdog.setChecked(not coupled); self.couple_file_watchdog.blockSignals(False)
            return
        if coupled:
            self._mount_file_watchdog()
        else:
            self._unmount_file_watchdog()

    def _mount_file_watchdog(self):
        """Embed FW once. Its own RDNA host is disabled to avoid recursive tabs."""
        if self.file_watchdog_window is not None or self._file_watchdog_dir is None: return
        try:
            entry = self._file_watchdog_dir / "__init__.py"
            spec = importlib.util.spec_from_file_location("rootdna_file_watchdog", entry)
            if spec is None or spec.loader is None: raise RuntimeError("File Watchdog entry could not be loaded")
            module = importlib.util.module_from_spec(spec)
            # dataclasses resolves its module through sys.modules while FW is
            # defining its route records.  A dynamic import must register it
            # before exec or Python hands dataclasses a None module.
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            fw_paths = module.OrganizerPaths(self._organizer)
            manifest = module.RouteManifest(fw_paths.manifest_path, fw_paths.game_identity())
            if manifest.conflict: raise RuntimeError(manifest.conflict)
            module._migrate_runtime_staging_name(fw_paths, manifest)
            module._retire_obsolete_routes(fw_paths, manifest)
            module._prune_empty_fw_mods(fw_paths, manifest)
            module._sync_fw_mods(fw_paths)
            self.file_watchdog_window = module.FileWatchdogWindow(fw_paths, manifest, self.tabs, embedded=True, allow_rootdna=False)
            self.tabs.addTab(self.file_watchdog_window, "File Watchdog")
        except Exception as exc:
            logger.warning("File Watchdog module was ignored: %s", exc)
            self.file_watchdog_window = None

    def _unmount_file_watchdog(self):
        if self.file_watchdog_window is None: return
        index = self.tabs.indexOf(self.file_watchdog_window)
        if index >= 0: self.tabs.removeTab(index)
        self.file_watchdog_window.deleteLater(); self.file_watchdog_window = None

    @property
    def _scheme_path(self):
        return self.panel.rootdna.state / "ui_colors.json"

    def _saved_color_scheme(self):
        try:
            data = json.loads(self._scheme_path.read_text(encoding="utf-8"))
            if data.get("game_identity") == self.panel.rootdna.game_identity():
                return data.get("scheme", "MO2 blue")
        except (OSError, ValueError, TypeError):
            pass
        return "MO2 blue"

    def _apply_color_scheme(self, name):
        accents = {
            "MO2 blue": ("#4bb9eb", "#dbf5ff", "#152c40"),
            "Ember": ("#ff9a4d", "#ffd0a8", "#542b15"),
            "Rainbow": ("#ffffff", "#ffffff", "#35215e"),
        }
        accent, text, hover = accents.get(name, accents["MO2 blue"])
        rainbow = "qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #ff5c7a, stop:.25 #ffcb4c, stop:.50 #68e788, stop:.75 #56b8ff, stop:1 #c877ff)"
        button_base = "background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #62417d, stop:.08 #3c2850, stop:.48 #21162b, stop:1 #130b1b); color:#eee7f8; border:2px solid #7e45ad; border-top-color:#e7c9ff; border-left-color:#bd83ea; border-right-color:#4b236e; border-bottom-color:#160a22; padding:3px 8px;"
        hover_fill = f"background:{rainbow}; color:#101018;" if name == "Rainbow" else f"background:{hover}; color:{text};"
        tab_base = "background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #503565, stop:.10 #2b1d38, stop:1 #160d20); color:#b5a9c3; border:2px solid #5c3978; border-top-color:#b895d2; border-left-color:#8053a6; border-right-color:#321a47; border-bottom-color:#12081a; padding:5px 11px;"
        tab_selected = f"background:{rainbow}; color:#101018; border:2px solid #ffffff; border-top-color:#ffffff; border-left-color:#ffe7fb; border-right-color:#a76bea; border-bottom-color:#633785;" if name == "Rainbow" else f"background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 {hover}, stop:.48 #171d27, stop:1 #0e1118); color:{text}; border:2px solid {accent}; border-top-color:{text}; border-left-color:{accent}; border-right-color:#241138; border-bottom-color:#160a22;"
        header_base = "background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #5a3a70, stop:.10 #352246, stop:.52 #21162b, stop:1 #120a19); color:#eee7f8; border:1px solid #7e45ad; padding:5px; font-weight:bold;"
        header_hover = f"background:{rainbow}; color:#101018; border:1px solid #ffffff;" if name == "Rainbow" else f"background:{hover}; color:{text}; border:1px solid {accent};"
        surface = "background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #342042, stop:.05 #281935, stop:.52 #21162b, stop:1 #160d20);"
        self.setStyleSheet(
            f"QDialog {{{surface}}} QTabWidget::pane {{ border:1px solid #704493; {surface} }} "
            f"QTableWidget {{ background:#21162b; color:#eee7f8; border:1px solid #704493; gridline-color:#4b2b61; }} "
            f"QTextBrowser,QComboBox {{ background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #2c1b38, stop:1 #160d20); border:1px solid #704493; }} "
            f"QPushButton {{{button_base}}} QPushButton:checked {{{hover_fill}}} QPushButton:hover {{{hover_fill}}} "
            "QPushButton:pressed { background-color:#100a16; border-top-color:#2a123e; border-left-color:#4b236e; border-right-color:#d9afff; border-bottom-color:#bd83ea; } "
            f"QTabBar::tab {{{tab_base}}} QTabBar::tab:selected {{{tab_selected}}} "
            f"QHeaderView::section {{{header_base}}} QHeaderView::section:hover {{{header_hover}}} QTableCornerButton::section {{{header_base}}} "
            f"QCheckBox::indicator:checked {{ background:{accent}; border:1px solid {text}; }}"
        )
        try:
            self._scheme_path.parent.mkdir(parents=True, exist_ok=True)
            self._scheme_path.write_text(json.dumps({"game_identity": self.panel.rootdna.game_identity(), "scheme": name}, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("Couldn't save RootDNA color scheme: %s", exc)


class RootDNAPlugin(mobase.IPluginTool):
    def __init__(self):
        super().__init__()
        self._organizer = None

    def init(self, organizer):
        self._organizer = organizer
        logger.info("RootDNA booted as its own MO2 tool.")
        return True

    def name(self): return "RootDNA"
    def author(self): return "SkyGen"
    def description(self): return "Explicit, manifest-owned game-root links for MO2 mods."
    def version(self): return mobase.VersionInfo("2.0.0", mobase.VersionScheme.DISCOVER)
    def isActive(self): return True
    def settings(self): return []
    def displayName(self): return "RootDNA"
    def tooltip(self): return "Manage explicitly adopted game-root payloads"
    def icon(self): return QIcon()
    def group(self): return mobase.PluginSettingGroup.Tools

    def display(self):
        try:
            if self._organizer is None:
                raise RuntimeError("MO2 handed RootDNA an empty leash somehow.")
            window = RootDNAWindow(OrganizerPaths(self._organizer), self._organizer)
            window.exec()
            if window.panel.changed or getattr(getattr(window, "file_watchdog_window", None), "changed", False):
                try:
                    self._organizer.refresh(True)
                except TypeError:
                    self._organizer.refresh()
        except Exception as exc:
            logger.exception("RootDNA window failed: %s", exc)


def createPlugin():
    return RootDNAPlugin()
