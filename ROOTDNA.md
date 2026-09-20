# RootDNA

RootDNA is optional. FW shows its tab only when `root_dna.module.json` and `root_dna.py` are both valid.

Use **Create profile template** in the RootDNA tab. It makes a profile-scoped definition here:

```text
plugins/data/root_dna/profiles/<profile>/rootdna_definition.json
```

Put only exact, physical game-root payloads in it. Data files still belong in normal MO2 mods; RootDNA is for things like a loader EXE or a root DLL MO2 cannot virtualize.

```json
{
  "schema_version": 1,
  "profile": "My Profile",
  "game_root": "H:\\Games\\Skyrim Special Edition",
  "protected_processes": ["SkyrimSE.exe", "CreationKit.exe"],
  "payloads": [
    {
      "id": "skse-root",
      "title": "SKSE root payload",
      "mod": "RootDNA - SKSE",
      "source": "root",
      "links": [
        {"source": "skse64_loader.exe", "game": "skse64_loader.exe", "kind": "file"},
        {"source": "SomeRootFolder", "game": "SomeRootFolder", "kind": "directory"}
      ]
    }
  ]
}
```

That means the source files live at:

```text
[MO2]/mods/RootDNA - SKSE/root/
```

Directory entries deploy as junctions. File entries deploy as symlinks. RootDNA backs up a pre-existing declared game file before replacing it, records every completed operation in its manifest and audit, and refuses removal if ownership no longer matches. No broad game-root scans. No "probably fine" deletes.
