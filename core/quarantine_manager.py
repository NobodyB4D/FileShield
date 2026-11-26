import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from core.security_shield import SecurityShield


class QuarantineManager:
    def __init__(self, quarantine_dir: str | Path | None = None):
        if quarantine_dir is None:
            self.quarantine_dir = Path.home() / ".fileshield_quarantine"
        else:
            self.quarantine_dir = Path(quarantine_dir).expanduser().resolve()

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "manifest.json"
        self.shield = SecurityShield()

        if not self.manifest_path.exists():
            self._save_manifest({})

    def _load_manifest(self) -> dict:
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_manifest(self, data: dict) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def move_to_quarantine(self, raw_path: str | Path) -> dict:
        target = Path(raw_path).expanduser().resolve()
        verdict = self.shield.inspect_path(target)

        if not verdict.is_safe:
            return {
                "success": False,
                "blocked": True,
                "verdict": verdict,
            }

        if not target.exists():
            return {
                "success": False,
                "blocked": False,
                "error": f"La ruta no existe: {target}",
            }

        item_id = uuid.uuid4().hex[:8]
        stored_name = f"{item_id}_{target.name}"
        destination = self.quarantine_dir / stored_name
        is_dir = target.is_dir()

        shutil.move(str(target), str(destination))

        manifest = self._load_manifest()
        manifest[item_id] = {
            "name": target.name,
            "original_path": str(target),
            "stored_name": stored_name,
            "is_dir": is_dir,
            "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save_manifest(manifest)

        return {
            "success": True,
            "blocked": False,
            "item_id": item_id,
            "original_path": str(target),
        }

    def list_items(self) -> list[dict]:
        manifest = self._load_manifest()
        items = []
        for item_id, info in manifest.items():
            items.append({"id": item_id, **info})
        return items

    def restore_item(self, item_id: str) -> dict:
        manifest = self._load_manifest()
        if item_id not in manifest:
            return {"success": False, "error": "ID no encontrado en cuarentena."}

        info = manifest[item_id]
        stored_path = self.quarantine_dir / info["stored_name"]
        original_path = Path(info["original_path"])

        if not stored_path.exists():
            del manifest[item_id]
            self._save_manifest(manifest)
            return {"success": False, "error": "El archivo ya no existe en cuarentena."}

        original_path.parent.mkdir(parents=True, exist_ok=True)
        final_destination = original_path

        if final_destination.exists():
            stem = original_path.stem
            suffix = original_path.suffix
            final_destination = original_path.with_name(f"{stem}_restaurado{suffix}")

        shutil.move(str(stored_path), str(final_destination))
        del manifest[item_id]
        self._save_manifest(manifest)

        return {
            "success": True,
            "restored_to": str(final_destination),
        }

    def purge_item(self, item_id: str) -> dict:
        manifest = self._load_manifest()
        if item_id not in manifest:
            return {"success": False, "error": "ID no encontrado en cuarentena."}

        info = manifest[item_id]
        stored_path = self.quarantine_dir / info["stored_name"]

        if stored_path.exists():
            if stored_path.is_dir():
                shutil.rmtree(stored_path)
            else:
                stored_path.unlink()

        del manifest[item_id]
        self._save_manifest(manifest)

        return {"success": True, "deleted_name": info["name"]}
    