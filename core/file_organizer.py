import shutil
from datetime import datetime
from pathlib import Path
from core.security_shield import SecurityShield


class FileOrganizer:
    CATEGORIES = {
        "Documentos": {".pdf", ".doc", ".docx", ".txt", ".xlsx", ".xls", ".csv", ".pptx", ".ppt", ".odt", ".md"},
        "Imagenes": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico", ".heic"},
        "Videos": {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm"},
        "Audio": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"},
        "Comprimidos": {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"},
        "Instaladores": {".exe", ".msi", ".bat", ".cmd", ".apk"},
        "Codigo": {".py", ".js", ".html", ".css", ".java", ".cpp", ".c", ".cs", ".php", ".json", ".sql", ".kt"},
    }

    def __init__(self):
        self.shield = SecurityShield()

    def _get_category(self, extension: str) -> str:
        ext = extension.lower()
        for category, extensions in self.CATEGORIES.items():
            if ext in extensions:
                return category
        return "Otros"

    def _resolve_collision(self, destination: Path) -> Path:
        if not destination.exists():
            return destination

        stem = destination.stem
        suffix = destination.suffix
        parent = destination.parent
        counter = 1

        while True:
            candidate = parent / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    def organize_folder(self, folder_path: str | Path, mode: str = "category", dry_run: bool = False) -> dict:
        target_dir = Path(folder_path).expanduser().resolve()
        verdict = self.shield.inspect_path(target_dir)

        if not verdict.is_safe:
            return {
                "success": False,
                "blocked": True,
                "verdict": verdict,
            }

        if not target_dir.exists() or not target_dir.is_dir():
            return {
                "success": False,
                "blocked": False,
                "error": f"La carpeta no existe o no es válida: {target_dir}",
            }

        moved_files = []
        skipped_files = []

        for item in target_dir.iterdir():
            if item.is_dir():
                continue

            item_verdict = self.shield.inspect_path(item)
            if not item_verdict.is_safe:
                skipped_files.append({
                    "file": item.name,
                    "reason": item_verdict.reason,
                })
                continue

            if mode == "date":
                modified_ts = item.stat().st_mtime
                subfolder_name = datetime.fromtimestamp(modified_ts).strftime("%Y-%m")
            else:
                subfolder_name = self._get_category(item.suffix)

            dest_folder = target_dir / subfolder_name
            dest_path = self._resolve_collision(dest_folder / item.name)

            if not dry_run:
                dest_folder.mkdir(parents=True, exist_ok=True)
                shutil.move(str(item), str(dest_path))

            moved_files.append({
                "file": item.name,
                "destination": f"{subfolder_name}/{dest_path.name}",
            })

        return {
            "success": True,
            "blocked": False,
            "dry_run": dry_run,
            "moved_count": len(moved_files),
            "skipped_count": len(skipped_files),
            "moved": moved_files,
            "skipped": skipped_files,
        }