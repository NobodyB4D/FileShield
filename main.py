import shutil
from pathlib import Path
from core.file_organizer import FileOrganizer


if __name__ == "__main__":
    organizer = FileOrganizer()

    blocked = organizer.organize_folder(r"C:\Windows\System32")
    if blocked.get("blocked"):
        print(f"[BLOQUEADO] {blocked['verdict'].reason}\n")

    test_dir = Path("test_desorden")
    test_dir.mkdir(exist_ok=True)

    sample_files = [
        "apuntes_inacap.pdf",
        "foto_perfil.png",
        "respaldo_web.zip",
        "instalador_app.exe",
        "script_prueba.py",
        "notas_sueltas.xyz",
    ]

    for name in sample_files:
        (test_dir / name).write_text("contenido de prueba", encoding="utf-8")

    result = organizer.organize_folder(test_dir, mode="category")
    if result["success"]:
        print(f"Archivos organizados: {result['moved_count']}")
        for entry in result["moved"]:
            print(f"  {entry['file']} -> {entry['destination']}")

    shutil.rmtree(test_dir)