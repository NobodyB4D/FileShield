from pathlib import Path
from core.quarantine_manager import QuarantineManager


if __name__ == "__main__":
    qm = QuarantineManager()

    blocked_attempt = qm.move_to_quarantine(r"C:\Windows\System32")
    if blocked_attempt.get("blocked"):
        v = blocked_attempt["verdict"]
        print(f"[BLOQUEADO - {v.risk_level}] {v.reason}")
        print(f"  Motivo: {v.explanation}\n")

    test_file = Path("prueba_basura.txt")
    test_file.write_text("Archivo temporal de prueba", encoding="utf-8")
    print(f"Archivo creado: {test_file.resolve()}")

    moved = qm.move_to_quarantine(test_file)
    if moved["success"]:
        print(f"Movido a cuarentena con ID: {moved['item_id']}")
        print(f"¿Sigue en la carpeta original?: {test_file.exists()}")

        restored = qm.restore_item(moved["item_id"])
        print(f"Restaurado en: {restored['restored_to']}")
        print(f"¿Volvió a aparecer?: {test_file.exists()}")
        test_file.unlink()