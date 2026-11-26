from core.security_shield import SecurityShield


def show_alert(verdict):
    if verdict.is_safe:
        print(f"[OK - {verdict.risk_level}] {verdict.resolved_path}")
        print(f"  Detalle: {verdict.explanation}\n")
    else:
        print(f"[BLOQUEADO - RIESGO {verdict.risk_level}] {verdict.resolved_path}")
        print(f"  Motivo: {verdict.reason}")
        print(f"  Por qué no borrarlo: {verdict.explanation}\n")


if __name__ == "__main__":
    shield = SecurityShield()

    test_paths = [
        r"C:\Windows\System32",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Program Files",
        r"C:\pagefile.sys",
        "README.md",
    ]

    for path in test_paths:
        result = shield.inspect_path(path)
        show_alert(result)