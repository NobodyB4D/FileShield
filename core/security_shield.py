import ctypes
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecurityVerdict:
    is_safe: bool
    risk_level: str
    reason: str
    explanation: str
    resolved_path: str


class SecurityShield:
    FILE_ATTRIBUTE_READONLY = 0x1
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_SYSTEM = 0x4
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

    CRITICAL_FILENAMES = {
        "bootmgr": "Gestor de arranque principal de Windows. Sin este archivo el equipo no puede iniciar.",
        "bcd": "Base de datos de configuración de arranque. Eliminarla impide que Windows encuentre el sistema operativo.",
        "ntoskrnl.exe": "Núcleo (Kernel) de Windows. Controla la memoria, los procesos y el hardware del computador.",
        "hal.dll": "Capa de abstracción de hardware. Permite que Windows se comunique con el procesador y la placa madre.",
        "winload.exe": "Cargador del sistema operativo durante el encendido.",
        "explorer.exe": "Interfaz gráfica principal de Windows (escritorio, barra de tareas y explorador de archivos).",
        "lsass.exe": "Proceso de seguridad local que gestiona contraseñas, permisos e inicios de sesión.",
        "pagefile.sys": "Archivo de paginación (memoria virtual) usado por Windows cuando se llena la memoria RAM.",
        "hiberfil.sys": "Archivo reservado por Windows para guardar el estado de la sesión al hibernar.",
        "swapfile.sys": "Archivo de intercambio de memoria utilizado por aplicaciones modernas de Windows.",
    }

    CRITICAL_EXTENSIONS = {
        ".sys": "Controlador de dispositivo en modo kernel. Borrarlo puede desactivar componentes críticos como pantalla, red o almacenamiento.",
        ".dll": "Librería de código compartido esencial para que Windows y los programas ejecuten sus funciones.",
        ".drv": "Controlador de hardware del sistema operativo.",
        ".cat": "Catálogo de firmas digitales que valida que los controladores de Windows sean auténticos y seguros.",
    }

    def __init__(self):
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files")).resolve()
        program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")).resolve()
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData")).resolve()
        system_drive = Path(os.environ.get("SystemDrive", "C:") + "\\").resolve()

        self.protected_directories = [
            (
                system_root / "System32",
                "Carpeta núcleo del sistema operativo (System32)",
                "Contiene los controladores, librerías (.dll) y ejecutables vitales de Windows. Borrar archivos aquí provocará pantallazos azules o impedirá que el computador vuelva a arrancar.",
            ),
            (
                system_root / "SysWOW64",
                "Subsistema de compatibilidad de 32 bits (SysWOW64)",
                "Almacena las librerías necesarias para que los programas de 32 bits funcionen en Windows de 64 bits.",
            ),
            (
                system_root / "WinSxS",
                "Almacén de componentes de Windows (WinSxS)",
                "Guarda las copias de seguridad y versiones de los componentes internos para actualizaciones y reparación del sistema.",
            ),
            (
                system_root,
                "Directorio principal de Windows",
                "Contiene la estructura base del sistema operativo, el registro de Windows y las configuraciones críticas de arranque.",
            ),
            (
                program_files,
                "Carpeta de programas instalados (Program Files)",
                "Contiene los archivos ejecutables de tus aplicaciones. Eliminarlos manualmente rompe los programas y deja entradas corruptas en el sistema.",
            ),
            (
                program_files_x86,
                "Carpeta de programas de 32 bits (Program Files x86)",
                "Almacena aplicaciones instaladas de 32 bits. Deben desinstalarse desde el panel de Windows, nunca borrando la carpeta.",
            ),
            (
                program_data,
                "Datos globales de aplicaciones (ProgramData)",
                "Guarda configuraciones, licencias y archivos compartidos que necesitan los servicios y programas para funcionar.",
            ),
            (
                system_drive / "Boot",
                "Carpeta de arranque de Windows (Boot)",
                "Contiene los archivos necesarios para iniciar el sistema operativo al encender el computador.",
            ),
            (
                system_drive / "Recovery",
                "Partición/Carpeta de recuperación de Windows",
                "Almacena las herramientas de reparación automática en caso de que Windows falle al iniciar.",
            ),
            (
                system_drive / "System Volume Information",
                "Información de restauración del sistema",
                "Carpeta protegida donde Windows guarda los puntos de restauración y el índice de búsqueda del disco.",
            ),
        ]

    def _get_windows_attributes(self, path: Path) -> int:
        if os.name != "nt":
            return 0
        get_attrs = ctypes.windll.kernel32.GetFileAttributesW
        get_attrs.argtypes = [ctypes.c_wchar_p]
        get_attrs.restype = ctypes.c_uint32
        attrs = get_attrs(str(path))
        if attrs == self.INVALID_FILE_ATTRIBUTES:
            return 0
        return attrs

    def _is_inside_directory(self, target: Path, protected_dir: Path) -> bool:
        try:
            return target == protected_dir or protected_dir in target.parents
        except Exception:
            return False

    def inspect_path(self, raw_path: str | Path) -> SecurityVerdict:
        target = Path(raw_path).expanduser().resolve()
        target_str = str(target)

        if target.parent == target:
            return SecurityVerdict(
                is_safe=False,
                risk_level="CRÍTICO",
                reason="Intento de eliminar la unidad de disco raíz completa",
                explanation="Borrar la raíz de una unidad eliminaría todos los archivos, carpetas y particiones almacenadas en ese disco.",
                resolved_path=target_str,
            )

        for protected_dir, reason, explanation in self.protected_directories:
            if self._is_inside_directory(target, protected_dir):
                return SecurityVerdict(
                    is_safe=False,
                    risk_level="CRÍTICO",
                    reason=reason,
                    explanation=explanation,
                    resolved_path=target_str,
                )

        filename_lower = target.name.lower()
        if filename_lower in self.CRITICAL_FILENAMES:
            return SecurityVerdict(
                is_safe=False,
                risk_level="CRÍTICO",
                reason=f"Archivo esencial del sistema ({target.name})",
                explanation=self.CRITICAL_FILENAMES[filename_lower],
                resolved_path=target_str,
            )

        attrs = self._get_windows_attributes(target)
        if attrs & self.FILE_ATTRIBUTE_SYSTEM:
            return SecurityVerdict(
                is_safe=False,
                risk_level="CRÍTICO",
                reason="Archivo marcado con atributo de Sistema por Windows",
                explanation="Windows asignó la bandera de protección de sistema a este elemento porque es necesario para la estabilidad del equipo.",
                resolved_path=target_str,
            )

        ext_lower = target.suffix.lower()
        if ext_lower in self.CRITICAL_EXTENSIONS:
            return SecurityVerdict(
                is_safe=False,
                risk_level="ALTO",
                reason=f"Extensión crítica del sistema ({ext_lower})",
                explanation=self.CRITICAL_EXTENSIONS[ext_lower],
                resolved_path=target_str,
            )

        if attrs & self.FILE_ATTRIBUTE_HIDDEN:
            return SecurityVerdict(
                is_safe=False,
                risk_level="MEDIO",
                reason="Archivo o carpeta oculta del sistema o configuración",
                explanation="Los elementos ocultos suelen contener configuraciones internas de Windows o de tus aplicaciones. Revisa su contenido antes de tocarlo.",
                resolved_path=target_str,
            )

        return SecurityVerdict(
            is_safe=True,
            risk_level="SEGURO",
            reason="Elemento de usuario sin restricciones de sistema",
            explanation="Este archivo o carpeta no pertenece a rutas críticas de Windows ni tiene atributos de protección.",
            resolved_path=target_str,
        )