"""Persistencia, comparación y reglas del Operations Center de Guardian Pro.

Este módulo no importa Tkinter ni ejecuta comandos del sistema. Su única
responsabilidad es transformar resultados de auditoría en datos duraderos,
informes JSON sanitizados y un plan de acción determinista.

Privacidad:
- El historial local no guarda evidencias, rutas, nombres de archivo ni
  contenido. Solo conserva metadatos de las comprobaciones y recomendaciones
  normalizadas.
- Los informes exportados usan el esquema ``guardian.report`` y excluyen
  cualquier evidencia o nombre de archivo detectado.
- Los informes importados son datos pasivos: nunca se ejecutan ni habilitan
  reparaciones.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import re
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_AUDIT = "guardian.audit"
SCHEMA_REPORT = "guardian.report"
SCHEMA_HISTORY = "guardian.history"
SCHEMA_FLEET = "guardian.fleet"
SCHEMA_VERSION = 1

MAX_AUDITS = 100
MAX_REPORTS = 200
MAX_HISTORY_BYTES = 5 * 1024 * 1024
MAX_FLEET_BYTES = 5 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_CHECKS = 100
MAX_TEXT_LENGTH = 500
MAX_NAME_LENGTH = 200
MAX_DEVICE_NAME = 100
MAX_OS_LENGTH = 200

STATUSES = {"ok", "finding", "error", "unverifiable"}
SEVERITIES = {"high", "medium", "low", "info"}
SUMMARY_KEYS = ("ok", "finding", "unverifiable", "error")

CHECK_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# Se redactan rutas absolutas de Windows, UNC y rutas con separadores. La
# recomendación normalizada no debería contenerlas, pero esta defensa evita
# exportar una ruta si una regla futura la incluye por error.
_WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![\w])(?:[a-z]:\\[^\s,;]+|\\\\[^\\\s]+\\[^\s,;]+|/(?:[^\s,;]+/)+[^\s,;]*)"
)


class WorkspaceError(ValueError):
    """Error de validación o de almacenamiento seguro."""


def utc_now_iso() -> str:
    """Fecha UTC en ISO 8601 con zona horaria explícita."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_workspace_dir() -> Path:
    """Directorio de datos local, con alternativa si LOCALAPPDATA no existe."""
    override = os.environ.get("GUARDIAN_PRO_DATA_DIR")
    if override:
        return Path(override).expanduser()
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / "GuardianPro"
    return Path.home() / ".guardianpro"


def _clean_text(value, max_length=MAX_TEXT_LENGTH, *, allow_empty=True) -> str:
    """Normaliza texto no confiable y limita su longitud."""
    if value is None:
        value = ""
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ord(ch) >= 32)
    text = re.sub(r"\s+", " ", text).strip()
    if not allow_empty and not text:
        raise WorkspaceError("El texto obligatorio está vacío.")
    if len(text) > max_length:
        text = text[:max_length]
    return text


def sanitize_text(value, max_length=MAX_TEXT_LENGTH, *, allow_empty=True) -> str:
    """Texto seguro para almacenar o exportar, sin rutas absolutas."""
    text = _clean_text(value, max_length, allow_empty=allow_empty)
    return _WINDOWS_PATH_RE.sub("[ruta omitida]", text).strip()


def _parse_datetime(value) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise WorkspaceError("La fecha de la auditoría no es válida.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorkspaceError("La fecha de la auditoría no es ISO 8601.") from exc
    if parsed.tzinfo is None:
        raise WorkspaceError("La fecha de la auditoría debe incluir zona horaria.")
    return parsed


def _datetime_key(value: str) -> datetime:
    try:
        return _parse_datetime(value)
    except WorkspaceError:
        return datetime.min.replace(tzinfo=timezone.utc)


def get_device_identity() -> dict:
    """Identificador estable y no reversible del dispositivo actual.

    En Windows se usa MachineGuid solo como material de hash. El valor original
    nunca se almacena ni se exporta. Si no está disponible, se usa una
    combinación de hostname y nodo de red.
    """
    material = ""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                material = str(value)
        except Exception:
            material = ""

    hostname = platform.node() or "Windows"
    if not material:
        material = f"{hostname}|{platform.system()}|{platform.release()}|{uuid.getnode()}"
    digest = hashlib.sha256(("guardian-pro-device:" + material).encode("utf-8")).hexdigest()
    return {
        "id": "dev_" + digest[:24],
        "name": _clean_text(hostname, MAX_DEVICE_NAME, allow_empty=False),
        "os": _clean_text(
            f"{platform.system()} {platform.release()}".strip() or "Windows",
            MAX_OS_LENGTH,
        ),
    }


def check_id_for(name: str, fix_action: str = "") -> str:
    """Identificador estable y legible para una comprobación."""
    known = {
        "Firewall de Windows": "firewall",
        "Microsoft Defender": "defender",
        "Escritorio Remoto (RDP)": "rdp",
        "Análisis de nombres de archivo": "file_names",
    }
    if fix_action == "firewall_enable_all":
        return "firewall"
    if fix_action == "rdp_disable":
        return "rdp"
    if name in known:
        return known[name]
    slug = re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:64]
    return slug or "check"


def _get(check, key, default=None):
    if isinstance(check, dict):
        return check.get(key, default)
    return getattr(check, key, default)


def normalize_check(check) -> dict:
    """Convierte un CheckResult o un diccionario en un check sanitizado."""
    name = sanitize_text(
        _get(check, "name", ""), MAX_NAME_LENGTH, allow_empty=False
    )
    status = str(_get(check, "status", "error") or "error").lower()
    if status not in STATUSES:
        status = "error"
    severity = str(_get(check, "severity", "info") or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    recommendation = sanitize_text(_get(check, "recommendation", ""), MAX_TEXT_LENGTH)
    fix_action = str(_get(check, "fix_action", "") or "")
    return {
        "check_id": check_id_for(name, fix_action),
        "name": name,
        "status": status,
        "severity": severity,
        "recommendation": recommendation,
    }


def summarize_checks(checks: list[dict]) -> dict:
    summary = {key: 0 for key in SUMMARY_KEYS}
    for check in checks:
        if check.get("status") in summary:
            summary[check["status"]] += 1
    return summary


def build_audit_record(
    checks,
    device: dict,
    *,
    collected_at: str | None = None,
    audit_id: str | None = None,
) -> dict:
    """Construye una auditoría válida y sin datos sensibles."""
    normalized = [normalize_check(check) for check in checks]
    if not normalized:
        raise WorkspaceError("No hay comprobaciones para guardar.")
    if len(normalized) > MAX_CHECKS:
        raise WorkspaceError("La auditoría supera el número máximo de comprobaciones.")
    if len({check["check_id"] for check in normalized}) != len(normalized):
        raise WorkspaceError("La auditoría contiene identificadores de comprobación duplicados.")
    if audit_id is None:
        audit_id = "audit_" + uuid.uuid4().hex
    if not AUDIT_ID_RE.match(str(audit_id)):
        raise WorkspaceError("El identificador de auditoría no es válido.")
    collected_at = collected_at or utc_now_iso()
    _parse_datetime(collected_at)

    normalized_device = _validate_device(device)
    record = {
        "schema": SCHEMA_AUDIT,
        "schema_version": SCHEMA_VERSION,
        "audit_id": str(audit_id),
        "collected_at": collected_at,
        "device": normalized_device,
        "summary": summarize_checks(normalized),
        "checks": normalized,
    }
    return record


def _validate_device(device) -> dict:
    if not isinstance(device, dict):
        raise WorkspaceError("El dispositivo debe ser un objeto.")
    if set(device) != {"id", "name", "os"}:
        raise WorkspaceError("El dispositivo contiene campos no permitidos.")
    device_id = _clean_text(device.get("id"), 128, allow_empty=False)
    if not DEVICE_ID_RE.match(device_id):
        raise WorkspaceError("El identificador del dispositivo no es válido.")
    name = sanitize_text(
        device.get("name"), MAX_DEVICE_NAME, allow_empty=False
    )
    os_name = sanitize_text(device.get("os"), MAX_OS_LENGTH)
    return {"id": device_id, "name": name, "os": os_name}


def _validate_checks(checks) -> list[dict]:
    if not isinstance(checks, list) or not checks:
        raise WorkspaceError("La lista de comprobaciones está vacía.")
    if len(checks) > MAX_CHECKS:
        raise WorkspaceError("La lista de comprobaciones es demasiado grande.")
    validated = []
    seen_ids = set()
    for item in checks:
        if not isinstance(item, dict):
            raise WorkspaceError("Cada comprobación debe ser un objeto.")
        expected = {"check_id", "name", "status", "severity", "recommendation"}
        if set(item) != expected:
            raise WorkspaceError("Una comprobación contiene campos no permitidos o faltantes.")
        check_id = _clean_text(item.get("check_id"), 64, allow_empty=False)
        if not CHECK_ID_RE.match(check_id):
            raise WorkspaceError("El identificador de comprobación no es válido.")
        if check_id in seen_ids:
            raise WorkspaceError(f"Identificador de comprobación duplicado: {check_id!r}")
        seen_ids.add(check_id)
        name = sanitize_text(
            item.get("name"), MAX_NAME_LENGTH, allow_empty=False
        )
        status = item.get("status")
        if status not in STATUSES:
            raise WorkspaceError(f"Estado de comprobación no permitido: {status!r}")
        severity = item.get("severity")
        if severity not in SEVERITIES:
            raise WorkspaceError(f"Severidad no permitida: {severity!r}")
        recommendation = sanitize_text(item.get("recommendation", ""), MAX_TEXT_LENGTH)
        validated.append({
            "check_id": check_id,
            "name": name,
            "status": status,
            "severity": severity,
            "recommendation": recommendation,
        })
    return validated


def _validate_summary(summary, checks: list[dict]) -> dict:
    if not isinstance(summary, dict) or set(summary) != set(SUMMARY_KEYS):
        raise WorkspaceError("El resumen de la auditoría no es válido.")
    normalized = {}
    for key in SUMMARY_KEYS:
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise WorkspaceError("Los contadores del resumen deben ser enteros.")
        if value < 0 or value > MAX_CHECKS:
            raise WorkspaceError("Un contador del resumen está fuera de rango.")
        normalized[key] = value
    if normalized != summarize_checks(checks):
        raise WorkspaceError("El resumen no coincide con las comprobaciones.")
    return normalized


def _validate_comparison(comparison):
    if comparison is None:
        return None
    if not isinstance(comparison, dict):
        raise WorkspaceError("La comparación no es un objeto.")
    allowed = {
        "previous_audit_id", "current_audit_id", "new", "persistent",
        "resolved", "unverifiable", "not_evaluated", "regressed", "summary",
    }
    if set(comparison) != allowed:
        raise WorkspaceError("La comparación contiene campos no permitidos.")
    for key in ("previous_audit_id", "current_audit_id"):
        value = comparison.get(key)
        if value is not None and not AUDIT_ID_RE.match(str(value)):
            raise WorkspaceError("La comparación contiene un identificador no válido.")
    for key in ("new", "persistent", "resolved", "unverifiable", "not_evaluated", "regressed"):
        items = comparison.get(key)
        if not isinstance(items, list):
            raise WorkspaceError("La comparación contiene listas no válidas.")
        for item in items:
            if not isinstance(item, dict):
                raise WorkspaceError("La comparación contiene un elemento no válido.")
            if set(item) != {"check_id", "name", "status", "severity"}:
                raise WorkspaceError("Un cambio de comparación contiene campos no permitidos.")
            if item.get("status") not in STATUSES:
                raise WorkspaceError("Un cambio de comparación tiene un estado no válido.")
            if item.get("severity") not in SEVERITIES:
                raise WorkspaceError("Un cambio de comparación tiene una severidad no válida.")
            _clean_text(item.get("check_id"), 64, allow_empty=False)
            _clean_text(item.get("name"), MAX_NAME_LENGTH, allow_empty=False)
    summary = comparison.get("summary")
    if not isinstance(summary, dict):
        raise WorkspaceError("La comparación no tiene resumen.")
    if set(summary) != {
        "new", "persistent", "resolved", "unverifiable", "not_evaluated", "regressed",
    }:
        raise WorkspaceError("El resumen de comparación no es válido.")
    for value in summary.values():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WorkspaceError("El resumen de comparación contiene contadores no válidos.")
    return copy.deepcopy(comparison)


def validate_audit_record(data, *, allow_comparison=True) -> dict:
    """Valida una auditoría local y devuelve una copia normalizada."""
    if not isinstance(data, dict):
        raise WorkspaceError("La auditoría debe ser un objeto.")
    required = {"schema", "schema_version", "audit_id", "collected_at", "device", "summary", "checks"}
    allowed = set(required)
    if allow_comparison:
        allowed.add("comparison")
    if not required.issubset(data) or set(data) - allowed:
        raise WorkspaceError("La auditoría contiene campos no permitidos o faltantes.")
    if data.get("schema") != SCHEMA_AUDIT:
        raise WorkspaceError("El esquema de la auditoría no es conocido.")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise WorkspaceError("La versión del esquema de auditoría no es compatible.")
    audit_id = _clean_text(data.get("audit_id"), 128, allow_empty=False)
    if not AUDIT_ID_RE.match(audit_id):
        raise WorkspaceError("El identificador de auditoría no es válido.")
    collected_at = _parse_datetime(data.get("collected_at"))
    device = _validate_device(data.get("device"))
    checks = _validate_checks(data.get("checks"))
    summary = _validate_summary(data.get("summary"), checks)
    record = {
        "schema": SCHEMA_AUDIT,
        "schema_version": SCHEMA_VERSION,
        "audit_id": audit_id,
        "collected_at": collected_at.isoformat(timespec="seconds"),
        "device": device,
        "summary": summary,
        "checks": checks,
    }
    if allow_comparison and "comparison" in data:
        record["comparison"] = _validate_comparison(data.get("comparison"))
    return record


def validate_report(data) -> dict:
    """Valida un informe importado del esquema público ``guardian.report``."""
    if not isinstance(data, dict):
        raise WorkspaceError("El informe debe ser un objeto.")
    required = {"schema", "schema_version", "audit_id", "collected_at", "device", "summary", "checks"}
    if set(data) != required:
        raise WorkspaceError("El informe contiene campos no permitidos o faltantes.")
    if data.get("schema") != SCHEMA_REPORT:
        raise WorkspaceError("El esquema del informe no es conocido.")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise WorkspaceError("La versión del informe no es compatible.")
    audit_id = _clean_text(data.get("audit_id"), 128, allow_empty=False)
    if not AUDIT_ID_RE.match(audit_id):
        raise WorkspaceError("El identificador de auditoría no es válido.")
    collected_at = _parse_datetime(data.get("collected_at"))
    device = _validate_device(data.get("device"))
    checks = _validate_checks(data.get("checks"))
    summary = _validate_summary(data.get("summary"), checks)
    return {
        "schema": SCHEMA_REPORT,
        "schema_version": SCHEMA_VERSION,
        "audit_id": audit_id,
        "collected_at": collected_at.isoformat(timespec="seconds"),
        "device": device,
        "summary": summary,
        "checks": checks,
    }


def report_from_audit(record: dict) -> dict:
    """Convierte una auditoría local en un informe público sanitizado."""
    validated = validate_audit_record(record)
    report = copy.deepcopy(validated)
    report.pop("comparison", None)
    report["schema"] = SCHEMA_REPORT
    return validate_report(report)


def _comparison_item(check: dict) -> dict:
    return {
        "check_id": check["check_id"],
        "name": check["name"],
        "status": check["status"],
        "severity": check["severity"],
    }


def compare_check_lists(previous_checks, current_checks) -> dict:
    """Compara dos listas de comprobaciones sin inferir resoluciones.

    Una comprobación solo se considera resuelta cuando la auditoría actual
    devuelve ``ok``. Un error, una comprobación no verificable o una
    comprobación ausente nunca cuentan como resolución.
    """
    previous = [normalize_check(c) for c in previous_checks]
    current = [normalize_check(c) for c in current_checks]
    previous_map = {c["check_id"]: c for c in previous}
    current_map = {c["check_id"]: c for c in current}

    result = {
        "previous_audit_id": None,
        "current_audit_id": None,
        "new": [],
        "persistent": [],
        "resolved": [],
        "unverifiable": [],
        "not_evaluated": [],
        "regressed": [],
        "summary": {},
    }

    for check_id, cur in current_map.items():
        prev = previous_map.get(check_id)
        if cur["status"] == "ok":
            if prev is not None and prev["status"] != "ok":
                result["resolved"].append(_comparison_item(cur))
            continue
        if cur["status"] == "finding":
            if prev is None or prev["status"] == "ok":
                result["new"].append(_comparison_item(cur))
                result["regressed"].append(_comparison_item(cur))
            else:
                result["persistent"].append(_comparison_item(cur))
        else:
            result["unverifiable"].append(_comparison_item(cur))
            if prev is not None and prev["status"] != "ok":
                result["persistent"].append(_comparison_item(cur))
            elif prev is None or prev["status"] == "ok":
                result["regressed"].append(_comparison_item(cur))

    for check_id, prev in previous_map.items():
        if check_id not in current_map and prev["status"] != "ok":
            result["not_evaluated"].append(_comparison_item(prev))

    result["summary"] = {
        key: len(result[key])
        for key in ("new", "persistent", "resolved", "unverifiable", "not_evaluated", "regressed")
    }
    return result


def _validate_any_record(data: dict) -> dict:
    """Acepta auditorías locales o informes públicos para comparar."""
    if isinstance(data, dict) and data.get("schema") == SCHEMA_REPORT:
        return validate_report(data)
    return validate_audit_record(data)


def compare_audits(previous: dict, current: dict) -> dict:
    """Compara dos auditorías validadas del mismo dispositivo."""
    prev = _validate_any_record(previous)
    cur = _validate_any_record(current)
    comparison = compare_check_lists(prev["checks"], cur["checks"])
    comparison["previous_audit_id"] = prev["audit_id"]
    comparison["current_audit_id"] = cur["audit_id"]
    return comparison


def _latest_record(records: list[dict], device_id: str | None = None):
    candidates = [
        record for record in records
        if device_id is None or record.get("device", {}).get("id") == device_id
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))


def _previous_record(records: list[dict], current: dict):
    device_id = current.get("device", {}).get("id")
    current_time = _datetime_key(current.get("collected_at", ""))
    candidates = [
        record for record in records
        if record.get("device", {}).get("id") == device_id
        and record.get("audit_id") != current.get("audit_id")
        and _datetime_key(record.get("collected_at", "")) <= current_time
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))


# ==================== PLAN DE ACCIÓN ====================

_RULES = {
    "firewall": {
        "what": "El firewall de Windows no está habilitado en todos los perfiles.",
        "why": "Un firewall desactivado permite conexiones no filtradas y reduce la capacidad de contener servicios expuestos.",
        "next": "Habilite el firewall en los perfiles afectados o revise las reglas que justifican su desactivación.",
        "verify": "Ejecute una nueva auditoría y confirme que los perfiles Domain, Private y Public aparecen habilitados.",
        "manual": False,
    },
    "defender": {
        "what": "La protección en tiempo real de Microsoft Defender está desactivada.",
        "why": "Sin protección en tiempo real, el malware puede ejecutarse antes de que una revisión posterior lo detecte.",
        "next": "Actívela manualmente desde Seguridad de Windows y vuelva a auditar. Guardian no modifica Defender ni intenta eludir Tamper Protection.",
        "verify": "Una nueva auditoría debe mostrar la protección en tiempo real como habilitada.",
        "manual": True,
    },
    "rdp": {
        "what": "Escritorio Remoto (RDP) está habilitado en el registro de Windows.",
        "why": "RDP habilitado amplía la superficie de acceso remoto y puede exponer el equipo a intentos de acceso no autorizados.",
        "next": "Si no usa RDP, deshabilítelo desde Guardian con confirmación y privilegios de administrador; si lo necesita, restrinja el acceso.",
        "verify": "Una nueva auditoría debe confirmar RDP deshabilitado en el registro y sin reglas RDP habilitadas.",
        "manual": False,
    },
    "file_names": {
        "what": "Se encontraron nombres de archivo con palabras potencialmente sensibles en el ámbito analizado.",
        "why": "Un nombre puede revelar la existencia o el propósito de información sensible, aunque por sí solo no confirma una filtración.",
        "next": "Revise los nombres señalados en la auditoría y confirme si la ubicación y el acceso son apropiados. Guardian no abre ni modifica esos archivos.",
        "verify": "Repita el análisis tras reorganizar o proteger los archivos. La ausencia de coincidencias no demuestra que el contenido sea seguro.",
        "manual": True,
    },
    "generic": {
        "what": "La comprobación requiere revisión.",
        "why": "Una comprobación incompleta o un hallazgo sin contexto puede ocultar un riesgo real.",
        "next": "Revise la recomendación de la auditoría y repita la comprobación.",
        "verify": "Una nueva auditoría debe aportar evidencia suficiente del estado del control.",
        "manual": True,
    },
}


def _plan_priority(status: str, severity: str) -> tuple:
    """Orden determinista y explicable.

    1. Hallazgos de severidad alta.
    2. Errores y comprobaciones no verificables (requieren revisión, no son OK).
    3. Hallazgos medios.
    4. Hallazgos bajos.
    """
    if status == "finding" and severity == "high":
        group = 0
    elif status in {"error", "unverifiable"}:
        group = 1
    elif status == "finding" and severity == "medium":
        group = 2
    elif status == "finding":
        group = 3
    else:
        group = 4
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}.get(severity, 4)
    return group, severity_rank


def build_action_plan(checks, *, allow_repair: bool = False, source: str = "live") -> list[dict]:
    """Genera un plan determinista a partir de comprobaciones.

    ``allow_repair`` solo debe ser True para la auditoría actual y real. Los
    informes importados y los datos de demostración siempre se construyen con
    False, de modo que no puedan activar una reparación.
    """
    items = []
    for raw in checks:
        check = normalize_check(raw)
        if check["status"] == "ok":
            continue
        rule = _RULES.get(check["check_id"], _RULES["generic"])
        status = check["status"]
        severity = check["severity"]
        fix_action = str(_get(raw, "fix_action", "") or "")
        can_fix = bool(_get(raw, "can_fix", False))
        repair_available = bool(
            allow_repair
            and status == "finding"
            and can_fix
            and fix_action in {"firewall_enable_all", "rdp_disable"}
        )

        if status == "finding":
            what = rule["what"]
            why = rule["why"]
            next_step = check["recommendation"] or rule["next"]
            verification = rule["verify"]
            manual = rule["manual"]
        else:
            what = f"No se pudo confirmar el estado de {check['name']}."
            why = (
                "La ausencia de una respuesta concluyente no equivale a seguridad. "
                "Un error o una comprobación no verificable debe revisarse antes de dar el control por bueno."
            )
            next_step = check["recommendation"] or (
                "Revise permisos, conectividad o la consulta del sistema y repita la auditoría."
            )
            verification = (
                "Repita la auditoría y obtenga un resultado concluyente. "
                "Un error no se considera una resolución."
            )
            manual = True

        if repair_available:
            action_kind = "repair"
            action_label = "Reparación disponible desde Guardian"
        elif rule["manual"] or status != "finding":
            action_kind = "manual"
            action_label = "Intervención manual necesaria"
        else:
            action_kind = "manual"
            action_label = "Revisión manual necesaria"

        items.append({
            "check_id": check["check_id"],
            "name": check["name"],
            "status": status,
            "severity": severity,
            "recommendation": check["recommendation"],
            "what": what,
            "why": why,
            "next_step": next_step,
            "verification": verification,
            "manual": bool(manual),
            "can_repair": repair_available,
            "action_kind": action_kind,
            "action_label": action_label,
            "fix_action": fix_action if repair_available else "",
            "source": source,
            "priority": _plan_priority(status, severity),
        })

    items.sort(key=lambda item: (
        item["priority"],
        {"high": 0, "medium": 1, "low": 2, "info": 3}.get(item["severity"], 4),
        0 if item["can_repair"] else 1,
        item["check_id"],
    ))
    return items


# ==================== ALMACENAMIENTO ====================


def _atomic_write_text(path: Path, text: str) -> None:
    """Escritura atómica en el mismo volumen mediante archivo temporal."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=str(path.parent), text=True
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, payload) -> None:
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


class GuardianWorkspace:
    """Almacén local acotado, seguro ante corrupción y sin bloqueo de auditorías."""

    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir) if base_dir else default_workspace_dir()
        self.history_path = self.base_dir / "history.json"
        self.fleet_path = self.base_dir / "fleet.json"
        self._lock = threading.RLock()
        self.warnings: list[str] = []
        self._history_cache = None
        self._fleet_cache = None
        self._history_corrupt = False
        self._fleet_corrupt = False

    # ---------- lectura segura ----------

    def _read_json(self, path: Path, max_bytes: int, label: str):
        if not path.exists():
            return None
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.warnings.append(f"No se pudo comprobar el tamaño de {label}: {exc}")
            return None
        if size > max_bytes:
            self.warnings.append(
                f"{label} supera el límite de {max_bytes} bytes y no se cargó. "
                "Se conservará una copia antes de escribir datos nuevos."
            )
            return "corrupt"
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                return json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.warnings.append(f"No se pudo leer {label}: {exc}")
            return "corrupt"

    def _backup_corrupt(self, path: Path, label: str) -> None:
        if not path.exists():
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = path.with_name(f"{path.stem}.corrupt-{stamp}{path.suffix}")
        counter = 1
        while backup.exists():
            backup = path.with_name(f"{path.stem}.corrupt-{stamp}-{counter}{path.suffix}")
            counter += 1
        try:
            backup.write_bytes(path.read_bytes())
            self.warnings.append(f"Se conservó una copia de {label} en {backup.name}.")
        except OSError as exc:
            self.warnings.append(f"No se pudo conservar la copia de {label}: {exc}")

    def load_history(self) -> list[dict]:
        with self._lock:
            if self._history_cache is not None:
                return copy.deepcopy(self._history_cache)
            payload = self._read_json(self.history_path, MAX_HISTORY_BYTES, "el historial local")
            if payload is None:
                self._history_cache = []
                return []
            if payload == "corrupt":
                self._history_corrupt = True
                self._history_cache = []
                return []
            if not isinstance(payload, dict) or set(payload) != {"schema", "schema_version", "audits"}:
                self.warnings.append("El historial local tiene un formato no reconocido.")
                self._history_corrupt = True
                self._history_cache = []
                return []
            if payload.get("schema") != SCHEMA_HISTORY or payload.get("schema_version") != SCHEMA_VERSION:
                self.warnings.append("El historial local usa un esquema o versión no compatible.")
                self._history_corrupt = True
                self._history_cache = []
                return []
            audits = payload.get("audits")
            if not isinstance(audits, list):
                self.warnings.append("El historial local no contiene una lista de auditorías.")
                self._history_corrupt = True
                self._history_cache = []
                return []
            valid = []
            invalid = 0
            for item in audits:
                try:
                    valid.append(validate_audit_record(item))
                except WorkspaceError:
                    invalid += 1
            if invalid:
                self.warnings.append(
                    f"Se omitieron {invalid} auditoría(s) dañada(s) del historial. "
                    "Se conservará una copia antes de escribir."
                )
                self._history_corrupt = True
            valid.sort(key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))
            if len(valid) > MAX_AUDITS:
                valid = valid[-MAX_AUDITS:]
            self._history_cache = valid
            return copy.deepcopy(valid)

    def load_fleet(self) -> list[dict]:
        with self._lock:
            if self._fleet_cache is not None:
                return copy.deepcopy(self._fleet_cache)
            payload = self._read_json(self.fleet_path, MAX_FLEET_BYTES, "los informes importados")
            if payload is None:
                self._fleet_cache = []
                return []
            if payload == "corrupt":
                self._fleet_corrupt = True
                self._fleet_cache = []
                return []
            if not isinstance(payload, dict) or set(payload) != {"schema", "schema_version", "reports"}:
                self.warnings.append("Los informes importados tienen un formato no reconocido.")
                self._fleet_corrupt = True
                self._fleet_cache = []
                return []
            if payload.get("schema") != SCHEMA_FLEET or payload.get("schema_version") != SCHEMA_VERSION:
                self.warnings.append("Los informes importados usan un esquema o versión no compatible.")
                self._fleet_corrupt = True
                self._fleet_cache = []
                return []
            reports = payload.get("reports")
            if not isinstance(reports, list):
                self.warnings.append("Los informes importados no contienen una lista válida.")
                self._fleet_corrupt = True
                self._fleet_cache = []
                return []
            valid = []
            invalid = 0
            for item in reports:
                try:
                    valid.append(validate_report(item))
                except WorkspaceError:
                    invalid += 1
            if invalid:
                self.warnings.append(
                    f"Se omitieron {invalid} informe(s) dañado(s) de la flota. "
                    "Se conservará una copia antes de escribir."
                )
                self._fleet_corrupt = True
            valid.sort(key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))
            if len(valid) > MAX_REPORTS:
                valid = valid[-MAX_REPORTS:]
            self._fleet_cache = valid
            return copy.deepcopy(valid)

    # ---------- escritura ----------

    def save_audit(self, checks, device: dict, *, collected_at=None) -> dict:
        """Guarda una auditoría y adjunta su comparación con la anterior."""
        with self._lock:
            history = self.load_history()
            record = build_audit_record(checks, device, collected_at=collected_at)
            previous = _previous_record(history, record)
            if previous is not None:
                record["comparison"] = compare_audits(previous, record)
            history.append(record)
            history.sort(key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))
            if len(history) > MAX_AUDITS:
                history = history[-MAX_AUDITS:]
            try:
                if self._history_corrupt:
                    self._backup_corrupt(self.history_path, "el historial local")
                    self._history_corrupt = False
                _atomic_write_json(self.history_path, {
                    "schema": SCHEMA_HISTORY,
                    "schema_version": SCHEMA_VERSION,
                    "audits": history,
                })
            except OSError as exc:
                raise WorkspaceError(f"No se pudo guardar el historial local: {exc}") from exc
            self._history_cache = history
            return copy.deepcopy(record)

    def latest_for_device(self, device_id: str):
        return _latest_record(self.load_history(), device_id)

    def previous_for(self, record: dict):
        return _previous_record(self.load_history(), record)

    def comparison_for(self, record: dict):
        previous = self.previous_for(record)
        if previous is None:
            return None
        return compare_audits(previous, record)

    # ---------- importación / exportación ----------

    def read_report_file(self, path) -> dict:
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise WorkspaceError(f"No se pudo abrir el archivo: {exc}") from exc
        if size > MAX_REPORT_BYTES:
            raise WorkspaceError(
                f"El archivo supera el límite de {MAX_REPORT_BYTES // 1024} KB."
            )
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                payload = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkspaceError(f"JSON inválido o ilegible: {exc}") from exc
        return validate_report(payload)

    def add_imported_reports(self, reports: list[dict]) -> list[dict]:
        """Añade informes validados y clasifica nuevos, antiguos y duplicados.

        Los informes se guardan como datos pasivos. Esta función no ejecuta
        nada de su contenido.
        """
        with self._lock:
            fleet = self.load_fleet()
            existing_ids = {report["audit_id"] for report in fleet}
            latest_by_device = {}
            for report in fleet:
                device_id = report["device"]["id"]
                current = latest_by_device.get(device_id)
                if current is None or _datetime_key(report["collected_at"]) > _datetime_key(current["collected_at"]):
                    latest_by_device[device_id] = report

            results = []
            added = False
            for report in reports:
                try:
                    validated = validate_report(report)
                except WorkspaceError as exc:
                    results.append({"audit_id": "", "outcome": "invalid", "detail": str(exc)})
                    continue
                audit_id = validated["audit_id"]
                if audit_id in existing_ids:
                    results.append({
                        "audit_id": audit_id,
                        "outcome": "duplicate",
                        "detail": "Ya existe un informe con el mismo audit_id.",
                    })
                    continue
                device_id = validated["device"]["id"]
                latest = latest_by_device.get(device_id)
                if latest is not None and _datetime_key(validated["collected_at"]) <= _datetime_key(latest["collected_at"]):
                    outcome = "older"
                    detail = "Es anterior o igual al último informe conocido del equipo."
                else:
                    outcome = "new"
                    detail = "Informe nuevo para el panel de equipos."
                fleet.append(validated)
                existing_ids.add(audit_id)
                if latest is None or _datetime_key(validated["collected_at"]) > _datetime_key(latest["collected_at"]):
                    latest_by_device[device_id] = validated
                added = True
                results.append({"audit_id": audit_id, "outcome": outcome, "detail": detail})

            if added:
                fleet.sort(key=lambda r: (_datetime_key(r.get("collected_at", "")), r.get("audit_id", "")))
                if len(fleet) > MAX_REPORTS:
                    fleet = fleet[-MAX_REPORTS:]
                try:
                    if self._fleet_corrupt:
                        self._backup_corrupt(self.fleet_path, "los informes importados")
                        self._fleet_corrupt = False
                    _atomic_write_json(self.fleet_path, {
                        "schema": SCHEMA_FLEET,
                        "schema_version": SCHEMA_VERSION,
                        "reports": fleet,
                    })
                except OSError as exc:
                    raise WorkspaceError(f"No se pudieron guardar los informes importados: {exc}") from exc
                self._fleet_cache = fleet
            return results

    def report_json(self, record: dict) -> str:
        return json.dumps(report_from_audit(record), ensure_ascii=False, indent=2) + "\n"

    def write_report(self, record: dict, path) -> None:
        try:
            _atomic_write_text(Path(path), self.report_json(record))
        except OSError as exc:
            raise WorkspaceError(f"No se pudo escribir el informe: {exc}") from exc


def fleet_overview(reports: list[dict]) -> list[dict]:
    """Consolida el último informe de cada dispositivo y calcula prioridades."""
    grouped = {}
    for report in reports:
        device_id = report["device"]["id"]
        grouped.setdefault(device_id, []).append(report)

    overview = []
    for device_id, items in grouped.items():
        items.sort(key=lambda r: (_datetime_key(r["collected_at"]), r["audit_id"]))
        latest = items[-1]
        previous = items[-2] if len(items) > 1 else None
        plan = build_action_plan(latest["checks"], allow_repair=False, source="imported")
        counts = latest["summary"]
        comparison = compare_audits(previous, latest) if previous else None
        overview.append({
            "device": latest["device"],
            "latest": latest,
            "previous": previous,
            "history_count": len(items),
            "plan": plan,
            "attention": len(plan),
            "high_findings": sum(
                1 for item in plan
                if item["status"] == "finding" and item["severity"] == "high"
            ),
            "review_items": sum(
                1 for item in plan if item["status"] in {"error", "unverifiable"}
            ),
            "summary": counts,
            "comparison": comparison,
            "sort_key": (
                -sum(1 for item in plan if item["status"] == "finding" and item["severity"] == "high"),
                -len(plan),
                -_datetime_key(latest["collected_at"]).timestamp(),
                latest["device"]["name"].lower(),
            ),
        })
    overview.sort(key=lambda item: item["sort_key"])
    return overview


# ==================== MODO DEMOSTRACIÓN ====================


def generate_demo_audits() -> list[dict]:
    """Genera tres equipos ficticios, solo en memoria y con el esquema real."""
    now = datetime.now(timezone.utc)
    device_1 = {
        "id": "demo-device-fin-01",
        "name": "FIN-LAPTOP-01",
        "os": "Windows 11 Pro",
    }
    device_2 = {
        "id": "demo-device-ops-02",
        "name": "OPS-DESK-02",
        "os": "Windows 11 Enterprise",
    }
    device_3 = {
        "id": "demo-device-admin-03",
        "name": "ADMIN-PC-03",
        "os": "Windows 10 Pro",
    }

    def at(minutes_ago):
        return (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")

    audits = []

    audits.append(build_audit_record([
        {
            "name": "Firewall de Windows", "status": "finding", "severity": "high",
            "recommendation": "Habilite el firewall en los perfiles desactivados.",
            "can_fix": True, "fix_action": "firewall_enable_all",
        },
        {
            "name": "Microsoft Defender", "status": "finding", "severity": "high",
            "recommendation": "Actívela manualmente desde Seguridad de Windows y vuelva a auditar.",
        },
        {
            "name": "Escritorio Remoto (RDP)", "status": "unverifiable", "severity": "info",
            "recommendation": "No se pudo confirmar el estado de RDP. Repita la comprobación.",
        },
        {
            "name": "Análisis de nombres de archivo", "status": "ok", "severity": "info",
            "recommendation": "Sin coincidencias en el ámbito seleccionado.",
        },
    ], device_1, collected_at=at(18), audit_id="demo-audit-fin-01"))

    audits.append(build_audit_record([
        {
            "name": "Firewall de Windows", "status": "ok", "severity": "info",
            "recommendation": "El firewall está activo en todos los perfiles.",
        },
        {
            "name": "Microsoft Defender", "status": "ok", "severity": "info",
            "recommendation": "La protección en tiempo real está activa.",
        },
        {
            "name": "Escritorio Remoto (RDP)", "status": "unverifiable", "severity": "info",
            "recommendation": "RDP está deshabilitado, pero no se pudo verificar el firewall.",
        },
        {
            "name": "Análisis de nombres de archivo", "status": "finding", "severity": "low",
            "recommendation": "Revise los nombres señalados. Solo se examinaron nombres.",
        },
    ], device_2, collected_at=at(42), audit_id="demo-audit-ops-02"))

    older = build_audit_record([
        {
            "name": "Firewall de Windows", "status": "finding", "severity": "high",
            "recommendation": "Habilite el firewall en los perfiles desactivados.",
            "can_fix": True, "fix_action": "firewall_enable_all",
        },
        {
            "name": "Microsoft Defender", "status": "finding", "severity": "high",
            "recommendation": "Actívela manualmente desde Seguridad de Windows y vuelva a auditar.",
        },
        {
            "name": "Escritorio Remoto (RDP)", "status": "ok", "severity": "info",
            "recommendation": "RDP está deshabilitado.",
        },
        {
            "name": "Análisis de nombres de archivo", "status": "ok", "severity": "info",
            "recommendation": "Sin coincidencias.",
        },
    ], device_3, collected_at=at(180), audit_id="demo-audit-admin-03-old")
    newer = build_audit_record([
        {
            "name": "Firewall de Windows", "status": "ok", "severity": "info",
            "recommendation": "El firewall está activo en todos los perfiles.",
        },
        {
            "name": "Microsoft Defender", "status": "finding", "severity": "high",
            "recommendation": "Actívela manualmente desde Seguridad de Windows y vuelva a auditar.",
        },
        {
            "name": "Escritorio Remoto (RDP)", "status": "ok", "severity": "info",
            "recommendation": "RDP está deshabilitado.",
        },
        {
            "name": "Análisis de nombres de archivo", "status": "ok", "severity": "info",
            "recommendation": "Sin coincidencias.",
        },
    ], device_3, collected_at=at(9), audit_id="demo-audit-admin-03-new")
    newer["comparison"] = compare_audits(older, newer)
    audits.extend([older, newer])
    audits.sort(key=lambda r: (_datetime_key(r["collected_at"]), r["audit_id"]))
    return audits
