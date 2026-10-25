#!/usr/bin/env python3
"""
faraday_to_defectdojo.py
========================

Exporta las vulnerabilidades de un workspace de Faraday a CSV y las importa
en DefectDojo, usando el campo "target" de Faraday como nombre de producto:

  1. Se autentica contra Faraday y obtiene las vulnerabilidades del workspace.
  2. Genera un CSV con todas las vulnerabilidades (export legible).
  3. Agrupa las vulnerabilidades por target y genera, por cada uno, un JSON
     en formato "Generic Findings Import" de DefectDojo. Se usa JSON y no CSV
     porque el formato JSON admite archivo y línea (file_path / line), que
     son necesarios para que la deduplicación distinga hallazgos de código.
  4. Para cada target:
       - valida si existe el producto en DefectDojo (nombre = target)
         y si no existe lo crea;
       - valida o crea el engagement donde se cargan los findings;
       - importa el JSON con /api/v2/import-scan/.

La deduplicación queda a cargo de DefectDojo (System Settings ->
"Deduplicate findings"). Ver README.md para los detalles.

Configuración: variables de entorno o archivo .env (ver .env.example).
Uso:  python faraday_to_defectdojo.py --help
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv es opcional
    load_dotenv = None

log = logging.getLogger("faraday2dojo")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

HTTP_TIMEOUT = 60  # segundos por request

# Severidades de Faraday -> severidades de DefectDojo
SEVERITY_MAP = {
    "critical": "Critical",
    "crit": "Critical",
    "high": "High",
    "medium": "Medium",
    "med": "Medium",       # el export de Faraday abrevia "medium" como "med"
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "inf": "Info",
    "unclassified": "Info",
}

# Columnas del CSV de export
CSV_COLUMNS = [
    "Target", "Title", "Severity", "Status", "Date", "File", "Line",
    "Host", "Port", "CWE", "CVE", "Tool", "Description", "Mitigation", "References",
]


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Falta o es inválida alguna variable de configuración."""


def build_session(verify: bool | str) -> requests.Session:
    """Crea una sesión HTTP con reintentos automáticos ante errores transitorios."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify
    return session


def env(name: str, default: str | None = None, required: bool = True) -> str | None:
    """Lee una variable de entorno; falla con un mensaje claro si es obligatoria."""
    value = os.getenv(name, default)
    if required and not value:
        raise ConfigError(f"Falta la variable de entorno {name}")
    return value


def tls_verify_setting() -> bool | str:
    """
    Interpreta VERIFY_TLS:
      - "true" (default) -> verifica certificados
      - "false"          -> no verifica (solo para laboratorios)
      - ruta a archivo   -> usa ese bundle de CA
    """
    raw = os.getenv("VERIFY_TLS", "true").strip()
    if raw.lower() in ("true", "1", "yes", ""):
        return True
    if raw.lower() in ("false", "0", "no"):
        log.warning("VERIFY_TLS=false: no se verifican certificados TLS. "
                    "Usalo solo en entornos de prueba.")
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        return False
    if not Path(raw).is_file():
        raise ConfigError(f"VERIFY_TLS apunta a un archivo inexistente: {raw}")
    return raw


def safe_filename(name: str) -> str:
    """Convierte un hostname en un nombre de archivo seguro."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:150] or "sin_nombre"


def raise_for_status(resp: requests.Response, context: str) -> None:
    """Como resp.raise_for_status(), pero con un mensaje legible y acotado."""
    if resp.ok:
        return
    body = resp.text[:500].replace("\n", " ")
    raise RuntimeError(f"{context}: HTTP {resp.status_code} - {body}")


# ---------------------------------------------------------------------------
# Faraday
# ---------------------------------------------------------------------------

class FaradayClient:
    """Cliente mínimo para la API v3 de Faraday."""

    def __init__(self, url: str, user: str, password: str, verify: bool | str):
        self.url = url.rstrip("/")
        self.session = build_session(verify)
        self._login(user, password)

    def _login(self, user: str, password: str) -> None:
        """
        Inicia sesión y obtiene un token de API.
        Si el endpoint de token no está disponible, sigue con la cookie de sesión.
        """
        resp = self.session.post(
            f"{self.url}/_api/login",
            json={"email": user, "password": password},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code in (400, 401, 403):
            raise RuntimeError("Faraday: credenciales inválidas o usuario sin permisos")
        raise_for_status(resp, "Faraday login")

        token_resp = self.session.get(f"{self.url}/_api/v3/token", timeout=HTTP_TIMEOUT)
        if token_resp.ok:
            token = token_resp.json()
            if isinstance(token, dict):
                token = token.get("token")
            if token:
                self.session.headers["Authorization"] = f"Token {token}"
        log.info("Autenticado en Faraday (%s)", self.url)

    def get_vulns(self, workspace: str) -> list[dict[str, Any]]:
        """Devuelve todas las vulnerabilidades del workspace."""
        resp = self.session.get(
            f"{self.url}/_api/v3/ws/{requests.utils.quote(workspace)}/vulns",
            timeout=HTTP_TIMEOUT * 5,
        )
        if resp.status_code == 404:
            raise RuntimeError(f"Faraday: el workspace '{workspace}' no existe")
        raise_for_status(resp, "Faraday get vulns")

        data = resp.json()
        items = data.get("vulnerabilities", data if isinstance(data, list) else [])
        # La API v3 suele envolver cada vuln en {"id", "key", "value": {...}}
        vulns = [item.get("value", item) for item in items]
        log.info("Faraday: %d vulnerabilidades en el workspace '%s'", len(vulns), workspace)
        return vulns


# ---------------------------------------------------------------------------
# Transformación Faraday -> CSV (export) y JSON genérico de DefectDojo (import)
# ---------------------------------------------------------------------------

LINE_SERVICE_RE = re.compile(r"^line\s+\d+$", re.IGNORECASE)


def vuln_product_name(vuln: dict[str, Any]) -> str | None:
    """Nombre de producto en DefectDojo: el campo 'target' de Faraday."""
    target = str(vuln.get("target") or "").strip()
    return target[:255] or None  # 255 = largo máximo del nombre de producto


def service_port(service: dict[str, Any]) -> int | None:
    """Faraday expone el puerto como 'port' o 'ports' (entero o lista)."""
    raw = service.get("port", service.get("ports"))
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    try:
        return int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def code_location(vuln: dict[str, Any]) -> tuple[str, int | None] | None:
    """
    Detecta hallazgos de código (SAST, ej. Semgrep). Faraday los guarda con el
    archivo en 'target' y la línea como un servicio llamado 'Line N' cuyo
    puerto es el número de línea. Devuelve (archivo, línea) o None si no aplica.
    """
    service = vuln.get("service") or {}
    if isinstance(service, dict) and LINE_SERVICE_RE.match(str(service.get("name", "")).strip()):
        return str(vuln.get("target") or "").strip(), service_port(service)
    return None


def parse_datetime(vuln: dict[str, Any]) -> date:
    """Fecha de creación de la vuln ('date' o metadata.create_time)."""
    raw = vuln.get("date") or (vuln.get("metadata") or {}).get("create_time")
    try:
        if isinstance(raw, (int, float)):
            # Faraday a veces devuelve epoch en milisegundos
            secs = raw / 1000 if raw > 10**11 else raw
            return datetime.fromtimestamp(secs, tz=timezone.utc).date()
        if isinstance(raw, str) and raw:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except (ValueError, OSError):
        pass
    return date.today()


def _texts(items: Any) -> list[str]:
    """Normaliza listas de Faraday que pueden venir como strings o dicts {'name': ...}."""
    out = []
    for item in items or []:
        text = item.get("name", "") if isinstance(item, dict) else str(item)
        if text.strip():
            out.append(text.strip())
    return out


def parse_cwe(vuln: dict[str, Any]) -> int | None:
    """Primer CWE numérico (ej. 'CWE-79' -> 79)."""
    for text in _texts(vuln.get("cwe")):
        match = re.search(r"(\d+)", text)
        if match:
            return int(match.group(1))
    return None


def parse_impact(vuln: dict[str, Any]) -> str:
    impact = vuln.get("impact") or {}
    if not isinstance(impact, dict):
        return str(impact)
    afectados = [k.capitalize() for k, v in impact.items() if v]
    return ("Impacto en: " + ", ".join(afectados)) if afectados else ""


def build_endpoint(vuln: dict[str, Any]) -> dict[str, Any] | None:
    """Endpoint de DefectDojo para hallazgos de infraestructura o web."""
    website = str(vuln.get("website") or "").strip()
    if website:
        if "://" not in website:
            website = f"http://{website}"
        parsed = urlparse(website)
        endpoint = {"protocol": parsed.scheme, "host": parsed.hostname}
        if parsed.port:
            endpoint["port"] = parsed.port
        path = (vuln.get("path") or parsed.path or "").lstrip("/")
        if path:
            endpoint["path"] = path
        return endpoint if endpoint["host"] else None

    target = str(vuln.get("target") or "").strip()
    if not target:
        return None
    endpoint: dict[str, Any] = {"host": target}
    service = vuln.get("service") or {}
    if isinstance(service, dict):
        port = service_port(service)
        if port:
            endpoint["port"] = port
            name = str(service.get("name") or "").lower()
            endpoint["protocol"] = name if name in ("http", "https") else (
                service.get("protocol") or "tcp")
    return endpoint


def build_description(vuln: dict[str, Any]) -> str:
    """
    Descripción del finding. Se mantiene estable entre corridas (sin fechas
    ni IDs que cambien) para que la deduplicación de DefectDojo funcione bien.
    """
    parts = [vuln.get("desc") or vuln.get("description") or ""]
    if vuln.get("data"):
        parts.append(f"\n**Datos técnicos:**\n{vuln['data']}")
    hostnames = _texts(vuln.get("hostnames"))
    if hostnames:
        parts.append(f"\n**Hostnames:** {', '.join(hostnames)}")
    if vuln.get("tool"):
        parts.append(f"\n**Herramienta:** {vuln['tool']}")
    return "\n".join(p for p in parts if p).strip() or "Sin descripción"


def map_severity(raw: Any) -> str:
    """Traduce la severidad de Faraday; si no la reconoce, avisa y usa Info."""
    key = str(raw or "").strip().lower()
    if key not in SEVERITY_MAP:
        log.warning("Severidad desconocida '%s', se importa como Info", raw)
        return "Info"
    return SEVERITY_MAP[key]


def vuln_to_finding(vuln: dict[str, Any]) -> dict[str, Any]:
    """Convierte una vuln de Faraday en un finding del JSON genérico de DefectDojo."""
    status = str(vuln.get("status", "open")).lower()
    cves = [c for c in _texts(vuln.get("cve")) if c.upper().startswith("CVE-")]
    finding: dict[str, Any] = {
        "title": (vuln.get("name") or "Sin título").strip()[:511],
        "description": build_description(vuln),
        "severity": map_severity(vuln.get("severity")),
        "date": parse_datetime(vuln).isoformat(),
        "mitigation": vuln.get("resolution") or "",
        "impact": parse_impact(vuln),
        "references": "\n".join(_texts(vuln.get("refs"))),
        "active": status in ("open", "re-opened"),
        "verified": bool(vuln.get("confirmed")),
    }
    cwe = parse_cwe(vuln)
    if cwe:
        finding["cwe"] = cwe
    if cves:
        finding["vulnerability_ids"] = cves

    location = code_location(vuln)
    if location:
        finding["file_path"], line = location
        if line is not None:
            finding["line"] = line
    else:
        endpoint = build_endpoint(vuln)
        if endpoint:
            finding["endpoints"] = [endpoint]
    return finding


def group_vulns(
    vulns: list[dict[str, Any]], statuses: set[str] | None
) -> dict[str, list[dict[str, Any]]]:
    """Filtra por estado y agrupa las vulns de Faraday por target."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped = 0
    for vuln in vulns:
        if statuses and str(vuln.get("status", "")).lower() not in statuses:
            continue
        product = vuln_product_name(vuln)
        if not product:
            skipped += 1
            continue
        grouped[product].append(vuln)
    if skipped:
        log.warning("%d vulnerabilidades salteadas por no tener target", skipped)
    return dict(grouped)


def write_export_csv(grouped: dict[str, list[dict[str, Any]]], path: Path) -> int:
    """CSV con todas las vulnerabilidades exportadas (para revisión o auditoría)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for target, vulns in grouped.items():
            for vuln in vulns:
                f = vuln_to_finding(vuln)
                ep = (f.get("endpoints") or [{}])[0]
                writer.writerow({
                    "Target": target,
                    "Title": f["title"],
                    "Severity": f["severity"],
                    "Status": vuln.get("status", ""),
                    "Date": f["date"],
                    "File": f.get("file_path", ""),
                    "Line": f.get("line", ""),
                    "Host": ep.get("host", ""),
                    "Port": ep.get("port", ""),
                    "CWE": f.get("cwe", ""),
                    "CVE": ", ".join(f.get("vulnerability_ids", [])),
                    "Tool": vuln.get("tool", ""),
                    "Description": f["description"],
                    "Mitigation": f["mitigation"],
                    "References": f["references"],
                })
                total += 1
    return total


def write_import_json(vulns: list[dict[str, Any]], path: Path) -> None:
    """JSON en formato 'Generic Findings Import' de DefectDojo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"findings": [vuln_to_finding(v) for v in vulns]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# DefectDojo
# ---------------------------------------------------------------------------

class DefectDojoClient:
    """Cliente mínimo para la API v2 de DefectDojo."""

    def __init__(self, url: str, api_key: str, verify: bool | str):
        self.url = url.rstrip("/")
        self.session = build_session(verify)
        self.session.headers.update({
            "Authorization": f"Token {api_key}",
            "Accept": "application/json",
        })

    # -- helpers ------------------------------------------------------------

    def _find_exact(self, endpoint: str, name: str, **filters: Any) -> dict | None:
        """
        Busca un objeto por nombre exacto. El filtro de la API puede devolver
        coincidencias parciales, así que se compara el nombre en Python.
        """
        params = {"name": name, "limit": 100, **filters}
        resp = self.session.get(f"{self.url}/api/v2/{endpoint}/", params=params,
                                timeout=HTTP_TIMEOUT)
        raise_for_status(resp, f"DefectDojo GET {endpoint}")
        for obj in resp.json().get("results", []):
            if obj.get("name") == name:
                return obj
        return None

    def _create(self, endpoint: str, payload: dict[str, Any]) -> dict:
        resp = self.session.post(f"{self.url}/api/v2/{endpoint}/", json=payload,
                                 timeout=HTTP_TIMEOUT)
        raise_for_status(resp, f"DefectDojo POST {endpoint}")
        return resp.json()

    # -- objetos ------------------------------------------------------------

    def check_connection(self) -> None:
        resp = self.session.get(f"{self.url}/api/v2/user_profile/", timeout=HTTP_TIMEOUT)
        if resp.status_code in (401, 403):
            raise RuntimeError("DefectDojo: API key inválida o sin permisos")
        raise_for_status(resp, "DefectDojo conexión")
        log.info("Conectado a DefectDojo (%s)", self.url)

    def get_or_create_product_type(self, name: str, dry_run: bool) -> int | None:
        found = self._find_exact("product_types", name)
        if found:
            return found["id"]
        if dry_run:
            log.info("[dry-run] Se crearía el Product Type '%s'", name)
            return None
        created = self._create("product_types", {"name": name})
        log.info("Product Type creado: '%s' (id %s)", name, created["id"])
        return created["id"]

    def get_or_create_product(
        self, name: str, prod_type_id: int | None, dry_run: bool
    ) -> tuple[int | None, bool]:
        """Devuelve (id_producto, fue_creado)."""
        found = self._find_exact("products", name)
        if found:
            return found["id"], False
        if dry_run:
            return None, True
        created = self._create("products", {
            "name": name,
            "description": f"Producto creado automáticamente desde Faraday para {name}",
            "prod_type": prod_type_id,
        })
        return created["id"], True

    def get_or_create_engagement(
        self, product_id: int | None, name: str, dry_run: bool
    ) -> int | None:
        if product_id is None:  # producto todavía no creado (dry-run)
            return None
        found = self._find_exact("engagements", name, product=product_id)
        if found:
            return found["id"]
        if dry_run:
            return None
        today = date.today().isoformat()
        created = self._create("engagements", {
            "name": name,
            "product": product_id,
            "target_start": today,
            "target_end": today,
            "engagement_type": "CI/CD",
            "status": "In Progress",
            "description": "Engagement para importaciones automáticas desde Faraday",
        })
        return created["id"]

    def import_scan(self, engagement_id: int, json_path: Path, test_title: str) -> dict:
        """Importa el JSON como 'Generic Findings Import' en el engagement indicado."""
        data = {
            "scan_type": "Generic Findings Import",
            "engagement": engagement_id,
            "scan_date": date.today().isoformat(),
            "minimum_severity": "Info",
            "active": "true",
            "verified": "false",
            "close_old_findings": "false",
            "test_title": test_title,
        }
        with json_path.open("rb") as fh:
            resp = self.session.post(
                f"{self.url}/api/v2/import-scan/",
                data=data,
                files={"file": (json_path.name, fh, "application/json")},
                timeout=HTTP_TIMEOUT * 5,
            )
        raise_for_status(resp, "DefectDojo import-scan")
        return resp.json()


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Exporta vulnerabilidades de Faraday a CSV y las importa en DefectDojo.",
    )
    p.add_argument("--workspace", help="Workspace de Faraday (pisa FARADAY_WORKSPACE)")
    p.add_argument("--output-dir", default="exports",
                   help="Carpeta donde se guardan el CSV y los JSON (default: exports)")
    p.add_argument("--status", default="open,re-opened",
                   help="Estados de Faraday a exportar, separados por coma, "
                        "o 'all' para todos (default: open,re-opened)")
    p.add_argument("--export-only", action="store_true",
                   help="Solo generar el CSV y los JSON, sin tocar DefectDojo")
    p.add_argument("--dry-run", action="store_true",
                   help="Generar los archivos y mostrar qué se haría en DefectDojo, sin escribir nada")
    p.add_argument("-v", "--verbose", action="store_true", help="Log detallado")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    # Evita que urllib3 loguee headers (con tokens) en modo verbose
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    if load_dotenv:
        load_dotenv()

    try:
        verify = tls_verify_setting()
        workspace = args.workspace or env("FARADAY_WORKSPACE")
        faraday = FaradayClient(
            env("FARADAY_URL"), env("FARADAY_USER"), env("FARADAY_PASSWORD"), verify
        )
        vulns = faraday.get_vulns(workspace)
    except (ConfigError, RuntimeError, requests.RequestException) as exc:
        log.error("%s", exc)
        return 2

    statuses = None if args.status.strip().lower() == "all" else {
        s.strip().lower() for s in args.status.split(",") if s.strip()
    }
    grouped = group_vulns(vulns, statuses)
    if not grouped:
        log.warning("No hay vulnerabilidades para exportar con los filtros indicados")
        return 0

    # 1) Export: un CSV con todo + un JSON de importación por target
    # Fecha y hora de la corrida: cada ejecución usa su propia carpeta y no pisa exports anteriores
    run_ts = datetime.now()
    out_dir = Path(args.output_dir) / f"{safe_filename(workspace)}_{run_ts:%Y%m%d_%H%M%S}"
    csv_path = out_dir / f"faraday_{safe_filename(workspace)}.csv"
    total = write_export_csv(grouped, csv_path)
    log.info("CSV generado: %s (%d vulns, %d targets)", csv_path, total, len(grouped))

    json_files: dict[str, Path] = {}
    for idx, (product, vulns_target) in enumerate(grouped.items(), start=1):
        # El índice evita colisiones entre targets que generan el mismo nombre de archivo
        path = out_dir / "import" / f"{idx:04d}_{safe_filename(product)}.json"
        write_import_json(vulns_target, path)
        json_files[product] = path
        log.debug("JSON generado: %s (%d vulns)", path, len(vulns_target))
    log.info("JSON de importación generados en %s", out_dir / "import")

    if args.export_only:
        log.info("Modo --export-only: no se importa en DefectDojo")
        return 0

    # 2) Importar en DefectDojo
    try:
        dojo = DefectDojoClient(env("DOJO_URL"), env("DOJO_API_KEY"), verify)
        dojo.check_connection()
        prod_type_id = dojo.get_or_create_product_type(
            env("DOJO_PRODUCT_TYPE", "Faraday", required=False), args.dry_run
        )
    except (ConfigError, RuntimeError, requests.RequestException) as exc:
        log.error("%s", exc)
        return 2

    engagement_name = env("DOJO_ENGAGEMENT_NAME", "Faraday - Import automatico",
                          required=False)
    test_title = f"Faraday {workspace} {run_ts:%Y-%m-%d %H:%M:%S}"
    summary = []
    errores = 0

    for product, path in json_files.items():
        try:
            product_id, created = dojo.get_or_create_product(product, prod_type_id,
                                                             args.dry_run)
            estado = "creado" if created else "existente"
            if args.dry_run:
                summary.append((product, estado, len(grouped[product]), "dry-run"))
                log.info("[dry-run] Producto '%s' (%s): se importarían %d vulns",
                         product, estado, len(grouped[product]))
                continue

            engagement_id = dojo.get_or_create_engagement(product_id, engagement_name,
                                                          args.dry_run)
            result = dojo.import_scan(engagement_id, path, test_title)
            stats = result.get("statistics", {}).get("after", {}).get("total", {})
            detalle = f"test {result.get('test', '?')}"
            if stats:
                detalle += f", total findings en el test: {stats.get('total', '?')}"
            summary.append((product, estado, len(grouped[product]), detalle))
            log.info("Producto '%s' (%s): importado OK (%s)", product, estado, detalle)
        except (RuntimeError, requests.RequestException) as exc:
            errores += 1
            summary.append((product, "error", len(grouped[product]), str(exc)[:120]))
            log.error("Producto '%s': %s", product, exc)

    # 3) Resumen
    print("\n=== Resumen ===")
    print(f"{'Producto':40} {'Estado':10} {'Vulns':>6}  Detalle")
    for product, estado, count, detalle in summary:
        print(f"{product[:40]:40} {estado:10} {count:>6}  {detalle}")
    print(f"\nProductos procesados: {len(summary)} | con error: {errores}")

    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())