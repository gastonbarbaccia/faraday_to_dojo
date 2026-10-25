# Faraday → DefectDojo

Script en Python que exporta las vulnerabilidades de un workspace de **Faraday** a CSV y las importa en **DefectDojo**, creando automáticamente un producto por cada **target** de Faraday.

## Cómo funciona

1. **Login en Faraday** con usuario y contraseña (`/_api/login`) y obtención de un token de API (`/_api/v3/token`).
2. **Extracción** de todas las vulnerabilidades del workspace (`/_api/v3/ws/<workspace>/vulns`) y filtrado por estado (por defecto `open` y `re-opened`).
3. **Agrupación por target.** El campo `target` de Faraday se usa como nombre del producto en DefectDojo. En hallazgos de código (por ejemplo Semgrep) el target es el path del archivo; en hallazgos de red es la IP o el host.
4. **Export.** Se generan dos tipos de archivo en `exports/<workspace>_<AAAAMMDD>_<HHMMSS>/`. La carpeta lleva fecha y hora, así que cada corrida queda separada y nunca se sobrescribe un export anterior:
   - `faraday_<workspace>.csv`: un CSV con todas las vulnerabilidades, pensado para revisión o auditoría;
   - `import/NNNN_<target>.json`: un JSON por target en formato *Generic Findings Import* de DefectDojo, que es el que se importa.
5. **En DefectDojo**, para cada target:
   - valida o crea el *Product Type* configurado (por defecto `Faraday`);
   - busca el producto con nombre exacto igual al target y, si no existe, lo crea;
   - valida o crea el engagement de importación (por defecto `Faraday - Import automatico`);
   - importa el JSON con `/api/v2/import-scan/` creando un nuevo Test, cuyo título incluye la fecha y hora de la corrida (por ejemplo `Faraday SR-Interno 2026-10-25 14:30:22`).
6. **Resumen final** con el estado de cada producto (creado, existente o error).

Si falla un target, el script sigue con el resto y termina con código de salida `1`.

### Por qué se importa en JSON y no en CSV

El CSV genérico de DefectDojo no tiene campos para archivo y línea. En hallazgos de código es habitual que la misma regla aparezca varias veces en un mismo archivo, en líneas distintas: en el export de prueba (`SR-Interno`), 1.208 de 1.381 vulnerabilidades comparten título y target con otra. Sin la línea, DefectDojo las marcaría como duplicadas. El formato JSON sí acepta `file_path` y `line`, así que cada hallazgo queda identificado de forma única.

### Hallazgos de código vs. infraestructura

Faraday guarda los hallazgos de herramientas SAST con el archivo en `target` y la línea como un "servicio" llamado `Line N`, cuyo puerto es el número de línea. El script detecta ese patrón y:

- si es un hallazgo de **código**, carga `file_path` (el target) y `line` (el número de línea);
- si es de **infraestructura o web**, carga un endpoint con host, puerto y protocolo (o la URL si la vuln tiene `website`).

## Requisitos

- Python 3.9 o superior.
- Usuario de Faraday con acceso de lectura al workspace.
- API key v2 de DefectDojo de un usuario con permiso para crear Product Types, productos, engagements e importar scans. Se obtiene en DefectDojo desde *menú de usuario → API v2 Key*.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuración

Copiá `.env.example` a `.env` y completá los valores. El script también lee las variables directamente del entorno, lo cual es lo recomendado en CI/CD o cron.

| Variable | Obligatoria | Descripción |
|---|---|---|
| `FARADAY_URL` | Sí | URL de Faraday, por ejemplo `http://localhost:5985` |
| `FARADAY_USER` | Sí | Usuario de Faraday |
| `FARADAY_PASSWORD` | Sí | Contraseña de Faraday |
| `FARADAY_WORKSPACE` | Sí* | Workspace a exportar (*o usar `--workspace`) |
| `DOJO_URL` | Sí | URL de DefectDojo |
| `DOJO_API_KEY` | Sí | API key v2 de DefectDojo |
| `DOJO_PRODUCT_TYPE` | No | Product Type para los productos nuevos (default `Faraday`) |
| `DOJO_ENGAGEMENT_NAME` | No | Nombre del engagement (default `Faraday - Import automatico`) |
| `VERIFY_TLS` | No | `true` (default), `false` o ruta a un bundle de CA |

El archivo `.env` contiene secretos: no lo subas al repositorio (agregalo a `.gitignore`) y restringí sus permisos con `chmod 600 .env`.

## Uso

```bash
# Primera prueba: genera los archivos y muestra qué haría en DefectDojo sin escribir nada
python faraday_to_defectdojo.py --dry-run

# Ejecución normal
python faraday_to_defectdojo.py

# Otro workspace, incluyendo todas las vulns sin importar su estado
python faraday_to_defectdojo.py --workspace pentest_q4 --status all

# Solo exportar el CSV y los JSON
python faraday_to_defectdojo.py --export-only
```

| Opción | Descripción |
|---|---|
| `--workspace` | Workspace de Faraday; pisa `FARADAY_WORKSPACE` |
| `--output-dir` | Carpeta de salida del CSV y los JSON (default `exports`) |
| `--status` | Estados a exportar separados por coma, o `all` (default `open,re-opened`) |
| `--export-only` | Solo genera el CSV y los JSON |
| `--dry-run` | Genera los archivos y simula los pasos en DefectDojo |
| `-v`, `--verbose` | Log detallado |

## Mapeo de campos

| Faraday | Finding en DefectDojo | Notas |
|---|---|---|
| `target` | Producto | Nombre exacto del producto (máx. 255 caracteres) |
| `name` | `title` | |
| `severity` | `severity` | `med` pasa a `Medium`; `informational` y `unclassified` pasan a `Info`; una severidad desconocida se avisa en el log y se carga como `Info` |
| `date` o `metadata.create_time` | `date` | Si falta, se usa la fecha actual |
| `desc` + `data` + hostnames + `tool` | `description` | |
| `resolution` | `mitigation` | |
| `impact` | `impact` | Lista de dimensiones afectadas |
| `refs` | `references` | |
| `cwe` | `cwe` | Primer CWE, solo el número |
| `cve` | `vulnerability_ids` | |
| `status` | `active` | `true` si está `open` o `re-opened` |
| `confirmed` | `verified` | |
| `target` (código) | `file_path` | Solo si el servicio es `Line N` |
| puerto del servicio `Line N` | `line` | Solo en hallazgos de código |
| `target` + servicio, o `website` | `endpoints` | Solo en hallazgos de infraestructura o web |

## Deduplicación

El script **no** deduplica: delega esa tarea en DefectDojo. Para que funcione:

1. Activá *System Settings → Deduplicate findings*.
2. Por defecto la comparación se hace dentro del mismo producto, lo que encaja con el esquema de un producto por target.
3. DefectDojo compara un hash calculado sobre ciertos campos del finding. Para *Generic Findings Import* esos campos se configuran en el servidor con `HASHCODE_FIELDS_PER_SCANNER`. El script ya envía `file_path` y `line` en hallazgos de código para que esos campos participen del hash. Si notás duplicados que no se detectan (por ejemplo, porque la descripción cambia entre corridas en Faraday), conviene ajustar esa configuración a campos estables como `title`, `file_path`, `line` y `cwe`.

Tené en cuenta que DefectDojo **crea igual** el finding repetido, pero lo marca como `duplicate` e inactivo. Si no querés que se acumulen, activá también *Delete duplicate findings* en *System Settings* y definí cuántos duplicados conservar.

Por diseño, el script no cierra en DefectDojo las vulnerabilidades que ya no están en Faraday (`close_old_findings=false`). Si en el futuro querés ese comportamiento, el cambio es usar `/api/v2/reimport-scan/` sobre un Test fijo por producto.

## Automatización

Ejemplo de cron que lo ejecuta todos los días a las 2 AM:

```cron
0 2 * * * cd /opt/faraday2dojo && ./venv/bin/python faraday_to_defectdojo.py >> logs/faraday2dojo.log 2>&1
```

## Códigos de salida

| Código | Significado |
|---|---|
| `0` | Todo OK (o no había vulnerabilidades para exportar) |
| `1` | Al menos un producto falló al importar |
| `2` | Error de configuración, autenticación o conexión |

## Problemas frecuentes

**"Faraday: credenciales inválidas"**: revisá usuario y contraseña. En Docker la contraseña inicial está en `docker compose logs faraday-server`. Si el usuario tiene 2FA activado, el login por API no funciona; usá un usuario de servicio sin 2FA.

**"DefectDojo: API key inválida"**: verificá que la key sea de API v2 y que el header se envíe como `Token <key>` (el script lo hace solo).

**Error de certificado TLS**: si DefectDojo o Faraday usan una CA interna, apuntá `VERIFY_TLS` al archivo `.pem` de esa CA. Usá `VERIFY_TLS=false` solo en laboratorio.

**Workspaces muy grandes**: el script pide todas las vulnerabilidades en una sola llamada. Si el workspace tiene decenas de miles y la API tarda demasiado, conviene filtrar con `--status` o adaptar `get_vulns()` para usar el endpoint `/vulns/filter` con paginación.
