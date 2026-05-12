# PRD – TFG: Monitorización de dominio Windows

## Problema original
Proyecto TFG de monitorización de un dominio Windows usando Sysmon + Snort,
con dos scripts Python que envían notificaciones a Discord vía webhook:
uno de alertas de seguridad y otro de copias de seguridad. Ampliado con un
panel web local para visualizar métricas en tiempo real.

## Entorno
- Windows Server (siempre encendido; scripts arrancan con la máquina)
- Snort → `C:\Snort\log\alert.ids`
- Sysmon → canal `Microsoft-Windows-Sysmon/Operational`
- 7-Zip → `C:\Program Files\7-Zip\7z.exe`
- Origen backups: `C:\DatosCriticos`  →  Destino: `C:\Backups`

## Webhooks Discord
- Alertas de seguridad → webhook `1499813450682204393/...`
- Backups             → webhook `1499813677560500344/...`

## Implementado (01/05/2026)
### Sesión 1
- `seguridad_activa.py` multihilo (Snort tail + regex IP + Event Log 4625
  con contador por ventana + Sysmon + bloqueo firewall + rate-limit Discord).
- `backup_seguro.py` con 7-Zip AES-256 + mhe=on, SHA-256, rotación 30 días,
  notificación éxito/error.
- `requirements.txt`, lanzadores `.bat`, `README.md` completo.

### Sesión 2 — Panel web local
- `panel_web.py` (FastAPI + Uvicorn) en `127.0.0.1:8080`.
- Parsers de los dos ficheros de log con regex; extracción automática de
  IPs, hashes SHA-256, archivos `Backup_*.7z`, tipos de alerta (scan, login,
  block, sysmon, malware, error, info).
- Endpoints: `/api/stats`, `/api/alertas`, `/api/backups`, `/api/ips`,
  `/api/archivos`, `/api/timeline`.
- Consulta de reglas `BLOCK_*` en firewall vía `netsh`.
- Dashboard `templates/index.html` dark theme (JetBrains Mono + Space Grotesk)
  con 5 tarjetas, gráfica apilada Chart.js (24 h x tipo) y 3 tablas
  (alertas, IPs bloqueadas, backups). Auto-refresh 10 s. `data-testid` en
  todas las secciones.
- `iniciar_panel.bat` + `schtasks /SC ONSTART` documentado.
- Dependencias añadidas: `fastapi`, `uvicorn`.

## Tests realizados
- Lint ruff limpio sobre los tres scripts.
- Sintaxis AST OK.
- `extraer_ip` con 4 casos → OK.
- `_procesar_linea_snort` 3 líneas → alertas + bloqueos correctos.
- `rotar_backups_antiguos` 3 ficheros → 2 borrados correctamente.
- `generar_hash_sha256` → hash correcto.
- `realizar_backup` con origen inexistente → False + notifica Discord.
- Envío real a ambos webhooks → HTTP 204.
- Panel web arrancado con logs de prueba (80 alertas, 8 backups):
  stats JSON correcto, timeline 24 cubetas, HTML renderizado en Chromium
  headless verificado por IA de imágenes → todo OK sin overflow ni
  problemas de contraste.

## Próximos pasos / backlog
- Añadir autenticación básica al panel si se expone en red interna.
- Detección de ransomware por volumen de Sysmon EventID 11.
- Firma GPG del hash SHA-256.
- Envío opcional de backups a almacenamiento externo (S3 / WebDAV).
- Botón "Bloquear IP manualmente" desde el dashboard.
