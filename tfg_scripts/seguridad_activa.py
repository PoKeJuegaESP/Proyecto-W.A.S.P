"""
seguridad_activa.py
-------------------
Script de vigilancia activa para Windows Server.
 - Monitoriza el log de Snort (alert.ids) y extrae IPs de alertas de escaneo.
 - Monitoriza el Visor de Eventos de Windows:
     * ID 4625  -> Login fallido (fuerza bruta)
     * Canal Microsoft-Windows-Sysmon/Operational (procesos sospechosos)
 - Bloquea automáticamente IPs tras N intentos fallidos usando Windows Firewall.
 - Envia todas las alertas a un webhook de Discord.

Autor: Proyecto TFG
Ejecución: servicio en background en Windows Server (arranque con la máquina).
"""

import os
import re
import sys
import time
import json
import queue
import socket
import logging
import threading
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler

import requests

# Forzar UTF-8 en stdout/stderr para que los emojis no rompan el script
# cuando se ejecuta como servicio Windows (NSSM redirige stdio a cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# win32evtlog solo existe en Windows; permitimos import opcional para poder
# ejecutar pruebas en otras plataformas sin que todo el script reviente.
try:
    import win32evtlog          # pywin32
    import win32evtlogutil
    import win32con
    WINDOWS_EVT_AVAILABLE = True
except ImportError:
    WINDOWS_EVT_AVAILABLE = False


# ============================================================
# CONFIGURACIÓN
# ============================================================
WEBHOOK_URL = (
    "https://discord.com/api/webhooks/1499813450682204393/"
    "234FEtpsm7HpCoC9cSlg9963AIExxf3_V0BOBtMhnVmt3bkrOu3QrfIMQ7Z7FhkA0lgN"
)

SNORT_LOG         = r"C:\Snort\log\alert.ids"
INTENTOS_MAXIMOS  = 5                # nº de fallos antes de bloquear IP
VENTANA_SEGUNDOS  = 300              # ventana temporal de conteo (5 min)
SERVIDOR_NOMBRE   = socket.gethostname()
LOG_FILE          = r"C:\Scripts\seguridad_activa.log"

# IPs y/o redes CIDR que NUNCA se bloquearán.
# Acepta IPs sueltas ("192.168.1.1") o redes ("192.168.1.0/24").
WHITELIST = [
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "192.168.1.1",        # IP del administrador del dominio
    "192.168.1.0/24",     # Red local completa (máscara 255.255.255.0)
]

# Pre-compilamos las redes una sola vez para que el check sea O(1) por IP.
_WHITELIST_NETS = []
for _item in WHITELIST:
    try:
        _WHITELIST_NETS.append(ipaddress.ip_network(_item, strict=False))
    except ValueError:
        pass


def en_whitelist(ip: str) -> bool:
    """True si la IP pertenece a cualquier entrada de la whitelist."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in red for red in _WHITELIST_NETS)

# IDs de Sysmon que se analizan. EventID=3 (conexión de red) está DESACTIVADO
# por defecto porque genera demasiado ruido (cada petición web de cualquier
# app lo dispara). Si quieres reactivarlo, añade 3 al conjunto y ajusta las
# heurísticas de red en _es_sospechoso_red().
#   1  -> Process creation   (con heurísticas de CommandLine e Image)
#   10 -> ProcessAccess      (solo sobre LSASS -> indicador de Mimikatz)
#   11 -> FileCreate         (solo en rutas de persistencia)
#   22 -> DNSEvent           (solo dominios sospechosos)
SYSMON_EVENTS_INTERES = {1, 10, 11, 22}

# Imágenes (rutas de .exe) cuyos eventos de Sysmon se IGNORAN siempre.
# Incluye nuestros propios scripts TFG + binarios comunes muy ruidosos.
SYSMON_EXCLUDE_IMAGES = [
    "python.exe",
    "pythonw.exe",
    "7z.exe",
    "7zg.exe",
    "netsh.exe",
    "conhost.exe",
    "svchost.exe",
]

# -----------------------------------------------------------
# Heurísticas (IOCs) - patrones que definen lo "sospechoso"
# -----------------------------------------------------------
# Fragmentos que si aparecen en CommandLine se consideran ataque.
PATRONES_CMD_SOSPECHOSOS = [
    # PowerShell ofuscado / descargas en memoria
    " -enc ", " -encodedcommand", " -ec ", "frombase64string",
    "iex ", "invoke-expression", "downloadstring", "downloadfile",
    "net.webclient", "bitstransfer", "invoke-webrequest",
    "-nop -w hidden", "-windowstyle hidden", "-noprofile",
    # LOLBins (Living Off The Land Binaries)
    "bitsadmin /transfer", "certutil -urlcache", "certutil -decode",
    "mshta ", "rundll32 javascript:", "regsvr32 /s /u /i:",
    "wmic process call create", "schtasks /create",
    # Herramientas ofensivas conocidas
    "mimikatz", "procdump", "lazagne", "psexec", "nc.exe -",
    "net user /add", "net localgroup administrators /add",
    # Anti-forense
    "vssadmin delete", "wbadmin delete", "wevtutil cl",
    "cipher /w:",
]

# Substrings de ruta que en Image = proceso desde ubicación sospechosa.
RUTAS_IMAGE_SOSPECHOSAS = [
    r"\appdata\local\temp\\"[:-1],
    r"\appdata\roaming\\"[:-1],
    r"\users\public\\"[:-1],
    r"\windows\temp\\"[:-1],
    r"\programdata\\"[:-1],
    r"\recycle.bin",
    r"\$recycle.bin",
]

# Si estos padres lanzan un shell/script -> "living off the land" clásico.
PADRES_OFFICE = [
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
]
HIJOS_SHELL = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe",
]

# TLDs gratuitos muy usados por C2 / phishing.
TLDS_SOSPECHOSOS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                    ".top", ".click", ".download")

# Rutas donde la creación de un fichero indica persistencia real.
# Se busca el substring dentro del TargetFilename (comparado en minúsculas).
RUTAS_PERSISTENCIA = [
    r"\start menu\programs\startup",   # carpeta Inicio (user y all-users)
    r"\windows\system32\tasks",        # tareas programadas
    r"\windows\system32\drivers",      # drivers del kernel
    r"\windows\tasks",
    r"\currentversion\run",            # clave de registro en ProfileList
]

# Procesos de seguridad que legítimamente acceden a LSASS (antivirus, EDR...).
ACCESO_LSASS_LEGITIMO = [
    "windefend", "msmpeng.exe", "sense.exe", "mssense.exe",
    "csagent.exe", "crowdstrike", "sentinelone",
    "wmiprvse.exe", "lsass.exe",
]


# ============================================================
# LOGGING LOCAL (fichero rotatorio)
# ============================================================
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True) if os.path.dirname(LOG_FILE) else None
logger = logging.getLogger("seguridad_activa")
logger.setLevel(logging.INFO)
_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(threadName)s - %(message)s"
)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5,
                          encoding="utf-8")
_fh.setFormatter(_formatter)
logger.addHandler(_fh)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(_formatter)
logger.addHandler(_ch)


# ============================================================
# UTILIDADES
# ============================================================
_ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extraer_ip(linea: str):
    """
    Devuelve la primera IP válida encontrada en una línea.
    Snort clásico imprime algo como:  10.0.0.5:3421 -> 10.0.0.10:445
    Nos quedamos con la IP de origen (la primera).
    """
    for ip in _ip_regex.findall(linea):
        octetos = [int(o) for o in ip.split(".")]
        if all(0 <= o <= 255 for o in octetos):
            return ip
    return None


# Cola única para despachar mensajes a Discord desde varios hilos sin
# saturar el webhook (Discord limita a ~30 req/min por webhook).
_discord_queue: "queue.Queue[str]" = queue.Queue()


def _discord_worker():
    """Consumidor único que envía mensajes al webhook de Discord."""
    while True:
        msg = _discord_queue.get()
        if msg is None:
            break
        payload = {"content": msg[:1900]}      # límite de 2000 chars
        for intento in range(3):
            try:
                r = requests.post(WEBHOOK_URL, json=payload, timeout=10)
                if r.status_code in (200, 204):
                    break
                if r.status_code == 429:       # rate limit
                    retry = r.json().get("retry_after", 2)
                    time.sleep(float(retry) + 0.5)
                    continue
                logger.warning("Discord respondió %s: %s", r.status_code, r.text)
            except requests.RequestException as e:
                logger.warning("Error enviando a Discord (intento %s): %s",
                               intento + 1, e)
                time.sleep(2)
        # pequeña pausa para no saturar
        time.sleep(0.4)
        _discord_queue.task_done()


def enviar_alerta(msg: str):
    """Encola un mensaje para Discord + lo escribe en el log local."""
    final = f"🚨 **[{SERVIDOR_NOMBRE}]** {msg}"
    logger.info(msg)
    _discord_queue.put(final)


# ============================================================
# BLOQUEO DE IP (Windows Firewall)
# ============================================================
_ips_bloqueadas: set[str] = set()
_lock_block = threading.Lock()


def precargar_ips_bloqueadas() -> int:
    """Lee las reglas BLOCK_* existentes del firewall y las añade a memoria.
    Útil al arrancar tras un reinicio del servicio para no volver a contar
    intentos sobre IPs que ya estaban bloqueadas. Devuelve el nº cargado.
    """
    if os.name != "nt":
        return 0
    cargadas = 0
    try:
        ps = ("Get-NetFirewallRule -DisplayName 'BLOCK_*' "
              "-ErrorAction SilentlyContinue | "
              "Select-Object -ExpandProperty DisplayName")
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20
        )
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("BLOCK_"):
                ip = line[len("BLOCK_"):].strip()
                if ip:
                    with _lock_block:
                        _ips_bloqueadas.add(ip)
                    cargadas += 1
    except Exception as e:
        logger.warning("No se pudo precargar IPs bloqueadas: %s", e)
    return cargadas


def ip_ya_bloqueada(ip: str) -> bool:
    """Comprueba si existe ya una regla BLOCK_<ip> en el firewall."""
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name=BLOCK_{ip}"],
            capture_output=True, text=True, timeout=10
        )
        return "No rules match" not in r.stdout and r.returncode == 0
    except Exception:
        return False


def bloquear_ip(ip: str, motivo: str = "comportamiento sospechoso"):
    if not ip or en_whitelist(ip):
        return
    with _lock_block:
        if ip in _ips_bloqueadas:
            return
        if ip_ya_bloqueada(ip):
            _ips_bloqueadas.add(ip)
            return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=BLOCK_{ip}",
                 "dir=in", "action=block", f"remoteip={ip}"],
                capture_output=True, text=True, check=True, timeout=15
            )
            _ips_bloqueadas.add(ip)
            enviar_alerta(f"⛔ IP **{ip}** BLOQUEADA en firewall. Motivo: {motivo}")
        except subprocess.CalledProcessError as e:
            enviar_alerta(
                f"❌ No se pudo bloquear la IP {ip}. "
                f"netsh stderr: {e.stderr.strip() if e.stderr else e}"
            )


# ============================================================
# MÓDULO 1 · Monitor de Snort
# ============================================================
# Anti-spam: una IP detectada por Snort solo dispara UNA alerta
# cada SNORT_DEDUP_SECONDS segundos. El resto se cuentan en silencio
# y se incluye un resumen "(N paquetes)" en la siguiente alerta.
SNORT_DEDUP_SECONDS = 60
_snort_last_alert: dict[str, float] = {}    # ip -> last alert timestamp
_snort_pkt_count: dict[str, int] = {}        # ip -> paquetes silenciados
_lock_snort = threading.Lock()


def monitorear_snort():
    """Sigue el fichero alert.ids en modo tail -f."""
    while True:
        if not os.path.exists(SNORT_LOG):
            logger.warning("Log de Snort no encontrado: %s. Reintentando en 30s.",
                           SNORT_LOG)
            time.sleep(30)
            continue
        try:
            with open(SNORT_LOG, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    _procesar_linea_snort(line.strip())
        except Exception as e:
            enviar_alerta(f"⚠️ Error en monitor Snort: {e}. Reiniciando en 10s...")
            time.sleep(10)


def _procesar_linea_snort(linea: str):
    if not linea:
        return
    # Palabras clave que consideramos ataques
    patrones = {
        "Posible escaneo":     "Posible escaneo de red (Snort)",
        "Portscan":            "Port scan detectado (Snort)",
        "SCAN":                "Actividad de escaneo (Snort)",
        "NMAP":                "Herramienta Nmap detectada (Snort)",
        "SHELLCODE":           "Posible shellcode (Snort)",
        "TROJAN":              "Tráfico de troyano (Snort)",
        "BACKDOOR":            "Posible backdoor (Snort)",
    }
    for clave, descripcion in patrones.items():
        if clave.lower() in linea.lower():
            ip = extraer_ip(linea)
            # ----- Anti-spam: dedup por IP en ventana de tiempo -----
            ahora = time.time()
            silenciar = False
            paquetes_acumulados = 0
            if ip:
                with _lock_snort:
                    last = _snort_last_alert.get(ip, 0.0)
                    if ahora - last < SNORT_DEDUP_SECONDS:
                        # Ya alertamos hace poco por esta IP, sumamos el paquete
                        # al contador y no enviamos otra alerta.
                        _snort_pkt_count[ip] = _snort_pkt_count.get(ip, 0) + 1
                        silenciar = True
                    else:
                        # Es una nueva alerta: recogemos el contador acumulado
                        paquetes_acumulados = _snort_pkt_count.pop(ip, 0)
                        _snort_last_alert[ip] = ahora
            if silenciar:
                return

            # Texto opcional con paquetes acumulados desde la última alerta
            extra = (f" · {paquetes_acumulados + 1} paquetes en último minuto"
                     if paquetes_acumulados > 0 else "")

            if ip and not en_whitelist(ip):
                enviar_alerta(
                    f"🔎 {descripcion}. IP origen: `{ip}`{extra}\n`{linea[:300]}`"
                )
                # bloqueo directo: estos patrones son de alta severidad
                bloquear_ip(ip, descripcion)
            elif ip and en_whitelist(ip):
                # IP en whitelist: informamos pero NO bloqueamos
                enviar_alerta(
                    f"🔎 {descripcion} (IP {ip} en whitelist, NO se bloquea){extra}.\n`{linea[:300]}`"
                )
            else:
                enviar_alerta(f"🔎 {descripcion} (IP no extraíble).\n`{linea[:300]}`")
            return


# ============================================================
# MÓDULO 2 · Monitor de Eventos de Windows
# ============================================================
# contador de intentos fallidos por IP (para 4625)
_fallos_por_ip: dict[str, list[float]] = {}
_lock_fallos = threading.Lock()


def _registrar_intento_fallido(ip: str, usuario: str, computer: str = "",
                               logon_type: str = ""):
    """Registra un intento fallido de login.

    - Siempre envía alerta al panel/Discord (también para IP vacía o whitelisted).
    - Solo bloquea la IP en el firewall si NO está en whitelist y no es vacía.
    """
    # Identificador interno para contar fallos.
    # Si no hay IP usable, agrupamos por hostname para no perder el evento.
    es_local = (not ip) or ip in ("-", "::1", "0.0.0.0")
    es_whitelisted = (not es_local) and en_whitelist(ip)
    clave = ip if not es_local else f"local:{computer or 'desconocido'}"

    # Si la IP ya está bloqueada en firewall, ignoramos para no spamear.
    if not es_local and not es_whitelisted:
        with _lock_block:
            if ip in _ips_bloqueadas:
                return

    ahora = time.time()
    with _lock_fallos:
        hist = _fallos_por_ip.setdefault(clave, [])
        hist[:] = [t for t in hist if ahora - t <= VENTANA_SEGUNDOS]
        hist.append(ahora)
        num = len(hist)

    # Tipo de login en formato humano (LogonType 4625):
    #   2  = Interactivo (pantalla de bloqueo / consola)
    #   3  = Red (SMB, RDP NLA, recursos compartidos)
    #   4  = Batch
    #   5  = Servicio
    #   7  = Desbloqueo de pantalla
    #   10 = RemoteInteractive (RDP clásico)
    tipo_login_map = {
        "2":  "pantalla de bloqueo",
        "3":  "red (SMB/recurso)",
        "4":  "batch",
        "5":  "servicio",
        "7":  "desbloqueo",
        "8":  "NetworkCleartext",
        "9":  "NewCredentials",
        "10": "RDP",
        "11": "CachedInteractive",
    }
    tipo_login_txt = tipo_login_map.get(str(logon_type), f"tipo {logon_type}" if logon_type else "")

    # Nombre de la máquina donde se intentó el login (donde ocurrió el 4625).
    maquina = computer or SERVIDOR_NOMBRE
    rol = "servidor" if maquina.lower() == SERVIDOR_NOMBRE.lower() else "cliente"

    # Origen del intento (de dónde viene el login)
    if es_local:
        origen = "local"
    elif es_whitelisted:
        origen = f"{ip} (whitelist)"
    else:
        origen = ip

    enviar_alerta(
        f"🔐 **Inicio de sesión incorrecto** en {rol} `{maquina}` "
        f"· cuenta: `{usuario}`"
        + (f" · vía {tipo_login_txt}" if tipo_login_txt else "")
        + f" · origen: `{origen}` ({num}/{INTENTOS_MAXIMOS} en {VENTANA_SEGUNDOS}s)"
    )

    # Solo se bloquea si no es local y no está en whitelist
    if not es_local and not es_whitelisted and num >= INTENTOS_MAXIMOS:
        bloquear_ip(ip, f"{num} intentos fallidos de login en {VENTANA_SEGUNDOS}s")


def _leer_inserts(evento):
    """Devuelve StringInserts o lista vacía (compat. API antigua)."""
    try:
        return list(evento.StringInserts or [])
    except Exception:
        return []


# ------------------------------------------------------------
# Parser de eventos en XML (API moderna EvtQuery/EvtRender)
# ------------------------------------------------------------
_EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parsear_evento_xml(xml_str: str):
    """Devuelve (event_id, {Campo: valor}, computer, provider) o
    (None, {}, '', '') si falla.

    `computer` = hostname donde se generó el evento (útil para WEF).
    `provider` = nombre del proveedor (para distinguir Sysmon / Security
    cuando los eventos vienen del canal ForwardedEvents).
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None, {}, "", ""
    system = root.find(f"{_EVT_NS}System")
    if system is None:
        return None, {}, "", ""
    eid_el = system.find(f"{_EVT_NS}EventID")
    if eid_el is None or not eid_el.text:
        return None, {}, "", ""
    try:
        event_id = int(eid_el.text)
    except ValueError:
        return None, {}, "", ""

    # Hostname origen del evento (Cliente1Proy.dominio.local -> Cliente1Proy)
    comp_el = system.find(f"{_EVT_NS}Computer")
    computer = (comp_el.text if comp_el is not None and comp_el.text else "")
    if computer:
        computer = computer.split(".")[0]

    # Provider (necesario para discriminar en ForwardedEvents)
    prov_el = system.find(f"{_EVT_NS}Provider")
    provider = prov_el.get("Name", "") if prov_el is not None else ""

    data = {}
    event_data = root.find(f"{_EVT_NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{_EVT_NS}Data"):
            name = d.get("Name", "")
            val = d.text or ""
            if name:
                data[name] = val
    return event_id, data, computer, provider


def _host_prefix(computer: str) -> str:
    """Devuelve '[Cliente1Proy] ' si el evento viene de otra máquina, '' si es local."""
    if computer and computer.lower() != SERVIDOR_NOMBRE.lower():
        return f"[{computer}] "
    return ""


def _procesar_evento_security(event_id: int, data: dict, computer: str = "", provider: str = ""):
    if event_id != 4625:
        return
    usuario = data.get("TargetUserName", "desconocido")
    ip      = data.get("IpAddress", "")
    logon_type = data.get("LogonType", "")
    # Siempre procesar el fallo: la función decide si bloquea o no según
    # la IP (vacía/whitelisted = solo alerta; pública = alerta + bloqueo).
    _registrar_intento_fallido(ip, usuario, computer, logon_type)


def _procesar_evento_sysmon(event_id: int, data: dict, computer: str = "", provider: str = ""):
    """Solo envía alerta si el evento supera las heurísticas de ataque."""
    if event_id not in SYSMON_EVENTS_INTERES:
        return
    sospechoso, motivo = _detectar_sospechoso(event_id, data)
    if not sospechoso:
        return
    interesantes = ["Image", "User", "CommandLine",
                    "TargetImage", "SourceImage",
                    "SourceIp", "DestinationIp", "DestinationPort",
                    "TargetFilename", "QueryName", "ParentImage"]
    resumen = " | ".join(f"{k}={data[k]}" for k in interesantes if k in data)[:240]
    enviar_alerta(
        f"🧪 {_host_prefix(computer)}**Sysmon ID={event_id}** · {motivo}\n`{resumen}`"
    )


def _procesar_evento_defender(event_id: int, data: dict, computer: str = "", provider: str = ""):
    """Procesa eventos de Windows Defender / Microsoft Antimalware.

    EventIDs relevantes:
      1006  -> El motor encontró malware u otro software no deseado.
      1007  -> Acción aplicada sobre la amenaza.
      1015  -> Detección heurística / comportamiento.
      1116  -> Detectado malware (alerta principal).
      1117  -> Acción tomada con éxito.
      1118  -> Acción crítica fallida.
      1119  -> Acción crítica que requiere intervención.
      5001  -> Protección en tiempo real DESACTIVADA (tampering).
      5007  -> Configuración de Defender modificada.
    """
    # Datos típicos en Defender 1116/1117:
    #   "Threat Name" / "Nombre de la amenaza"
    #   "Severity Name" / "Gravedad"
    #   "Path"
    #   "Process Name"
    #   "Detection User"
    threat = (data.get("Threat Name") or data.get("threat name")
              or data.get("Threat") or "amenaza desconocida")
    severity = (data.get("Severity Name") or data.get("severity name")
                or data.get("Severity") or "")
    path = (data.get("Path") or data.get("path") or "")
    proc = (data.get("Process Name") or data.get("process name") or "")
    user = (data.get("Detection User") or data.get("detection user") or "")
    action = (data.get("Action Name") or data.get("action name") or "")

    # Si no llegan campos con nombre (eventos sin EventData "Name="),
    # caemos a las raw inserts numéricas via win32evtlogutil.
    extra_raw = ""
    if threat == "amenaza desconocida":
        # Algunos ProviderNames de Defender no exponen nombres de campo,
        # así que pasamos cualquier valor que tengamos como contexto.
        valores = [v for v in data.values() if v]
        if valores:
            extra_raw = " | ".join(valores)[:240]

    if event_id in (1006, 1015, 1116):
        msg_partes = [f"🦠 {_host_prefix(computer)}**Windows Defender · MALWARE detectado**"]
        msg_partes.append(f"Amenaza: `{threat}`")
        if severity:
            msg_partes.append(f"Gravedad: `{severity}`")
        if path:
            msg_partes.append(f"Ruta: `{path}`")
        if proc:
            msg_partes.append(f"Proceso: `{proc}`")
        if user:
            msg_partes.append(f"Usuario: `{user}`")
        if extra_raw:
            msg_partes.append(f"`{extra_raw}`")
        enviar_alerta(" · ".join(msg_partes))
    elif event_id in (1117,):
        enviar_alerta(
            f"🦠 {_host_prefix(computer)}Defender aplicó acción `{action or 'limpieza'}` "
            f"sobre amenaza `{threat}` en `{path or proc or 'objetivo desconocido'}`."
        )
    elif event_id in (1118, 1119):
        enviar_alerta(
            f"🦠 {_host_prefix(computer)}**Defender FALLÓ** al neutralizar amenaza "
            f"`{threat}` (EventID {event_id}). Revisar manualmente."
        )
    elif event_id in (5001, 5007):
        enviar_alerta(
            f"🦠 {_host_prefix(computer)}⚠️ **Tampering en Defender** "
            f"(EventID {event_id}): protección modificada/desactivada."
        )
    # Resto de IDs se ignoran (informativos, scans completados, etc.)


def _procesar_evento_forwarded(event_id: int, data: dict, computer: str = "", provider: str = ""):
    """Dispatcher para el canal ForwardedEvents (eventos llegados via WEF).
    Decide si es Sysmon, Security o Defender en función del Provider.
    """
    if "Microsoft-Windows-Security-Auditing" in provider:
        _procesar_evento_security(event_id, data, computer, provider)
    elif "Microsoft-Windows-Sysmon" in provider:
        _procesar_evento_sysmon(event_id, data, computer, provider)
    elif ("Microsoft-Windows-Windows Defender" in provider
          or "Microsoft Antimalware" in provider):
        _procesar_evento_defender(event_id, data, computer, provider)
    # otros eventos reenviados se ignoran silenciosamente


def _es_dominio_sospechoso(dominio: str) -> bool:
    """Heurística simple para detectar dominios tipo C2/phishing."""
    if not dominio:
        return False
    d = dominio.lower().rstrip(".")
    if d.endswith(TLDS_SOSPECHOSOS):
        return True
    # DGA heurística: etiqueta principal muy larga y sin vocales
    etiquetas = d.split(".")
    if not etiquetas:
        return False
    primera = etiquetas[0]
    if len(primera) >= 18 and sum(c in "aeiou" for c in primera) <= 2:
        return True
    # muchísimos dígitos en el dominio
    if sum(c.isdigit() for c in primera) >= 8:
        return True
    return False


def _detectar_sospechoso(event_id: int, data: dict):
    """
    Devuelve (True, 'motivo') si el evento es sospechoso, o (False, '') si es
    ruido normal. Cada EventID tiene su propia lógica.
    """
    image         = (data.get("Image") or "").lower()
    parent_image  = (data.get("ParentImage") or "").lower()
    command_line  = (data.get("CommandLine") or "").lower()

    # Proceso excluido explícitamente -> nunca alerta
    for ex in SYSMON_EXCLUDE_IMAGES:
        if ex.lower() in image or ex.lower() in parent_image:
            return False, ""

    # ========= ID 1 · Creación de proceso =========
    if event_id == 1:
        # a) Línea de comandos con patrones de ataque
        for pat in PATRONES_CMD_SOSPECHOSOS:
            if pat in command_line:
                return True, f"CommandLine sospechosa ('{pat.strip()}')"
        # b) Proceso ejecutado desde ruta de staging (Temp, AppData, ...)
        for ruta in RUTAS_IMAGE_SOSPECHOSAS:
            if ruta in image:
                return True, f"Ejecutable en ruta inusual: {ruta.strip(chr(92))}"
        # c) Living-off-the-land: Office/script -> shell
        nombre_padre = parent_image.rsplit("\\", 1)[-1]
        nombre_hijo  = image.rsplit("\\", 1)[-1]
        if nombre_padre in PADRES_OFFICE and nombre_hijo in HIJOS_SHELL:
            return True, f"Proceso hijo de Office: {nombre_padre} -> {nombre_hijo}"
        return False, ""

    # ========= ID 3 · Conexión de red =========
    if event_id == 3:
        dest_ip   = data.get("DestinationIp", "")
        dest_port = data.get("DestinationPort", "")
        if not dest_ip:
            return False, ""
        try:
            addr = ipaddress.ip_address(dest_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False, ""
        except ValueError:
            return False, ""
        # Puertos típicos de backdoors / metasploit / mineros
        puertos_malos = {"4444", "5555", "1337", "31337", "9001", "6666",
                         "6667", "8333", "14444", "3333"}
        if str(dest_port) in puertos_malos:
            return True, f"Conexión saliente a {dest_ip}:{dest_port} (puerto sospechoso)"
        return False, ""

    # ========= ID 10 · Acceso a proceso =========
    if event_id == 10:
        target_image = (data.get("TargetImage") or "").lower()
        source_image = (data.get("SourceImage") or "").lower()
        granted_access = (data.get("GrantedAccess") or "").lower()
        if target_image.endswith("lsass.exe"):
            # Excluir accesos legítimos de antivirus / el propio Windows
            for legit in ACCESO_LSASS_LEGITIMO:
                if legit in source_image:
                    return False, ""
            return True, (f"Acceso a LSASS desde "
                          f"{source_image.rsplit(chr(92),1)[-1]} "
                          f"(GrantedAccess={granted_access}) "
                          f"-> posible volcado de credenciales")
        return False, ""

    # ========= ID 11 · Creación de archivo =========
    if event_id == 11:
        target = (data.get("TargetFilename") or "").lower()
        if not target:
            return False, ""
        for ruta in RUTAS_PERSISTENCIA:
            if ruta in target:
                # Ignorar si lo crea el propio instalador de Windows / MsiExec
                if "msiexec.exe" in image or "trustedinstaller" in image:
                    return False, ""
                return True, f"Archivo creado en ruta de persistencia: {data.get('TargetFilename')}"
        return False, ""

    # ========= ID 22 · DNS =========
    if event_id == 22:
        query = data.get("QueryName", "")
        if _es_dominio_sospechoso(query):
            return True, f"Consulta DNS sospechosa: {query}"
        return False, ""

    return False, ""


def _poll_event_log(canal: str, procesador):
    """
    Polling de un canal del Visor de Eventos usando la API moderna EvtQuery.
    Funciona tanto para canales clásicos (Security, ForwardedEvents) como
    modernos (Microsoft-Windows-Sysmon/Operational).
    """
    if not WINDOWS_EVT_AVAILABLE:
        return

    # 1) Verificar que el canal existe y es accesible.
    try:
        h_test = win32evtlog.EvtQuery(
            canal,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            None, None
        )
        try:
            win32evtlog.EvtClose(h_test)
        except Exception:
            pass
    except Exception as e:
        enviar_alerta(
            f"⚠️ Canal `{canal}` no disponible: {e}\n"
            f"Monitor DESACTIVADO. Posibles causas:\n"
            f"• Sysmon no instalado (instálalo desde Sysinternals).\n"
            f"• Suscripción WEF no creada (canal ForwardedEvents).\n"
            f"• Servicio no ejecutándose como SYSTEM / Administrador."
        )
        return

    last_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    fallos = 0

    while True:
        try:
            xpath = f"*[System[TimeCreated[@SystemTime>'{last_ts}']]]"
            h = win32evtlog.EvtQuery(
                canal,
                win32evtlog.EvtQueryChannelPath,
                xpath, None
            )
            procesados = 0
            while True:
                events = win32evtlog.EvtNext(h, 256)
                if not events:
                    break
                for ev in events:
                    try:
                        xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                        eid, data, computer, provider = _parsear_evento_xml(xml_str)
                        if eid is not None:
                            procesador(eid, data, computer, provider)
                            procesados += 1
                    except Exception as e:
                        logger.error("Error procesando evento %s: %s", canal, e)
                    finally:
                        try:
                            win32evtlog.EvtClose(ev)
                        except Exception:
                            pass
            try:
                win32evtlog.EvtClose(h)
            except Exception:
                pass

            if procesados > 0:
                last_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            fallos = 0
            time.sleep(3)
        except Exception as e:
            fallos += 1
            espera = min(300, 15 * (2 ** min(fallos - 1, 4)))
            if fallos <= 3:
                logger.error("Error leyendo canal %s: %s (reintento en %ds)",
                             canal, e, espera)
            time.sleep(espera)


def monitorear_eventos_windows():
    """Lanza un hilo por cada canal a monitorizar y los reinicia si mueren."""
    if not WINDOWS_EVT_AVAILABLE:
        enviar_alerta("ℹ️ pywin32 no disponible: monitor de eventos DESACTIVADO.")
        return

    canales = [
        # (nombre_canal, procesador, alias)
        ("Security",                                 _procesar_evento_security,  "EvtSecurity"),
        ("Microsoft-Windows-Sysmon/Operational",     _procesar_evento_sysmon,    "EvtSysmon"),
        ("Microsoft-Windows-Windows Defender/Operational",
                                                     _procesar_evento_defender,  "EvtDefender"),
        ("ForwardedEvents",                          _procesar_evento_forwarded, "EvtForwarded"),
    ]
    hilos = {}

    def _lanzar(canal, proc, alias):
        t = threading.Thread(target=_poll_event_log, args=(canal, proc),
                             name=alias, daemon=True)
        t.start()
        return t

    for canal, proc, alias in canales:
        hilos[alias] = _lanzar(canal, proc, alias)

    # Watchdog: reinicia hilos que mueran
    while True:
        for canal, proc, alias in canales:
            if not hilos[alias].is_alive():
                logger.warning("Hilo %s caído, reiniciando...", alias)
                hilos[alias] = _lanzar(canal, proc, alias)
        time.sleep(30)


# ============================================================
# MAIN
# ============================================================
def main():
    # lanza worker de Discord
    threading.Thread(target=_discord_worker, name="DiscordWorker",
                     daemon=True).start()

    # Cargar las IPs ya bloqueadas en el firewall (de ejecuciones anteriores)
    n_pre = precargar_ips_bloqueadas()

    enviar_alerta(
        f"✅ Servicio de vigilancia iniciado en **{SERVIDOR_NOMBRE}** "
        f"({datetime.now():%Y-%m-%d %H:%M:%S}) · "
        f"{n_pre} IP(s) ya bloqueadas en firewall."
    )

    # Snort en un hilo
    threading.Thread(target=monitorear_snort, name="SnortMonitor",
                     daemon=True).start()
    # Event Log en otro
    threading.Thread(target=monitorear_eventos_windows, name="EvtMonitor",
                     daemon=True).start()

    # el hilo principal se queda vivo
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        enviar_alerta("🛑 Servicio de vigilancia DETENIDO manualmente.")


if __name__ == "__main__":
    main()
