"""
panel_web.py
------------
Panel web local para el TFG. Lee los logs generados por `seguridad_activa.py`
y `backup_seguro.py` y muestra un dashboard en tiempo real.

Ejecución:  python panel_web.py
Acceso:     http://localhost:8080
"""
import os
import re
import sys
import socket
import subprocess
from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# Forzar UTF-8 en stdout/stderr para que los emojis no rompan el script
# cuando se ejecuta como servicio Windows (NSSM redirige stdio a cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ============================================================
# CONFIGURACIÓN  (coincide con los otros dos scripts)
# ============================================================
LOG_SEGURIDAD = r"C:\Scripts\seguridad_activa.log"
LOG_BACKUPS   = r"C:\Backups\verificacion_backups.log"
CARPETA_BACKUPS = r"C:\Backups"

HOST = "127.0.0.1"
PORT = 8080

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
SERVIDOR = socket.gethostname()

app = FastAPI(title="Proyecto W.A.S.P – Panel de Monitorización")


# ============================================================
# PARSERS
# ============================================================
# Formato seguridad:  2026-05-01 16:50:13,896 [INFO] SnortMonitor - MENSAJE
RE_SEG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),?\d*\s+"
    r"\[(?P<lvl>\w+)\]\s+(?P<thread>\S+)\s+-\s+(?P<msg>.*)$"
)
# Formato backups:    2026-05-01 16:50:13,896 [INFO] MENSAJE
RE_BK = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),?\d*\s+"
    r"\[(?P<lvl>\w+)\]\s+(?P<msg>.*)$"
)
RE_IP      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_HASH    = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_ARCHIVO = re.compile(r"Backup_\d{8}_\d{4}\.7z")


def _leer_cola(path: str, max_bytes: int = 512 * 1024) -> list[str]:
    """Lee aprox. los últimos `max_bytes` bytes de un fichero y devuelve líneas."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            datos = f.read().decode("utf-8", errors="ignore")
        return datos.splitlines()[-2000:]
    except Exception:
        return []


def parsear_alertas() -> list[dict]:
    lineas = _leer_cola(LOG_SEGURIDAD)
    out = []
    for ln in lineas:
        m = RE_SEG.match(ln)
        if not m:
            continue
        msg = m.group("msg")
        ip = None
        ips = RE_IP.findall(msg)
        if ips:
            ip = ips[0]
        tipo = "info"
        low = msg.lower()
        # Orden importa: primero los más específicos.
        if ("login fallido" in low or "4625" in low
                or "inicio de sesión incorrecto" in low
                or "inicio de sesion incorrecto" in low
                or "🔐" in msg):
            tipo = "login"
        elif ("escaneo" in low or "portscan" in low or "port scan" in low
                or "nmap" in low or "🔎" in msg):
            tipo = "scan"
        elif "bloqueada" in low or "blocked" in low or "⛔" in msg:
            tipo = "block"
        # ---- MALWARE ----
        # Defender (🦠) o cualquier indicador de Sysmon (🧪) ahora cuentan
        # como "malware" para que aparezcan en la gráfica del timeline.
        elif (
            "🦠" in msg or "🧪" in msg
            or "defender" in low or "antimalware" in low
            or "amenaza" in low or "threat" in low
            or "malware" in low or "virus" in low
            or "sysmon" in low
            or "shellcode" in low or "trojan" in low or "backdoor" in low
            or "mimikatz" in low or "ransomware" in low
            or "eicar" in low or "lsass" in low
            or "persistencia" in low or "ofuscad" in low
        ):
            tipo = "malware"
        elif "error" in low or "⚠️" in msg or "❌" in msg:
            tipo = "error"
        elif "iniciado" in low or "✅" in msg:
            tipo = "info"
        out.append({
            "ts": m.group("ts"),
            "nivel": m.group("lvl"),
            "hilo": m.group("thread"),
            "mensaje": msg,
            "ip": ip,
            "tipo": tipo,
        })
    return out


def parsear_backups() -> list[dict]:
    lineas = _leer_cola(LOG_BACKUPS)
    out = []
    for ln in lineas:
        m = RE_BK.match(ln)
        if not m:
            continue
        msg = m.group("msg")
        h = RE_HASH.search(msg)
        a = RE_ARCHIVO.search(msg)
        ok = msg.startswith("Backup OK") or "éxito" in msg.lower() or "✅" in msg
        err = msg.startswith("❌") or "ERROR" in msg
        estado = "ok" if ok and not err else ("error" if err else "info")
        out.append({
            "ts": m.group("ts"),
            "nivel": m.group("lvl"),
            "archivo": a.group(0) if a else None,
            "hash": h.group(0) if h else None,
            "estado": estado,
            "mensaje": msg,
        })
    return out


def listar_ips_bloqueadas() -> list[dict]:
    """Consulta el firewall por reglas BLOCK_<ip>.
    Usa PowerShell Get-NetFirewallRule, que es independiente del idioma
    de Windows (al contrario que `netsh`, cuya salida cambia de ES/EN/DE...).
    """
    if os.name != "nt":
        return []
    try:
        ps = ("Get-NetFirewallRule -DisplayName 'BLOCK_*' "
              "-ErrorAction SilentlyContinue | "
              "Select-Object -ExpandProperty DisplayName")
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20
        )
        out = r.stdout or ""
    except Exception:
        out = ""
    resultado = []
    vistas = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("BLOCK_"):
            ip = line[len("BLOCK_"):].strip()
            if ip and ip not in vistas:
                vistas.add(ip)
                resultado.append({"ip": ip, "regla": line})
    # Fallback: si PowerShell no devuelve nada, parseamos netsh con regex
    # bilingüe (ES + EN) por si algún día PowerShell no estuviera disponible.
    if not resultado:
        try:
            r2 = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15
            )
            for m in re.finditer(
                r"(?:Rule Name|Nombre de regla)\s*:\s*BLOCK_(\S+)",
                r2.stdout or "", re.IGNORECASE
            ):
                ip = m.group(1).strip()
                if ip and ip not in vistas:
                    vistas.add(ip)
                    resultado.append({"ip": ip, "regla": f"BLOCK_{ip}"})
        except Exception:
            pass
    return resultado


def listar_archivos_backup() -> list[dict]:
    if not os.path.isdir(CARPETA_BACKUPS):
        return []
    res = []
    for n in os.listdir(CARPETA_BACKUPS):
        if n.startswith("Backup_") and n.endswith(".7z"):
            p = os.path.join(CARPETA_BACKUPS, n)
            try:
                st = os.stat(p)
                res.append({
                    "archivo": n,
                    "tamanio_bytes": st.st_size,
                    "fecha": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                continue
    res.sort(key=lambda x: x["fecha"], reverse=True)
    return res


def _fmt_bytes(n: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {u}"
        n /= 1024
    return f"{n:.2f} PB"


# ============================================================
# ENDPOINTS
# ============================================================
@app.get("/", response_class=HTMLResponse)
def index():
    html = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html.replace("{{SERVIDOR}}", SERVIDOR))


@app.get("/api/stats")
def stats():
    alertas = parsear_alertas()
    backups = parsear_backups()
    archivos = listar_archivos_backup()
    bloqueadas = listar_ips_bloqueadas()
    ahora = datetime.now()
    hace_24h = ahora - timedelta(hours=24)
    alertas_24h = [
        a for a in alertas
        if datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S") >= hace_24h
    ]
    ok_backups = [b for b in backups if b["estado"] == "ok"]
    err_backups = [b for b in backups if b["estado"] == "error"]
    tam_total = sum(a["tamanio_bytes"] for a in archivos)
    return {
        "servidor": SERVIDOR,
        "generado": ahora.strftime("%Y-%m-%d %H:%M:%S"),
        "alertas_totales": len(alertas),
        "alertas_24h": len(alertas_24h),
        "ips_bloqueadas": len(bloqueadas),
        "backups_ok": len(ok_backups),
        "backups_error": len(err_backups),
        "backups_archivos": len(archivos),
        "backups_tamanio": _fmt_bytes(tam_total) if archivos else "0 B",
        "ultimo_backup": archivos[0] if archivos else None,
    }


@app.get("/api/alertas")
def alertas(limit: int = Query(50, ge=1, le=500)):
    data = parsear_alertas()
    data.reverse()
    return JSONResponse(data[:limit])


@app.get("/api/backups")
def backups(limit: int = Query(30, ge=1, le=200)):
    data = parsear_backups()
    data.reverse()
    return JSONResponse(data[:limit])


@app.get("/api/ips")
def ips():
    return JSONResponse(listar_ips_bloqueadas())


@app.get("/api/archivos")
def archivos(limit: int = Query(30, ge=1, le=200)):
    return JSONResponse(listar_archivos_backup()[:limit])


@app.get("/api/timeline")
def timeline(horas: int = Query(24, ge=1, le=168)):
    """Alertas agregadas por hora, para gráfica."""
    alertas = parsear_alertas()
    ahora = datetime.now().replace(minute=0, second=0, microsecond=0)
    cubetas = [(ahora - timedelta(hours=h)) for h in range(horas - 1, -1, -1)]
    claves = [c.strftime("%Y-%m-%d %H:00") for c in cubetas]
    cnt = Counter()
    tipos = {"scan": Counter(), "login": Counter(),
             "block": Counter(), "malware": Counter()}
    for a in alertas:
        try:
            ts = datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        if ts < cubetas[0]:
            continue
        k = ts.replace(minute=0, second=0).strftime("%Y-%m-%d %H:00")
        cnt[k] += 1
        if a["tipo"] in tipos:
            tipos[a["tipo"]][k] += 1
    return {
        "labels": [c.strftime("%H:00") for c in cubetas],
        "total": [cnt[k] for k in claves],
        "scan":    [tipos["scan"][k]    for k in claves],
        "login":   [tipos["login"][k]   for k in claves],
        "block":   [tipos["block"][k]   for k in claves],
        "malware": [tipos["malware"][k] for k in claves],
    }


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    # Asegurar que la carpeta de templates existe (por si alguien la renombra)
    if not TEMPLATES_DIR.is_dir():
        print(f"[ERROR] No existe {TEMPLATES_DIR}", file=sys.stderr)
        sys.exit(1)
    print(f"🌐  Panel Web disponible en  http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
