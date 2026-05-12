"""
backup_seguro.py
----------------
Script de copia de seguridad automatizada para Windows Server.
 - Comprime y cifra C:\\DatosCriticos con 7-Zip (AES-256 + cabeceras cifradas).
 - Genera un hash SHA-256 del archivo resultante y lo registra en log.
 - Rota backups antiguos (>30 días).
 - Notifica a Discord tanto ÉXITOS como ERRORES.

Autor: Proyecto TFG
Ejecución: tarea programada / arranque automático en Windows Server.
"""

import os
import sys
import socket
import hashlib
import logging
import datetime
import subprocess
from logging.handlers import RotatingFileHandler

import requests

# Forzar UTF-8 en stdout/stderr para que los emojis no rompan el script
# cuando se ejecuta como servicio Windows (NSSM redirige stdio a cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ============================================================
# CONFIGURACIÓN
# ============================================================
ORIGEN       = r"C:\DatosCriticos"
DESTINO      = r"C:\Backups"
PASSWORD     = "ClaveSegura2026"              # hardcoded (requisito TFG)
PATH_7Z      = r"C:\Program Files\7-Zip\7z.exe"
DIAS_RETENER = 30                             # rotación automática
LOG_FILE     = os.path.join(DESTINO, "verificacion_backups.log")

WEBHOOK_URL = (
    "https://discord.com/api/webhooks/1499813677560500344/"
    "IbrrHuq0SQraK-5aWE5dymjVjtpAPp7UFMsArBR3JAUMvWhLxcSZgfN3bBmeBXh3JOVu"
)

SERVIDOR = socket.gethostname()


# ============================================================
# LOGGING
# ============================================================
os.makedirs(DESTINO, exist_ok=True)
logger = logging.getLogger("backup_seguro")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_fh = RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=5,
                          encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(_fmt)
logger.addHandler(_ch)


# ============================================================
# UTILIDADES
# ============================================================
def notificar_discord(msg: str):
    """Envia un mensaje al webhook de backups. Nunca lanza excepción."""
    final = f"💾 **[{SERVIDOR}]** {msg}"[:1900]
    try:
        r = requests.post(WEBHOOK_URL, json={"content": final}, timeout=10)
        if r.status_code not in (200, 204):
            logger.warning("Discord respondió %s: %s", r.status_code, r.text)
    except Exception as e:
        logger.warning("No se pudo notificar a Discord: %s", e)


def generar_hash_sha256(ruta: str) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(8192), b""):
            h.update(bloque)
    return h.hexdigest()


def tamanio_humano(bytes_: int) -> str:
    for unidad in ("B", "KB", "MB", "GB", "TB"):
        if bytes_ < 1024:
            return f"{bytes_:.2f} {unidad}"
        bytes_ /= 1024
    return f"{bytes_:.2f} PB"


# ============================================================
# ROTACIÓN
# ============================================================
def rotar_backups_antiguos():
    """Elimina ficheros Backup_*.7z con más de DIAS_RETENER días."""
    limite = datetime.datetime.now() - datetime.timedelta(days=DIAS_RETENER)
    eliminados = []
    if not os.path.isdir(DESTINO):
        return eliminados
    for nombre in os.listdir(DESTINO):
        if not (nombre.startswith("Backup_") and nombre.endswith(".7z")):
            continue
        ruta = os.path.join(DESTINO, nombre)
        try:
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(ruta))
            if mtime < limite:
                os.remove(ruta)
                eliminados.append(nombre)
                logger.info("Rotado (borrado) backup antiguo: %s", nombre)
        except Exception as e:
            logger.warning("No se pudo rotar %s: %s", nombre, e)
    return eliminados


# ============================================================
# BACKUP
# ============================================================
def realizar_backup() -> bool:
    # Validaciones previas
    if not os.path.isdir(ORIGEN):
        msg = f"❌ Directorio origen no existe: `{ORIGEN}`. Backup ABORTADO."
        logger.error(msg)
        notificar_discord(msg)
        return False

    if not os.path.isfile(PATH_7Z):
        msg = f"❌ No se encuentra 7-Zip en `{PATH_7Z}`. Backup ABORTADO."
        logger.error(msg)
        notificar_discord(msg)
        return False

    os.makedirs(DESTINO, exist_ok=True)

    fecha         = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    nombre_archivo = f"Backup_{fecha}.7z"
    ruta_final    = os.path.join(DESTINO, nombre_archivo)

    comando = [
        PATH_7Z, "a",
        "-t7z",
        f"-p{PASSWORD}",
        "-mhe=on",          # cabeceras cifradas
        "-mx=5",            # nivel de compresión medio
        ruta_final,
        ORIGEN,
    ]

    logger.info("Iniciando backup: %s  ->  %s", ORIGEN, ruta_final)
    inicio = datetime.datetime.now()

    try:
        resultado = subprocess.run(
            comando, capture_output=True, text=True, check=False
        )
    except Exception as e:
        msg = f"❌ Excepción ejecutando 7-Zip: {e}"
        logger.exception(msg)
        notificar_discord(msg)
        return False

    duracion = (datetime.datetime.now() - inicio).total_seconds()

    if resultado.returncode != 0 or not os.path.exists(ruta_final):
        stderr = (resultado.stderr or resultado.stdout or "").strip()[:800]
        msg = (f"❌ **ERROR en copia de seguridad** (rc={resultado.returncode}).\n"
               f"Archivo: `{nombre_archivo}`\n```\n{stderr}\n```")
        logger.error(msg)
        notificar_discord(msg)
        return False

    # Éxito: calcular hash + tamaño
    try:
        hash_sha = generar_hash_sha256(ruta_final)
        tam      = tamanio_humano(os.path.getsize(ruta_final))
    except Exception as e:
        msg = f"⚠️ Backup creado pero no se pudo verificar: {e}"
        logger.error(msg)
        notificar_discord(msg)
        return False

    logger.info("Backup OK: %s  SHA256=%s  size=%s  dur=%.1fs",
                nombre_archivo, hash_sha, tam, duracion)

    # Rotación
    eliminados = rotar_backups_antiguos()
    txt_rot = (f"\n🗑️ Rotación: {len(eliminados)} backup(s) antiguo(s) eliminados"
               if eliminados else "")

    exito_msg = (
        f"✅ **Backup completado con éxito**\n"
        f"📦 Archivo: `{nombre_archivo}`\n"
        f"📏 Tamaño: `{tam}`\n"
        f"⏱️ Duración: `{duracion:.1f}s`\n"
        f"🔐 SHA-256: `{hash_sha}`"
        f"{txt_rot}"
    )
    notificar_discord(exito_msg)
    return True


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    try:
        ok = realizar_backup()
        sys.exit(0 if ok else 1)
    except Exception as e:
        logger.exception("Fallo inesperado en backup")
        notificar_discord(f"❌ Fallo inesperado en backup: {e}")
        sys.exit(1)
