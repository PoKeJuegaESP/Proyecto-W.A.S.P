# TFG – Monitorización de dominio Windows

Scripts para la monitorización activa y la realización de copias de seguridad
cifradas de un dominio Windows, con notificaciones a Discord.

## Contenido

| Archivo | Descripción |
|---|---|
| `seguridad_activa.py`   | Vigilancia en tiempo real (Snort + Event Log + Sysmon) |
| `backup_seguro.py`      | Copia de seguridad cifrada 7-Zip con verificación SHA-256 y rotación de 30 días |
| `panel_web.py`          | Panel web local (FastAPI + Chart.js) en `http://localhost:8080` |
| `templates/index.html`  | Dashboard del panel web |
| `iniciar_seguridad.bat` | Lanza `seguridad_activa.py` en segundo plano (sin ventana) |
| `iniciar_panel.bat`     | Lanza `panel_web.py` en segundo plano |
| `ejecutar_backup.bat`   | Ejecuta un backup puntual |
| `requirements.txt`      | Dependencias Python |

## Requisitos

- Windows Server (probado en 2019/2022)
- **Python 3.10+** instalado (marca “Add Python to PATH”)
- **7-Zip** instalado en `C:\Program Files\7-Zip\7z.exe`
- **Snort** escribiendo alertas en `C:\Snort\log\alert.ids`
- **Sysmon** instalado (si quieres el canal `Microsoft-Windows-Sysmon/Operational`)
- Permisos de Administrador (para leer el log *Security* y usar `netsh`)

## Instalación

1. Copia la carpeta `tfg_scripts` en el servidor, por ejemplo en `C:\Scripts\`.
2. Abre **PowerShell como Administrador** y ejecuta:

```powershell
cd C:\Scripts\tfg_scripts
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3. Crea las carpetas necesarias (si no existen):

```powershell
mkdir C:\DatosCriticos   # datos a respaldar
mkdir C:\Backups         # destino de backups
mkdir C:\Scripts         # logs del servicio
```

## 1. Arranque automático del script de vigilancia

El script `seguridad_activa.py` debe correr **siempre** mientras el servidor
está encendido. Recomendado usar el **Programador de Tareas** con arranque al
iniciar sesión del sistema:

```powershell
schtasks /Create ^
  /TN "TFG_SeguridadActiva" ^
  /TR "C:\Scripts\tfg_scripts\iniciar_seguridad.bat" ^
  /SC ONSTART ^
  /RU SYSTEM ^
  /RL HIGHEST ^
  /F
```

> `/SC ONSTART` = al encender la máquina.
> `/RU SYSTEM`  = se ejecuta con la cuenta SISTEMA (tiene permisos sobre el log Security).
> `/RL HIGHEST` = privilegios máximos (necesario para `netsh`).

Para verificar:

```powershell
schtasks /Query /TN "TFG_SeguridadActiva" /V /FO LIST
```

Para detenerlo / eliminarlo:

```powershell
schtasks /End    /TN "TFG_SeguridadActiva"
schtasks /Delete /TN "TFG_SeguridadActiva" /F
```

### Alternativa (más robusta): NSSM como servicio Windows

```powershell
nssm install TFG_SeguridadActiva "C:\Python311\pythonw.exe" "C:\Scripts\tfg_scripts\seguridad_activa.py"
nssm set    TFG_SeguridadActiva Start SERVICE_AUTO_START
nssm start  TFG_SeguridadActiva
```

## 2. Panel web local (dashboard)

Acceso: **http://localhost:8080** (solo accesible desde la propia máquina).

Muestra en tiempo real (auto-refresh cada 10 s):
- Contadores: alertas 24h, IPs bloqueadas, backups OK/error, tamaño total, último backup.
- **Gráfica apilada** de alertas por hora (últimas 24h) separadas por tipo: Escaneo, Login, Bloqueo, Malware.
- Tabla de **IPs bloqueadas** (leídas directamente del firewall de Windows con `netsh`).
- Tabla de **últimas 50 alertas** con su tipo, IP y mensaje.
- **Historial de backups** con estado, archivo y hash SHA-256.

Para que arranque automáticamente con Windows, regístralo como tarea:

```powershell
schtasks /Create ^
  /TN "TFG_PanelWeb" ^
  /TR "C:\Scripts\tfg_scripts\iniciar_panel.bat" ^
  /SC ONSTART ^
  /RU SYSTEM /RL HIGHEST /F
```

Alternativa (servicio Windows con NSSM):

```powershell
nssm install TFG_PanelWeb "C:\Python311\pythonw.exe" "C:\Scripts\tfg_scripts\panel_web.py"
nssm set    TFG_PanelWeb Start SERVICE_AUTO_START
nssm start  TFG_PanelWeb
```

> El panel escucha en `127.0.0.1:8080` para que **NO** sea accesible desde fuera
> del servidor. Si quieres exponerlo en la red interna, cambia `HOST = "0.0.0.0"`
> en `panel_web.py` y abre el puerto en el firewall (no recomendado sin auth).

## 3. Programación de los backups

Programar `ejecutar_backup.bat` a la hora deseada (p. ej. diario a las 3:00):

```powershell
schtasks /Create ^
  /TN "TFG_BackupDiario" ^
  /TR "C:\Scripts\tfg_scripts\ejecutar_backup.bat" ^
  /SC DAILY /ST 03:00 ^
  /RU SYSTEM /RL HIGHEST /F
```

## Configuración rápida

Ambos scripts tienen una sección `CONFIGURACIÓN` al principio. Lo más habitual
que querrás tocar:

### `seguridad_activa.py`
- `SNORT_LOG`         – ruta del `alert.ids`
- `INTENTOS_MAXIMOS`  – fallos de login antes de bloquear IP (por defecto **5**)
- `VENTANA_SEGUNDOS`  – ventana temporal (por defecto **300** = 5 min)
- `WHITELIST_IPS`     – IPs que NUNCA se bloquearán (añade tu IP de admin)
- `SYSMON_EVENTS_INTERES` – IDs de Sysmon a alertar

### `backup_seguro.py`
- `ORIGEN`       – carpeta a respaldar (`C:\DatosCriticos`)
- `DESTINO`      – carpeta destino     (`C:\Backups`)
- `PASSWORD`     – contraseña del 7z (`ClaveSegura2026`)
- `DIAS_RETENER` – días de retención antes de rotar (por defecto **30**)

## Notificaciones a Discord

- Canal **alertas de seguridad** → webhook de `seguridad_activa.py`
- Canal **backups** → webhook de `backup_seguro.py`

Ambos webhooks ya están configurados dentro de los scripts. Si necesitas
cambiarlos, edita la variable `WEBHOOK_URL` al principio de cada archivo.

## Logs locales

- `C:\Scripts\seguridad_activa.log`   (rotación 5×5 MB)
- `C:\Backups\verificacion_backups.log` (rotación 5×2 MB)

## Prueba manual rápida

```powershell
# 1) lanzar vigilancia en primer plano (para ver salida)
python C:\Scripts\tfg_scripts\seguridad_activa.py

# 2) probar backup ahora
python C:\Scripts\tfg_scripts\backup_seguro.py

# 3) abrir panel web
python C:\Scripts\tfg_scripts\panel_web.py
# luego abre http://localhost:8080 en el navegador
```

Deberías ver un mensaje en cada canal de Discord y el dashboard con datos en vivo.

## Resolución de problemas

- **No llega nada a Discord** → revisa el webhook y que el servidor tenga salida a `discord.com`.
- **`netsh` falla** → el servicio debe ejecutarse como Administrador / SYSTEM.
- **`Access is denied` al leer `Security`** → usa `/RU SYSTEM` en la tarea programada.
- **`ModuleNotFoundError: win32evtlog`** → `pip install pywin32` y reiniciar.
- **Snort no genera alertas** → confirma la ruta `C:\Snort\log\alert.ids` y que las reglas estén activas.
