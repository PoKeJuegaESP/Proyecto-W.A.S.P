<div align="center">

# 🛡️ Proyecto · W.A.S.P
**W**indows **A**uditing & **S**ecurity **P**latform.

### Detección de amenazas en tiempo real con Snort + Sysmon + WEF + Python

[![Windows Server](https://img.shields.io/badge/Windows%20Server-2019%2F2022-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows-server)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Snort](https://img.shields.io/badge/Snort-IDS-EF1B24?logo=snort&logoColor=white)](https://www.snort.org/)
[![Sysmon](https://img.shields.io/badge/Sysmon-Sysinternals-0078D6)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
[![Discord](https://img.shields.io/badge/Discord-Webhook-5865F2?logo=discord&logoColor=white)](https://discord.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Recolecta eventos de seguridad de toda la red, los analiza con heurísticas basadas en
**MITRE ATT&CK** y reacciona automáticamente bloqueando IPs en el firewall.

</div>

---

## 📑 Tabla de contenidos

- [✨ Características](#-características)
- [🏗️ Arquitectura](#️-arquitectura)
- [📸 Capturas](#-capturas)
- [⚙️ Requisitos previos](#️-requisitos-previos)
- [🚀 Instalación paso a paso](#-instalación-paso-a-paso)
  - [1. Servidor (Collector / SIEM)](#1️⃣-servidor-collector--siem)
  - [2. Clientes (Forwarders)](#2️⃣-clientes-forwarders)
  - [3. Snort (NIDS)](#3️⃣-snort-nids)
  - [4. Auto-arranque con NSSM](#4️⃣-auto-arranque-con-nssm)
  - [5. Backups automáticos (semanales)](#5️⃣-backups-automáticos-semanales)
- [🧪 Pruebas de validación](#-pruebas-de-validación)
- [🎯 Mapeo MITRE ATT&CK](#-mapeo-mitre-attck)
- [🔧 Configuración avanzada](#-configuración-avanzada)
- [🩺 Resolución de problemas](#-resolución-de-problemas)
- [📚 Referencias](#-referencias)

---

## ✨ Características

| Módulo | Función |
|--------|---------|
| 🔍 **`seguridad_activa.py`** | Vigilancia en tiempo real (Snort + Event Log + Sysmon + Windows Defender) |
| 💾 **`backup_seguro.py`** | Backups cifrados 7-Zip con verificación SHA-256 y rotación de 30 días |
| 📊 **`panel_web.py`** | Dashboard web (FastAPI + Chart.js) en `http://localhost:8080` |
| 📡 **`wef/`** | Suscripción XML para centralizar eventos vía Windows Event Forwarding |
| 🛰️ **`sysmon/`** | Configuración Sysmon para los clientes (basada en SwiftOnSecurity) |
| 🔎 **`snort/`** | `snort.conf` y reglas personalizadas del NIDS |
| 🛡️ **Auto-bloqueo** | Reglas dinámicas en Windows Firewall ante fuerza bruta o escaneos |
| 💬 **Discord Webhook** | Notificaciones inmediatas en canal SOC |

### 🎯 Tipos de alerta detectadas

- 🟡 **Login** — Fuerza bruta de credenciales (Security 4625, todos los logon types)
- 🦠 **Malware** — Detecciones de Defender + heurísticas Sysmon (PowerShell ofuscado, mimikatz, LOLBins, persistencia, acceso a LSASS, DGA…)
- 🔵 **Escaneo** — Port scans, NMAP, shellcode, troyanos detectados por Snort
- 🌸 **Bloqueo** — Respuesta automática al firewall

### 📁 Estructura del repositorio

```
tfg_scripts/
├── 📜 seguridad_activa.py       # Backend SIEM (heurísticas + Discord + firewall)
├── 📜 panel_web.py              # Dashboard FastAPI
├── 📜 backup_seguro.py          # Backups cifrados 7-Zip
├── 📂 templates/
│   └── index.html               # UI del panel
├── 📂 wef/                      # Windows Event Forwarding
│   ├── TFG_Subscription.xml     # Suscripción (Sysmon + Security 4625 + Defender)
│   └── WEF_SETUP.md             # Guía detallada de WEF
├── 📂 sysmon/                   # Configuración Sysmon (clientes)
│   ├── sysmonconfig.xml         # Config completa (~1200 líneas)
│   ├── sysmon-minimal.xml       # Config mínima de demo
│   └── README.md                # Guía de instalación
├── 📂 snort/                    # Configuración Snort (servidor)
│   ├── snort.conf               # Config principal (con HOME_NET ajustado)
│   ├── local.rules              # Regla anti-portscan personalizada
│   └── README.md                # Guía de instalación
├── 📂 *.bat                     # Scripts de arranque (Programador de Tareas)
├── 📜 requirements.txt          # Dependencias Python
└── 📜 README.md                 # Este documento
```

---

## 🏗️ Arquitectura

```
                    ┌─────────────────────────────────────┐
                    │        DOMINIO ACTIVE DIRECTORY      │
                    │      DOMINIOPROY25CSR.EDU            │
                    └─────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
 ┌─────────────┐              ┌─────────────┐              ┌─────────────┐
 │ CLIENTE 1   │              │ CLIENTE 2   │              │  KALI LINUX │
 │   Sysmon    │              │   Sysmon    │              │  (host-only)│
 │   Defender  │              │   Defender  │              │    nmap     │
 └──────┬──────┘              └──────┬──────┘              └──────┬──────┘
        │   WEF · WinRM 5985         │                            │
        │   (Source-Initiated)       │                            │ Tráfico
        └─────────────┬──────────────┘                            │ malicioso
                      ▼                                           ▼
        ┌─────────────────────────────┐              ┌─────────────────────┐
        │     SERVIDOR (Collector)    │◄─────────────┤   Snort (NIDS)      │
        │                             │   alert.ids  │   host-only iface   │
        │   ┌────────────────────┐    │              └─────────────────────┘
        │   │  ForwardedEvents   │    │
        │   └─────────┬──────────┘    │
        │             ▼               │
        │   ┌────────────────────┐    │              ┌─────────────────────┐
        │   │ seguridad_activa.py│────┼──────────────►   Discord Webhook   │
        │   │  (heurísticas SIEM)│    │              └─────────────────────┘
        │   └─────────┬──────────┘    │
        │             ▼               │              ┌─────────────────────┐
        │   ┌────────────────────┐    │              │  Windows Firewall   │
        │   │   panel_web.py     │    │   netsh      │   BLOCK_<ip> rules  │
        │   │  FastAPI :8080     │◄───┼──────────────┤  (auto-bloqueo)     │
        │   └────────────────────┘    │              └─────────────────────┘
        └─────────────────────────────┘
```

**Modo WEF**: `Source-Initiated` con `MinLatency` (~5 segundos cliente→panel).

---

## 📸 Capturas

| Dashboard Web (`:8080`) | Notificación Discord |
|<img width="1665" height="886" alt="image" src="https://github.com/user-attachments/assets/6eefc86f-b21d-42a4-850c-2d11161fe436" /> |<img width="1832" height="903" alt="image" src="https://github.com/user-attachments/assets/1101ccf9-71fb-417d-9924-e92a26884929" />
||
| 
|

---

## ⚙️ Requisitos previos

### Hardware mínimo (laboratorio)

| Componente | Especificación |
|---|---|
| 1 × Servidor Windows | Windows Server 2019/2022, 4 GB RAM, 40 GB disco, **rol AD DS + DNS** |
| 2 × Cliente Windows | Windows 10/11 Pro o Enterprise, unidos al dominio |
| 1 × VM Kali Linux | (Opcional) para tests de escaneo en NIC `host-only` |
| Red | LAN interna del dominio + opcionalmente NIC `host-only` para Kali |

### Software requerido

| Componente | Dónde se instala | Versión |
|---|---|---|
| **Python** | Servidor | ≥ 3.10 (con "Add to PATH") |
| **7-Zip** | Servidor | ≥ 22.x en `C:\Program Files\7-Zip\` |
| **Snort** | Servidor | 2.9.x con WinPcap/Npcap |
| **Sysmon** | Clientes (y opcional servidor) | ≥ 14.x |
| **NSSM** _(opcional)_ | Servidor | Para servicios Windows persistentes |

---

## 🚀 Instalación paso a paso

### 1️⃣ Servidor (Collector / SIEM)

#### 1.1 Clonar el repositorio

```powershell
cd C:\
git clone https://github.com/<tu-usuario>/Proyecto.git
cd C:\Proyecto\tfg_scripts
```

> Si no usas git, descarga el ZIP y descomprímelo en `C:\Proyecto\tfg_scripts\`.

#### 1.2 Instalar dependencias Python

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Esto instala: `pywin32`, `requests`, `fastapi`, `uvicorn`, `jinja2`.

#### 1.3 Crear directorios del proyecto

```powershell
New-Item -ItemType Directory -Force -Path C:\Scripts          # logs
New-Item -ItemType Directory -Force -Path C:\DatosCriticos    # origen backups
New-Item -ItemType Directory -Force -Path C:\Backups          # destino backups
```

#### 1.4 Configurar el webhook de Discord

Edita `seguridad_activa.py` y `backup_seguro.py`, busca la variable
`WEBHOOK_URL` y pon la URL de **tu** webhook de Discord:

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/XXXXXXXXX/YYYYYYYYY"
```

> Cómo crear un webhook: en Discord → ajustes del canal → **Integraciones** → **Webhooks** → **Nuevo webhook** → copiar URL.

#### 1.5 Habilitar Windows Event Forwarding

```powershell
# Habilitar WinRM
winrm quickconfig -force

# Habilitar el servicio Windows Event Collector
wecutil qc /quiet

# Permitir tráfico WEF entrante (TCP 5985)
New-NetFirewallRule -DisplayName "WEF-WinRM-HTTP" `
    -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow

# Crear la suscripción a partir del XML del proyecto
wecutil cs C:\Proyecto\tfg_scripts\wef\TFG_Subscription.xml

# Configurar latencia mínima (~5 segundos)
wecutil ss "TFG_Sysmon_Security" /cm:MinLatency

# Verificar
wecutil gs "TFG_Sysmon_Security"
```

📖 Más detalles en [`wef/WEF_SETUP.md`](./wef/WEF_SETUP.md).

#### 1.6 Activar auditoría de logon (en español)

```powershell
auditpol /set /subcategory:"Inicio de sesión" /failure:enable
auditpol /set /subcategory:"Inicio de sesión de cuenta" /failure:enable
```

> Si tu Windows está en inglés, usa `"Logon"` y `"Account Logon"`.

#### 1.7 Lanzar los scripts (modo manual, primera prueba)

```powershell
# Terminal 1 - Vigilancia
python C:\Proyecto\tfg_scripts\seguridad_activa.py

# Terminal 2 - Panel web
python C:\Proyecto\tfg_scripts\panel_web.py
```

Abre 🌐 **http://localhost:8080** en el navegador del servidor.

---

### 2️⃣ Clientes (Forwarders)

> Repetir en **CLIENTE 1** y **CLIENTE 2** (PowerShell admin).

#### 2.1 Instalar Sysmon con la configuración del proyecto

```powershell
# Descargar Sysmon de Sysinternals
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon" -Force

# Copiar la configuración del repo (sysmon/sysmonconfig.xml) a C:\Sysmon\
# (por carpeta compartida, USB o Copy-Item)

# Instalar con la config del proyecto
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

# Verificar
Get-Service Sysmon64
```

📖 Detalles completos en [`sysmon/README.md`](./sysmon/README.md).

#### 2.2 Configurar el cliente como forwarder WEF

```powershell
# Apuntar al servidor colector
$server = "DCPROY25CSR"   # ← cambia por TU hostname del DC
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" `
    /v 1 /t REG_SZ `
    /d "Server=http://$server.DOMINIOPROY25CSR.EDU:5985/wsman/SubscriptionManager/WEC,Refresh=60" /f

# Permisos para que NETWORK SERVICE lea los logs
net localgroup "Event Log Readers" "NT AUTHORITY\NETWORK SERVICE" /add

# Permisos sobre el canal Sysmon
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x5;;;SO)(A;;0x1;;;IU)(A;;0x3;;;SU)(A;;0x1;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)"

# Permisos sobre el canal Defender
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x5;;;SO)(A;;0x1;;;IU)(A;;0x3;;;SU)(A;;0x1;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)"

# Aplicar y reiniciar WinRM
gpupdate /force
Restart-Service WinRM
```

#### 2.3 Activar auditoría de logon

```powershell
auditpol /set /subcategory:"Inicio de sesión" /failure:enable
auditpol /set /subcategory:"Inicio de sesión de cuenta" /failure:enable
```

#### 2.4 Verificación

En el **servidor**, comprueba que los clientes están reenviando:

```powershell
wecutil gr "TFG_Sysmon_Security"
```

Busca cada cliente con `RuntimeStatus: Active`. ✅

---

### 3️⃣ Snort (NIDS)

> En el **servidor**, en la NIC que quieras monitorizar (ej. `host-only` para
> recoger ataques desde Kali).

#### 3.1 Instalar Snort + Npcap

Descarga e instala desde:
- **Snort 2.9.x** → https://www.snort.org/downloads
- **Npcap** → https://npcap.com/#download

#### 3.2 Aplicar la configuración del proyecto

```powershell
# Sustituye los archivos por defecto con los del repo
Copy-Item C:\Proyecto\tfg_scripts\snort\snort.conf   C:\Snort\etc\snort.conf   -Force
Copy-Item C:\Proyecto\tfg_scripts\snort\local.rules  C:\Snort\rules\local.rules -Force
```

La `snort.conf` ya viene con `HOME_NET` configurado para LAN del dominio +
host-only:

```ini
ipvar HOME_NET [192.168.1.0/24,192.168.56.0/24]
```

#### 3.3 Identificar el índice de la NIC

```powershell
cd C:\Snort\bin
.\snort.exe -W
```

Localiza el `Index` de la NIC objetivo (ej. `4` para host-only `192.168.56.10`).

#### 3.4 Lanzar Snort en background

```powershell
Start-Process -FilePath "C:\Snort\bin\snort.exe" `
    -ArgumentList "-i 4 -c C:\Snort\etc\snort.conf -A fast -l C:\Snort\log" `
    -WindowStyle Hidden

# Verificar
Get-Process snort
```

> Sustituye `-i 4` por el índice real de tu NIC.

📖 Detalles completos y reglas explicadas en [`snort/README.md`](./snort/README.md).

---

### 4️⃣ Auto-arranque con NSSM

Para que todo arranque automáticamente al encender el servidor:

```powershell
# Descargar NSSM desde https://nssm.cc y añadirlo al PATH

# Vigilancia
nssm install TFG_Seguridad "C:\Python311\pythonw.exe" "C:\Proyecto\tfg_scripts\seguridad_activa.py"
nssm set    TFG_Seguridad Start SERVICE_AUTO_START
nssm start  TFG_Seguridad

# Panel web
nssm install TFG_Panel "C:\Python311\pythonw.exe" "C:\Proyecto\tfg_scripts\panel_web.py"
nssm set    TFG_Panel Start SERVICE_AUTO_START
nssm start  TFG_Panel

# Snort (envuelto con cmd para preservar argumentos)
nssm install TFG_Snort "C:\Snort\bin\snort.exe"
nssm set    TFG_Snort AppParameters "-i 4 -c C:\Snort\etc\snort.conf -A fast -l C:\Snort\log"
nssm set    TFG_Snort Start SERVICE_AUTO_START
nssm start  TFG_Snort
```

Verificar:

```powershell
Get-Service TFG_*
```

---

### 5️⃣ Backups automáticos (semanales)

El módulo `backup_seguro.py` realiza una copia de seguridad **cifrada con AES-256
y cabeceras también cifradas** mediante 7-Zip, genera el **hash SHA-256** del
archivo resultante, lo registra en log y envía notificación a Discord
(tanto éxitos como errores).

#### 5.1 ¿Qué se respalda?

| Variable | Valor por defecto | Significado |
|---|---|---|
| `ORIGEN` | `C:\DatosCriticos` | 📂 Carpeta cuyo contenido se respalda |
| `DESTINO` | `C:\Backups` | 💾 Carpeta donde se guardan los `.7z` |
| `PASSWORD` | `ClaveSegura2026` | 🔑 Contraseña del archivo cifrado (cámbiala) |
| `DIAS_RETENER` | `30` | 🔄 Días antes de borrar backups antiguos |

> ⚠️ Coloca dentro de `C:\DatosCriticos` los datos sensibles que quieras proteger
> (ej. documentos del dominio, configuraciones, dumps de AD, etc.). El script
> respalda **todo el contenido recursivo** de esa carpeta.

Resultado: un archivo `Backup_YYYYMMDD_HHMM.7z` por ejecución en `C:\Backups\`.

#### 5.2 Programar el backup en el **Programador de Tareas**

Programa una tarea que ejecute el script **todos los lunes a las 12:00**:

```powershell
schtasks /Create `
  /TN "TFG_BackupSemanal" `
  /TR "C:\Proyecto\tfg_scripts\ejecutar_backup.bat" `
  /SC WEEKLY /D LUN /ST 12:00 `
  /RU SYSTEM /RL HIGHEST /F
```

Parámetros explicados:

| Flag | Valor | Significado |
|---|---|---|
| `/TN` | `TFG_BackupSemanal` | Nombre visible en el Programador |
| `/TR` | Ruta del `.bat` | Lo que se ejecuta |
| `/SC WEEKLY` | semanal | Frecuencia |
| `/D LUN` | LUN | Día de la semana (LUN/MAR/MIE/JUE/VIE/SAB/DOM en Windows español) |
| `/ST 12:00` | 12:00 | Hora de ejecución |
| `/RU SYSTEM` | SYSTEM | Cuenta de ejecución (permisos para leer todo `C:\`) |
| `/RL HIGHEST` | máximos | Privilegios elevados |
| `/F` | — | Sobrescribe la tarea si ya existe |

> 💡 Si tu Windows está en **inglés**, sustituye `/D LUN` por `/D MON`.

#### 5.3 Verificar la tarea

```powershell
# Detalle de la tarea
schtasks /Query /TN "TFG_BackupSemanal" /V /FO LIST

# Ejecutar AHORA mismo (test manual sin esperar al lunes)
schtasks /Run /TN "TFG_BackupSemanal"
```

Tras ejecutarla, comprueba:

```powershell
# Hay un nuevo .7z
Get-ChildItem C:\Backups\Backup_*.7z | Sort-Object LastWriteTime -Descending |
    Select-Object Name, Length, LastWriteTime -First 3

# Log del backup
Get-Content C:\Backups\verificacion_backups.log -Tail 10
```

Y verás llegar la notificación al canal Discord de backups con:
- Nombre del archivo
- Tamaño
- **Hash SHA-256** (para verificación de integridad)

#### 5.4 Programaciones alternativas

Si en lugar de semanal prefieres otra periodicidad, sustituye el `/SC` y `/D`:

```powershell
# Diario a las 3:00
schtasks /Create /TN "TFG_BackupDiario" /TR "C:\Proyecto\tfg_scripts\ejecutar_backup.bat" `
  /SC DAILY /ST 03:00 /RU SYSTEM /RL HIGHEST /F

# Lunes, miércoles y viernes a las 12:00
schtasks /Create /TN "TFG_Backup_LMV" /TR "C:\Proyecto\tfg_scripts\ejecutar_backup.bat" `
  /SC WEEKLY /D LUN,MIE,VIE /ST 12:00 /RU SYSTEM /RL HIGHEST /F

# Primer día de cada mes a las 2:00
schtasks /Create /TN "TFG_BackupMensual" /TR "C:\Proyecto\tfg_scripts\ejecutar_backup.bat" `
  /SC MONTHLY /D 1 /ST 02:00 /RU SYSTEM /RL HIGHEST /F
```

#### 5.5 Eliminar la tarea

```powershell
schtasks /Delete /TN "TFG_BackupSemanal" /F
```

#### 5.6 Restaurar un backup manualmente

```powershell
# Descomprime un backup concreto (te pedirá la contraseña)
& "C:\Program Files\7-Zip\7z.exe" x "C:\Backups\Backup_20260512_1200.7z" -o"C:\Restauracion"
```

---

## 🧪 Pruebas de validación

### Limpieza pre-demo (opcional)

```powershell
Clear-Content C:\Scripts\seguridad_activa.log
Clear-Content C:\Snort\log\alert.ids
Get-NetFirewallRule -DisplayName "BLOCK_*" | Remove-NetFirewallRule
Restart-Service TFG_Seguridad
```

### 🟡 Test 1 · Login fallido (fuerza bruta)

**En CLIENTE** (PowerShell admin):

```powershell
1..5 | ForEach-Object {
    net use \\<IP_SERVIDOR>\C$ /user:atacante PasswordMala$_!
    Start-Sleep -Seconds 1
}
net use * /delete /yes
```

**Esperado**: 5 alertas `🔐 Inicio de sesión incorrecto en servidor` → barras 🟡 **Login**.

---

### 🦠 Test 2 · Malware con Defender (EICAR)

**En CLIENTE** (PowerShell admin):

```powershell
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
[System.IO.File]::WriteAllText("$env:TEMP\eicar_test.txt", $eicar)
```

**Esperado**: alerta `🦠 Windows Defender · MALWARE detectado · Amenaza: EICAR_Test_File` → barra rosa **Malware**.

---

### 🦠 Test 3 · Malware sin Defender (PowerShell ofuscado)

**En CLIENTE** (PowerShell admin):

```powershell
powershell -nop -w hidden -enc VABlAHMAdABfAFAAcgB1AGUAYgBhAF8AVABGAEcA
```

**Esperado**: alerta `🧪 Sysmon ID=1 · CommandLine sospechosa ('-enc')`.

---

### 🔵🌸 Test 4 · Escaneo + Bloqueo automático

**En KALI**:

```bash
sudo nmap -sS -p 1-1000 192.168.56.10
```

**Esperado**:
- 🔎 `Posible escaneo de red (Snort). IP origen: 192.168.56.20`
- ⛔ `IP 192.168.56.20 BLOQUEADA en firewall`

Comprobar el bloqueo:

```powershell
Get-NetFirewallRule -DisplayName "BLOCK_*"
```

Y desde Kali, ahora el ping fallará. ✅

---

## 🎯 Mapeo MITRE ATT&CK

Las heurísticas implementadas cubren las siguientes técnicas de la matriz **MITRE ATT&CK**:

| Técnica | ID | Detección |
|---------|----|-----------|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Security 4625 con threshold 5/300s |
| User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | Defender + Sysmon FileCreate |
| PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | CommandLine con `-enc`, `iex`, `downloadstring` |
| Living-off-the-Land | [T1218](https://attack.mitre.org/techniques/T1218/) | bitsadmin, certutil, mshta, rundll32 |
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) | Sysmon EID 10 → acceso a `lsass.exe` |
| Persistence (Run keys) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Sysmon EID 11 en `Startup` / `\Run` |
| Network Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) | Snort SYN flood, NMAP |
| C2 / DGA | [T1568](https://attack.mitre.org/techniques/T1568/) | Sysmon EID 22 con dominios sospechosos |
| Defense Evasion | [T1562](https://attack.mitre.org/techniques/T1562/) | Defender 5001/5007 (tampering) |

**Mitigación implementada**: [M1037](https://attack.mitre.org/mitigations/M1037/) - Filter Network Traffic.

---

## 🔧 Configuración avanzada

### `seguridad_activa.py` — variables principales

```python
SNORT_LOG         = r"C:\Snort\log\alert.ids"
INTENTOS_MAXIMOS  = 5            # fallos antes de bloquear IP
VENTANA_SEGUNDOS  = 300          # ventana de conteo (segundos)
SNORT_DEDUP_SECONDS = 60         # anti-spam de alertas Snort
WHITELIST = [
    "127.0.0.1",
    "192.168.1.0/24",            # red interna del dominio
]
SYSMON_EVENTS_INTERES = {1, 10, 11, 22}    # Process, ProcessAccess, FileCreate, DNS
```

### `panel_web.py`

```python
HOST = "127.0.0.1"   # solo localhost. Cambia a "0.0.0.0" para exponer en LAN
PORT = 8080
```

### `backup_seguro.py`

```python
ORIGEN       = r"C:\DatosCriticos"
DESTINO      = r"C:\Backups"
PASSWORD     = "ClaveSegura2026"   # ⚠️ cambia esto
DIAS_RETENER = 30
```

---

## 🩺 Resolución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| ❌ No llegan alertas a Discord | Sin salida a Internet en el servidor | `Test-NetConnection discord.com -Port 443` y revisar NIC NAT |
| ❌ ForwardedEvents vacío | Suscripción inactiva o cliente sin permisos | `wecutil rs TFG_Sysmon_Security` y revisar paso 2.2 |
| ❌ `EventID 102` en cliente | Firewall del cliente o DNS | `Test-NetConnection <SERVIDOR> -Port 5985` |
| ❌ `EventID 5004` Wecsvc | Permisos `NETWORK SERVICE` faltan en canal | Aplicar SDDL del paso 2.2 |
| ❌ Snort no genera alertas | `HOME_NET` no incluye la red atacante | Editar `snort.conf` (paso 3.2) |
| ❌ `0x8033808F` en cliente | DNS o Kerberos roto | Verificar que el cliente resuelve el DC y `klist` |
| ❌ Latencia alta WEF (>1 min) | Modo `Normal` por defecto | `wecutil ss <sub> /cm:MinLatency` |
| ❌ `netsh: Access denied` | Script no corre como admin | NSSM con cuenta `LocalSystem` o tarea programada con `RU SYSTEM` |
| ❌ `ModuleNotFoundError: win32evtlog` | Falta `pywin32` | `pip install pywin32 && python Scripts\pywin32_postinstall.py -install` |
| ❌ Loop de bloqueos en clientes | IP cliente fuera de whitelist | Añadir red `192.168.1.0/24` a `WHITELIST` |

---

## 📚 Referencias

### Documentación oficial

- 📘 [Microsoft · Use Windows Event Forwarding to assist in intrusion detection](https://learn.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- 📘 [NSA · Cybersecurity Information Sheet: Windows Event Forwarding (U/OO/197503-19)](https://media.defense.gov/2019/Sep/09/2002180327/-1/-1/0/Windows%20Event%20Forwarding%20Guidance.pdf)
- 📘 [Sysmon · Microsoft Docs](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- 📘 [Snort 2.9 User Manual](https://www.snort.org/documents)

### Recursos de la comunidad

- 🔧 [SwiftOnSecurity / sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — configuración Sysmon recomendada
- 🔧 [Palantir · Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding)
- 🎯 [MITRE ATT&CK Framework](https://attack.mitre.org/)
- 🧪 [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — pruebas adicionales por TTP

---

<div align="center">

### Hecho con ❤️ para el Trabajo de Fin de Grado

⭐ Si este proyecto te ha sido útil, ¡dale una estrella en GitHub!

</div>
