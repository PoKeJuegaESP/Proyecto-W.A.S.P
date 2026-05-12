# 🔎 Configuración de Snort (NIDS)

Esta carpeta contiene los archivos de configuración de **Snort 2.9** que se aplican
en el **servidor**. Snort actúa como NIDS (Network Intrusion Detection System)
inspeccionando el tráfico en una o varias NICs y generando alertas en
`C:\Snort\log\alert.ids`, que `seguridad_activa.py` consume en tiempo real.

---

## 📁 Archivos

| Fichero | Descripción |
|---|---|
| **`snort.conf`** | Configuración principal de Snort. Variables de red, preprocesadores, salidas y rutas a reglas. |
| **`local.rules`** | Reglas personalizadas del proyecto. Contiene la regla anti-portscan que dispara las alertas azules del panel. |

---

## 🚀 Instalación

### 1. Instalar Snort + WinPcap/Npcap en el servidor

Descarga e instala desde:
- **Snort 2.9.x** → https://www.snort.org/downloads
- **Npcap** → https://npcap.com/#download (necesario para capturar paquetes en Windows moderno)

Por defecto se instala en `C:\Snort\`.

### 2. Copiar las configuraciones del proyecto

```powershell
# Sobrescribe los archivos por defecto con los del proyecto
Copy-Item .\snort.conf   C:\Snort\etc\snort.conf   -Force
Copy-Item .\local.rules  C:\Snort\rules\local.rules -Force
```

### 3. Identificar la NIC a monitorizar

```powershell
cd C:\Snort\bin
.\snort.exe -W
```

Apunta el `Index` de la NIC objetivo. En el laboratorio del TFG es la
**host-only** (donde se conecta Kali), normalmente `Index 4` con IP `192.168.56.10`.

### 4. Validar la configuración (test mode)

```powershell
.\snort.exe -i 4 -c C:\Snort\etc\snort.conf -A fast -l C:\Snort\log -T
```

Si termina con `Snort successfully validated the configuration!`, todo OK.

### 5. Lanzar Snort en background

```powershell
Start-Process -FilePath "C:\Snort\bin\snort.exe" `
    -ArgumentList "-i 4 -c C:\Snort\etc\snort.conf -A fast -l C:\Snort\log" `
    -WindowStyle Hidden

# Verificar
Get-Process snort
```

---

## 🛠️ Configuración clave de `snort.conf`

```ini
# Redes a proteger (incluye LAN del dominio + host-only de Kali)
ipvar HOME_NET [192.168.1.0/24,192.168.56.0/24]
ipvar EXTERNAL_NET any

# Rutas a las reglas
var RULE_PATH ../rules

# Salidas (genera alert.ids)
output alert_fast: alert.ids
output log_tcpdump: snort.log

# Inclusión de las reglas locales del proyecto
include $RULE_PATH/local.rules
```

> ⚠️ **Importante**: si tu red interna tiene una subred distinta, ajusta `HOME_NET`
> añadiendo tus rangos. Las reglas que monitorizan tráfico hacia `$HOME_NET` no
> dispararán contra IPs fuera de esa variable.

---

## 🎯 Regla personalizada del TFG (`local.rules`)

```
alert tcp any any -> $HOME_NET any (msg:"Posible escaneo de puertos o Flood";
    flow:stateless;
    detection_filter:track by_src, count 30, seconds 5;
    sid:1000002; rev:1;)
```

**Cómo funciona**:
- `flow:stateless` → analiza cada paquete TCP individualmente.
- `detection_filter` → solo dispara cuando **una misma IP origen** envía
  **30 paquetes en 5 segundos** hacia cualquier IP de `$HOME_NET`.
- Esta heurística detecta el patrón típico de `nmap -sS` y otros port scans
  agresivos sin saturar de falsos positivos.

`seguridad_activa.py` aplica además un **anti-spam** propio
(`SNORT_DEDUP_SECONDS = 60`) para que un escaneo de miles de puertos solo
genere 1-2 alertas en Discord/panel.

---

## 🧪 Prueba rápida

Desde Kali (en la NIC host-only):

```bash
sudo nmap -sS -p 1-1000 192.168.56.10
```

En segundos verás en `C:\Snort\log\alert.ids`:

```
[**] [1:1000002:1] Posible escaneo de puertos o Flood [**]
[Priority: 0] {TCP} 192.168.56.20:54321 -> 192.168.56.10:445
```

Y `seguridad_activa.py`:
1. Detecta la línea.
2. Manda 🔵 alerta a Discord/panel.
3. Crea regla `BLOCK_192.168.56.20` en el firewall del servidor.

---

## 🔄 Auto-arranque con NSSM (recomendado)

```powershell
nssm install TFG_Snort "C:\Snort\bin\snort.exe"
nssm set    TFG_Snort AppParameters "-i 4 -c C:\Snort\etc\snort.conf -A fast -l C:\Snort\log"
nssm set    TFG_Snort Start SERVICE_AUTO_START
nssm start  TFG_Snort
```

> ⚠️ Sustituye `-i 4` por el índice real de tu NIC.

---

## 🩺 Resolución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| ❌ `alert.ids` vacío tras nmap | NIC equivocada o Snort detenido | `Get-Process snort` y revisar `-i N` |
| ❌ Snort detecta tráfico de la LAN pero no de host-only | `HOME_NET` no incluye la red de host-only | Ajustar `ipvar HOME_NET` |
| ❌ Spam de alertas con tráfico legítimo | `local.rules` demasiado agresiva | Subir el `count` o el `seconds` del `detection_filter` |
| ❌ `Snort successfully validated` pero no captura | Falta Npcap o usuario sin privilegios | Reinstalar Npcap, ejecutar como Admin |
| ❌ Logs binarios `snort.log.<timestamp>` muy grandes | Por defecto guarda PCAP | Quitar `output log_tcpdump:` o rotar manualmente |

---

## 📚 Referencias

- 📘 [Snort 2.9 User Manual](https://www.snort.org/documents)
- 📘 [Snort Rule Writing Guide](https://docs.snort.org/rules/)
- 🔧 [Emerging Threats Open Rules](https://rules.emergingthreats.net/) (reglas comunitarias adicionales)
- 🎯 [MITRE ATT&CK · T1046 Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
