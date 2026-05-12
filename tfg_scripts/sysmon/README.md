# 🛰️ Configuración de Sysmon

Esta carpeta contiene los archivos de configuración de **Sysmon** que se aplican
en los **clientes Windows** del dominio (CLIENTE 1 y CLIENTE 2).

Sysmon (System Monitor, de Sysinternals) instala un driver de kernel y un servicio
que registra actividad detallada del sistema en el log de eventos
`Microsoft-Windows-Sysmon/Operational`. Esos eventos los reenvían los clientes al
servidor central mediante **WEF**, donde `seguridad_activa.py` los analiza.

---

## 📁 Archivos

| Fichero | Descripción |
|---|---|
| **`sysmonconfig.xml`** | ⭐ **Configuración recomendada** (~1200 líneas). Basada en SwiftOnSecurity con ajustes adicionales para entornos AD. Cubre prácticamente todas las técnicas MITRE ATT&CK de relevancia. |
| **`sysmon-minimal.xml`** | Configuración mínima de demostración (~25 líneas). Útil para entender el formato de filtros antes de pasar a la completa. |

---

## 🚀 Instalación en cada cliente

> Ejecutar en **PowerShell como Administrador** en CLIENTE 1 y CLIENTE 2.

### 1. Descargar Sysmon de Sysinternals

```powershell
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon" -Force
```

### 2. Copiar la configuración del proyecto

Copia `sysmonconfig.xml` de esta carpeta a `C:\Sysmon\sysmonconfig.xml` en el
cliente (por carpeta compartida, USB, o `Copy-Item` si tienes acceso remoto).

### 3. Instalar Sysmon con la configuración

```powershell
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### 4. Verificar la instalación

```powershell
# Servicio activo
Get-Service Sysmon64

# Ver últimos 5 eventos generados (debe haber decenas en segundos)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Format-List TimeCreated, Id, Message
```

---

## 🔄 Actualizar la configuración (sin reinstalar)

Si modificas `sysmonconfig.xml`:

```powershell
C:\Sysmon\Sysmon64.exe -c C:\Sysmon\sysmonconfig.xml
```

Sysmon recarga la nueva config sin necesidad de reiniciar el servicio.

---

## 🔓 Permisos para WEF (importante)

Para que el servicio `Wecsvc` del servidor pueda leer el canal de Sysmon en los
clientes, hay que dar permisos al SID `S-1-5-20` (`NETWORK SERVICE`):

```powershell
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x5;;;SO)(A;;0x1;;;IU)(A;;0x3;;;SU)(A;;0x1;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)"
```

---

## 📊 Eventos clave que detecta esta configuración

| EventID | Tipo | Para qué se usa en el TFG |
|---------|------|---------------------------|
| **1**  | ProcessCreate | Detecta PowerShell ofuscado (`-enc`), LOLBins, herramientas ofensivas |
| **3**  | NetworkConnect | Conexiones salientes a puertos típicos de C2 (4444, 1337, 31337…) |
| **7**  | ImageLoad | Carga de DLLs sin firmar |
| **8**  | CreateRemoteThread | Inyección de código (a `explorer.exe`, `svchost.exe`) |
| **10** | ProcessAccess | Acceso a `lsass.exe` → posible Mimikatz / volcado de credenciales |
| **11** | FileCreate | Creación de archivos en rutas de persistencia (`Run`, `Startup`, `Tasks`) |
| **22** | DnsQuery | Consultas DNS a dominios sospechosos (TLDs `.tk`, `.xyz`…, DGA) |

Los EventIDs que se procesan en `seguridad_activa.py` están definidos en la
constante `SYSMON_EVENTS_INTERES = {1, 10, 11, 22}`.

---

## 📚 Referencias

- 📘 [Microsoft · Sysmon Documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- 🔧 [SwiftOnSecurity / sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (base de `sysmonconfig.xml`)
- 🎯 [Olaf Hartong · Sysmon-Modular](https://github.com/olafhartong/sysmon-modular) (alternativa modular)
