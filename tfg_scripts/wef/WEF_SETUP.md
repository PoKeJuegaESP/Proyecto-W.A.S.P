# Configuración de Windows Event Forwarding (WEF) para el TFG

Esta guía configura el reenvío automático de eventos desde **CLIENTE1CSR** y
**CLIENTE2CSR** al servidor central donde corre `seguridad_activa.py`.

## Arquitectura

```
   ┌──────────────┐                ┌──────────────┐
   │ CLIENTE1CSR │                │ CLIENTE2CSR │
   │   (Sysmon)   │                │   (Sysmon)   │
   └──────┬───────┘                └──────┬───────┘
          │                                │
          └────────[ WinRM / HTTP 5985 ]───┘
                          │
                          ▼
                  ┌───────────────┐
                  │  Servidor     │
                  │  (Colector)   │
                  │               │
                  │ ForwardedEvts │──→ seguridad_activa.py ──→ Discord + Panel
                  └───────────────┘
```

Modo elegido: **Source-Initiated** (los clientes empujan al servidor).
Es la opción estándar en dominios Active Directory porque no requiere
abrir puertos en los clientes y se configura una sola vez por GPO.

---

## Paso 1 · Configurar el SERVIDOR (colector)

Abre **PowerShell como Administrador en el servidor**:

```powershell
# 1.1 Habilitar WinRM (Windows Remote Management)
winrm quickconfig -force

# 1.2 Habilitar el servicio Windows Event Collector
wecutil qc /quiet

# 1.3 Permitir conexiones entrantes al puerto 5985 (HTTP WinRM)
New-NetFirewallRule -DisplayName "WEF-WinRM-HTTP" -Direction Inbound `
    -Protocol TCP -LocalPort 5985 -Action Allow

# 1.4 Crear la suscripción usando el XML del proyecto
#     (copia antes el archivo TFG_Subscription.xml a C:\Scripts\wef\)
wecutil cs C:\Scripts\tfg_scripts\wef\TFG_Subscription.xml

# 1.5 Verificar que se ha creado
wecutil es                                # lista suscripciones
wecutil gs TFG_Sysmon_Security            # detalle
wecutil gr TFG_Sysmon_Security            # runtime status (clientes activos)
```

> Si `wecutil gr` muestra `RuntimeStatus: Active` y luego algunas máquinas
> con `Active`, significa que están reenviando correctamente.

---

## Paso 2 · Configurar los CLIENTES (forwarders)

### Opción A · Por GPO (recomendado para dominio AD)

En el **controlador de dominio**, abre **Group Policy Management** y crea
una nueva GPO llamada `TFG_WEF_Forwarders`. Edítala y configura:

1. **Computer Configuration → Policies → Administrative Templates →
   Windows Components → Event Forwarding**
   - `Configure target Subscription Manager` → **Enabled**
   - Add: `Server=http://SERVIDOR.DOMINIOPROY25CSR.EDU:5985/wsman/SubscriptionManager/WEC,Refresh=60`

2. **Computer Configuration → Policies → Windows Settings → Security
   Settings → Restricted Groups**
   - Añadir grupo `Event Log Readers`
   - Miembros: `NT AUTHORITY\NETWORK SERVICE`
   (Necesario para que el servicio que lee el log de Security tenga permisos.)

3. **Computer Configuration → Policies → Windows Settings → Security
   Settings → System Services**
   - `Windows Remote Management (WS-Management)` → Startup mode = **Automatic**

Vincular la GPO a la OU donde estén CLIENTE1CSR y CLIENTE2CSR.

Forzar refresco en cada cliente:
```powershell
gpupdate /force
```

### Opción B · Manual (sin GPO, útil si solo son 2-3 clientes)

En **CLIENTE1CSR** y **CLIENTE2CSR**, PowerShell como Administrador:

```powershell
# B.1 Habilitar WinRM
winrm quickconfig -force

# B.2 Configurar la URL del colector
$server = "SERVIDOR"   # ← cambia por el hostname de TU servidor
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" `
    /v 1 /t REG_SZ /d "Server=http://$server.DOMINIOPROY25CSR.EDU:5985/wsman/SubscriptionManager/WEC,Refresh=60" /f

# B.3 Dar permisos a NETWORK SERVICE para leer el log Security
net localgroup "Event Log Readers" "NT AUTHORITY\NETWORK SERVICE" /add

# B.4 Reiniciar los servicios para que apliquen
Restart-Service WinRM
```

---

## Paso 3 · Verificación end-to-end

### En el servidor

```powershell
# Estado de la suscripción - debe mostrar los 2 clientes "Active"
wecutil gr TFG_Sysmon_Security

# Ver eventos llegando al canal ForwardedEvents
Get-WinEvent -LogName ForwardedEvents -MaxEvents 5 |
    Format-Table TimeCreated, Id, MachineName, ProviderName -AutoSize
```

Salida esperada tras unos minutos:
```
TimeCreated         Id MachineName            ProviderName
-----------         -- -----------            ------------
2026-05-06 10:15:22  1 CLIENTE1CSR.DOMINI... Microsoft-Windows-Sysmon
2026-05-06 10:15:35  3 CLIENTE2CSR.DOMINI... Microsoft-Windows-Sysmon
2026-05-06 10:16:01  4625 CLIENTE1CSR.DOM... Microsoft-Windows-Security-Auditing
```

### En el cliente

Si algo no llega, comprueba en el cliente:
```powershell
# Estado del Subscription Manager
Get-WinEvent -LogName "Microsoft-Windows-Forwarding/Operational" -MaxEvents 5 |
    Format-List TimeCreated, Id, Message
```

Códigos típicos:
- **EventID 100** → suscripción activada correctamente.
- **EventID 102** → error contactando al colector (firewall? DNS?).
- **EventID 105** → autenticación fallida (Kerberos, revisa que ambas máquinas estén unidas al dominio).

### Test real

En **CLIENTE1CSR**, dispara un evento sospechoso:
```powershell
powershell -nop -w hidden -enc VABlAHMAdABfAFcARQBGAA==
```

En menos de 1 minuto deberías ver en Discord:
```
🧪 [CLIENTE1CSR] **Sysmon ID=1** · CommandLine sospechosa ('-enc')
```

Y en el panel `http://localhost:8080` aparecerá la alerta con el host origen
ya identificado.

---

## Paso 4 · Reiniciar el servicio del proyecto

Una vez creada la suscripción y conectados los clientes, reinicia:

```powershell
nssm restart TFG_SeguridadActiva
```

El script detectará automáticamente el canal `ForwardedEvents` y empezará a
procesar eventos de **TODAS** las máquinas, prefijando cada alerta con
`[NombreCliente]` para que sepas siempre de dónde viene.

---

## Resolución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| El panel sigue sin ver eventos de los clientes | Suscripción inactiva | `wecutil rs TFG_Sysmon_Security` |
| `RuntimeStatus: Disabled` | Servicio Wecsvc parado | `Start-Service Wecsvc` |
| Cliente con EventID 102 en Forwarding/Operational | Firewall del cliente o DNS | Comprueba `Test-NetConnection SERVIDOR -Port 5985` |
| Cliente con EventID 105 | Permisos / Kerberos | Confirma que la GPO aplica `NETWORK SERVICE` en `Event Log Readers` |
| ForwardedEvents llena pero el script ignora | Provider name ≠ esperado | El dispatcher solo procesa Sysmon y Security-Auditing — añade más en `_procesar_evento_forwarded` si quieres |

---

## Para la memoria del TFG

Referencias citables:

- Microsoft Docs · *Use Windows Event Forwarding to assist in intrusion
  detection*: https://learn.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection
- NSA · *Cybersecurity Information Sheet: Windows Event Forwarding (WEF)*
  U/OO/197503-19.
- Palantir · *Windows Event Forwarding Guidance*:
  https://github.com/palantir/windows-event-forwarding
