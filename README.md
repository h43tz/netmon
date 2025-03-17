```
 _   _ _____ _____ __  __  ___  _   _ 
| \ | | ____|_   _|  \/  |/ _ \| \ | |
|  \| |  _|   | | | |\/| | | | |  \| |
| |\  | |___  | | | |  | | |_| | |\  |
|_| \_|_____| |_| |_|  |_|\___/|_| \_|
                                      
```

# NETMON - Monitor de Seguridad de Red

## Descripción

NETMON es una herramienta avanzada de monitoreo de seguridad de red escrita en Python que combina las funcionalidades de `arpwatch` y `tcpdump`. Permite detectar dispositivos nuevos en la red, identificar cambios sospechosos en direcciones MAC, monitorear actividad ARP anómala y generar alertas en tiempo real.

## Características principales

- 🔍 **Detección de dispositivos nuevos** con identificación de fabricante
- 🛡️ **Detección de posibles ataques ARP spoofing** 
- 🚨 **Alertas sobre actividad anómala** como múltiples MACs en una IP o múltiples IPs en una MAC
- 📊 **Generación de logs detallados** en formato JSON para análisis posterior
- 📱 **Sistema de alertas** vía correo electrónico y Telegram

## Requisitos

- Python 3.6+
- Bibliotecas: scapy, netifaces, mac-vendor-lookup, python-telegram-bot (opcional)
- Permisos de administrador para captura de paquetes

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/yourusername/netmon.git
cd netmon

# Instalar dependencias
pip install -r requirements.txt
```

## Uso básico

```bash
# Uso básico (detecta automáticamente la interfaz)
sudo python3 netmon.py

# Especificar interfaz de red
sudo python3 netmon.py -i eth0

# Habilitar alertas
sudo python3 netmon.py -a -e -t

# Ver todas las opciones
python3 netmon.py --help
```

## Opciones

```
-i, --interface     Interfaz de red a monitorear
-l, --log-dir       Directorio para archivos de log
-s, --scan-interval Intervalo de escaneo en segundos
-a, --alerts        Habilitar alertas
-e, --email         Habilitar alertas por correo
-t, --telegram      Habilitar alertas por Telegram
```

## Configuración de alertas

Edita las variables de configuración al inicio del script:

```python
CONFIG = {
    # ... otras configuraciones ...
    "email_alert": {
        "enabled": False,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender": "your_email@gmail.com",
        "password": "your_app_password",
        "recipient": "recipient@example.com"
    },
    "telegram_alert": {
        "enabled": False,
        "bot_token": "YOUR_BOT_TOKEN",
        "chat_id": "YOUR_CHAT_ID"
    }
}
```

## Ejemplo de salida JSON

```json
{
  "timestamp": "2025-03-17T10:15:23.123456",
  "devices": {
    "aa:bb:cc:dd:ee:ff": {
      "ip": "192.168.1.10",
      "vendor": "Apple Inc.",
      "first_seen": "2025-03-17T09:45:12.654321"
    }
  },
  "suspicious_activity": [
    {
      "type": "mac_change",
      "timestamp": "2025-03-17T10:10:15.789123",
      "ip": "192.168.1.15",
      "old_mac": "11:22:33:44:55:66",
      "new_mac": "aa:bb:cc:11:22:33",
      "details": "Posible ARP spoofing o cambio de dispositivo"
    }
  ]
}
```

## Aviso legal

Esta herramienta está destinada únicamente para el monitoreo y protección de redes propias o autorizadas. El uso en redes sin autorización puede violar leyes locales.

## Licencia

MIT

## Contribuir

Las contribuciones son bienvenidas! Por favor, crea un issue o envía un pull request.
