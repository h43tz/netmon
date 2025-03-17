#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 _   _ _____ _____ __  __  ___  _   _ 
| \ | | ____|_   _|  \/  |/ _ \| \ | |
|  \| |  _|   | | | |\/| | | | |  \| |
| |\  | |___  | | | |  | | |_| | |\  |
|_| \_|_____| |_| |_|  |_|\___/|_| \_|
                                      
Network Monitoring Script by h43tz
----------------------------------
Este script monitorea una red local para detectar nuevos dispositivos, cambios de MAC
y actividad anómala, combinando funcionalidades similares a arpwatch y tcpdump.

Requisitos:
    - Python 3.6+
    - scapy
    - netifaces
    - mac-vendor-lookup
    - python-telegram-bot (opcional para alertas)

Instalar dependencias:
    pip install scapy netifaces mac-vendor-lookup python-telegram-bot
"""

import argparse
import json
import logging
import os
import signal
import smtplib
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Set, Tuple

import netifaces
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, conf, sniff
from scapy.layers.inet import IP, TCP, UDP

# Configuración global (modificar según necesidades)
CONFIG = {
    "interface": None,  # Se detectará automáticamente o se puede especificar por línea de comandos
    "log_dir": "network_logs",
    "json_log": "network_activity.json",
    "scan_interval": 60,  # Intervalo de escaneo de red en segundos
    "alert_enabled": False,
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

# Estado global para seguimiento de dispositivos
network_state = {
    "ip_to_mac": {},            # Mapeo de IP a MAC
    "mac_to_ip": defaultdict(set),  # Mapeo de MAC a múltiples IPs
    "ip_to_macs": defaultdict(set), # Mapeo de IP a múltiples MACs (para detectar conflictos)
    "devices": {},              # Información de dispositivos conocidos
    "first_seen": {},           # Cuándo se vio por primera vez un dispositivo
    "last_seen": {},            # Cuándo se vio por última vez un dispositivo
    "suspicious_activity": []   # Registro de actividad sospechosa
}

# Configuración de logging
logger = None

class TelegramHandler:
    """Gestor de alertas de Telegram."""
    
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.enabled = False
        try:
            # Intentar importar la biblioteca de Telegram
            from telegram import Bot
            self.bot = Bot(token=token)
            self.enabled = True
        except ImportError:
            logging.warning("La biblioteca python-telegram-bot no está instalada. Las alertas de Telegram están deshabilitadas.")
        except Exception as e:
            logging.error(f"Error al inicializar el bot de Telegram: {e}")
    
    def send_alert(self, message):
        """Envía una alerta a través de Telegram."""
        if not self.enabled:
            return False
        
        try:
            self.bot.send_message(chat_id=self.chat_id, text=message)
            return True
        except Exception as e:
            logging.error(f"Error al enviar alerta por Telegram: {e}")
            return False

def setup_logging(log_dir: str) -> logging.Logger:
    """Configura el sistema de logging."""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Configurar el archivo de log principal
    log_file = os.path.join(log_dir, 'network_monitor.log')
    file_handler = RotatingFileHandler(log_file, maxBytes=5242880, backupCount=5)
    file_handler.setFormatter(log_formatter)
    
    # Configurar la salida a consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    
    # Configurar el logger
    logger = logging.getLogger('NetworkMonitor')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_mac_vendor(mac_address: str) -> str:
    """Obtiene el fabricante de una dirección MAC."""
    try:
        mac_lookup = MacLookup()
        # Actualizar la base de datos de fabricantes si es necesario
        try:
            mac_lookup.update_vendors()
        except:
            pass  # Si falla la actualización, usar la base existente
        
        vendor = mac_lookup.lookup(mac_address)
        return vendor
    except Exception as e:
        return "Desconocido"

def get_default_interface() -> str:
    """Detecta la interfaz de red predeterminada."""
    try:
        # Método 1: Usando scapy
        return conf.iface
    except:
        try:
            # Método 2: Usando la interfaz de puerta de enlace predeterminada
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][1]
        except:
            # Método 3: Usar la primera interfaz que no sea loopback
            for iface in netifaces.interfaces():
                if iface != 'lo':
                    return iface
            
            # Si todo falla, usar loopback
            return 'lo'

def normalize_mac(mac: str) -> str:
    """Normaliza el formato de dirección MAC."""
    mac = mac.lower().replace(':', '').replace('-', '').replace('.', '')
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

def scan_network(interface: str) -> None:
    """Escanea la red para encontrar dispositivos activos."""
    logger.info(f"Iniciando escaneo de red en la interfaz {interface}")
    
    # Enviar paquetes ARP para descubrir dispositivos
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=get_network_range(interface))
    
    try:
        # Enviar paquetes y recibir respuestas
        ans, _ = srp(arp_request, timeout=2, verbose=0, iface=interface)
        
        for _, rcv in ans:
            ip = rcv[ARP].psrc
            mac = normalize_mac(rcv[ARP].hwsrc)
            process_device(ip, mac)
            
    except Exception as e:
        logger.error(f"Error durante el escaneo de red: {e}")

def get_network_range(interface: str) -> str:
    """Obtiene el rango de red basado en la interfaz."""
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Cálculo simple para redes /24
        ip_parts = ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except Exception as e:
        logger.error(f"Error al obtener rango de red: {e}")
        return "192.168.1.0/24"  # Valor predeterminado

def process_device(ip: str, mac: str) -> None:
    """Procesa la información de un dispositivo detectado."""
    current_time = datetime.now().isoformat()
    
    # Comprobar si es un dispositivo nuevo
    if ip not in network_state["ip_to_mac"]:
        vendor = get_mac_vendor(mac)
        logger.info(f"Nuevo dispositivo detectado - IP: {ip}, MAC: {mac}, Fabricante: {vendor}")
        
        network_state["devices"][mac] = {
            "ip": ip,
            "vendor": vendor,
            "first_seen": current_time
        }
        network_state["first_seen"][mac] = current_time
        
        # Enviar alerta para nuevo dispositivo
        if CONFIG["alert_enabled"]:
            send_alert(f"Nuevo dispositivo detectado:\nIP: {ip}\nMAC: {mac}\nFabricante: {vendor}")
    
    # Comprobar cambio de MAC para una IP existente
    if ip in network_state["ip_to_mac"] and network_state["ip_to_mac"][ip] != mac:
        old_mac = network_state["ip_to_mac"][ip]
        logger.warning(f"Cambio de MAC detectado - IP: {ip}, MAC anterior: {old_mac}, MAC nueva: {mac}")
        
        # Registrar actividad sospechosa
        suspicious_activity = {
            "type": "mac_change",
            "timestamp": current_time,
            "ip": ip,
            "old_mac": old_mac,
            "new_mac": mac,
            "details": "Posible ARP spoofing o cambio de dispositivo"
        }
        network_state["suspicious_activity"].append(suspicious_activity)
        
        # Agregar MAC a la lista de MACs asociadas con esta IP
        network_state["ip_to_macs"][ip].add(mac)
        
        # Enviar alerta para cambio de MAC
        if CONFIG["alert_enabled"]:
            send_alert(f"ALERTA: Cambio de MAC detectado\nIP: {ip}\nMAC anterior: {old_mac}\nMAC nueva: {mac}")
    
    # Actualizar los mapeos
    network_state["ip_to_mac"][ip] = mac
    network_state["mac_to_ip"][mac].add(ip)
    network_state["ip_to_macs"][ip].add(mac)
    network_state["last_seen"][mac] = current_time
    
    # Comprobar si una MAC tiene múltiples IPs
    if len(network_state["mac_to_ip"][mac]) > 1:
        ips = ", ".join(network_state["mac_to_ip"][mac])
        logger.warning(f"MAC {mac} asociada a múltiples IPs: {ips}")
        
        # Registrar como actividad sospechosa si es primera vez
        if len(network_state["mac_to_ip"][mac]) == 2:  # Solo registrar en el momento que pasa de 1 a 2
            suspicious_activity = {
                "type": "multiple_ips",
                "timestamp": current_time,
                "mac": mac,
                "ips": list(network_state["mac_to_ip"][mac]),
                "details": "Posible proxy, NAT o máquina virtual"
            }
            network_state["suspicious_activity"].append(suspicious_activity)
            
            if CONFIG["alert_enabled"]:
                send_alert(f"ALERTA: MAC con múltiples IPs\nMAC: {mac}\nIPs: {ips}")
    
    # Comprobar si una IP tiene múltiples MACs
    if len(network_state["ip_to_macs"][ip]) > 1:
        macs = ", ".join(network_state["ip_to_macs"][ip])
        logger.warning(f"IP {ip} asociada a múltiples MACs: {macs}")
        
        # Registrar como actividad sospechosa si es primera vez
        if len(network_state["ip_to_macs"][ip]) == 2:  # Solo registrar en el momento que pasa de 1 a 2
            suspicious_activity = {
                "type": "multiple_macs",
                "timestamp": current_time,
                "ip": ip,
                "macs": list(network_state["ip_to_macs"][ip]),
                "details": "Posible ARP spoofing o conflicto de IP"
            }
            network_state["suspicious_activity"].append(suspicious_activity)
            
            if CONFIG["alert_enabled"]:
                send_alert(f"ALERTA: IP con múltiples MACs\nIP: {ip}\nMACs: {macs}")

def arp_monitor_callback(pkt):
    """Callback para monitorear paquetes ARP."""
    if ARP in pkt:
        arp = pkt[ARP]
        
        # Procesar direcciones ARP
        if arp.op == 1:  # ARP request
            process_device(arp.psrc, normalize_mac(arp.hwsrc))
        elif arp.op == 2:  # ARP reply
            process_device(arp.psrc, normalize_mac(arp.hwsrc))
            
            # Detectar ARP gratuitos (respuestas sin solicitud previa)
            # Esto puede indicar ARP spoofing
            if hasattr(pkt, 'pdst') and pkt.pdst == "0.0.0.0":
                logger.warning(f"ARP gratuito detectado desde {arp.psrc} ({arp.hwsrc})")
                
                suspicious_activity = {
                    "type": "gratuitous_arp",
                    "timestamp": datetime.now().isoformat(),
                    "ip": arp.psrc,
                    "mac": normalize_mac(arp.hwsrc),
                    "details": "ARP gratuito detectado - posible ARP poisoning"
                }
                network_state["suspicious_activity"].append(suspicious_activity)
                
                if CONFIG["alert_enabled"]:
                    send_alert(f"ALERTA: ARP gratuito detectado\nIP: {arp.psrc}\nMAC: {arp.hwsrc}")

def save_state_to_json(log_file: str):
    """Guarda el estado actual de la red en un archivo JSON."""
    data = {
        "timestamp": datetime.now().isoformat(),
        "devices": network_state["devices"],
        "suspicious_activity": network_state["suspicious_activity"],
        "ip_to_mac": network_state["ip_to_mac"],
        "mac_to_ip": {k: list(v) for k, v in network_state["mac_to_ip"].items()},
        "ip_to_macs": {k: list(v) for k, v in network_state["ip_to_macs"].items()}
    }
    
    with open(log_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Estado de red guardado en {log_file}")

def send_email_alert(subject: str, message: str) -> bool:
    """Envía una alerta por correo electrónico."""
    if not CONFIG["email_alert"]["enabled"]:
        return False
    
    try:
        msg = EmailMessage()
        msg.set_content(message)
        msg["Subject"] = subject
        msg["From"] = CONFIG["email_alert"]["sender"]
        msg["To"] = CONFIG["email_alert"]["recipient"]
        
        server = smtplib.SMTP(CONFIG["email_alert"]["smtp_server"], CONFIG["email_alert"]["smtp_port"])
        server.starttls()
        server.login(CONFIG["email_alert"]["sender"], CONFIG["email_alert"]["password"])
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Alerta por correo enviada: {subject}")
        return True
    except Exception as e:
        logger.error(f"Error al enviar correo: {e}")
        return False

def send_alert(message: str) -> None:
    """Envía alertas a través de los canales configurados."""
    # Alerta por correo
    if CONFIG["email_alert"]["enabled"]:
        send_email_alert("Alerta de seguridad de red", message)
    
    # Alerta por Telegram
    if CONFIG["telegram_alert"]["enabled"] and telegram_handler:
        telegram_handler.send_alert(message)

def signal_handler(sig, frame):
    """Manejador de señales para salida controlada."""
    logger.info("Recibida señal de terminación. Guardando estado y saliendo...")
    save_state_to_json(os.path.join(CONFIG["log_dir"], CONFIG["json_log"]))
    sys.exit(0)

def parse_arguments():
    """Parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(description='Monitor de red para detección de dispositivos y anomalías')
    parser.add_argument('-i', '--interface', help='Interfaz de red a monitorear')
    parser.add_argument('-l', '--log-dir', help='Directorio para archivos de log', default=CONFIG["log_dir"])
    parser.add_argument('-s', '--scan-interval', type=int, help='Intervalo de escaneo en segundos', default=CONFIG["scan_interval"])
    parser.add_argument('-a', '--alerts', action='store_true', help='Habilitar alertas')
    parser.add_argument('-e', '--email', action='store_true', help='Habilitar alertas por correo')
    parser.add_argument('-t', '--telegram', action='store_true', help='Habilitar alertas por Telegram')
    
    return parser.parse_args()

def main():
    """Función principal."""
    global logger, telegram_handler
    
    # Parsear argumentos
    args = parse_arguments()
    
    # Actualizar configuración con argumentos
    if args.interface:
        CONFIG["interface"] = args.interface
    else:
        CONFIG["interface"] = get_default_interface()
    
    if args.log_dir:
        CONFIG["log_dir"] = args.log_dir
    
    if args.scan_interval:
        CONFIG["scan_interval"] = args.scan_interval
    
    # Configurar alertas
    CONFIG["alert_enabled"] = args.alerts
    CONFIG["email_alert"]["enabled"] = args.email and args.alerts
    CONFIG["telegram_alert"]["enabled"] = args.telegram and args.alerts
    
    # Configurar logging
    logger = setup_logging(CONFIG["log_dir"])
    logger.info(f"Iniciando monitor de red en la interfaz {CONFIG['interface']}")
    
    # Inicializar manejador de Telegram si está habilitado
    telegram_handler = None
    if CONFIG["telegram_alert"]["enabled"]:
        telegram_handler = TelegramHandler(
            CONFIG["telegram_alert"]["bot_token"],
            CONFIG["telegram_alert"]["chat_id"]
        )
    
    # Configurar manejador de señales para salida controlada
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Realizar escaneo inicial
    scan_network(CONFIG["interface"])
    
    # Iniciar sniffer en un hilo separado
    logger.info("Iniciando monitoreo ARP...")
    sniff_thread = None
    
    try:
        # Bucle principal
        last_scan_time = time.time()
        while True:
            # Iniciar sniffer ARP si no está activo
            if sniff_thread is None or not sniff_thread.is_alive():
                from threading import Thread
                sniff_thread = Thread(
                    target=lambda: sniff(
                        filter="arp",
                        prn=arp_monitor_callback,
                        store=0,
                        iface=CONFIG["interface"]
                    ),
                    daemon=True
                )
                sniff_thread.start()
            
            # Realizar escaneo periódico
            current_time = time.time()
            if current_time - last_scan_time >= CONFIG["scan_interval"]:
                scan_network(CONFIG["interface"])
                save_state_to_json(os.path.join(CONFIG["log_dir"], CONFIG["json_log"]))
                last_scan_time = current_time
            
            # Dormir un poco para reducir uso de CPU
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Programa interrumpido por el usuario")
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
    finally:
        # Guardar estado antes de salir
        save_state_to_json(os.path.join(CONFIG["log_dir"], CONFIG["json_log"]))
        logger.info("Monitor de red finalizado")

if __name__ == "__main__":
    # Importar dependencias específicas que solo se usan en el método principal
    from scapy.all import srp
    main()
