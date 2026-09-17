import os
import sys
import time
import json
import socket
import ctypes
import sqlite3
import platform
import threading
import ipaddress
from datetime import datetime
from collections import defaultdict, deque

try:
    import psutil
except ImportError:
    print("psutil is not installed.")
    print("Run: python -m pip install psutil")
    sys.exit(1)

try:
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        get_if_addr,
        get_if_hwaddr,
        get_if_list,
        conf,
        srp,
        sniff,
        wrpcap
    )
except ImportError:
    print("Scapy is not installed.")
    print("Run: python -m pip install scapy")
    sys.exit(1)

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

running = True
capture_error = ""
selected_interface = None
local_address = "unknown"
local_netmask = None
local_network = None
local_gateway = None

lock = threading.RLock()

events = deque(maxlen=500)
devices = {}
domains = defaultdict(int)
connections = defaultdict(int)

packet_count = 0
dns_count = 0
connection_count = 0
device_count = 0
arp_count = 0
ipv4_count = 0
ipv6_count = 0
tcp_count = 0
udp_count = 0
bytes_count = 0

last_event_id = 0

DB_FILE = "netscope.db"
EXPORT_FILE = "netscope_export.json"

db_lock = threading.RLock()


def is_admin():
    if os.name != "nt":
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    try:
        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )
    except Exception:
        return False


def clear():
    os.system(
        "cls" if os.name == "nt" else "clear"
    )


def now():
    return datetime.now().strftime("%H:%M:%S")


def full_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def terminal_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 120


def center(value):
    width = terminal_width()

    plain = value

    for code in (
        RESET,
        BOLD,
        DIM,
        RED,
        GREEN,
        YELLOW,
        BLUE,
        MAGENTA,
        CYAN,
        WHITE
    ):
        plain = plain.replace(code, "")

    if len(plain) >= width:
        return value[:width]

    return (
        " " * ((width - len(plain)) // 2)
        + value
    )


def safe_hostname(address):
    try:
        return socket.gethostbyaddr(address)[0]
    except Exception:
        return "-"


def init_database():
    with db_lock:
        db = sqlite3.connect(DB_FILE)

        db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                mac TEXT,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                category TEXT,
                source TEXT,
                destination TEXT,
                detail TEXT,
                extra TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS dns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                destination TEXT,
                domain TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                protocol TEXT,
                source TEXT,
                destination TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                flags TEXT
            )
        """)

        db.commit()
        db.close()


def db_execute(query, values=()):
    try:
        with db_lock:
            db = sqlite3.connect(DB_FILE)
            db.execute(query, values)
            db.commit()
            db.close()
    except Exception:
        pass


def get_interfaces():
    result = []

    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, items in addresses.items():
        ipv4 = None
        netmask = None
        mac = None

        for item in items:
            family = item.family

            if family == socket.AF_INET:
                ipv4 = item.address
                netmask = item.netmask

            elif (
                getattr(psutil, "AF_LINK", None) is not None
                and family == psutil.AF_LINK
            ):
                mac = item.address

        if not mac:
            try:
                mac = get_if_hwaddr(name)
            except Exception:
                mac = "-"

        if not ipv4:
            try:
                ipv4 = get_if_addr(name)
            except Exception:
                ipv4 = "0.0.0.0"

        is_up = False

        try:
            is_up = stats[name].isup
        except Exception:
            pass

        result.append(
            {
                "name": name,
                "ip": ipv4,
                "netmask": netmask,
                "mac": mac or "-",
                "up": is_up
            }
        )

    return result


def get_default_route_interface():
    candidates = []

    try:
        route = conf.route.route("8.8.8.8")

        if route:
            iface = route[0]
            source = route[1]
            gateway = route[2]

            return iface, source, gateway
    except Exception:
        pass

    try:
        route = conf.route.route("1.1.1.1")

        if route:
            iface = route[0]
            source = route[1]
            gateway = route[2]

            return iface, source, gateway
    except Exception:
        pass

    return None, None, None


def choose_interface():
    global selected_interface
    global local_address
    global local_netmask
    global local_network
    global local_gateway

    interfaces = get_interfaces()

    iface, source, gateway = get_default_route_interface()

    if iface:
        for item in interfaces:
            if item["name"] == iface:
                selected_interface = item["name"]
                local_address = (
                    source
                    if source and source != "0.0.0.0"
                    else item["ip"]
                )
                local_netmask = item["netmask"]
                local_gateway = gateway
                break

    if not selected_interface:
        usable = []

        for item in interfaces:
            address = item["ip"]

            if not item["up"]:
                continue

            if not address:
                continue

            if address == "0.0.0.0":
                continue

            if address.startswith("127."):
                continue

            if ":" in address:
                continue

            usable.append(item)

        if not usable:
            print(
                RED +
                "No usable network interface found." +
                RESET
            )

            print()

            for item in interfaces:
                print(
                    f"  {item['name']}  "
                    f"{item['ip']}  "
                    f"{'UP' if item['up'] else 'DOWN'}"
                )

            sys.exit(1)

        if len(usable) == 1:
            item = usable[0]
        else:
            clear()

            print(
                BOLD +
                CYAN +
                "NETSCOPE NETWORK INTERFACE" +
                RESET
            )

            print()

            for index, item in enumerate(
                usable,
                start=1
            ):
                print(
                    f"{CYAN}[{index}]{RESET} "
                    f"{item['name']}"
                )
                print(
                    f"    IP      : {item['ip']}"
                )
                print(
                    f"    NETMASK : {item['netmask'] or '-'}"
                )
                print(
                    f"    MAC     : {item['mac']}"
                )
                print()

            while True:
                choice = input(
                    "Select interface: "
                ).strip()

                try:
                    number = int(choice)

                    if 1 <= number <= len(usable):
                        item = usable[number - 1]
                        break
                except ValueError:
                    pass

                print(
                    RED +
                    "Invalid selection." +
                    RESET
                )

        selected_interface = item["name"]
        local_address = item["ip"]
        local_netmask = item["netmask"]
        local_gateway = gateway

    if not local_netmask:
        local_netmask = detect_netmask(
            selected_interface,
            local_address
        )

    try:
        local_network = ipaddress.ip_network(
            f"{local_address}/{local_netmask}",
            strict=False
        )
    except Exception:
        local_network = None


def detect_netmask(interface, address):
    try:
        for item in psutil.net_if_addrs().get(
            interface,
            []
        ):
            if item.family == socket.AF_INET:
                if item.address == address:
                    return item.netmask
    except Exception:
        pass

    return "255.255.255.0"


def network_size():
    if not local_network:
        return 0

    return local_network.num_addresses


def register_device(
    address,
    mac="",
    hostname=""
):
    global device_count

    if not address:
        return

    with lock:
        existing = devices.get(address)

        if not existing:
            devices[address] = {
                "ip": address,
                "mac": mac or "-",
                "hostname": hostname or "-",
                "first_seen": full_time(),
                "last_seen": full_time(),
                "events": 0,
                "domains": 0,
                "packets": 0
            }

            device_count += 1

            device = devices[address]

        else:
            device = existing

            if mac and mac != "-":
                device["mac"] = mac

            if hostname and hostname != "-":
                device["hostname"] = hostname

            device["last_seen"] = full_time()

        device["packets"] += 1


def arp_scan():
    global arp_count

    if not selected_interface:
        return

    if not local_network:
        return

    if local_network.version != 4:
        return

    if local_network.num_addresses > 4096:
        event(
            "INFO",
            local_address,
            "-",
            f"Network too large for automatic ARP scan: {local_network}",
            "DISCOVERY"
        )
        return

    try:
        packet = (
            Ether(
                dst="ff:ff:ff:ff:ff:ff"
            )
            /
            ARP(
                pdst=str(local_network)
            )
        )

        answered, _ = srp(
            packet,
            iface=selected_interface,
            timeout=2,
            retry=1,
            verbose=False
        )

        for sent, received in answered:
            if not running:
                return

            ip = received.psrc
            mac = received.hwsrc

            hostname = safe_hostname(ip)

            register_device(
                ip,
                mac,
                hostname
            )

            with lock:
                arp_count += 1

            db_execute(
                """
                INSERT INTO devices(
                    timestamp,
                    ip,
                    mac,
                    hostname,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    full_time(),
                    ip,
                    mac,
                    hostname,
                    devices[ip]["first_seen"],
                    devices[ip]["last_seen"]
                )
            )

            event(
                "ARP",
                ip,
                "-",
                mac,
                hostname
            )

    except Exception as error:
        event(
            "ERROR",
            "SYSTEM",
            "-",
            str(error),
            "ARP"
        )


def discovery_loop():
    first = True

    while running:
        try:
            arp_scan()
        except Exception as error:
            event(
                "ERROR",
                "SYSTEM",
                "-",
                str(error),
                "DISCOVERY"
            )

        if first:
            first = False
            time.sleep(5)
        else:
            time.sleep(30)


def event(
    category,
    source,
    destination,
    detail,
    extra=""
):
    global last_event_id

    with lock:
        last_event_id += 1

        item = {
            "id": last_event_id,
            "time": now(),
            "full_time": full_time(),
            "category": category,
            "source": source or "-",
            "destination": destination or "-",
            "detail": detail or "-",
            "extra": extra or "-"
        }

        events.append(item)

    db_execute(
        """
        INSERT INTO events(
            timestamp,
            category,
            source,
            destination,
            detail,
            extra
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            item["full_time"],
            item["category"],
            item["source"],
            item["destination"],
            item["detail"],
            item["extra"]
        )
    )


def domain_from_packet(packet):
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    try:
        if int(dns.qr) != 0:
            return None
    except Exception:
        return None

    if not packet.haslayer(DNSQR):
        return None

    try:
        name = packet[DNSQR].qname

        if isinstance(name, bytes):
            name = name.decode(
                "utf-8",
                errors="ignore"
            )

        name = name.rstrip(".")

        if not name:
            return None

        return name
    except Exception:
        return None


def packet_source(packet):
    if packet.haslayer(IP):
        return packet[IP].src

    if packet.haslayer(IPv6):
        return packet[IPv6].src

    return None


def packet_destination(packet):
    if packet.haslayer(IP):
        return packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].dst

    return None


def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(IP):
        return "IPv4"

    if packet.haslayer(IPv6):
        return "IPv6"

    return "OTHER"


def process_packet(packet):
    global packet_count
    global dns_count
    global connection_count
    global ipv4_count
    global ipv6_count
    global tcp_count
    global udp_count
    global bytes_count

    with lock:
        packet_count += 1
        bytes_count += len(packet)

        if packet.haslayer(IP):
            ipv4_count += 1

        if packet.haslayer(IPv6):
            ipv6_count += 1

        if packet.haslayer(TCP):
            tcp_count += 1

        if packet.haslayer(UDP):
            udp_count += 1

    source = packet_source(packet)
    destination = packet_destination(packet)

    if source:
        register_device(source)

    domain = domain_from_packet(packet)

    if domain and source:
        with lock:
            dns_count += 1
            domains[domain] += 1

            if source in devices:
                devices[source]["domains"] += 1
                devices[source]["events"] += 1

        event(
            "DNS",
            source,
            destination or "-",
            domain,
            "DOMAIN"
        )

        db_execute(
            """
            INSERT INTO dns(
                timestamp,
                source,
                destination,
                domain
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                full_time(),
                source,
                destination or "-",
                domain
            )
        )

        return

    if not source or not destination:
        return

    if packet.haslayer(TCP):
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

        flags = str(
            packet[TCP].flags
        )

        with lock:
            connection_count += 1
            connections[dport] += 1

            if source in devices:
                devices[source]["events"] += 1

        event(
            "TCP",
            source,
            destination,
            f"{sport} -> {dport}",
            flags
        )

        db_execute(
            """
            INSERT INTO connections(
                timestamp,
                protocol,
                source,
                destination,
                source_port,
                destination_port,
                flags
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                full_time(),
                "TCP",
                source,
                destination,
                sport,
                dport,
                flags
            )
        )

    elif packet.haslayer(UDP):
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

        with lock:
            connection_count += 1
            connections[dport] += 1

            if source in devices:
                devices[source]["events"] += 1

        event(
            "UDP",
            source,
            destination,
            f"{sport} -> {dport}",
            "UDP"
        )

        db_execute(
            """
            INSERT INTO connections(
                timestamp,
                protocol,
                source,
                destination,
                source_port,
                destination_port,
                flags
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                full_time(),
                "UDP",
                source,
                destination,
                sport,
                dport,
                "UDP"
            )
        )


def capture_loop():
    global capture_error

    try:
        sniff(
            iface=selected_interface,
            prn=process_packet,
            store=False
        )

    except Exception as error:
        with lock:
            capture_error = str(error)

        event(
            "ERROR",
            "SYSTEM",
            "-",
            str(error),
            "CAPTURE"
        )


def device_label(address):
    with lock:
        device = devices.get(address)

        if not device:
            return address

        hostname = device["hostname"]

        if hostname and hostname != "-":
            return hostname

        return address


def print_banner():
    print()
    print(
        center(
            BOLD +
            CYAN +
            "▄▄     ▄▄▄   ▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄    ▄▄▄▄▄    ▄   ▄▄▄▄    ▄▄▄▄      ▄▄▄▄▄▄     ▄▄▄▄▄▄▄" +
            RESET
        )
    )
    print(
        center(
            BOLD +
            CYAN +
            "██▄   ██▀   █▀██▀▀▀   █▀▀██▀▀▀▀  ██▀▀▀▀█▄  ▀██████▀  ▄█▀▀████▄  █▀██▀▀▀█▄  █▀██▀▀▀" +
            RESET
        )
    )
    print(
        center(
            BOLD +
            CYAN +
            "███▄  ██      ██         ██      ▀██▄  ▄▀    ██      ██    ██     ██▄▄▄█▀    ██" +
            RESET
        )
    )
    print(
        center(
            BOLD +
            CYAN +
            "██ ▀█▄██      ████       ██        ▀██▄▄     ██      ██    ██     ██▀▀▀      ████" +
            RESET
        )
    )
    print(
        center(
            BOLD +
            CYAN +
            "██   ▀██      ██         ██      ▄   ▀██▄    ██      ██    ██   ▄ ██         ██" +
            RESET
        )
    )
    print(
        center(
            BOLD +
            CYAN +
            "▀██▀    ██      ▀█████     ▀██▄    ▀██████▀    ▀█████   ▀████▀    ▀██▀         ▀█████" +
            RESET
        )
    )
    print()
    print(
        center(
            DIM +
            "LIVE NETWORK VISIBILITY" +
            RESET
        )
    )
    print()


def print_header():
    status = (
        GREEN +
        "● LIVE" +
        RESET
    )

    print(
        status +
        "  " +
        WHITE +
        "Interface: " +
        CYAN +
        str(selected_interface) +
        RESET +
        "  " +
        WHITE +
        "IP: " +
        CYAN +
        local_address +
        RESET
    )

    print(
        DIM +
        "Network: " +
        str(local_network or "-") +
        "   "
        "Gateway: " +
        str(local_gateway or "-") +
        RESET
    )

    print(
        DIM +
        "Packets: " +
        str(packet_count) +
        "   DNS: " +
        str(dns_count) +
        "   Connections: " +
        str(connection_count) +
        "   Devices: " +
        str(device_count) +
        "   ARP: " +
        str(arp_count) +
        RESET
    )

    print(
        DIM +
        "IPv4: " +
        str(ipv4_count) +
        "   IPv6: " +
        str(ipv6_count) +
        "   TCP: " +
        str(tcp_count) +
        "   UDP: " +
        str(udp_count) +
        "   Bytes: " +
        str(bytes_count) +
        RESET
    )

    print()


def print_devices():
    with lock:
        rows = list(devices.values())

    print(
        BOLD +
        BLUE +
        "DEVICES" +
        RESET
    )

    print()

    print(
        DIM +
        f"{'IP':<18}"
        f"{'HOSTNAME':<30}"
        f"{'MAC':<20}"
        f"{'DOMAINS':<10}"
        f"{'PACKETS':<10}" +
        RESET
    )

    print(
        DIM +
        "─" * 88 +
        RESET
    )

    if not rows:
        print(
            DIM +
            "No devices discovered yet." +
            RESET
        )

        print()
        return

    rows.sort(
        key=lambda x: x["ip"]
    )

    for device in rows:
        hostname = device["hostname"]

        if len(hostname) > 28:
            hostname = hostname[:28]

        print(
            WHITE +
            f"{device['ip']:<18}"
            f"{hostname:<30}"
            f"{device['mac']:<20}" +
            CYAN +
            f"{device['domains']:<10}" +
            WHITE +
            f"{device['packets']:<10}" +
            RESET
        )

    print()


def print_events():
    with lock:
        rows = list(events)[-25:]

    print(
        BOLD +
        MAGENTA +
        "NETWORK ACTIVITY" +
        RESET
    )

    print()

    print(
        DIM +
        f"{'TIME':<10}"
        f"{'TYPE':<8}"
        f"{'DEVICE':<22}"
        f"{'DESTINATION':<18}"
        f"{'DETAIL':<38}"
        f"{'INFO':<12}" +
        RESET
    )

    print(
        DIM +
        "─" * 108 +
        RESET
    )

    if not rows:
        print(
            DIM +
            "No network events captured." +
            RESET
        )

        print()
        return

    for item in rows:
        source = device_label(
            item["source"]
        )

        destination = item["destination"]
        detail = item["detail"]

        if len(source) > 20:
            source = source[:20]

        if len(destination) > 16:
            destination = destination[:16]

        if len(detail) > 36:
            detail = detail[:36]

        if item["category"] == "DNS":
            color = GREEN
        elif item["category"] == "ERROR":
            color = RED
        elif item["category"] == "TCP":
            color = CYAN
        elif item["category"] == "ARP":
            color = BLUE
        else:
            color = YELLOW

        print(
            WHITE +
            f"{item['time']:<10}" +
            color +
            f"{item['category']:<8}" +
            RESET +
            f"{source:<22}"
            f"{destination:<18}" +
            GREEN +
            f"{detail:<38}" +
            RESET +
            f"{item['extra']:<12}"
        )

    print()


def print_domains():
    with lock:
        rows = sorted(
            domains.items(),
            key=lambda x: x[1],
            reverse=True
        )[:12]

    print(
        BOLD +
        YELLOW +
        "TOP OBSERVED DOMAINS" +
        RESET
    )

    print()

    if not rows:
        print(
            DIM +
            "No observable DNS domains yet." +
            RESET
        )

        print()
        return

    for domain, count in rows:
        print(
            CYAN +
            f"{domain:<60}" +
            RESET +
            WHITE +
            str(count) +
            RESET
        )

    print()


def export_json():
    with lock:
        data = {
            "exported_at": full_time(),
            "network": {
                "interface": selected_interface,
                "local_ip": local_address,
                "netmask": local_netmask,
                "network": str(local_network)
                if local_network
                else None,
                "gateway": local_gateway
            },
            "statistics": {
                "packets": packet_count,
                "dns": dns_count,
                "connections": connection_count,
                "devices": device_count,
                "arp": arp_count,
                "ipv4": ipv4_count,
                "ipv6": ipv6_count,
                "tcp": tcp_count,
                "udp": udp_count,
                "bytes": bytes_count
            },
            "devices": list(
                devices.values()
            ),
            "domains": dict(domains),
            "events": list(events)
        }

    try:
        with open(
            EXPORT_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False
            )

        return True
    except Exception:
        return False


def render():
    clear()

    print_banner()
    print_header()

    if capture_error:
        print(
            RED +
            "CAPTURE ERROR" +
            RESET
        )

        print(
            YELLOW +
            capture_error +
            RESET
        )

        print()

    print_devices()
    print_events()
    print_domains()

    print(
        DIM +
        "Only traffic observable by this interface is displayed. "
        "Encrypted HTTPS paths and encrypted DNS contents are not reconstructed." +
        RESET
    )

    print()

    print(
        DIM +
        "Press CTRL+C to stop and export the current session." +
        RESET
    )

    print()


def startup():
    clear()

    print_banner()

    print(
        WHITE +
        "Checking privileges..." +
        RESET
    )

    if is_admin():
        print(
            GREEN +
            "✓ Elevated privileges detected" +
            RESET
        )
    else:
        print(
            YELLOW +
            "⚠ Elevated privileges not detected" +
            RESET
        )

        if os.name == "nt":
            print(
                DIM +
                "Run PowerShell/CMD as Administrator for packet capture." +
                RESET
            )
        else:
            print(
                DIM +
                "Run with sudo/root if packet capture is denied." +
                RESET
            )

    print()

    print(
        WHITE +
        "Detecting active network..." +
        RESET
    )

    choose_interface()

    print(
        GREEN +
        "✓ Interface:" +
        RESET,
        selected_interface
    )

    print(
        GREEN +
        "✓ Local IP:" +
        RESET,
        local_address
    )

    print(
        GREEN +
        "✓ Netmask:" +
        RESET,
        local_netmask or "-"
    )

    print(
        GREEN +
        "✓ Network:" +
        RESET,
        local_network or "-"
    )

    print(
        GREEN +
        "✓ Gateway:" +
        RESET,
        local_gateway or "-"
    )

    print()

    if local_network:
        if local_network.num_addresses <= 4096:
            print(
                GREEN +
                "✓ Automatic LAN discovery available" +
                RESET
            )
        else:
            print(
                YELLOW +
                "⚠ LAN is larger than automatic discovery limit" +
                RESET
            )

    print()

    init_database()

    time.sleep(1)


def save_session():
    export_json()

    print()

    if os.path.exists(EXPORT_FILE):
        print(
            GREEN +
            f"✓ Exported: {EXPORT_FILE}" +
            RESET
        )

    print(
        GREEN +
        f"✓ Database: {DB_FILE}" +
        RESET
    )


def main():
    global running

    startup()

    discovery = threading.Thread(
        target=discovery_loop,
        daemon=True
    )

    discovery.start()

    capture_thread = threading.Thread(
        target=capture_loop,
        daemon=True
    )

    capture_thread.start()

    time.sleep(2)

    last_packet_count = -1
    last_device_count = -1
    last_dns_count = -1
    last_connection_count = -1

    try:
        while running:
            with lock:
                packets = packet_count
                current_devices = device_count
                current_dns = dns_count
                current_connections = connection_count
                current_error = capture_error

            if (
                packets != last_packet_count
                or current_devices != last_device_count
                or current_dns != last_dns_count
                or current_connections != last_connection_count
                or current_error
            ):
                render()

                last_packet_count = packets
                last_device_count = current_devices
                last_dns_count = current_dns
                last_connection_count = current_connections

            time.sleep(0.5)

    except KeyboardInterrupt:
        running = False

    finally:
        running = False

        clear()

        print_banner()

        print(
            center(
                BOLD +
                GREEN +
                "NETSCOPE STOPPED" +
                RESET
            )
        )

        print()

        print(
            center(
                WHITE +
                f"Packets captured: {packet_count}" +
                RESET
            )
        )

        print(
            center(
                WHITE +
                f"DNS events: {dns_count}" +
                RESET
            )
        )

        print(
            center(
                WHITE +
                f"Connections: {connection_count}" +
                RESET
            )
        )

        print(
            center(
                WHITE +
                f"Devices discovered: {device_count}" +
                RESET
            )
        )

        print()

        save_session()

        print()


if __name__ == "__main__":
    main()
