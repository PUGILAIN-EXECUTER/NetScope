import os
import sys
import time
import socket
import ctypes
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, deque

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
        get_working_ifaces,
        send,
        sniff
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

lock = threading.RLock()

events = deque(maxlen=300)
devices = {}
domains = defaultdict(int)
connections = defaultdict(int)

packet_count = 0
dns_count = 0
connection_count = 0
device_count = 0

last_event_id = 0


def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0

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
    return datetime.now().strftime(
        "%H:%M:%S"
    )


def full_time():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def terminal_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 120


def center(value):
    width = terminal_width()

    if len(value) >= width:
        return value[:width]

    return (
        " " * ((width - len(value)) // 2)
        + value
    )


def safe_hostname(address):

    try:
        return socket.gethostbyaddr(address)[0]
    except Exception:
        return "-"


def get_interfaces():

    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = []

    result = []

    for interface in interfaces:

        try:
            address = get_if_addr(interface)
        except Exception:
            address = "0.0.0.0"

        try:
            mac = get_if_hwaddr(interface)
        except Exception:
            mac = "00:00:00:00:00:00"

        result.append(
            {
                "name": interface,
                "ip": address,
                "mac": mac
            }
        )

    return result


def choose_interface():

    global selected_interface
    global local_address

    interfaces = get_interfaces()

    usable = []

    for interface in interfaces:

        address = interface["ip"]

        if address == "0.0.0.0":
            continue

        if address.startswith("127."):
            continue

        usable.append(interface)

    if not usable:

        print(
            RED +
            "No usable network interface found." +
            RESET
        )

        print()

        print(
            "Interfaces detected:"
        )

        for interface in interfaces:

            print(
                f"  {interface['name']}  "
                f"{interface['ip']}"
            )

        sys.exit(1)

    if len(usable) == 1:

        selected_interface = usable[0]["name"]
        local_address = usable[0]["ip"]

        return

    clear()

    print()

    print(
        BOLD +
        CYAN +
        "NETSCOPE NETWORK INTERFACE" +
        RESET
    )

    print()

    for index, interface in enumerate(
        usable,
        start=1
    ):

        print(
            f"{CYAN}[{index}]{RESET} "
            f"{interface['name']}"
        )

        print(
            f"    IP   : {interface['ip']}"
        )

        print(
            f"    MAC  : {interface['mac']}"
        )

        print()

    while True:

        choice = input(
            "Select interface: "
        ).strip()

        try:
            number = int(choice)

            if 1 <= number <= len(usable):

                selected_interface = usable[
                    number - 1
                ]["name"]

                local_address = usable[
                    number - 1
                ]["ip"]

                return

        except ValueError:
            pass

        print(
            RED +
            "Invalid selection." +
            RESET
        )


def network_prefix():

    parts = local_address.split(".")

    if len(parts) != 4:
        return None

    return ".".join(parts[:3])


def register_device(
    address,
    mac="",
    hostname=""
):

    global device_count

    if not address:
        return

    with lock:

        if address not in devices:

            devices[address] = {
                "ip": address,
                "mac": mac or "-",
                "hostname": hostname or "-",
                "first_seen": full_time(),
                "last_seen": full_time(),
                "events": 0,
                "domains": 0
            }

            device_count += 1

        else:

            device = devices[address]

            if mac and mac != "-":
                device["mac"] = mac

            if (
                hostname
                and hostname != "-"
            ):
                device["hostname"] = hostname

            device["last_seen"] = full_time()


def arp_scan():

    prefix = network_prefix()

    if not prefix:
        return

    for number in range(1, 255):

        if not running:
            return

        target = (
            f"{prefix}.{number}"
        )

        if target == local_address:
            continue

        try:

            packet = (
                Ether(
                    dst="ff:ff:ff:ff:ff:ff"
                )
                /
                ARP(
                    pdst=target
                )
            )

            answer = srp_once(
                packet,
                timeout=0.35
            )

            if answer:

                register_device(
                    target,
                    answer[0],
                    safe_hostname(target)
                )

        except Exception:
            continue


def srp_once(packet, timeout=1):

    from scapy.all import srp

    answered, _ = srp(
        packet,
        timeout=timeout,
        verbose=False,
        iface=selected_interface
    )

    if not answered:
        return None

    result = answered[0]

    return (
        result[1].hwsrc,
        result[1].psrc
    )


def discovery_loop():

    while running:

        try:
            arp_scan()
        except Exception:
            pass

        time.sleep(10)


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

        events.append(
            {
                "id": last_event_id,
                "time": now(),
                "category": category,
                "source": source,
                "destination": destination,
                "detail": detail,
                "extra": extra
            }
        )


def domain_from_packet(packet):

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    if int(dns.qr) != 0:
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


def process_packet(packet):

    global packet_count
    global dns_count
    global connection_count

    with lock:
        packet_count += 1

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

        return

    if source and destination:

        if packet.haslayer(TCP):

            sport = int(
                packet[TCP].sport
            )

            dport = int(
                packet[TCP].dport
            )

            flags = str(
                packet[TCP].flags
            )

            with lock:
                connection_count += 1
                connections[dport] += 1

            event(
                "TCP",
                source,
                destination,
                f"{sport} -> {dport}",
                flags
            )

        elif packet.haslayer(UDP):

            sport = int(
                packet[UDP].sport
            )

            dport = int(
                packet[UDP].dport
            )

            with lock:
                connection_count += 1
                connections[dport] += 1

            event(
                "UDP",
                source,
                destination,
                f"{sport} -> {dport}",
                "UDP"
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

        if hostname != "-":
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

    print(
        GREEN +
        "● LIVE" +
        RESET +
        "  "
        +
        WHITE +
        "Interface: " +
        CYAN +
        str(selected_interface) +
        RESET +
        "  "
        +
        WHITE +
        "IP: " +
        CYAN +
        local_address +
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
        f"{'DOMAINS':<10}" +
        RESET
    )

    print(
        DIM +
        "─" * 78 +
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
            RESET
        )

    print()


def print_events():

    with lock:
        rows = list(events)[-30:]

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

        destination = item[
            "destination"
        ]

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

        else:
            color = YELLOW

        print(
            WHITE +
            f"{item['time']:<10}"
            + color +
            f"{item['category']:<8}"
            + RESET +
            f"{source:<22}"
            f"{destination:<18}"
            + GREEN +
            f"{detail:<38}"
            + RESET +
            f"{item['extra']:<12}"
        )

    print()


def print_domains():

    with lock:

        rows = sorted(
            domains.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

    print(
        BOLD +
        YELLOW +
        "TOP DOMAINS" +
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
            f"{domain:<55}" +
            RESET +
            WHITE +
            str(count) +
            RESET
        )

    print()


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
        "HTTPS paths and encrypted DNS contents are not reconstructed." +
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
            "✓ Administrator privileges detected" +
            RESET
        )

    else:

        print(
            YELLOW +
            "⚠ Administrator privileges not detected" +
            RESET
        )

        print(
            DIM +
            "Packet capture may fail without elevation." +
            RESET
        )

    print()

    print(
        WHITE +
        "Detecting network interfaces..." +
        RESET
    )

    choose_interface()

    print(
        GREEN +
        "✓ Interface selected:" +
        RESET,
        selected_interface
    )

    print(
        WHITE +
        "✓ Local IP:" +
        RESET,
        local_address
    )

    print()

    time.sleep(1)


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

    try:

        while running:

            with lock:

                packets = packet_count
                current_devices = device_count

            if (
                packets != last_packet_count
                or
                current_devices != last_device_count
                or
                capture_error
            ):

                render()

                last_packet_count = packets
                last_device_count = current_devices

            time.sleep(0.25)

    except KeyboardInterrupt:

        running = False

        clear()

        print()

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
                f"Devices discovered: {device_count}"
            )
        )

        print()


if __name__ == "__main__":
    main()
