# NetScope

<p align="center">

<img src="https://img.shields.io/badge/NetScope-Network%20Monitoring-00D4FF?style=for-the-badge&logo=linux&logoColor=white" alt="NetScope">

</p>

<p align="center">

<b>Real-Time Network Visibility & Security Monitoring</b>

</p>

<p align="center">

<img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
<img src="https://img.shields.io/badge/Scapy-Packet%20Analysis-FF6F00?style=for-the-badge" alt="Scapy">
<img src="https://img.shields.io/badge/Npcap-Packet%20Capture-00AEEF?style=for-the-badge" alt="Npcap">

</p>

<p align="center">

<img src="https://img.shields.io/badge/Status-Active%20Development-00C853?style=for-the-badge" alt="Status">
<img src="https://img.shields.io/badge/Open%20Source-Yes-2EA44F?style=for-the-badge&logo=github&logoColor=white" alt="Open Source">
<img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="License">
<img src="https://img.shields.io/badge/Security-Focused-8E44AD?style=for-the-badge&logo=shield&logoColor=white" alt="Security">

</p>

---

## About

NetScope is a lightweight real-time network visibility and security monitoring tool for Windows.

It uses Python, Scapy and Npcap to inspect network traffic that is actually observable from the selected network interface.

The project is designed for:

- Network administration
- Network troubleshooting
- Cybersecurity education
- Security research
- Home labs
- Authorized testing environments
- Network traffic analysis
- Learning packet analysis

NetScope runs directly from the terminal and does not require a large external monitoring platform.

---

# Features

| Feature | Status | Description |
|---|:---:|---|
| Real-Time Packet Capture | 🟢 | Processes observable packets as they arrive |
| Npcap Support | 🟢 | Windows packet capture |
| Scapy Support | 🟢 | Packet parsing and analysis |
| Interface Detection | 🟢 | Detect available network interfaces |
| Interface Selection | 🟢 | Select the interface to monitor |
| IPv4 Monitoring | 🟢 | Track observable IPv4 traffic |
| IPv6 Monitoring | 🟢 | Basic IPv6 visibility |
| LAN Discovery | 🟢 | Discover observable local IPv4 devices |
| Device Inventory | 🟢 | Track discovered devices |
| MAC Addresses | 🟢 | Display available MAC addresses |
| Hostnames | 🟢 | Attempt hostname resolution |
| First Seen | 🟢 | Track first device observation |
| Last Seen | 🟢 | Track latest device observation |
| DNS Monitoring | 🟢 | Display observable DNS queries |
| Domain Tracking | 🟢 | Track observed domains |
| Domain Statistics | 🟢 | Count domain activity |
| TCP Monitoring | 🟢 | Monitor TCP traffic |
| UDP Monitoring | 🟢 | Monitor UDP traffic |
| Source IP | 🟢 | Display packet source |
| Destination IP | 🟢 | Display packet destination |
| Source Port | 🟢 | Display source ports |
| Destination Port | 🟢 | Display destination ports |
| TCP Flags | 🟢 | Display TCP flags |
| Packet Counters | 🟢 | Runtime packet statistics |
| DNS Counters | 🟢 | Runtime DNS statistics |
| Connection Counters | 🟢 | Runtime connection statistics |
| Live Events | 🟢 | Display events in real time |
| Event History | 🟢 | Maintain recent runtime events |
| Top Domains | 🟢 | Display frequently observed domains |
| Color Terminal UI | 🟢 | Color-coded terminal interface |
| Administrator Detection | 🟢 | Detect Windows administrator privileges |
| Port Scan Detection | 🟡 | Planned |
| DNS Anomaly Detection | 🟡 | Planned |
| Connection Burst Detection | 🟡 | Planned |
| Security Rules | 🟡 | Planned |
| SQLite Storage | 🟡 | Planned |
| CSV Export | 🟡 | Planned |
| JSON Export | 🟡 | Planned |
| Historical Search | 🟡 | Planned |
| Network Topology | 🟡 | Planned |
| Web Dashboard | 🟡 | Planned |
| HTTPS Decryption | 🔴 | Not provided |
| HTTPS Bypass | 🔴 | Not provided |
| DoH Bypass | 🔴 | Not provided |
| DoT Bypass | 🔴 | Not provided |
| Credential Collection | 🔴 | Not provided |
| Authentication Bypass | 🔴 | Not provided |

### Status

🟢 Available

🟡 Planned

🔴 Intentionally not provided

---

# Dashboard

NetScope provides a terminal-based dashboard designed to keep important network information visible without unnecessary clutter.

Example:

```text
╔══════════════════════════════════════════════════════════════╗
║                         NETSCOPE                             ║
║              REAL-TIME NETWORK MONITOR                       ║
╚══════════════════════════════════════════════════════════════╝

STATUS

Interface       Wi-Fi
Local IP        192.168.1.20
Capture         LIVE
Packets         18,421
DNS Queries     213
Connections     1,204
Devices         7


CONNECTED DEVICES

IP              HOSTNAME              MAC
──────────────────────────────────────────────────────────────
192.168.1.1     router                XX:XX:XX:XX:XX:XX
192.168.1.20    workstation           XX:XX:XX:XX:XX:XX
192.168.1.24    phone                 XX:XX:XX:XX:XX:XX


LIVE NETWORK ACTIVITY

TIME      TYPE   DEVICE       DESTINATION       DOMAIN
──────────────────────────────────────────────────────────────
22:31:04  DNS    phone        8.8.8.8           google.com
22:31:09  TCP    phone        142.250.x.x        -
22:31:14  DNS    laptop       1.1.1.1            github.com
