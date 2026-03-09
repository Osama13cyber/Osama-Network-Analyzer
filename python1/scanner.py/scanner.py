import socket
import os
import pandas as pd
import requests
from flask import Flask, render_template, jsonify, send_file
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
SOFTWARE_NAME = "OSAMA NETWORK ANALYZER v2.0"

# Colors for CLI
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RESET = '\033[0m'

COMMON_PORTS = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}

def print_logo():
    logo = f"""{GREEN}
 ██████╗ ███████╗ █████╗ ███╗   ███╗ █████╗ 
██╔═══██╗██╔════╝██╔══██╗████╗ ████║██╔══██╗
██║   ██║███████╗███████║██╔████╔██║███████║
██║   ██║╚════██║██╔══██║██║╚██╔╝██║██╔══██║
╚██████╔╝███████║██║  ██║██║ ╚═╝ ██║██║  ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
      {CYAN}--- {SOFTWARE_NAME} ---{RESET}
      {YELLOW}Author: OSAMA | Status: READY{RESET}
    """
    print(logo)

def get_vendor(mac):
    try:
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
        return res.text if res.status_code == 200 else "Unknown Device"
    except: return "Generic"

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return COMMON_PORTS[port] if s.connect_ex((ip, port)) == 0 else None

def get_details(ip):
    with ThreadPoolExecutor(max_workers=10) as ex:
        ports = [p for p in ex.map(lambda p: scan_port(ip, p), COMMON_PORTS.keys()) if p]
    risk = "HIGH RISK" if any(x in ["FTP", "SMB"] for x in ports) else "SECURE"
    return ", ".join(ports) if ports else "No Ports", risk

@app.route('/')
def index():
    return render_template('index.html', name=SOFTWARE_NAME)

@app.route('/scan')
def scan():
    print(f"{YELLOW}[!] Scanning started...{RESET}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    target = ".".join(s.getsockname()[0].split('.')[:-1]) + ".0/24"
    
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2, verbose=False)[0]
    devices = []
    for _, r in ans:
        srv, risk = get_details(r.psrc)
        vendor = get_vendor(r.hwsrc)
        print(f"{GREEN}[+] Found: {r.psrc} ({vendor}){RESET}")
        devices.append({'ip': r.psrc, 'mac': r.hwsrc, 'vendor': vendor, 'services': srv, 'risk': risk})
    
    pd.DataFrame(devices).to_csv("osama_report.csv", index=False)
    return jsonify(devices)

if __name__ == '__main__':
    print_logo()
    app.run(debug=True, port=5000)