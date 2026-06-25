"""
Bilgisayar Ağ Güvenliği — Final Projesi
Flask + python-nmap ile Canlı Ağ Tarama Sunucusu

Ömer Faruk Özgür — 22430070048
Bilişim Sistemleri ve Teknolojileri, 4. Sınıf
Mayıs 2026

Kullanım:
    pip install flask flask-cors python-nmap
    sudo python ag_tarama_server.py
"""

from flask import Flask, jsonify
from flask_cors import CORS
import nmap
import socket
import platform

app = Flask(__name__)
CORS(app)  # HTML sayfasının bu sunucuya erişebilmesi için


def get_local_ip():
    """Kendi IP adresini bul."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_range(ip):
    """IP'den /24 ağ aralığını hesapla."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ──────────────────────────────────────────
# Endpointler
# ──────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "status": "online",
        "mesaj": "Ağ Tarama Sunucusu Çalışıyor",
        "endpoints": ["/scan/hosts", "/scan/ports/<ip>", "/scan/full", "/info"]
    })


@app.route("/info")
def info():
    """Sunucu bilgileri."""
    local_ip = get_local_ip()
    return jsonify({
        "local_ip": local_ip,
        "network": get_network_range(local_ip),
        "platform": platform.system(),
        "nmap_version": nmap.PortScanner().nmap_version()
    })


@app.route("/scan/hosts")
def scan_hosts():
    """
    Ağdaki tüm aktif cihazları tara — ping sweep.

    Sırasıyla ICMP ping sweep, TCP SYN ve ARP yöntemlerini dener;
    ilk sonuç üreten yöntemde durur.
    """
    try:
        local_ip = get_local_ip()
        network = get_network_range(local_ip)

        nm = nmap.PortScanner()

        # 1) ICMP ping sweep
        nm.scan(hosts=network, arguments="-sn")

        # 2) Bulunamazsa TCP SYN
        if not nm.all_hosts():
            nm.scan(hosts=network, arguments="-sP")

        # 3) Hâlâ bulunamazsa ARP
        if not nm.all_hosts():
            nm.scan(hosts=network, arguments="-PR -sn")

        hosts = []
        for host in nm.all_hosts():
            info = nm[host]
            hosts.append({
                "ip": host,
                "hostname": info.hostname() or "",
                "status": info.state(),
                "mac": info.get("addresses", {}).get("mac", ""),
                "vendor": (
                    list(info.get("vendor", {}).values())[0]
                    if info.get("vendor")
                    else "Bilinmiyor"
                ),
            })

        return jsonify({
            "success": True,
            "network": network,
            "local_ip": local_ip,
            "host_count": len(hosts),
            "hosts": hosts,
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scan/ports/<ip>")
def scan_ports(ip):
    """
    Belirli bir IP'nin portlarını tara.

    En yaygın 100 porta servis/sürüm tespiti (-sV) uygular.
    Risk seviyesi: port numarasına göre basit üç kademeli sınıflandırma.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-sV --top-ports 100")

        if ip not in nm.all_hosts():
            return jsonify({"success": False, "error": "Host bulunamadı"}), 404

        host_info = nm[ip]
        ports = []

        for proto in host_info.all_protocols():
            for port in host_info[proto].keys():
                port_info = host_info[proto][port]
                ports.append({
                    "port": port,
                    "protocol": proto,
                    "state": port_info["state"],
                    "service": port_info["name"],
                    "version": port_info.get("version", ""),
                    "risk": (
                        "KRİTİK" if port in [21, 23]
                        else "YÜKSEK" if port in [80, 8080, 8443]
                        else "NORMAL"
                    ),
                })

        return jsonify({
            "success": True,
            "ip": ip,
            "hostname": host_info.hostname(),
            "os_guess": (
                host_info.get("osmatch", [{}])[0].get("name", "Bilinmiyor")
                if host_info.get("osmatch")
                else "Bilinmiyor"
            ),
            "port_count": len(ports),
            "ports": ports,
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scan/full")
def scan_full():
    """
    Tam tarama — host keşfi + port taraması bir arada.

    Önce ping sweep ile aktif hostları bulur, ardından her hostun
    en yaygın 100 portunu servis tespiti ile tarar.
    """
    try:
        local_ip = get_local_ip()
        network = get_network_range(local_ip)

        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments="-sn --send-ip")
        all_hosts = nm.all_hosts()

        nm2 = nmap.PortScanner()
        targets = " ".join(all_hosts)
        nm2.scan(hosts=targets, arguments="-sV --top-ports 100")

        result = []
        for host in all_hosts:
            host_data = {
                "ip": host,
                "vendor": (
                    list(nm[host].get("vendor", {}).values())[0]
                    if nm[host].get("vendor")
                    else "Bilinmiyor"
                ),
                "ports": [],
            }
            if host in nm2.all_hosts():
                for proto in nm2[host].all_protocols():
                    for port in nm2[host][proto].keys():
                        p = nm2[host][proto][port]
                        host_data["ports"].append({
                            "port": port,
                            "state": p["state"],
                            "service": p["name"],
                            "risk": "KRİTİK" if port in [21, 23] else "NORMAL",
                        })
            result.append(host_data)

        return jsonify({
            "success": True,
            "network": network,
            "local_ip": local_ip,
            "hosts": result,
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ──────────────────────────────────────────
# Başlatma
# ──────────────────────────────────────────

if __name__ == "__main__":
    local_ip = get_local_ip()
    banner = "=" * 52
    print(banner)
    print("  AĞ TARAMA SUNUCUSU BAŞLIYOR")
    print("  Ömer Faruk Özgür — 22430070048")
    print(banner)
    print(f"  Yerel IP   : {local_ip}")
    print(f"  Ağ Aralığı : {get_network_range(local_ip)}")
    print(f"  Sunucu URL : http://localhost:5000")
    print(banner)
    print("  Endpointler:")
    print("    GET /info               — Sunucu bilgileri")
    print("    GET /scan/hosts         — Aktif cihazları tara")
    print("    GET /scan/ports/<ip>    — Portları tara")
    print("    GET /scan/full          — Tam tarama")
    print(banner)
    app.run(host="0.0.0.0", port=5000, debug=False)
