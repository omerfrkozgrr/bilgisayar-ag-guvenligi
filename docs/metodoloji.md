# Sızma Testi Metodoloji Notları

Bu belge projede izlenen sızma testi metodolojisini adım adım açıklar.
Gerçek bir pentest akışını akademik amaçlarla simüle etmektedir.

---

## Genel Akış

```
Planlama → Keşif → Tarama → Zafiyet Tespiti → Saldırı → Raporlama
```

---

## 1. Keşif (Reconnaissance)

### Pasif Keşif
Hedef hakkında dışarıdan, sisteme dokunmadan bilgi toplama.
Araçlar: WHOIS, Shodan, Google Dork, LinkedIn.

### Aktif Keşif
Sisteme doğrudan paket göndererek bilgi toplama.

**Ping Sweep:**
```bash
nmap -sn <ağ-aralığı>/24
```
Avantaj: Hızlı, düşük gürültü.  
Dezavantaj: ICMP engelliyse çalışmaz; TCP SYN'e geç.

**Servis/Sürüm Tespiti:**
```bash
nmap -sV --top-ports 1000 <ip>
```
`-sV` bayrağı, açık portlardaki servislerin sürümünü belirler.
Bu bilgi exploit seçiminde kritiktir.

**OS Tespiti:**
```bash
nmap -O <ip>
```
TCP/IP stack davranışına bakarak işletim sistemini tahmin eder.
%90+ güven oranı genellikle güvenilirdir.

**NSE Script Kullanımı:**
```bash
nmap --script http-headers,smb-security-mode <ip>
```
HTTP güvenlik başlıkları eksikliği (X-Frame-Options, CSP vb.)
doğrudan zafiyet göstergesidir.

---

## 2. Zafiyet Tespiti

### Kritik Port/Servis Değerlendirmesi

| Port | Servis | Risk Neden Yüksek? |
|------|--------|-------------------|
| 21 | FTP | Genellikle anonim giriş, clear-text |
| 23 | Telnet | Tüm trafik şifresiz, man-in-the-middle kolaylığı |
| 80 | HTTP | Yönetim paneli dış erişime açıksa kritik |
| 445 | SMB | EternalBlue gibi critik exploit'lere açık |
| 3306 | MySQL | Dışa açıksa direkt veritabanı erişimi |

### Telnet Analizi (Port 23)

Bu projede port 23, Nmap'te `tcpwrapped` göründü ancak bağlantı reddedildi.
Bu durum **ACL (Access Control List)** varlığına işaret eder — muhtemelen
yalnızca ISP yönetim IP'lerine izin verilmektedir.

Ancak bu yeterli değildir:
- ACL devre dışı bırakılabilir
- Protokol hâlâ clear-text iletişim kullanır
- Wireshark ile tüm oturum dinlenebilir

**Doğru çözüm:** Telnet'i tamamen kapat, SSH kullan.

---

## 3. Web Uygulama Saldırıları (OWASP Top 10)

### SQL Injection — Neden Çalışır?

```python
# Savunmasız kod (asla yapma)
query = "SELECT * FROM users WHERE id = " + user_input

# Güvenli kod — Prepared Statement
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```

Kullanıcı girdisi doğrudan SQL sorgusuna eklenince saldırgan
`' OR 1=1--` gibi yapılarla sorguyu manipüle edebilir.

**UNION SQLi adımları:**
1. Kolon sayısını tespit et (`ORDER BY N#`)
2. Hangi kolonların görünür olduğunu bul (`UNION SELECT 1,2,...#`)
3. Veritabanı bilgilerini çek (`database()`, `user()`, `version()`)
4. Tablo/kolon listesi al (`information_schema`)
5. Hedef veriyi çek

**Blind SQLi:** Doğrudan çıktı olmadığında TRUE/FALSE farkını gözlemle.

---

### XSS — Neden Tehlikeli?

```html
<!-- Reflected XSS — URL parametresinde -->
<input value="<script>alert(document.cookie)</script>">

<!-- Stored XSS — Veritabanına yazılıyor -->
<!-- Her sayfa yüklendiğinde tetiklenir, tüm kullanıcıları etkiler -->
```

**Etki zinciri:**
1. Script çalışır → `document.cookie` okunur
2. PHPSESSID ele geçirilir → Session hijacking
3. Saldırgan kurbanın oturumunu devralır

**Savunma:**
- Output encoding (`htmlspecialchars()` PHP'de)
- Content-Security-Policy header
- HttpOnly cookie flag

---

### CSRF — Form Olmadan İşlem

```
GET /change-password?new=hacked&confirm=hacked
```

Tarayıcı aynı oturumun cookie'lerini otomatik gönderir.
Kurban bu URL'ye tıklarsa şifresi değişir, farkında olmadan.

**Savunma:**
- CSRF token (her form isteğinde benzersiz, sunucu doğrular)
- `SameSite=Strict` cookie flag
- Referer header kontrolü

---

## 4. Güvenlik Duvarı Tasarımı

### Default-Deny Prensibi

```bash
# Önce her şeyi reddet
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Sonra sadece gerekenlere izin ver
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.X.0/24 -j ACCEPT
```

Bu proje `DROP` tabanlı kural seti kullandı. Gerçek üretim ortamında
**default-deny** politikası tercih edilmelidir.

### Loglama Zorunluluğu

Sessiz DROP: Saldırıyı engeller ama iz bırakmaz.

```bash
# Önce logla (syslog'a yazar)
iptables -A INPUT -p tcp --dport 23 -j LOG --log-prefix "TELNET: " --log-level 4

# Sonra düşür
iptables -A INPUT -p tcp --dport 23 -j DROP
```

Loglar olmadan:
- Saldırı fark edilmez
- Forensik analiz yapılamaz
- SLA/compliance gereksinimleri karşılanamaz

---

## 5. Raporlama

İyi bir pentest raporu şunları içermelidir:

1. **Yönetici özeti** — Teknik olmayan dil, genel risk durumu
2. **Metodoloji** — Hangi araçlar, hangi yöntemler
3. **Bulgular** — CVSS puanlı, önceliklendirilmiş
4. **Kanıtlar** — Ekran görüntüsü, komut çıktısı
5. **Öneriler** — Her bulgu için somut düzeltme adımı
6. **Etik beyan** — Test kapsamı ve izin belgesi

---

*Bu notlar yalnızca eğitim amaçlıdır. İzinsiz sistemlere uygulama yasaldışıdır.*
