# VulnForge — İlk Çalıştırma Kılavuzu

Bu paket VulnForge projesinin **v0.2.0 prototip kodudur**. Gerçek bir AI/LLM modeline bağlanmıyor; ilk aşamada deterministik güvenlik kuralları, GitHub API'si ve OSV güvenlik veri tabanını bir agent akışında birleştiriyor. Böylece daha büyük otonom güvenlik sistemi için test edilebilir bir temel sunuyor.

## 1. Bilgisayarda başlatma

Python 3.11 veya üzeri yüklü olmalı. Proje klasöründe terminal aç:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

`.env` içindeki `WEBHOOK_SECRET` ve `ADMIN_TOKEN` alanlarını farklı, rastgele değerlerle doldur. Her birini üretmek için:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Bir GitHub App oluşturmadan önce **sadece testleri ve dashboard'u** çalıştırabilirsin:

```bash
python -m pytest -q
uvicorn vulnforge.api:app --reload
```

Tarayıcıdan `http://127.0.0.1:8000` adresini aç. Admin token ile paneldeki verileri görebilirsin. Repolar eklenmeden önce tabloların boş olması normal.

## 2. GitHub App oluştur

GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.

- App adı: `VulnForge-Development` gibi hesabında benzersiz bir ad.
- Webhook URL: `https://SENIN-HTTPS-DOMAININ/github/webhook`.
- Secret: `.env` içindeki `WEBHOOK_SECRET`.
- Webhook olayları: `push`, `installation`, `installation_repositories`, `dependabot_alert`, `security_advisory`.
- Repository Permissions: **Contents: Read**, **Metadata: Read**, **Dependabot alerts: Read**. Otomatik taslak PR istiyorsan ek olarak **Contents: Read & Write**, **Pull requests: Read & Write**.

GitHub App'in ID'sini `GITHUB_APP_ID` olarak doldur. Uygulama için üretilen `.pem` özel anahtarını `private-key.pem` adıyla proje klasörüne koy. `.gitignore`, `.pem` dosyalarını Git'e göndermemek için ayarlıdır; bu anahtarı başka birine gönderme.

## 3. API ve Worker'ı aynı anda çalıştır

İki farklı terminalde aynı ortam değişkenleri yüklü olmalı:

```bash
# Terminal 1
set -a; source .env; set +a
uvicorn vulnforge.api:app --host 127.0.0.1 --port 8000

# Terminal 2
set -a; source .env; set +a
python -m vulnforge.worker
```

`uvicorn` GitHub olaylarını alıp kalıcı kuyruğa kaydeder. `worker` bu işleri işler. Her commit için ayrı tarama görevi oluşturulur. Varsayılan `SCAN_INTERVAL_SECONDS=3600` ile saatlik ek bağımlılık kontrolü yapılır.

GitHub'ın dış dünyadan webhook gönderebilmesi için yerel adresi doğrudan kullanamazsın. Bir HTTPS reverse proxy veya güvenli test tüneli kurman gerekir. Üretimde kimlik doğrulamalı erişim katmanı ve oran sınırlaması ekle.

## 4. Otomatik güncellemenin davranışı

Varsayılan `ENABLE_AUTO_PR=false`. Bu durumda sadece riskleri gösterir. True yaparsan **yalnızca `requirements.txt` dosyasındaki birebir sürüme sabitlenmiş Python paketleri** için, yeni sürüm OSV'de temiz görünüyorsa, **taslak** Pull Request oluşturur.

Şimdilik aşağıdakileri **yapmaz**: kodu production'a gönderme, otomatik merge, CI test sonucunu bekleyip merge etme, karmaşık kod refactoring, LLM ile sıfırdan exploit analizi.

## 5. Nereden geliştirmeye başlayacağız?

- `vulnforge/api.py` — GitHub webhook endpoint, HMAC kontrolü, admin API
- `vulnforge/worker.py` — olaylardan tarama işi oluşturma, agent akışı
- `vulnforge/github.py` — GitHub App kimlik doğrulama / commit ve PR işlemleri
- `vulnforge/dependencies.py` — bağımlılık sürüm ayrıştırma
- `vulnforge/osv.py` — CVE / GHSA / OSV veri sorgulama
- `vulnforge/scanner.py` — kod tarama kuralları
- `vulnforge/remediation.py` — güvenli sürüm güncelleme önerisi
- `tests/` — çevrimdışı birim ve entegrasyon testleri

**Önerilen sonraki sprint:** Semgrep + Gitleaks + CodeQL SARIF, CISA KEV & GHSA olay akışı, güvenlik puanlama, agent'a kontrollü LLM katmanı, geçici test ortamında doğrulama, GitHub Checks entegrasyonu.

## 6. Yeni yayınlanan güvenlik açıklarının takibi

GitHub'dan `security_advisory` webhook'u gelirse VulnForge, açıklanan paketi en son taramada oluşturduğu bağımlılık envanterinde arar. Eşleşen repolar için yeni OSV taraması sıraya eklenir. OSV gerçekten o sürümün etkilendiğini doğrularsa bulgu açılır ve `ENABLE_AUTO_PR=true` ise güvenli Python pin güncellemesi için taslak PR önerilir.

Bu olay tabanlı mekanizma bildirimin platform tarafından gönderilmesiyle çalışır; tüm dünyadaki her CVE için saniye bazında tespit garantisi değildir. GitHub dışındaki yeni güvenlik duyuruları saatlik tarama ile yakalanabilir.
