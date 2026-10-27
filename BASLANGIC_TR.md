# VulnForge — güncel yerel kurulum

27 Ekim 2026. Python **3.11 veya üzeri** gerekir. Uygulama geliştirme aşamasındadır; özel müşteri repolarına açık çok kullanıcılı hizmet olarak hazır değildir. [İş listesi](docs/TASKS_TR.md) gerçek ilerlemeyi gösterir.

## 1. Güvenli varsayılanla paneli aç

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,postgres]'
cp .env.example .env
python -c 'import secrets; print(secrets.token_hex(32))'
```

Son komutu her sır için ayrı çalıştır. `.env` içindeki `WEBHOOK_SECRET` ve `ADMIN_TOKEN` değerlerini bağımsız rastgele değerlerle doldur. Dosyayı ve sırları paylaşma. Başlangıçta GitHub özel anahtarı gerekmez.

```bash
set -a; source .env; set +a
uvicorn vulnforge.api:app --host 127.0.0.1 --port 8000
```

Müşteri ekranı `http://127.0.0.1:8000/account`, ayrı operatör konsolu `http://127.0.0.1:8000/operator` adresindedir. Operatör için adlandırılmış `OPERATOR_CREDENTIALS` kullan; eski yerel ADMIN_TOKEN müşteri kimliği değildir. Varsayılan `SCAN_MODE=customer_runner`, sunucunun GitHub kaynak erişimini kapatır. `INTELLIGENCE_MODE=disabled`, OSV sorgularını kapatır. Panel bu durumu gösterir. Çevrimdışı CLI ve yerel testli Action hazırlandı; değişmez dağıtım ve güvenilir sonuç kabulü henüz tamamlanmadı. [Kurulum ve sınırlar](docs/RUNNER_TR.md). Varsayılan kurulum otomatik proje taraması yapmaz. Operatör raporları ayrı token ile yalnız karantinaya alınır.

Standart Docker seçeneği `docker compose up --build -d`. Kaynak erişimi kapalıdır; anahtar dosyası bağlanmaz. Docker imajı bu geliştirmede canlı oluşturulup denenmedi. Panel localhost'a bağlıdır. Dış erişim için HTTPS, kimlik denetimi ve ağ sınırları ayrıca kurulmalıdır.

## 2. Kontrollü yönetilen tarama seçeneği

Repo sahibinin açık onayı varsa `.env` içinde birlikte ayarla:

```dotenv
SCAN_MODE=managed
ALLOW_MANAGED_SOURCE_ACCESS=true
MANAGED_SCAN_CONSENT_ID=owner-approval-2026-10-27
GITHUB_APP_ID=<managed-app-id>
GITHUB_PRIVATE_KEY_PATH=./private-key.pem
ENABLE_AUTO_PR=false
```

Onay referansı self-hosted operatör kaydıdır; müşteri kimliği veya kriptografik onay kanıtı değildir. Bu mod kaynak metnini sunucu belleğine alır. İzolasyon, tenant güvenliği ve anahtar kasası işleri tamamlanmadan genel müşteri hizmeti olarak açılmaz.

GitHub App oluştururken webhook URL `https://SENIN-HTTPS-DOMAININ/github/webhook`, secret `.env` içindeki `WEBHOOK_SECRET` olmalı. Managed App için **Metadata: read, Contents: read, Pull requests: read**, kullanılacaksa **Dependabot alerts: read**; olaylar `push`, `pull_request`, `installation`, `installation_repositories`, `dependabot_alert`, `security_advisory`. İsteğe bağlı Checks için **Checks: write** ve `ENABLE_CHECKS=true` gerekir. Uygulamanın gerçekten abone olabildiği olaylar/izinler canlı kurulumda ayrıca doğrulanacaktır.

Anahtarı `private-key.pem` olarak yerelde tut; Git'e ekleme. Müşteri koşucusu için tasarlanan metadata App bu Contents izinlerini istemeyecek; ayrı App kaydı ve kurulum doğrulaması henüz tamamlanmadı. Otomatik düzeltme için yazma izinlerini bu pilotun varsayılanına ekleme.

## 3. İstihbarat paylaşımını ayrıca aç

Public OSV'ye gönderilen bilgi paket adı, ekosistem ve sürümdür. Bunlar da hassas olabilir; tam onay listesi gerekir:

```dotenv
INTELLIGENCE_MODE=public_osv
ALLOW_EXTERNAL_PACKAGE_METADATA=true
OSV_ALLOWED_PACKAGES=PyPI:requests,npm:lodash
PRIVATE_PACKAGE_PATTERNS=PyPI:company-*,npm:@company/*
```

Örnekteki paketleri gerçek ve onaylı envanterle değiştir. Wildcard onay kabul edilmez; private engeli onaydan üstündür. Bir onaysız paket bile tüm sorgu grubunu ağ çağrısından önce durdurur. Onay hatası temiz tarama sayılmaz. Kendi OSV uyumlu HTTPS servisin için `INTELLIGENCE_MODE=private_osv` ve `OSV_API_URL` kullan; gerçek ağ izolasyonu ayrıca gerekir. Private advisory namespace tamamlanana kadar private_osv kuyruk taramaları kapalıdır. [Ayrıntılar](docs/PRIVACY_ARCHITECTURE_TR.md).

## 4. İşçiyi çalıştır

Aynı ortam ayarlarıyla ikinci terminalde:

```bash
source .venv/bin/activate
set -a; source .env; set +a
python -m vulnforge.worker
```

Managed taramada push/PR kaynak işleri açılır; bağımlılık kontrolü varsayılan **900 saniyede** sıraya alınır. Bu süre tamamlanma garantisi değildir. Customer runner modunda kaynak işleri engellenir; eski/manual dependency işi başarısız olarak görünür ve eski bulguları kapatmaz.

Compose ile managed modu için ayrıca `docker-compose.managed.yml` gerekir:

```bash
docker compose -f docker-compose.yml -f docker-compose.managed.yml up --build -d
```

Onay ayarları boşsa overlay başlamaz; anahtar yalnız worker'a bağlanır. Yerel API/worker aynı veritabanını kullanmalıdır. `DATABASE_URL` doluysa PostgreSQL, boşsa `DATABASE_PATH` ile SQLite seçilir. [Taşıma ve geri dönüş rehberi](docs/DATABASE_MIGRATION_TR.md).

## 5. Güncelleme önerilerinin sınırı

İmzalı advisory olayları ve etkin OSV kontrolleri paket/sürümü proje envanteriyle eşler. Panel önerileri insan incelemesi içindir; hedefin yayımlandığı, lockfile uyumluluğu ve build/test sonucu doğrulanmış değildir. `ENABLE_AUTO_PR=false` kalır. Repo bazlı opt-in olsa da izole doğrulama ve SHA/diff onayı tamamlanana kadar worker PR yayımlamaz. Otomatik merge veya üretime dağıtım yoktur. [Yeni açık ve proje etkisi](docs/THREAT_INTELLIGENCE_TR.md).

## 6. Doğrulama ve sonraki iş

```bash
python -m pytest -q
```

PostgreSQL testleri, yalnız özel olarak oluşturulmuş geçici yerel test kümesi sağlandığında çalışır; normal geliştirme çalıştırmasında atlanır. Kayıtlı doğrulamada gerçek geçici PostgreSQL dahil 301 test geçti. Canlı GitHub App/OSV, container kabulü ve iki müşteri arasındaki izolasyon henüz doğrulanmadı. VF-013/014 giriş ve oturum kodu eklendi; canlı callback kabulü beklediğinden işaretlenmedi. HTTPS adresi ve yerel OAuth ayarları için [giriş rehberini](docs/GITHUB_LOGIN_TR.md) kullan. VF-015/016 rol ve org sorgu kontrolleri yalnız [yerel API önizlemesinde](docs/ORGANIZATION_ACCESS_TR.md) tamamlandı; müşteri kapısı varsayılan kapalıdır. VF-017 PostgreSQL DB izolasyonu da tamamlandı; PostgreSQL önizlemesi için [ayrı hesap kurulumunu](docs/DATABASE_ISOLATION_TR.md) uygula. Worker/queue/cache izolasyonu hâlâ açık iş.

Toplu yerel doğrulama: geliştirme ve postgres bağımlılıkları kurulduktan sonra `python scripts/check.py --postgres`. Araç yalnız yeni geçici test kümesi kurar, bütün testleri çalıştırır ve kümeyi kapatıp temizler. [Operatör/davet/repo politikası](docs/ACCOUNT_OPERATIONS_TR.md), [kuyruk ve dead letter](docs/QUEUE_OPERATIONS_TR.md).
