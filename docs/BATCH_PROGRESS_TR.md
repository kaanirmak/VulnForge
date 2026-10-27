# Toplu uygulama durumu — 27 Ekim 2026

İşler tek tek kullanıcı onayı beklenmeden bağlantılı gruplar halinde ilerletildi. **110 görevin tamamı bitmedi: 24 tamamlandı, 86 açık.** Kısmi kod veya mock test, canlı kabul ve bağımsız inceleme yerine tamamlanmış sayılmadı.

Önceki toplu grupta kapatılanlar: **VF-020, VF-021, VF-029, VF-031, VF-040, VF-061, VF-086**. Ayrıntılı tamamlanma kanıtları [ana listede](TASKS_TR.md).

Son devamda **VF-037/038** kapatıldı: gerçek RSA/JWKS doğrulama kodu, metadata-only installation/repo kontrolü, connection-bound runner policy, canonical receipt/dedup/replay bariyeri, explicit-consent uploader ve reusable workflow yayın şablonu eklendi. 119 yeni testle toplam 522 test geçti. VF-035/036 canlı provider/installation kabulü ve baseline promotion açık; [protokol ve sınırlar](RUNNER_IDENTITY_TR.md).

| Çalışma grubu | Uygulanan çıktı | Hâlâ açık |
|---|---|---|
| Hesap/erişim | Hedef GitHub ID'ye bağlı hashed tek-kullanımlık davet, kabul/iptal, rol değişimi/üyelik silme, session revoke, son admin koruması | GitHub kişi/ekip/repo yetki değişimini doğrulanmış installation ile otomatik uzlaştırma; VF-019 tamamen kapatılmadı. |
| Operatör | Ayrı `/operator`, named credentials, erişim audit'i, sır içermeyen config/log | Merkezi secret store, MFA/SSO ve immutable audit. |
| GitHub | Modlara göre ayrı registration profilleri, kayıt hazırlama URL'si, repo/read daraltılmış job token ve cache temizliği | Gerçek App/HTTPS, kurulum dönüşü/sahiplik, repo seçimi ve canlı callback. |
| Müşteri koşucusu | Offline CLI, metadata-only v1 rapor, symlink/submodule/limit kontrolleri, composite Action, push/default/schedule/PR profilleri, temp cleanup | Immutable yayın/bağımlılık hashes/provenance, üretim OIDC/installation kabulü, baseline promotion, canlı Actions kabulü. Yerel OIDC karantina protokolü uygulandı. Şablonlar aktif hale getirilmedi. |
| Kuyruk | Connection/claim fencing, guarded worker arayüzü, heartbeat/timeout, backoff/deneme sınırı, audited dead-letter retry | Ayrı job-scoped DB rolü, özel advisory namespace'i, kota/adalet/metrikler. |
| Düzeltme | Repo/bağlantı/Org Admin onayına bağlı exact allowlist; test/onay yoksa yayın kapalı; merge ve non-draft write reddi | İzole resolver/build/test, SHA+diff onayı, doğrulanmış PR retry ve merge sonrası kanıt. |
| Panel | Yerel önizlemede org seçimi/rol, projeler, tarama/SHA, severity filtresi, bulgu ve etki/öneri; boş/hata/expired-session durumları | Proje bağlama/kurulum, güvenilir rapor akışı, ayarlar, davet UI, triage/approval UI, bildirimler ve tüm erişilebilirlik kabulü. |
| Doğrulama | 522 test, gerçek geçici PostgreSQL, yeni cluster oluştur/temizle komutu; CI'da DB testlerinin atlanmasını kaldıran akış; wheel/CLI/YAML/JS ve yerel mobil görünüm kontrolü | GitHub CI'nın uzakta çalıştırılması, tam dependency lock, Docker, gerçek provider/runner, yük/pilot/bağımsız inceleme. |

## Dış ortam veya karar gerektirenler

- HTTPS alan adı henüz yok: VF-013/014 canlı kabulü ve VF-022/094 kurulum zinciri açıktır. GitHub client/App sırları sohbete alınmaz. Sahte üretim origin'i veya kurulum kanıtı oluşturulmadı.
- GitHub App izin onayı, gerçek repository/runner ve korumalı workflow ayarı gerekir. Yerel Action testini canlı koşucu kabulü olarak yazmadık.
- Staging/production hesapları, TLS/özel ağ, secret store, şifreli backup ve restore tatbikatı gerçek altyapı ve erişim gerektirir. Yerel dosya/konfigürasyon bunları kurulu hale getirmez.
- Bağımsız pentest/inceleme, iki gerçek müşteri pilotu, kapasite/false-positive ölçümü ve hukuki/operasyonel yayın kararları agent'ın kendi testleriyle kapanmaz.
- P2 ödeme/plan, kurumsal SSO, veri bölgesi ve compliance maddeleri için sağlayıcı/ürün kararları ve müşteri kabulü gerekir. Bunlar sessizce uydurulmadı veya kapsamdan çıkarılmadı.

## Kodda kalan ana gruplar

Kalanların hepsi dışarıya bağımlı değildir. Özellikle worker DB izolasyonu/private katalog (VF-018), installation/OIDC (VF-024–038), gerçek scanner/parser/graph (VF-041–050), feed cursor/freshness/registry önerileri (VF-051–060), doğrulanmış düzeltme (VF-062–070), panel/bildirim/API tamamlama (VF-071–080), işletim (VF-081–090) ve P2 ürün geliştirmeleri açık kod işleridir. Tam döküm ve bağımlılıklar ana listededir. Bu gruplar bitmeden `customer_ingestion_ready=false`, `tenant_isolation_ready=false` ve PR yayın kapısı kapalı kalır.

## Rehberler

[Koşucu/Action](RUNNER_TR.md), [hesap/operatör/repo politikası](ACCOUNT_OPERATIONS_TR.md), [kuyruk işletimi](QUEUE_OPERATIONS_TR.md), [GitHub giriş/kayıt](GITHUB_LOGIN_TR.md), [worker izolasyonu](QUEUE_ISOLATION_TR.md).

Docker doğrulama kaydı: yerel motor 29.1.3'e erişildi; iki Compose profilinin statik config kontrolü geçti. `.dockerignore` yalnız uygulama ve pyproject build context'ine izin verir. Gerçek build, `python:3.12-slim` metadata adımında ilerlemediği için durduruldu; imaj/sandbox testi başarılı sayılmadı. Sorunun kök nedeni belirlenmedi. Yeni port/servis dışarıya açılmadı ve imaj yayımlanmadı.
