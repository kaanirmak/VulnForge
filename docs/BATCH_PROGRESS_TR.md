# Toplu uygulama durumu — 29 Ekim 2026

İşler tek tek kullanıcı onayı beklenmeden bağlantılı gruplar halinde ilerletildi. **110 görevin tamamı bitmedi: 32 tamamlandı, 78 açık.** Kısmi kod veya mock test, canlı kabul ve bağımsız inceleme yerine tamamlanmış sayılmadı.

Önceki toplu grupta kapatılanlar: **VF-018, VF-020, VF-021, VF-026, VF-029, VF-030, VF-031, VF-037, VF-038, VF-040, VF-043, VF-044, VF-054, VF-061, VF-062, VF-075, VF-086**. Ayrıntılı tamamlanma kanıtları [ana listede](TASKS_TR.md).

27 Ekim grubunda **VF-037/038** kapatıldı: gerçek RSA/JWKS doğrulama kodu, metadata-only installation/repo kontrolü, connection-bound runner policy, canonical receipt/dedup/replay bariyeri, explicit-consent uploader ve reusable workflow yayın şablonu eklendi. 119 yeni testle toplam 522 test geçti. VF-035/036 canlı provider/installation kabulü ve baseline promotion açık; [protokol ve sınırlar](RUNNER_IDENTITY_TR.md).

28 Ekim devamında **VF-054** kapatıldı: eksik/eski envanter ve açık verisi, değişen varsayılan dal ve duyuru revision, etkili durum/öneri görünümü ve snapshot/geçmiş ayrımı API, ekran ve exportlarda uygulandı. 59 yeni testle toplam **581 test** geçti, skip yok. 009 migration ve beş PostgreSQL rolü doğrulandı. VF-034 ilk kurulum/baseline kabulü açık kaldı. [Politika ve sınırlar](EVIDENCE_FRESHNESS_TR.md).

| Çalışma grubu | Uygulanan çıktı | Hâlâ açık |
|---|---|---|
| Hesap/erişim | Hedef GitHub ID'ye bağlı hashed tek-kullanımlık davet, kabul/iptal, rol değişimi/üyelik silme, session revoke, son admin koruması | GitHub kişi/ekip/repo yetki değişimini doğrulanmış installation ile otomatik uzlaştırma; VF-019 tamamen kapatılmadı. |
| Operatör | Ayrı `/operator`, named credentials, erişim audit'i, sır içermeyen config/log | Merkezi secret store, MFA/SSO ve immutable audit. |
| GitHub | Modlara göre ayrı registration profilleri, kayıt hazırlama URL'si, repo/read daraltılmış job token ve cache temizliği | Oturuma bağlı metadata bağlantı önizlemesi ve ownership kontrolleri testli; gerçek App/callback, tam kurulum/repo seçicisi ve sürekli uzlaştırma açık. |
| Müşteri koşucusu | Offline CLI, metadata-only v1 rapor, symlink/submodule/limit kontrolleri, composite Action, push/default/schedule/PR profilleri, temp cleanup | Immutable yayın/bağımlılık hashes/provenance, üretim OIDC/installation kabulü, baseline promotion, canlı Actions kabulü. Yerel OIDC karantina protokolü uygulandı. Şablonlar aktif hale getirilmedi. |
| Kuyruk | Connection/claim fencing, guarded worker arayüzü, ayrı PostgreSQL `WorkerStore` (`--worker-role`) + iş kanıtı RLS, `org:<org_id>` özel advisory katalog namespace'i, heartbeat/timeout, backoff/deneme sınırı, audited dead-letter retry | Kota/adalet/metrikler (VF-087/088). |
| Düzeltme | Repo/bağlantı/Org Admin onayına bağlı exact allowlist; `build_patch_plans` ile baseline SHA + izinli dosya + hedef sürüm + zorunlu kontroller planı (VF-062); test/onay yoksa yayın kapalı; merge ve non-draft write reddi | İzole resolver/build/test, SHA+diff onayı, doğrulanmış PR retry ve merge sonrası kanıt (VF-063–070). |
| Panel | Yerel önizlemede org seçimi/rol, projeler, tarama/SHA, severity filtresi, bulgu ve etki/öneri; `false_positive`/`risk_accepted`/`suppressed` rol-bağlı triage (VF-075); boş/hata/expired-session durumları | Proje bağlama/kurulum, güvenilir rapor akışı, ayarlar, davet UI, approval UI, bildirimler ve tüm erişilebilirlik kabulü. |
| Doğrulama | 659 test, hash kilitli temiz kurulum ve Docker build/ağsız container açılışı; gerçek geçici PostgreSQL, yeni cluster oluştur/temizle komutu; CI'da DB testlerinin atlanmasını kaldıran akış; wheel/CLI/YAML/JS ve yerel mobil görünüm kontrolü | Son commit için uzak GitHub CI kabulü, gerçek provider/runner, yük/pilot/bağımsız inceleme. |

## Dış ortam veya karar gerektirenler

- HTTPS alan adı henüz yok; ilk gerçek login/bağlantı testi loopback callback ile yapılabilir. VF-013/014 canlı kabulü ve VF-022/094 public kurulum zinciri açıktır. GitHub client/App sırları sohbete alınmaz. Sahte üretim origin'i veya kurulum kanıtı oluşturulmadı.
- GitHub App izin onayı, gerçek repository/runner ve korumalı workflow ayarı gerekir. Yerel Action testini canlı koşucu kabulü olarak yazmadık.
- Staging/production hesapları, TLS/özel ağ, secret store, şifreli backup ve restore tatbikatı gerçek altyapı ve erişim gerektirir. Yerel dosya/konfigürasyon bunları kurulu hale getirmez.
- Bağımsız pentest/inceleme, iki gerçek müşteri pilotu, kapasite/false-positive ölçümü ve hukuki/operasyonel yayın kararları agent'ın kendi testleriyle kapanmaz.
- P2 ödeme/plan, kurumsal SSO, veri bölgesi ve compliance maddeleri için sağlayıcı/ürün kararları ve müşteri kabulü gerekir. Bunlar sessizce uydurulmadı veya kapsamdan çıkarılmadı.

## Kodda kalan ana gruplar

Kalanların hepsi dışarıya bağımlı değildir. Özellikle worker DB izolasyonu/private katalog (VF-018), installation/OIDC (VF-024–038), gerçek scanner/parser/graph (VF-041–050), feed cursor/freshness/registry önerileri (VF-051–060), doğrulanmış düzeltme (VF-062–070), panel/bildirim/API tamamlama (VF-071–080), işletim (VF-081–090) ve P2 ürün geliştirmeleri açık kod işleridir. Tam döküm ve bağımlılıklar ana listededir. Bu gruplar bitmeden `customer_ingestion_ready=false`, `tenant_isolation_ready=false` ve PR yayın kapısı kapalı kalır.

## Rehberler

[Koşucu/Action](RUNNER_TR.md), [hesap/operatör/repo politikası](ACCOUNT_OPERATIONS_TR.md), [kuyruk işletimi](QUEUE_OPERATIONS_TR.md), [GitHub giriş/kayıt](GITHUB_LOGIN_TR.md), [worker izolasyonu](QUEUE_ISOLATION_TR.md).

27 Ekim tarihsel Docker doğrulama kaydı: yerel motor 29.1.3'e erişildi; iki Compose profilinin statik config kontrolü geçti. `.dockerignore` yalnız uygulama ve pyproject build context'ine izin verir. Gerçek build, `python:3.12-slim` metadata adımında ilerlemediği için durduruldu; imaj/sandbox testi başarılı sayılmadı. Sorunun kök nedeni belirlenmedi. Yeni port/servis dışarıya açılmadı ve imaj yayımlanmadı.

## 28 Ekim son grup

VF-026 tamamlandı. Kuruluş oluşturma ve oturuma/CSRF/consent’e bağlı kaynak erişimsiz proje bağlantısı eklendi. OAuth user erişimi, repo admin, App/installation ve immutable repo/owner kimliği birlikte doğrulanır; source işi kuyruğa alınmaz. 010 private intent migration, 42 bağlantı ve 13 korumalı ayar kontrolü testi dahil temiz kilitli ortamda **642 test geçti, skip yok**. VF-023/024/025 gerçek provider, picker ve uzlaştırma kabulü açık kaldı.

Docker build bu grupta başarıyla tamamlandı; gözlenen base image digest’i sabitlendi. UID 10001, network none ve read-only kök ile yerel container açılışı geçti. Üç Compose profili statik doğrulandı. Bu, patch sandbox veya üretim kabulü değildir. İki yerel paket derlemesi aynı checksum’ı üretti; yayın/imza yapılmadı. [Kilitli kurulum](REPRODUCIBLE_SETUP_TR.md).

## 29 Ekim son grup

VF-018, VF-062 ve VF-075 tamamlandı:
- **VF-018**: `011_worker_isolation` migration'ları, `WorkerStore` (`python -m vulnforge.rls --worker-role <role>`, `WORKER_DATABASE_URL`), iş kanıtına (`vulnforge.job_id`, `vulnforge.claim_token`, `vulnforge.connection_id`, `vulnforge.organization_id`, `vulnforge.catalog_scope`) bağlı PostgreSQL FORCE RLS politikaları ve organizasyon-bazlı (`org:<organization_id>`) özel OSV katalog namespace'i ile legacy katalog karantinası tamamlandı.
- **VF-030**: İlk dal (`before=0000...`), silinen dal (`deleted`/`after=0000...`), force-push (`forced=true` / `diverged`), büyük push ve kaçırılan webhook teslimatı (`last_sha != before`) için `reconcile_push`/`backfill_commits`, kanıt invalidation ve `push_reconciled` audit akışı eklendi.
- **VF-043**: `scanner.py` içinde `normalize_finding`, `compute_fingerprint`, `runner_fingerprint` ve `to_runner_finding` ile `code`, `dependency` ve `coverage` bulguları ortak şemaya (`schema_version=1`), deterministik SHA-256 fingerprint'e ve `path_id` pseudonym'e bağlandı.
- **VF-044**: PR `base_sha`/`head_sha` karşılaştırması ile hem kod bulgularında (satır kaymasına dayanıklı `_line_sig` eşlemesi) hem bağımlılık bulgularında (`base_packages` farkı) `new` ve `pre_existing` ayrımı yapıldı; GitHub Check sonuçları ve annotation seviyeleri buna göre ayrıştırıldı.
- **VF-062**: `remediation.py` içinde `build_patch_plan` / `build_patch_plans` ile paket, mevcut/hedef sürüm, `major`/`minor`/`patch` sınıfı, 40-hex baseline SHA, manifest SHA-256, izinli dosya allowlist'i ve zorunlu kontrolleri içeren deterministik patch planı üretimi eklendi; `publication_allowed=False` ve `automerge_allowed=False` korundu.
- **VF-075**: `false_positive` (`finding.triage`: Org Admin, Maintainer, Analyst), `risk_accepted` (`finding.accept_risk`: Org Admin, Maintainer; <= 366 gün süre sonu zorunlu) ve `suppressed` (`finding.suppress`) işlemleri hem uygulama hem PostgreSQL RLS politikalarında rollere bağlandı.
- Doğrulama: SQLite + geçici gerçek PostgreSQL 14.23 üzerinde **663 test geçti, skip yok**.

Tam ürün hedefi [README](../README.md) ve [mimari](../ARCHITECTURE.md) içindedir. Kullanıcının şimdiki hazırlığı [GitHub App rehberi](USER_NEXT_STEPS_TR.md) ile sınırlıdır; açık kod görevleri kullanıcıya devredilmez.
