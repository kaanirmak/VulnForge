# VulnForge — tüm iş listesi

29 Ekim 2026 güncellemesi. Kaynak: teknik tasarım belgesi, mevcut çalışma ağacı, gereksinim raporu ve kaynak kodunun müşteri ortamında kalmasını sağlayacak bağlantı modeli.

İşaretli maddeler aşağıdaki kanıt kapsamıyla tamamlandı; boş kutular açık işlerdir. İşaretler bütün ürünün veya canlı ortamın hazır olduğu anlamına gelmez. Öncelikler: P0 gerçek özel repolu kullanıcı almadan önce; P1 ürün pilotunu tamamlamak için; P2 sonraki ürün fazları. Görev grupları arasında bağımlılıklar vardır; numara sırası tek başına uygulama sırası değildir.

## Mevcut temel

Yerelde mevcut: imzalı webhook ve transaction/dedup, kuyruk/worker, SHA'ya bağlı tarama ve kapsama kayıtları, temel AST/regex scanner, OSV sorguları, desteklenen GitHub sürüm aralıkları, advisory→proje etkisi, doğrulanan güncelleme adayları, temel dashboard, SBOM/SARIF çıktıları, süreli suppression ve bulgu geçmişi. Gizlilik kapıları, PostgreSQL/migration ve identity temeli de eklendi. Son doğrulama: Python 3.11 + geçici gerçek PostgreSQL 14.23 ile 664 test geçti; GitHub/OSV çağrıları mock, canlı sağlayıcı kabul testi yapılmadı.

## A. Gizlilik ve güvenlik tasarımı — P0

- [x] VF-001: Varsayılan modeli netleştir: kod müşteri koşucusunda, servisimizde yalnız izin verilen metadata.
- [x] VF-002: Yönetilen sunucu taramasını ayrı ve açık onay gerektiren seçenek olarak tasarla.
- [x] VF-003: GitHub izinlerini modlara göre ayır; içerik okuma ve yazma erişiminin ayrı entegrasyon/kurulum gereksinimini belirle.
- [x] VF-004: Hangi verinin hangi servise gittiğini gösteren veri akışı ve tehdit modeli oluştur.
- [x] VF-005: Rapor yüklemelerinde alan allowlist'i uygula; kaynak, diff, dosya içeriği ve sır taşıyan ek alanları reddet.
- [x] VF-006: Paket adı, sürüm, dosya yolu ve bulgular için hassasiyet/maskeleme kuralları belirle.
- [x] VF-007: OSV dahil dış servislere gönderilen metadata için açık bildirim, izin ve özel paket engelleme politikası ekle.
- [x] VF-008: Dışa veri çıkışı kapalı/self-hosted istihbarat seçeneğinin sözleşmesini tasarla.
- [x] VF-009: Saklama süresi, silme, yedeklerden silinme ve bağlantı kaldırma politikalarını tanımla.
- [x] VF-010: Güvenlik/gizlilik metinlerini gerçek uygulamayla uyumlu yaz; lisans ve veri kaynağı kullanım şartlarını değerlendir.

## B. Hesaplar, yetkiler ve veri ayrımı — P0

- [x] VF-011: PostgreSQL şemasını ve sürümlü migration altyapısını oluştur; SQLite verisini taşıma yolunu test et.
- [x] VF-012: Kullanıcı, organizasyon, üyelik ve repo sahipliği modelini oluştur.
- [ ] VF-013: GitHub ile giriş; state, callback doğrulaması ve uygulanabilir güvenli OAuth kontrollerini ekle.
- [ ] VF-014: Güvenli oturum, çıkış, süre sonu, CSRF ve cookie kontrollerini ekle.
- [x] VF-015: Org Admin, Maintainer, Analyst, Viewer/Auditor rollerini uygula.
- [x] VF-016: Repo, scan, finding, impact, öneri ve export sorgularını organizasyon kapsamına bağla.
- [x] VF-017: Veritabanında RLS veya eşdeğer izolasyon uygula; uygulama bağlantısının korumayı aşmasını engelle.
- [x] VF-018: Kuyruk işleri, cache, dosyalar ve arka plan görevlerinde aynı organizasyon sınırını uygula.
  Bağlantı/organizasyon anlık görüntüsü, claim fencing, iptal sonrası yazma engeli, repo/scan kapsamlı worker arayüzü, iş başına istemci/cache, repo sınırlı GitHub token isteği, ayrı kısıtlı PostgreSQL `WorkerStore` DB rolü + iş kanıtı RLS politikaları ve organizasyon-bazlı (`org:<org_id>`) özel advisory katalog namespace'i tamamlandı. [Alt kontrol listesi ve kanıt](QUEUE_ISOLATION_TR.md).
- [ ] VF-019: Davet, üyelikten çıkarma ve repo erişimi kaybında oturum/yetkiyi güncelle.
- [x] VF-020: Ortak admin token'ını müşteri akışından kaldır; ayrı ve denetlenen operatör erişimi oluştur.

## C. GitHub bağlantısı ve kurulum deneyimi — P0

- [x] VF-021: Uygulama kaydı/manifestini ve yalnız gereken GitHub izinlerini hazırla.
- [ ] VF-022: Herkese açık App kurulumu, alan adı, HTTPS ve webhook adreslerini yapılandır.
- [ ] VF-023: Panelde GitHub ile giriş ve Proje bağla akışını oluştur.
- [ ] VF-024: Kurulum dönüşünü oturum ve kurulum yetkisiyle doğrula; rastgele installation_id ile hesap bağlanmasını engelle.
- [ ] VF-025: Kullanıcının erişebildiği kurulum ve repoları listele; repo seçimi/senkronizasyonu ekle.
- [x] VF-026: Kullanıcıya istenen izinleri, tarama modunu ve veri paylaşımını onay öncesinde göster.
- [ ] VF-027: İlk tarama/ilk envanter akışını kur; bekleyen ve hatalı kurulum durumlarını göster.
- [ ] VF-028: Repo ekleme/çıkarma, uninstall, suspend/unsuspend ve yetki değişimini uzlaştır.
- [x] VF-029: Süresi kısa, repo/izin kapsamı daraltılmış installation token kullanımını uygula.
- [x] VF-030: İlk/silinecek dal, force-push, büyük push ve kaçırılan teslimatları backfill ile uzlaştır.

## D. Müşteri ortamında tarama ve GitHub Action — P0

- [x] VF-031: Kaynak kodu çalıştırmadan analiz eden tekrar kullanılabilir scanner CLI çıkar.
- [ ] VF-032: CLI'ı çalıştıran GitHub Action ve kuruluma hazır workflow şablonları oluştur.
- [ ] VF-033: Push/PR, varsayılan dal ve zamanlanmış tarama profillerini ekle.
- [ ] VF-034: İlk kurulumda geçmiş/snapshot kapsamını açıkça göster; eksik envanteri geçerli baseline sayma.
  Snapshot/geçmiş ve tazelik API/ekran/export uyarıları eklendi; ilk kurulum ve müşteri baseline promotion kabulü açık. [Kanıt sınırı](EVIDENCE_FRESHNESS_TR.md).
- [ ] VF-035: Sonuç yüklemek için OIDC doğrulaması veya eşdeğer kısa ömürlü kimlik mekanizması kur.
  Kriptografik doğrulama, metadata-only App kontrolü, yerel policy/API/client ve reusable workflow şablonu eklendi; gerçek sağlayıcı/kurulum kabulü bekliyor. [Kod, kanıt ve sınırlar](RUNNER_IDENTITY_TR.md).
- [ ] VF-036: Yüklemede repo, organizasyon, SHA, workflow kimliği, güvenilen workflow ref'i ve izin kapsamını doğrula; beyanı tek başına kanıt sayma.
- [x] VF-037: Fork PR ve güvenilmeyen workflow kodunun sır/ayrıcalıklı yükleme yetkisi almasını engelle.
- [x] VF-038: Sürümlü sonuç şeması, boyut limitleri, kaynak/sır reddi ve tekrar yükleme dedup'u ekle.
- [ ] VF-039: Action/CLI bağımlılıklarını sabitle; değişmez sürüm referansları, checksum ve dağıtım kanıtı üret.
- [x] VF-040: İptal, timeout ve hata sonrasında geçici veriyi temizle; müşterinin kendi koşucusunu destekle.

## E. Tarama motoru ve gerçek bağımlılık envanteri — P1

- [ ] VF-041: Semgrep adapter'ını ekle; güvenilen kural paketini ve araç sürümünü sabitle.
- [ ] VF-042: Gitleaks adapter'ını ekle; sır değerlerini bulgu, log ve export'lardan çıkar.
- [x] VF-043: Scanner sonuçlarını ortak bulgu/fingerprint şemasına normalize et.
- [x] VF-044: PR base/head karşılaştırmasıyla yeni ve önceden mevcut bulguları ayır.
- [ ] VF-045: Python için extras/marker/include ve çözümlenmiş dolaylı bağımlılıkları güvenilir biçimde envantere al.
- [ ] VF-046: npm workspaces/alias/link, pnpm ve Yarn kilit dosyalarını destekle.
- [ ] VF-047: Go build listesi, Rust workspace/git ve Composer paket kaynaklarını doğru ayır; çözümleyicileri yalnız izole ortamda çalıştır.
- [ ] VF-048: Doğrudan/dolaylı, runtime/dev, dependency edge ve commit/digest kanıtlarını modele ekle.
- [ ] VF-049: CycloneDX/SARIF çıktısını resmi şemalarla doğrula; gerekli SPDX/VEX ve envanter farkı çıktısını ekle.
- [ ] VF-050: Her parser/kural için pozitif-negatif fixture; büyük/bozuk dosya, symlink, submodule ve kapsam testlerini genişlet.

## F. Yeni açık takibi, etki ve sürüm önerileri — P1

- [ ] VF-051: Ayrı advisory ingestion görevi oluştur; kaynak cursor'u, tekrar ve kesinti sonrası devamı kalıcı tut.
- [x] VF-052: GHSA değişiklik/withdrawal akışını uzlaştır; OSV ile alias ve revision geçmişini ilişkilendir.
- [ ] VF-053: NVD/CVSS ve EPSS kaynaklarını ekle; KEV ile birlikte kaynak/zaman/hash kanıtını koru.
- [x] VF-054: Eksik veya eski envanter ile eski istihbaratı görünür yap; güvenli sonuç veya güncel öneri olarak sunma.
- [ ] VF-055: Ekosisteme uygun sürüm karşılaştırmalarını genişlet; desteklenmeyen aralığı unknown tut.
- [ ] VF-056: Yeni açık→paket→proje→snapshot ilişkisini sürümlü geçmişiyle sakla.
- [ ] VF-057: Önerilen sürümün gerçekten yayımlandığını ve yank/deprecation durumunu paket kaydından doğrula.
- [ ] VF-058: Constraint, parent bağımlılık, override ve major geçiş gereksinimini öneriye ekle.
- [ ] VF-059: CVSS severity ile müdahale önceliğini ayır; KEV/EPSS, ortam ve exposure üzerinden açıklanabilir politika uygula.
- [ ] VF-060: Düzeltme olmayan açıklar için mitigasyon, yeniden kontrol ve sahip/SLA takibi oluştur.

## G. Güvenli düzeltme ve PR — P1

- [x] VF-061: Repo bazlı düzeltme politikası ve açık opt-in ekle; otomatik birleştirmeyi kapalı tut.
- [x] VF-062: Paket, mevcut/hedef sürüm, baseline SHA, izinli dosyalar ve gerekli kontrollerle patch planı üret.
- [ ] VF-063: Python ve npm yamalarında manifest/lockfile'ı gerçek paket yöneticisiyle yeniden çözümle.
- [ ] VF-064: Secret içermeyen, geçici, ağ/dosya/CPU/bellek/süre sınırları olan izole koşucu kur; yönetilen taramalarda da uygula.
- [ ] VF-065: Unit, integration, build, SAST/SCA tekrar taraması ve envanter farkını kanıt olarak kaydet.
- [ ] VF-066: Eksik/başarısız doğrulama, riskli dosya, major geçiş ve değişmiş HEAD durumlarında yayını durdur.
- [ ] VF-067: İnsan onayını kullanıcı, repo, SHA ve diff'e bağla; içerik değişince onayı geçersizleştir.
- [ ] VF-068: Draft PR'a advisory, pre/post sonuçlar, testler ve bilinmeyen riskleri ekle.
- [ ] VF-069: Branch/PR oluşturma retry'sında mevcut işi uzlaştır; duplicate PR ve insan değişikliğinin üzerine yazmayı engelle.
- [ ] VF-070: Merge sonrası yeniden tarama, başarısızlıkta geri alma PR'ı ve bulgu kapanış kanıtı ekle.

## H. Kullanıcı paneli, bildirimler ve API — P1

- [ ] VF-071: Organizasyon/repo seçimi, kurulum durumu ve ilk kullanım ekranlarını tamamla.
- [ ] VF-072: Proje risk özeti, son tarama, kapsam, istihbarat tazeliği ve bağlantı sağlığını göster.
- [ ] VF-073: Bulgu detayında kanıt, advisory, paket grafı, SHA, geçmiş ve güncelleme alternatiflerini göster.
- [ ] VF-074: Etkilenen projeler ve öneriler ekranına sahip atama, toplu filtre ve geçmiş karşılaştırması ekle.
- [x] VF-075: False positive, kabul edilen risk ve süreli suppression işlemlerini rollere bağla.
- [ ] VF-076: Onay bekleyen, doğrulanan, engellenen ve yayımlanan düzeltmeleri ayrı göster.
- [ ] VF-077: Kullanıcıların ayarlayabildiği e-posta/Slack/Teams bildirim entegrasyonları oluştur.
- [ ] VF-078: Bildirim dedup'u, toplulaştırma, kritik risk escalation'ı ve hassas içerik filtrelerini uygula.
- [ ] VF-079: API'leri tutarlı v1 şeması, filtreler, cursor, hata kodu, request ID ve mutation idempotency ile tamamla.
- [ ] VF-080: Mobil/erişilebilir kullanım, boş/hata/expired-session durumları ve gizlilik/bağlantı silme ayarlarını tamamla.

## I. Altyapı, sırlar ve işletim — P0 temel / P1 ölçek

- [ ] VF-081: Geliştirme, staging ve production ortamlarını hesap/anahtar/veri bakımından ayır.
- [ ] VF-082: TLS, ağ sınırları, güvenli ingress, limitler ve veritabanının özel ağ erişimini kur.
- [ ] VF-083: GitHub anahtarı ve sırları kasaya taşı; gereksiz API/worker/container erişimini kaldır, rotasyonu test et.
- [ ] VF-084: Veri ve yedek şifrelemesi, anahtar erişimi ve müşteri veri silme görevlerini uygula.
- [ ] VF-085: Audit'i aktör/organizasyon/repo/iş kimliğiyle genişlet; log maskeleme ve operatör erişimini denetle.
- [x] VF-086: Kuyruk lease yenileme/sahiplik kontrolü, stale-worker engeli, retry/backoff ve dead-letter akışını kur.
- [ ] VF-087: Organizasyon başına eşzamanlılık, API/scan kotası, adil iş dağıtımı ve kötüye kullanım sınırları ekle.
- [ ] VF-088: Event→job→scan→finding→PR korelasyonu; kuyruk yaşı, tarama süresi, kaynak hatası ve freshness metriklerini ekle.
- [ ] VF-089: Yedek/geri yükleme tatbikatı, RPO/RTO, dağıtım rollback'i ve felaket kurtarma runbook'u hazırla.
- [ ] VF-090: Anahtar sızıntısı, yetkisiz erişim, feed kesintisi, PR spam ve güvenlik olayı müdahale/alarm akışlarını hazırla.

## J. Doğrulama ve ilk yayın — P0/P1 yayın kapıları

- [ ] VF-091: Mevcut çalışma ağacı değişikliklerini gözden geçir, tekrarlanabilir bağımlılık/CI düzenine al ve sürümle.
- [ ] VF-092: İki ayrı müşteriyle çapraz hesap/rol/repo/scan/export/queue erişim testlerini çalıştır.
- [ ] VF-093: Müşteri koşucusu trafiğini incele; kaynak/sır/log sızıntısı olmadığını negatif payload testleriyle doğrula.
- [ ] VF-094: Canlı kontrollü repolarda kurulum→ilk scan→push/PR→yeni advisory→öneri→uninstall kabul testini çalıştır.
- [ ] VF-095: Resolver/build sandbox'ını kaçış, egress, secret erişimi ve kaynak tüketimi bakımından test et.
- [ ] VF-096: Webhook redelivery, force-push, branch değişimi, rate limit, crash ve iptal hata senaryolarını doğrula.
- [ ] VF-097: Yük/kapasite ve false-positive ölçümlerini yap; gerçek pilot verisiyle SLO ve alarm eşiklerini belirle.
- [ ] VF-098: Bağımsız güvenlik incelemesi ve yetkilendirilmiş penetrasyon testi yaptır; kritik bulguları kapat.
- [ ] VF-099: App/Action kurulumu, izin açıklamaları, müşteri koşucusu, kaldırma ve sorun giderme belgelerini tamamla.
- [ ] VF-100: Kapalı pilot, kabul raporu, destek süreci ve genel yayın kontrolünü tamamla; dış yayımlama adımlarını somut çıktı üzerinden ayrıca onaylat.

## K. Sonraki ürün fazları — P2

- [ ] VF-101: GitLab adapter'ı, OAuth/webhook ve MR/Pipeline entegrasyonu ekle.
- [ ] VF-102: Kurumsal OIDC/SSO ve gerekiyorsa otomatik kullanıcı/üyelik yönetimi ekle.
- [ ] VF-103: Self-hosted/on-prem kurulum paketini ve dışa kapalı çalışma modunu tamamla.
- [ ] VF-104: Java/.NET ve diğer ekosistemler, container/image SBOM ve provenance kapsamını genişlet.
- [ ] VF-105: Kanıta dayalı reachability ve runtime exposure sinyalleri ekle.
- [ ] VF-106: Açık izinli, varsayılan kapalı LLM triage/patch; yerel ve uzaktaki model seçeneklerini değerlendir.
- [ ] VF-107: Modelden bağımsız tool/policy gate, yapılandırılmış çıktı ve prompt-injection/exfiltration değerlendirme seti kur.
- [ ] VF-108: Tüm CI, policy, güncel SHA ve onay kapıları tamamlandıktan sonra dar kapsamlı koşullu automerge pilotu değerlendir.
- [ ] VF-109: Kullanım/plan limitleri, bütçe görünürlüğü ve gerekiyorsa ödeme/faturalandırma ekle.
- [ ] VF-110: Veri bölgesi, ayrı müşteri ortamı/anahtarı ve kurumsal denetim/uyumluluk ihtiyaçlarını ürünleştir.

## Bağımlılık ve çıkış kapıları

- İlk sıra: VF-001–010 ile veri paylaşımı kararı → VF-011–020 ile hesap/organizasyon sınırı → VF-021–040 ile güvenli kurulum ve müşteri koşucusu. Bunlarla birlikte VF-081–085 ve ilgili VF-092–094 güvenlik kontrolleri gerekir.
- Kaynak erişimi verilmeyen modun kabulü: VulnForge App'in içerik okuma izni olmadan kurulum yapılır; kullanıcı koşucusu yalnız şemaya uyan metadata yükleyebilir; yanlış müşteri/repo/SHA/workflow raporu ve kaynak içeren payload reddedilir. Bağımlılık metadata'sının dış kaynağa çıkışı da belirtilen politikaya uyar.
- Özel repolu pilotun kapısı: hesap/rol/tenant izolasyonu, anahtar yönetimi, veri sınırı, canlı kurulum ve kaldırma kabul testleri tamamlanır. İzole doğrulama hazır olmadan otomatik patch/build çalıştırılmaz.
- Düzeltme PR'ının kapısı: VF-061–069; başarısız veya eksik test hiçbir zaman geçmiş sayılmaz. Salt öneri özelliği bunlar bitmeden de insan incelemesi için sunulabilir.
- Genel yayın: ilgili P0 görevleri, canlı kabul, silme/rotasyon/geri yükleme ve güvenlik incelemesi sonuçlanır. VF-101–110 ilk pilotun zorunlu ön koşulları değildir.
- Her görev ancak gerekli kod, anlamlı doğrulama, yetki/veri etkisi ve ilgili dokümantasyon birlikte tamamlandığında kapatılır. Canlı kanıt gerektiren görevler mock testle kapatılmaz.

## Tamamlanma kanıtları — 29 Ekim 2026

**33/110 madde tamamlandı (VF-001–012, VF-015–018, VF-020/021/026/029/030/031/037/038/040/043/044/052/054/061/062/075/086).** Bu sayı iş maddesi sayımıdır; ürünün hazır olma oranı veya bütün güvenlik kontrollerinin tamamlandığı iddiası değildir. Sıradaki açık iş **VF-013: GitHub ile giriş**. VF-013/014 kodu ve 40 auth protokol testi eklendi; gerçek GitHub App callback kabulü beklediği için kutuları açık kaldı. [Kurulum ve kanıt](GITHUB_LOGIN_TR.md). Kullanıcı HTTPS adresinin henüz olmadığını bildirdi. İlk gerçek OAuth/bağlantı testi iki loopback callback ile yapılabilir; public üretim kurulumu HTTPS bekler. [Yerel hazırlık](USER_NEXT_STEPS_TR.md). Bu dış bağımlılığı beklerken bağımsız VF-015/016 API kontrolleri yerel önizleme kapsamında tamamlandı. VF-017 ve VF-018, ayrı non-owner runtime hesapları (`customer`, `operator`, `worker`), PostgreSQL RLS ve organizasyon-bazlı özel advisory katalog namespace'i ile tamamlandı. Toplu uygulama ile VF-018/020/021/026/029/030/031/037/038/040/043/044/052/054/061/062/075/086 tamamlandı; VF-019, Action dağıtımı ve müşteri paneli gibi diğer maddelerde kısmi ilerleme var. [Toplu çalışma kaydı](BATCH_PROGRESS_TR.md).

| İşler | Çıktı ve kanıt | Kapsam sınırı |
|---|---|---|
| VF-001–004 | [Gizlilik mimarisi/veri akışı/tehdit modeli](PRIVACY_ARCHITECTURE_TR.md), config/GitHub/worker erişim kapıları, anahtarsız default Compose + ayrı managed overlay | Varsayılan model ve opt-in uygulanır; canlı App izin ayrımı, Action ve müşteri kabul akışı VF-021–040'ta açık. |
| VF-005–006 | `runner_report.py`, JSON Schema v1, strict nested allowlist, yol pseudonym'i, bilinen sır reddi, generic hata ve ayrı operatör karantinası; `test_privacy.py` | Şema güvenilir workflow veya gizli kanal engeli kanıtı değildir. Karantina baseline'a terfi edemez. |
| VF-007–008 | `privacy.py` metadata politikası; disabled/public/private OSV, tam allowlist, private deny, tüm-liste preflight; OSV/worker kapıları | Offline/private sözleşme hazır; mirror kurulum/ağ izolasyonu VF-082/103'te açık. |
| VF-009 | [Saklama/silme/yedek politikası](DATA_RETENTION_TR.md); mevcut uninstall temizliği ve testleri | Görev politika tanımıydı. TTL, tenant silme ve yedek silme otomasyonu VF-084/089'da açık. |
| VF-010 | [Teknik gizlilik taslağı](PRIVACY_NOTICE_DRAFT_TR.md), SECURITY/kurulum güncellemesi, [lisans/veri kaynağı değerlendirmesi](LICENSE_REVIEW_TR.md), kurulu paket envanteri | Ürün lisansı/yasal işletmeci seçilmedi; hukuki yayın onayı ve dağıtılan sürüm incelemesi VF-091/100'de açık. |
| VF-011 | [Veritabanı taşıma rehberi](DATABASE_MIGRATION_TR.md), iki dialect migration, checksum kontrolü ve SQLite→PostgreSQL aracı; gerçek DB aktarım/rollback/concurrency testleri | Migration/runtime rol ayrımı ve PostgreSQL RLS eklendi; HA ve üretim backup/restore tatbikatı tamamlanmadı. |
| VF-012 | [Identity modeli](IDENTITY_MODEL_TR.md), kullanıcı/org/üyelik/sahiplik tabloları; son admin ve repo sahiplenme kontrolleri | Kalıcı model tamamlandı; Giriş/oturum kodu yerelde test edildi, canlı kabulü açık; Yeni müşteri API önizlemesinde rol/org sınırı var; PostgreSQL DB ve worker sınırı eklendi; gerçek GitHub ownership doğrulaması açık. |

| VF-015–016 | [Rol ve organizasyon erişimi](ORGANIZATION_ACCESS_TR.md); deny-by-default matris, session/CSRF, org kapsamlı repo/finding/scan/impact/öneri/export/audit sorguları; 49 yeni iki-org API testi ve 2 gerçek PostgreSQL kabul testi | Yalnız loopback önizleme; müşteri kapısı default kapalı. PostgreSQL RLS ve runtime hesap ayrımı eklendi. Canlı OAuth ve gerçek kurulum sahipliği tamamlanmadı. |

| VF-017 | [PostgreSQL izolasyon rehberi](DATABASE_ISOLATION_TR.md), migration 004, FORCE RLS, ayrı customer/operator runtime, oturum kanıtı ve fail-closed rol/ACL kontrolleri; 44 yeni RLS/parser testi | Gerçek geçici PostgreSQL 14.23; non-superuser migration sahibi ve non-owner runtime'lar ile doğrulandı. SQLite RLS sunmaz; canlı kabul ve üretim altyapısı açık. |
| VF-018 | [Kuyruk ve worker izolasyonu](QUEUE_ISOLATION_TR.md), migration 005 + 011, `WorkerStore` (`--worker-role`), iş kanıtına bağlı PostgreSQL RLS, `org:<org_id>` özel advisory katalog namespace'i ve legacy karantina | Gerçek geçici PostgreSQL 14.23 ve non-superuser migration sahibiyle doğrulandı; dış ağ/container runtime ayrımı VF-064/081–083'te açık. |

Doğrulama: **664 test geçti, atlanan test yok**. Yeni `scripts/check.py --postgres` kendi geçici yerel PostgreSQL kümesini oluşturup testlerden sonra kapatıp temizledi. Mevcut test kümesi ayrıca kapatıldı. Wheel oluşturuldu; 22 SQL migration, iki HTML ekranı ve CLI giriş noktası kontrol edildi, paketten bağımsız SQLite/CLI açılışı doğrulandı. Action/workflow YAML ve iki ekranın JavaScript sözdizimi kontrol edildi. Müşteri ekranı yalnız sahte iki kuruluş verisiyle yerel tarayıcıda, filtre ve görünüm bakımından incelendi; bu canlı müşteri kabulü değildir. Suite'de bir üçüncü taraf Starlette/httpx deprecation uyarısı var. Hash kilitleriyle temiz kurulum, Docker build ve ağsız/read-only container açılışı geçti. Canlı GitHub/OSV, GitHub Action, trusted runner upload ve gerçek iki-müşteri kabulü açık kalır. Yayın yapılmadı. [Kurulum kanıtı](REPRODUCIBLE_SETUP_TR.md).

| Yeni tamamlananlar | Çıktı ve kanıt | Kapsam sınırı |
|---|---|---|
| VF-020 | `/account` ve `/operator` ayrımı; named operator credentials, sır içermeyen erişim audit'i ve 11 test | Global operatör yetkisi; merkezi sır kasası/MFA/immutable audit açık. |
| VF-021 | `github_app.py`: modlara ayrılmış izinlerle yerel kayıt hazırlığı ve HTTPS/policy testleri | Gerçek App, HTTPS ve kurulum kabulü VF-022–028/094. |
| VF-026 | Yerel proje bağlantısında Metadata read, customer-runner modu, hassas metadata ve kapalı kaynak/dış paylaşım/yazma kapıları onaydan önce gösterilir; sürümlü zorunlu consent, CSRF ve audit; 42 bağlantı testi ve tarayıcıda boş consent reddi | VF-023/024/025 canlı kabul, kurulum seçicisi ve sürekli uzlaştırma açık; diğer modlara izin vermez. [Protokol](PROJECT_CONNECTION_TR.md). |
| VF-029 | Bağlantı/claim kontrolü, repo daraltılmış token isteği, job-local cache temizliği, read-only worker yazma kapısı | Canlı token kabulü yapılmadı; fixture/provider sözleşmesi test edildi. |
| VF-030 | `github.py` `backfill_commits`/`reconcile_push`, silinen dal (`deleted`/`0000...`) invalidation + audit, force-push/büyük push/kaçırılan teslimat (`last_sha` takibi) backfill ve `push_reconciled` audit kaydı | Yönetilen modda `/commits` ve `/compare` backfill penceresi (`max_backfill=200`); canlı GitHub redelivery/force-push kabulü VF-096'da açık. |
| VF-031 | Kurulabilir offline CLI, güvenli descriptor-relative okuma, limits/coverage, metadata-only v1 çıktı | Temel AST/regex ve altı parser; Semgrep/Gitleaks/resolver ayrı açık işlerdir. |
| VF-040 | Kaynak kopyalamayan CLI/Action; atomik owner-only rapor, iptal/hata cleanup ve sınırlı cleanup komutu | POSIX customer runner; host crash/SIGKILL ephemeral-runner/retention gerektirir. |
| VF-043 | `scanner.py` `normalize_finding` / `compute_fingerprint` / `runner_fingerprint` / `to_runner_finding`: `code`, `dependency` ve `coverage` bulguları için ortak şema (`schema_version=1`), severity eşleme, secret maskeleme, `path_id` pseudonym ve deterministik SHA-256 fingerprint | Harici Semgrep/Gitleaks CLI adaptörleri VF-041/042'de açık. |
| VF-044 | `classify_pr_code_findings` / `classify_pr_dependency_findings`, PR `base_sha`/`head_sha` karşılaştırması (satır kaymasına dayanıklı `_line_sig` eşlemesi ve base manifest farkı), `diff_status` (`new` / `pre_existing` / `unknown`) ve GitHub Check sonucu/annotation ayrımı | Yönetilen PR tarama modunda base/head karşılaştırması; müşteri koşucusu PR profili canlı kabulü VF-033/094'te açık. |
| VF-052 | `save_advisory` / `advisory` çapraz kaynak (OSV/PYSEC/CVE ↔ GHSA) alias birleştirme, `identifiers` desteği, `_revisions` / `revision_count` geçmişi, geri çekme (`withdrawn`) ve daha yeni GHSA ile yeniden etkinleştirme uzlaştırması | Ayrı periyodik cursor tabanlı feed ingestion görevi VF-051'de açık. |
| VF-061 | Org Admin + CSRF ile connection-bound repo opt-in, exact paket/dosya allowlist; merge ve doğrulanmamış yayın engeli | Gerçek patch/build/test/approval/publication VF-063–070'te açık. |
| VF-062 | `remediation.py` `build_patch_plan` / `build_patch_plans`: paket, mevcut/hedef sürüm, `major`/`minor`/`patch` sınıfı, 40-hex baseline SHA, manifest SHA-256, izinli dosyalar ve zorunlu kontrollerle deterministik patch planı + audit kaydı | `publication_allowed=False`, `automerge_allowed=False`; izole paket yöneticisi/test koşucusu ve insan onayı VF-063–069'da açık. |
| VF-075 | `false_positive` (`finding.triage`: Org Admin/Maintainer/Analyst), `risk_accepted` (`finding.accept_risk`: Org Admin/Maintainer, zorunlu <= 366 gün süre sonu) ve `suppressed` (`finding.suppress`) uygulama + PostgreSQL RLS + UI/operator bağlantısı | Süresi dolan `risk_accepted` ve `suppressed` otomatik `open`'a döner; bildirim/SLA eskalasyonu VF-060/077–078'de açık. |
| VF-037–038 | [Koşucu kimliği ve karantina](RUNNER_IDENTITY_TR.md); PR/fork/dynamic/unknown workflow privilege reddi, v1 şema/1 MB/secret-source filtresi, canonical dedup/replay/conflict ve transaction kanıtı | Gerçek RSA/JWKS fixture ve yerel PostgreSQL; production intake ve baseline promotion kapalı; canlı kabul VF-035/036/094. |
| VF-054 | [Kanıt tazeliği](EVIDENCE_FRESHNESS_TR.md); 24 saat envanter/1 saat sorgu kanıtı, push/dal/revision invalidation, son başarısız/kısmi tarama, tarihsel öneri ve etkili durum; 59 yeni test | Gerçek geçici PostgreSQL, beş rol, API/export ve transfer; feed sync/cursor, canlı provider/kurulum, current HEAD ve release/test doğrulaması açık. |
| VF-086 | 60 saniye heartbeat/300 saniye lease, 1800 saniye timeout, retry/backoff/4 deneme, audited single-use dead-letter retry | Adalet/kota ve alarm işletimi VF-087/090'da açık. |

## Referanslar

- `REQUIREMENTS_COMPLIANCE_TR.md`: FR-001–FR-017 mevcut uygunluk durumu.
- `THREAT_INTELLIGENCE_TR.md`: şu an çalışan etki ve güncelleme önerisi akışı.
- Kullanıcının sağladığı `VulnForge_Tam_Teknik_Dokumantasyon.md`: hedef mimari ve ürün kapsamı. Buradaki görevler belgeyi ve konuşmada eklenen gizlilik modelini birlikte ele alır.
