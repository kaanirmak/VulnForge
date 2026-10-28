# VulnForge — teknik belgeye uygunluk ve geliştirme kaydı

Referans: `VulnForge_Tam_Teknik_Dokumantasyon.md`, 25 Ekim 2026 tarihli v1.0 tasarım belgesi. Değerlendirilen uygulama: bu çalışma ağacındaki 0.3.0 geliştirmeleri.

## Sonuç

**Belgenin tamamı karşılanmıyor.** Belge, mevcut MVP ile çok fazlı ürün hedeflerini açıkça ayırıyor. Kaynakta bir sınıfın veya API'nin bulunması, canlı GitHub kurulumu, üretim ölçeği, izolasyon veya güvenlik sertifikasyonu kanıtı değildir. Aşağıdaki durumlar kaynak incelemesi ve yerel birim/mock testleri içindir; canlı sağlayıcı kabul testi yapılmadı.

## Tehdit istihbaratı ek geliştirmesi

Yeni duyuru→proje etkisi ve güncelleme önerisi akışı eklendi: kalıcı advisory/alias/impact kayıtları, OSV ve desteklenen imzalı GitHub sürüm aralıkları, OSV'de tekrar kontrol edilen hedef sürümler, dashboard filtreleri ve manuel kontrol. Periyodik tarama aralığı 900 saniye; çalışması için managed kaynak erişimi ve OSV paylaşım politikası açıkça etkinleştirilmelidir. Varsayılan customer_runner/disabled modunda uçtan uca müşteri taraması henüz yoktur. [Gizlilik kapıları](PRIVACY_ARCHITECTURE_TR.md). [Özellik ve sınırlar](THREAT_INTELLIGENCE_TR.md). FR-006 için izlenebilir proje etkisi artık var; bağımsız tüm-feed ingestion/backfill ve canlı kabul testi hâlâ eksik. Öneri üretimi tam inventory gerektirmeden doğrulanmış paket gözleminden yapılabilir; otomatik PR kapıları aynı kalır.

GitHub giriş ve oturum kodu ayrıca eklendi: browser-bound tek kullanımlık state, S256 PKCE, sabit origin/callback ve süreli yerel oturum. Müşteri cookie'si operatör verilerine erişmez. Yerel önizleme API'si rol ve org kapsamını uygular; 49 iki-org API testi ve 2 gerçek PostgreSQL testi eklendi. Canlı provider kabulü ve tam sistem tenant izolasyonu açık kalır. [API sınırı](ORGANIZATION_ACCESS_TR.md). [Giriş rehberi](GITHUB_LOGIN_TR.md).

VF-017: PostgreSQL müşteri bağlantısı ayrı non-owner/NOBYPASSRLS rolü kullanır; session kanıtı, güncel üyelik ve FORCE RLS DB'de uygulanır. Migration ve operator runtime hesapları da ayrıldı. Ham SQL ve beş rol API testleri yerel gerçek PostgreSQL'de başarılıdır; [sınırlar ve kurulum](DATABASE_ISOLATION_TR.md). Bu, worker veya gerçek müşteri kabulünü tamamlamaz.

## Gereksinim eşlemesi

| Gereksinim | Durum | Uygulama / kalan sınır |
|---|---|---|
| FR-001 GitHub App kurulum/çıkarma | Kısmi | Kurulum, repo çıkarma, repo listesi gelmeyen uninstall/suspend olayında kurulumdaki tüm kayıtların kaldırılması. Canlı App izin/revoke testi ve suspend→unsuspend otomatik uzlaştırma yok. |
| FR-002 Webhook bütünlüğü | Yerelde karşılanıyor | HMAC, delivery dedup, akış sırasında 2 MB sınırı. Delivery ve kuyruk/repo değişimleri tek transaction; kuyruk hatasında delivery de rollback olur. Sağlayıcı redelivery/backfill servisi yok. |
| FR-003 Her commit için iş | Kısmi | Compare sayfalaması; başlangıç/sıfır SHA için webhook alt kümesi yerine SHA'ya bağlı geçmiş sayfalaması. 2.000 commit sınırında sessiz atlamak yerine iş başarısız. Force-push ve sınırsız backfill yok. |
| FR-004 Snapshot'a bağlı tarama | Yerelde karşılanıyor | Kalıcı scan_id, immutable SHA, zamanlar, snapshot bulguları, bağımlılıklar ve manifest SHA-256. Varsayılan dal ilerlerse sonuç incomplete olur; eski sonuç baseline'ı kapatmaz. Tarihsel scan bulguları sonraki taramadan bağımsızdır. |
| FR-005 SCA kesin sürüm | Kısmi | Altı format ve OSV ecosystem/package/version sorgusu. Belirsiz sürümler unknown kapsamına girer. Requirements transitif grafı, Go build listesi, yerel/git paketler ve diğer ekosistemler tamamlanmadı. |
| FR-006 Advisory yeniden değerlendirme | Kısmi | published/updated/withdrawn tetikleyicileri; OSV detay önbelleği her sorgulamada yenilenir. Eksik inventory bulunan repolar ihtiyatlı biçimde yeniden aday seçilir. GHSA/NVD akış ingestion, alias geçmişi ve webhook backfill yok. |
| FR-007 Kapsama/atlama kaydı | Yerelde karşılanıyor | complete/incomplete/failed/running tarama kayıtları; dosya sayıları, atlama nedenleri, syntax/manifest hataları, scanner sınırları, feed hataları. Eksik audit eski dependency bulgusunu kapatamaz. |
| FR-008 Güvenli draft PR | Kısmi, güvenlik kapısında engelli | Eski exact-pin yama yardımcıları korunuyor. Eksik inventory otomatik PR'ı engeller ve audit kaydı üretir. Mevcut requirements parser transitif grafı kanıtlamadığı için normal requirements akışında otomatik PR yayımlanmaz. Repo policy/approval ve izole test kanıtı henüz yok. |
| FR-009 Checks / SARIF | Kısmi | PR açılma/synchronize/reopen olayları, tüm PR dosyalarının sayfalaması ve HEAD kontrolü; SHA'ya bağlı kod ve dependency scan; SARIF 2.1.0 export. Opt-in Checks, 50'lik annotation grupları; eksik sonuç action_required. PR base ile net-yeni bulgu karşılaştırması ve canlı Checks kabul testi yok. |
| FR-010 Semgrep / secret scanner | Eksik | Mevcut küçük AST/regex motoru ve maskelenmiş secret kanıtları var. Semgrep/Gitleaks adapter, kapsamlı pozitif/negatif kural veri kümesi yok. |
| FR-011 SBOM | Kısmi | CycloneDX 1.6 JSON; PURL, repo/SHA/scan kimliği, zaman, manifest digest ve kapsama kanıtı. Eksik SBOM açıkça incomplete. Dependency edge graph, tam transitif çözümleme, container/provenance attestation yok. |
| FR-012 CVSS / EPSS / KEV | Kısmi | OSV severity vektörleri, kaynak hash/zaman ve advisory modified, opsiyonel KEV. EPSS null; reachability unknown. Severity hâlâ heuristic; CVSS hesaplama ve EPSS ingestion yok. |
| FR-013 İzole patch/test koşucusu | Eksik | Depo kodu API/worker'da çalıştırılmaz. Ephemeral sandbox, resolver ve unit/build doğrulama hattı kurulmadı. |
| FR-014 RBAC / audit / OIDC | Kısmi | Admin bearer, bulgu gözlem/resolve/triage geçmişi, gerekçeli ve süreli tek-bulgu suppression; rescan suppression'ı korur, expiry tekrar açar. Kullanıcı/organizasyon/üyelik/sahiplik şeması ve iç admin kontrolleri var; canlı OAuth kabulü, OIDC/SSO, production worker/queue/cache tenant izolasyonu ve tüm eylemler için değiştirilemez audit yok. |
| FR-015 GitLab adapter | Eksik | GitHub dışında sağlayıcı yok. |
| FR-016 LLM triage/patch | Eksik | Worker deterministik. Model/tool router, injection değerlendirmesi, human approval token altyapısı yok. |
| FR-017 Koşullu automerge | Bilerek kapalı; hedef eksik | Hiçbir merge çağrısı yok. CI/approval/policy/isolasyon tamamlanmadan etkinleştirilmemeli. |

## Bu geliştirmede eklenen davranışlar

- SQLite/PostgreSQL için checksummed, transactional, sürümlü migration altyapısı eklendi. Eski desteklenen SQLite şeması kayıtları silmeden yükseltilir. Boş PostgreSQL hedefe read-only kaynak aktarımı ve satır/içerik doğrulaması gerçek yerel sunucuda test edildi. [Taşıma rehberi](DATABASE_MIGRATION_TR.md). Yükseltmeden önce tutarlı yedek alınmalıdır.
- PR taramaları varsayılan dal inventory'sini değiştirmez veya onun açıklarını kapatmaz. PR kod bulguları snapshot'ta tutulur; genel bulgu listesine baseline bulgusu olarak yazılmaz.
- Bozuk/okunamayan manifest atlanma nedeni ile kaydedilir; okunabilen diğer manifestler taranabilir. Hiç desteklenen manifest bulunmaması güvenli envanter kabul edilmez.
- Requirements'taki çözümlenmemiş satırlar, include/URL/marker gibi desteklenmeyen bildirimler ve transitif graf eksikliği görünürdür. Son başarılı inventory silinmez; güncel kısmi veriye scan/SBOM üzerinden ulaşılır.
- OSV pagination tek paket `/v1/query` devam sayfalarıyla tamamlanır; tekrarlayan token veya 100 devam sayfası sınırı hatadır. Withdrawn kayıtlar sonraki audit'te güncellenir.
- Paket adları ekosisteme göre normalize edilir; Go ve RubyGems gibi case-sensitive adlar keyfi olarak küçültülmez.
- Dashboard toplam sayaçları ayrı sorgular; listeler sayfa sınırına tabidir. Son taramalar, kapsama sorunları ve kimlik doğrulamalı SBOM/SARIF indirmeleri görünür. Token kalıcı tarayıcı depolamasına yazılmaz.

## Yeni API ve yapılandırma

Tüm aşağıdaki yollar `Authorization: Bearer ADMIN_TOKEN` gerektirir. Eski `/api/*` uçları korunur.

| Yol | İşlev |
|---|---|
| `GET /api/scans?repo=ORG/REPO` | Son taramaların durum/kapsama listesi |
| `GET /api/v1/scans/{scan_id}` | SHA, kapsama, bağımlılıklar ve o taramanın bulguları |
| `GET /api/v1/scans/{scan_id}/sarif` | SARIF 2.1.0 JSON |
| `GET /api/v1/sbom/{scan_id}` | Dependency taramasından CycloneDX 1.6 JSON; kod scan'i için 409 |
| `GET /api/v1/findings?repo=...&status=...&severity=...&limit=50&cursor=0` | Artan ID cursor, en fazla 100; `items` ve `next_cursor` |
| `PATCH /api/v1/findings/{finding_id}/triage` | open/resolved/suppressed, reason, suppression için expires_at |
| `GET /api/v1/audit/events?repo=...` | Son bulgu değişim/istisna geçmişi |
| `GET /api/v1/overview` | Sayfa sınırından bağımsız toplamlar |

Triage örneği: `{"status":"suppressed","reason":"İncelendi, süreli risk kabulü","expires_at":<gelecekteki Unix saniyesi>}`. Son kullanma tarihi en fazla 366 gün olabilir. Bu endpoint admin içindir; farklı kullanıcı/rol kimliği sunmaz. Manuel resolved, sonraki taramada hâlâ görülen bulgunun yeniden açılmasını engellemez.

`ENABLE_CHECKS=true` için GitHub App'te **Checks: write** ve PR taraması için **Pull requests: read** izinlerini açın; `pull_request` olayına abone olun. Eksik tarama `action_required`, tam taramada high/critical bulgu `failure`, diğer tam taramalar `success` üretir. Bir check yalnız kendi scan türü/kapsamı hakkında konuşur. Dependency veya scanner servis hatasında yerel scan failed olur; check'in eksikliği başarılı sayılmamalıdır. Fork SHA'sına Contents erişimi yoksa başarısız tarama olarak görünür.

## Doğrulama ve sonraki işlerin sırası

27 Ekim 2026 doğrulamasında Python 3.11 ve gerçek geçici PostgreSQL 14.23 ile 301 test geçti. GitHub/OSV çağrıları testlerde taklittir; canlı GitHub App, container kurulumu, yük testi ve formal schema validator ile export uyumluluğu doğrulanmadı.

Güncel sıra [TASKS_TR.md](TASKS_TR.md) içinde izlenir: gizlilik kapıları ve PostgreSQL/identity temeli → GitHub giriş/oturum/RBAC/tenant izolasyonu → doğrulanmış App/Action kurulumu → resolved inventory ve izole doğrulama → ileri ürün fazları. Tasarım belgesindeki SLO, kurumsal portal, bildirim kanalları ve HA ölçeği mevcut sürümün taahhüdü değildir.

## Entegrasyon sözleşmesi kaynakları

- [GitHub Checks API](https://docs.github.com/en/rest/checks/runs): check sonuçları, izinler ve istek başına en fazla 50 annotation.
- [OSV query pagination](https://google.github.io/osv.dev/post-v1-query/): `page_token` ve paket/ekosistem sürüm sorgusu.
- [CycloneDX 1.6 şeması](https://cyclonedx.org/schema/bom-1.6.schema.json): SBOM biçim referansı.

## Toplu uygulama güncellemesi — 27 Ekim 2026

Offline scanner CLI, yerel testli Action/şablonlar, davet ve session revocation, named operatör erişimi, repo opt-in ve worker heartbeat/dead-letter eklendi. Müşteri önizleme paneli org/proje/bulgu/impact/öneri gösterir. Bu, gerçek provider kabulü veya trusted runner intake anlamına gelmez. Eski doğrulanmamış worker PR yayın yolu kapatıldı; source erişimi olan işlerde bile yayın kapısı bitmeden read-only token istenir. [Toplu durum ve açık gereksinimler](BATCH_PROGRESS_TR.md).

Kimliği doğrulanmış runner önizlemesi: sabit issuer/audience ile RSA/JWKS, protected branch ve SHA-pinned reusable workflow, metadata-only App installation kontrolü ve transaction içinde tekrar yükleme bariyeri eklendi. Kod kaynak erişimli App kurulumunu ve managed/runner önizleme karışımını reddeder. Raporlar yalnız karantinada kalır; canlı installation yetkilendirmesi ve baseline promotion tamamlanmadı. Son tüm-suite doğrulaması gerçek geçici PostgreSQL dahil 522 test, sıfır skip; ayrıntılar [runner protokolünde](RUNNER_IDENTITY_TR.md).

## 28 Ekim güncellemesi

Kanıt tazeliği, kaynak erişimsiz oturuma bağlı proje bağlantısı, zorunlu izin/paylaşım consent’i ve hash kilitli kurulum eklendi. Son yerel doğrulama **642 test, sıfır skip**, gerçek geçici PostgreSQL; Docker build ve ağsız container açılışı geçti. Provider çağrıları mock’tur. Canlı kabul, worker DB izolasyonu, güvenilir baseline ve doğrulanmış düzeltme açıktır. [Hedef ürün mimarisi](../ARCHITECTURE.md) uygulama tamamlanma iddiası değildir.
