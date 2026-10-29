# Roller ve organizasyon kapsamlı veri erişimi

27 Ekim 2026 — VF-015/016 uygulama kaydı. Rol politikası ve müşteri veri sorguları yerel önizlemede uygulanır. **Canlı OAuth kabulü ve worker/queue izolasyonu tamamlanmadığı için genel müşteri kullanımı açılmaz.** `tenant_isolation_ready` ve `customer_access_ready` false kalır.

VF-017 güncellemesi: PostgreSQL önizlemesinde ayrı non-owner operator/customer bağlantıları ve DB session kanıtıyla FORCE RLS zorunludur. Owner veya geniş yetkili bağlantıyla müşteri API'si başlamaz; operatör bağlantısına fallback yapılmaz. SQLite hâlâ yalnız yerel uygulama kapsamı kontrolleri sunar. [DB kurulumu ve kanıt](DATABASE_ISOLATION_TR.md).

## Yetki matrisi

| İşlem | Org Admin | Maintainer | Analyst | Viewer | Auditor |
|---|---|---|---|---|---|
| Proje, dependency, finding, scan, impact/öneri görüntüleme | Evet | Evet | Evet | Evet | Evet |
| Kendi organizasyonunun SBOM/SARIF çıktısı | Evet | Evet | Evet | Evet | Evet |
| Bulguyu `open` / `resolved` / `false_positive` (`finding.triage`) olarak değerlendirme | Evet | Evet | Evet | Hayır | Hayır |
| Süreli `risk_accepted` (`finding.accept_risk`, zorunlu <= 366 gün süre sonu) | Evet | Evet | Hayır | Hayır | Hayır |
| Süreli `suppressed` (`finding.suppress`, zorunlu <= 366 gün süre sonu) | Evet | Evet | Hayır | Hayır | Hayır |
| Organizasyon audit görüntüleme | Evet | Hayır | Hayır | Hayır | Evet |
| Üyelik/sahiplik değiştirme | Yalnız güvenilen iç servis metotları | Hayır | Hayır | Hayır | Hayır |

Tanımlanmayan rol veya işlem reddedilir. Tarama başlatma, repo bağlama, davet, düzeltme yayını ve background job müşteri endpoint'leri bu önizlemede yoktur; mevcut müşteri oturumu bunlara yetki vermez. Bu özellikler açılırken ayrı izin kontrolleri eklenmelidir. Maintainer/Org Admin için gelecekteki tarama/bağlantı akışı VF-018/021–040 kapsamındadır.

Kullanıcı kimliği yalnız sunucuda doğrulanan session'dan alınır. `user_id`, `organization_id`, `role`, `X-Role` veya `X-Organization-ID` beyanı oturumun yetkisini değiştirmez. URL'deki organization ID bir yetki değildir; o organizasyonda mevcut üyelik aranır. Üyelik ve rol DB'den her işlemde okunur; mevcut session ile yapılan sonraki istekte rol düşürme/üyelik kaldırma geçerli olur. Bütün cihazlardan session iptali ve davet akışı VF-019'da açık kalır.

## Yerel API önizlemesi

Varsayılan `CUSTOMER_API_PREVIEW=false`. Açılması için OAuth ayarları, `ALLOW_INSECURE_LOCAL_AUTH=true` ve localhost/127.0.0.1/::1 origin birlikte gerekir; public hostname ile açılmaya çalışılırsa konfigürasyon reddedilir. Bu kural gerçek ağ firewall'u değildir; geliştirme sunucusunu yine loopback'e bağla. Gerçek sırları veya müşteri verisini test fixture'ı yerine kullanma.

Önizleme için ayrı, gerçek müşteri içermeyen yerel ortamda örnek origin `http://127.0.0.1:8000` olabilir. Bu ayar eksik GitHub App kaydını veya canlı OAuth kabulünü tamamlamaz. Müşteri API kapalıyken operatör bearer token'ı ile bu kapı atlanamaz; açık önizlemede de bearer, müşteri cookie'sinin yerine geçmez. Müşteri cookie'si eski `/api/*` operatör uçlarını açmaz.

| Yol | Davranış |
|---|---|
| `GET /api/v1/organizations` | Yalnız session sahibinin organizasyonları ve mevcut rolleri |
| `GET /api/v1/organizations/{org}/overview` | Kapsamlı proje/bulgu/öneri sayaçları |
| `…/{org}/repositories`, `/dependencies`, `/remediations` | Yalnız org'a bağlı projelerin kayıtları |
| `…/{org}/findings` | Repo/status/severity, limit ve sayısal cursor |
| `PATCH …/{org}/findings/{id}/triage` | Rol + Origin + cookie/header/DB CSRF doğrulaması; gerekçe ve suppression süresi |
| `…/{org}/scans`, `/scans/{id}` | Snapshot ve o scan'e bağlı bulgular |
| `…/{org}/scans/{id}/sarif`, `/scans/{id}/sbom` | Önce org/scan erişimi; SBOM için dependency türü ve tamamlanmış çalışma kontrolü |
| `…/{org}/impacts`, `/advisories` | Etki ve güncelleme önerileri; yalnız bu org'un proje sayıları |
| `…/{org}/audit/events` | İzin verilen org/repo audit kayıtları |

Listeler en fazla 100 kayıt alır. Findings/remediations/impacts/audit sayısal cursor kullanır. Repo/dependency/scan listeleri henüz tam cursor sunmaz; `truncated` alanı sınıra ulaşıldığını açıkça belirtir. Bütün API cursor/snapshot standardizasyonu VF-079'dadır. Yeni endpoint'lerde henüz proje seçme/bağlama UI'si yoktur; bu VF-071–080'de açık kalır.

## Veri sınırının uygulanması

`OrganizationData`, her veri sorgusunu `repository_ownership.organization_id` ve güncel üyeliğe bağlar. Önce tüm veriyi getirip uygulamada filtrelemez. Repo filtresinin başka organizasyona veya sahipsiz repoya işaret etmesi 404 döndürür; boş filtre tüm projelere genişlemez. Başkasının scan/finding ID'si kendi org yoluyla verilse bile detail/export/triage erişimi reddedilir. Üyesi olunmayan ve bulunmayan organizasyon aynı 404 yanıtını verir.

Advisory sayıları global katalog sayaçlarından alınmaz; yalnız ilgili organizasyonun bağlı projeleri sayılır. Public advisory aynı olsa bile başka müşterinin etki sayısı taşınmaz. Scan findings yalnız erişimi doğrulanan scan'den okunur. Triage audit'i gerçek yerel kullanıcı ID'sini ve organization ID'sini kaydeder; authorized export isteği ayrıca kaydedilir. Suppression süre sonu, müşteri read/overview akışında yalnız kendi organizasyonundaki bulguları yeniden açar; başka müşterinin verisini değiştirmez.

Role/ownership güncellemeleriyle veri işlemi aynı organization lock protokolünü kullanır: PostgreSQL transaction advisory lock, SQLite write transaction. Bu, işlem sürerken üyelik değişiminin araya girmesini önler; global account revocation veya dış GitHub erişim değişimini çözmez. Bunlar VF-019/028 kapsamındadır.

Müşteri mutation gövdesi 4 KB ile sınırlı; triage şeması extra alanları, yanlış tipleri, geçersiz süreyi ve bilinen sır örüntülerini reddeder. Yeni müşteri endpoint'lerinin validation hatası input'u geri yansıtmaz. Yanıtlar no-store/no-referrer kullanır. Serbest gerekçe için bu kontroller gizli kanalı matematiksel olarak engellediği veya tüm altyapı loglarını denetlediği iddiası değildir.

## Doğrulama ve kalan kapılar

49 yeni SQLite/API testi iki ayrı dummy organizasyon ve sahipsiz üçüncü repo kullanır. Her read/export yolu, farklı org yolu, repo filtresi, scan/finding ID'si, beş rolün triage/suppression/audit matrisi, session değiştirmeden rol düşürme, üyelik kaldırma, CSRF, pagination, secret/extra alan reddi ve scoped suppression expiry sınanır. İki gerçek PostgreSQL testi bütün read/export sorguları ve mevcut session ile rol/üyelik değişimini ayrıca doğrular. Canlı müşteri/GitHub trafiği kullanılmaz.

VF-015/016 bu uygulama/API kapsamıyla tamamlanır. **Bütün sistemde tenant güvenliği tamamlandı denmez:** PostgreSQL DB rol/RLS sınırı VF-017 ile eklendi. VF-018 worker/queue/cache verisi, VF-019 revoke/davet, VF-024 gerçek kurulum sahipliği, VF-028 transfer/uninstall yarışları, VF-082 ingress ve VF-092 tam iki-müşteri kabulü açık kalır. Eski operatör yolları instance genelinde yetkilidir; bunların müşteri trafiğine sunulması bu önizlemenin parçası değildir.
