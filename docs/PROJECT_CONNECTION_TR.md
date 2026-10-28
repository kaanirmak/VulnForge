# Kaynak erişimi olmadan proje bağlama — yerel önizleme

28 Ekim 2026. Yeni akış, seçilen projeyi mevcut kullanıcı oturumuna, kuruluş yöneticiliğine, GitHub kullanıcı kimliğine, GitHub repo yöneticiliğine ve aktif metadata-only App kurulumuna bağlar. Production müşteri kabulü, worker tenant izolasyonu ve runner baseline promotion kapalıdır.

## Akış

1. GitHub ile giriş yapan kullanıcı kendi kuruluşunu oluşturabilir. Oluşturan kişi o kuruluşun yöneticisidir; başka kuruluşun üyeliği verilmez. Oluşturma ve bağlantı başlatma işlemleri mevcut session, sabit Origin ve CSRF gerektirir.
2. Kuruluş yöneticisi tam `sahip/proje` adını girer. Form, Metadata read iznini, kaynak kodun koşucuda kaldığını ve paket/bulgu metadata'sının hassas olabileceğini açıklar. `metadata-v1` onayı zorunludur. Kaynak erişimi, dış paket paylaşımı veya otomatik düzeltme bu onaya dahil değildir.
3. POST `/api/v1/organizations/{org}/connections/begin` en çok 10 dakika geçerli, o session/kuruluş/repo seçimine bağlı bir bağlantı isteği oluşturur. Aynı session'daki önceki seçim iptal edilir. DB'de state/verifier ve session yalnız hash'leriyle ilişkilendirilir. Verifier ayrı HttpOnly cookie'de, S256 challenge GitHub authorize isteğindedir.
4. `/auth/github/connect/callback` yalnız sabit callback'i, tekil ve sınırlı OAuth parametrelerini kabul eder. Query access log'dan çıkarılır; slash/alt yol, ek installation/user/repo alanı ve karışık code/error reddedilir. Browser/session/state/süre ve güncel kuruluş yöneticiliği provider çağrısından önce doğrulanır. State bir kez tüketilir.
5. Sunucu aynı App'in OAuth akışıyla kullanıcı kimliğini tekrar doğrular; bu ID yerel session sahibinin immutable GitHub ID'siyle aynı olmalıdır. App ID veya login adının kullanıcıdan beyanı yetki oluşturmaz.
6. `/user/installations` ve yalnız seçilen sahibin `/user/installations/{id}/repositories` listeleri sabit GitHub API adresinden sayfalanır. İzinler tam Metadata read olmalı; kurulum suspend edilmemiş olmalı; repo üzerindeki GitHub `admin` izni gerçek boolean true olmalıdır. Sadece read/write erişimi kuruluş dışına proje bağlamaya yetmez. Liste sınırları 500 installation ve ilgili installation başına 2.000 repository'dir; eksik, değişen, yinelenen veya limit aşan liste sessizce tamam sayılmaz. Provider Link/repositories_url alanı izlenmez.
7. App anahtarıyla ayrıca aktif installation, App ID, immutable repo/owner ID ve default branch doğrulanır. Yalnız seçilen repo için metadata:read token istenir. Kaynak, diff, commit veya Contents endpoint'i çağrılmaz.
8. Ağ beklemesi dışında kısa transaction'da kuruluş, session ve repo bağlantısı yeniden kontrol edilir. Başka kuruluşun sahipliği, kaldırılmış/değişmiş connection veya farklı installation üzerine yazılmaz. Yeni sahiplik ve consent audit kaydı birlikte yazılır. PostgreSQL org/session/repo kilitleri ve private intent RLS'i uygulanır.

Sonuç **awaiting_runner** durumundadır. Otomatik source işi, scan, dependency inventory, finding veya patch üretilmez. App kurulmuş olması, taramanın tamamlandığı anlamına gelmez. İlk güvenilir snapshot kabulü ayrıca geliştirilecektir.

## Credential ve veri sınırı

User access/refresh token, OAuth code ve ham state/verifier DB, audit veya response'a yazılmaz. Provider token yalnız callback'in belleğinde kullanılır; tarayıcıya verilmez. Bu, GitHub tarafında revoke edildiği veya bellekten kriptografik silindiği iddiası değildir. Callback'te toplam 45 saniye; metadata doğrulamasında ayrıca 30 saniye ve bounded response sınırları vardır. Redirect ve ortam proxy'si kullanılmaz; hata yanıtı provider içeriğini göstermez.

010 migration, auth_states ve user_sessions ile FK cascade bağlı private connection_intents tablosunu ekler. Logout/session revoke veya state expiry temizliği intent'i de kaldırır. Tüm customer rollerinin doğrudan SQL erişimi reddedilir. Migration sonrası operator provisioning yeniden uygulanmalıdır. SQLite→PostgreSQL aktarımı hash/intent/session ilişkisinin aynen korunduğunu doğrular.

## Etkinleştirme ve açık işler

Yalnız `SCAN_MODE=customer_runner`, loopback `CUSTOMER_API_PREVIEW`, mevcut OAuth ayarları ve `GITHUB_CONNECTION_PREVIEW=true` ile açılır. Genel hostname'de açılmaz. Metadata App ID/PEM ile OAuth client ID/secret aynı App kaydına ait olmalıdır. Ayrı managed App veya klasik OAuth App bu kimlik kontrolünün yerini tutmaz.

Canlı provider kabulü yapılmadığından VF-013/014/023/024/025/028 tamamlandı sayılmaz. VF-025'in kullanıcıya tam installation/repo seçici sunması ve devamlı erişim uzlaştırması hâlâ eksiktir; bu akış tek repo adını doğrular. VF-026'nın customer-runner onay ekranı/kayıt/izin doğrulaması yerelde tamamlandı; managed source ve dış paylaşım için ayrı onay ekranları açılmadı. İstek/organizasyon kotaları, staging secret store, webhook backfill, worker DB rolü ve bağımsız inceleme olmadan private müşteri alımı açılmaz.

Kanıt: gerçek RSA App JWT, sabit hostlu iki ayrı provider credential türü, tam pagination, yanlış hesap/App/kurulum/izin/repo/owner/branch, CSRF ve beş rol, farklı browser/session, replay/expiry, provider beklerken logout/rol/connection/ownership değişimi; API→mock GitHub→ownership zincirinde sıfır token persist; non-owner PostgreSQL operator ve customer SQL reddi, pending intent veri aktarımı test edildi.

Kaynaklar: [GitHub user access token installation/repository API](https://docs.github.com/en/rest/apps/installations), [callback URL kuralları](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url), [yerel login ve çoklu callback örneği](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-a-login-with-github-button-with-a-github-app).
