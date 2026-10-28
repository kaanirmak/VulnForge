# SQLite / PostgreSQL ve veri taşıma rehberi

VF-011 — 27 Ekim 2026. SQLite yerel geliştirme için korunur; PostgreSQL kalıcı store, kuyruk, bulgu, istihbarat ve kimlik ve giriş/oturum tablolarını aynı arayüzle destekler. VF-017 ile PostgreSQL FORCE RLS ve migration/runtime rol ayrımı da eklendi; [izolasyon kurulumunu](DATABASE_ISOLATION_TR.md) birlikte uygula. HA, connection pool veya üretim yedekleme hizmeti kurulmadı.

## Bağlantı ve şema

Yerelde `pip install -e '.[dev,postgres]'` PostgreSQL sürücüsünü yükler. Dockerfile aynı optional grubu içerir; container build/kabul testi henüz yapılmadı. API, worker ve taşıma aracı aynı `DATABASE_URL` değerini kullanmalıdır. URI doluysa `DATABASE_PATH` dikkate alınmaz; boşsa SQLite kullanılır. Gerçek URL/şifreyi komut geçmişine veya issue'ya yapıştırma; korunan ortam dosyası/secret manager üzerinden ver.

`vulnforge/migrations/` içinde iki dialect için numaralı SQL dosyaları vardır. Store açılışında tek transaction içinde uygulanır; sürüm ve SHA-256 özeti `schema_migrations` tablosuna yazılır. PostgreSQL'de advisory lock, SQLite'ta write transaction eşzamanlı açılışı sıralar. Uygulanmış dosyanın değişmesi veya uygulamanın bilmediği daha yeni şema açılışı durdurur. Yeni değişiklik için eski dosyayı düzenlemek yerine yeni migration ekle. Genel downgrade komutu yoktur.

PostgreSQL şeması `public` olarak sabitlenir. İlk kurulum/upgrade için migration rolünün DDL yetkisi gerekir; Migration/runtime rol ayrımı ve RLS VF-017 ile uygulandı; üretim ağ/TLS ve ortam kurulumu VF-081–082'de açık kalır. Üretimde TLS doğrulamalı özel ağ bağlantısı ve en az yetkili ayrı hesaplar ayrıca kurulmalıdır. Bağlantı ve SQL hataları DSN veya satır içeriğini yanıt metnine eklemez. Bu uygulama kontrolü altyapı loglarını tek başına güvenli yapmaz.

PostgreSQL testleri bu geliştirmede **14.23** yerel sunucuda çalıştırıldı; başka major sürümler veya yönetilen sağlayıcılarda canlı kabul yapılmadı. Kurulu sunucu sürümünü gerçek doğrulama çıktısıyla birlikte kaydet.

## SQLite'tan PostgreSQL'e geçiş

1. Webhook ingress, API yazma işlemleri ve worker'ları durdur. İki store'a aynı anda yazan süreç bırakma. GitHub redelivery/yeniden uzlaştırma planını kaydet; araç yeni olayları takip eden online replication değildir.
2. SQLite'ın tutarlı yedeğini SQLite backup API'si veya doğrulanmış yedekleme aracıyla al. WAL kullanımında çalışan DB dosyasını tek başına kopyalamak tutarlı yedek kanıtı değildir. Geri yüklemeyi ayrı ortamda dene; orijinal dosyayı koru.
3. Ayrı ve boş bir PostgreSQL veritabanı hazırla. `DATABASE_URL` değerini bu hedefe ayarla. Araç şemayı oluşturabilir; müşteri verisi olan hedefi kabul etmez ve üzerine yazmaz.
4. Kaynak için mevcut SQLite dosyasının yolunu kullan:

   ```bash
   python -m vulnforge.migrate --source /absolute/path/to/vulnforge.db
   ```

5. Çıktıda `verified: true`, `source_modified: false` ve tablo sayımları bulunmalı. Kaynak read-only transaction ile okunur. Desteklenen eski sürümde bulunmayan ek tablolar boş kalabilir; mevcut bir tablonun kolonları beklenenden farklıysa işlem geri alınır. Beklenmeyen tablo/uyarlama için inceleme yap; veri silerek geçişi zorlama.
6. Araç bütün uygulama tablolarını tek hedef transaction'da kilitler, ID/JSON/zaman/durum değerlerini korur ve tablo başına satır sayısı + içerik özetiyle doğrular. Başarısızlıkta taşınan satırlar geri alınır; yeni boş şema kalabilir. Sequence değerleri kaynak high-watermark'ını korur; PostgreSQL sequence işlemleri transactional olmadığından başarısız denemeden sonra ID boşlukları olabilir, veri kaybı veya ID yeniden kullanımı kabul edilmez.
7. `running` işlerin lease/attempt bilgileri aynen korunur. Worker başlatmadan pending/running işleri ve artık geçerli olmayan kurulumları incele. Süresi dolan lease yeniden işlenebilir; bu araç dış servis etkileri için exactly-once garantisi sağlamaz.
8. API'yi hedef PostgreSQL ile başlat; health, yetkili repo/finding/scan/export sayımları ve test repolu kontrollü iş doğrulamasını yap. Ardından worker ve ingress'i aç. Mevcut gizlilik ayarları taşınmaz; bunlar ortam konfigürasyonudur ve ayrıca doğrulanmalıdır.

Aktarılan tablolar: users, organizations, memberships, repositories, deliveries, jobs, findings, dependency_inventory, remediations, scans, scan_findings, audit_events, suppressions, advisories, advisory_aliases, advisory_impacts, runner_reports, repository_ownership, auth_states, user_sessions, invitations, remediation_policies, runner_policies, runner_receipts, runner_token_uses. Hedef migration geçmişi kendi kurulumundan üretilir; kaynak şema checksum'ları hedef dialect'e kopyalanmaz.

## Geri dönüş

PostgreSQL'e yeni yazma başlamadan sorun görülürse süreçleri durdur, korunan SQLite yedeğini/doğrulanmış kaynağı seç ve `DATABASE_URL` değerini kaldırarak geri dön. PostgreSQL'e yeni veri yazıldıktan sonra eski SQLite'a doğrudan dönmek bu yeni verileri kaybettirir; önce yazmayı durdurup veri uzlaştırma/restore planı gerekir. Ters yön aktarım aracı henüz yoktur. Üretim RPO/RTO, yedek şifrelemesi ve tatbikat VF-084/089 kapsamında açık kalır.

## Doğrulama kanıtı

`tests/test_database.py`: eski SQLite kaydının korunması, checksum değişikliğinde durma, gerçek PostgreSQL'de 64-bit kimlikler/upsert, suppression expiry, scan/finding roundtrip, rollback, eşzamanlı queue claim, API roundtrip, sabit namespace, bütün tabloların eksiksiz aktarımı, sequence korunması, dolu hedefi reddetme ve geçiş ortasında hata geri alma. `tests/test_identity.py` ve PostgreSQL concurrency testi kimlik/üyelik sınırlarını kapsar. Testler yalnız ayrı geçici yerel cluster kullanır; paylaşılan/uzak veya TCP test hedefleri fixture tarafından reddedilir.

Bu kanıt mevcut migration baseline'ı içindir; bozuk/tamamen özelleştirilmiş her eski SQLite dosyasına otomatik uyumluluk veya gerçek üretim restore tatbikatı iddiası değildir.

## 005–007 güncellemesi ve doğrulama

005 connection/claim kanıtı, 006 davet ve 007 repo düzeltme politikası ekler. Eski kanıtsız pending/running işler iptal edilir; mevcut repo için yeni tarama planlanmalıdır. Schema migration'ı migration hesabıyla uygula, ardından mevcut operator runtime rolleri için provisioning'i yeniden çalıştır: yeni private tablolara gerekli DML grants bu aşamada verilir. Customer rolüne davet/operatör/policy tablosu erişimi verilmez. Eski role ayarının yeni tabloya sessizce genişletildiği varsayılmaz.

`python scripts/check.py --postgres` yeni ve owner-only geçici Unix-socket cluster'ı UTF-8 ile kurar, testi çalıştırır ve kapanışta siler. `/private/tmp/vulnforge-pg.*` (macOS) veya `/tmp/vulnforge-pg.*` (Linux), yalnız `vulnforge_test` hesabı kabul edilir; uzak/TCP hedef reddi sürer. Mevcut kullanıcı veritabanını başlatma/durdurma/taşıma komutu değildir. Son doğrulamada 522 test skip olmadan geçti; CI yapılandırması bu komutu çağırır ancak uzaktaki GitHub CI run'ı henüz çalıştırılmadı.

## 008 — kimliği doğrulanmış runner karantinası

008 her iki veritabanında runner_policies, runner_receipts ve runner_token_uses tablolarını ekler. Repo kaldırılırsa bu kayıtlar FK cascade ile temizlenir. PostgreSQL tablolarında FORCE RLS ve private operator politikası vardır; müşteri rolüne erişim verilmez. Migration hesabıyla yükselttikten sonra operator provisioning komutunu yeniden çalıştır. Var olan raporlar otomatik envanter veya güvenilir baseline olmaz.

Taşıma testi policy, receipt ve token kullanım özetlerinin SQLite→PostgreSQL geçişinde aynen korunduğunu doğrular. Non-owner operator ile kabul ve müşteri rolüyle SQL reddi gerçek geçici PostgreSQL üzerinde test edildi. [Akış ve kalan canlı kabul](RUNNER_IDENTITY_TR.md).

## 009 — kanıt geçersizleşme zamanı

009 repository kaydına `evidence_invalidated_at` ekler. Varsayılan dal değişikliği veya imzalı varsayılan dal push'u eski snapshot'ın güncel sonuç gibi sunulmasını engeller. Yeni tablo veya rol grant'i yoktur; mevcut repository RLS uygulanır. Timestamp beş müşteri rolü ve SQLite→PostgreSQL aktarımıyla test edildi. Eski kaynak dosyasını taşımadan önce desteklenen güncel şemaya migration hesabıyla yükselt; farklı kolon şeması aktarımda reddedilir. 009 aşamasında 581 test geçti; 010 dahil son doğrulama 642 testtir. [Tazelik politikası](EVIDENCE_FRESHNESS_TR.md).

## 010 — Oturuma bağlı proje bağlantısı

`connection_intents`, tek kullanımlık auth state ve session hash ile bağlantı niyetini, beklenen bağlantıyı ve consent sürümünü bağlar. State/session silinmesi intent’i cascade ile siler. PostgreSQL FORCE RLS ve internal-only erişim kullanır; customer runtime bu tabloyu okuyamaz. İki dialect için toplam 20 migration kaynağı (10’ar) vardır. SQLite→PostgreSQL aktarımı dolu intent ile testlidir; migration sahibi yeni şemayı kurduktan sonra runtime rol doğrulamasını uygula.
