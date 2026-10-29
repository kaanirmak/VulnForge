# PostgreSQL müşteri veri sınırı ve çalışma hesapları

VF-017 — 27 Ekim 2026. Migration 004, ayrı müşteri/operatör bağlantıları, DB rol denetimleri ve oturum kanıtına bağlı PostgreSQL RLS eklendi. **Bu çalışma bütün ürünün müşteri kullanımına hazır olduğu anlamına gelmez.** Canlı GitHub kabulü, worker/queue/cache sınırı, kurulum sahipliği ve üretim altyapısı açık kalır; müşteri kapısı varsayılan kapalı ve yalnız loopback önizlemesi desteklenir.

## Hesapların ayrılması

| Hesap | Erişim | Nerede kullanılır? |
|---|---|---|
| Migration hesabı | Özel uygulama DB/schema sahibi; DDL ve incelemesi yapılmış güvenlik fonksiyonlarının sahibi | Upgrade/provision/SQLite aktarım işi; müşteri API'sinde kullanılamaz |
| Operatör runtime | Non-owner, NOINHERIT, NOBYPASSRLS; uygulama verisinde açıkça tanımlı global operatör politikası | Login/session, webhook, eski bearer API ve kuyruk scheduler/claim. DDL/role registry/migration yazma yetkisi yok |
| Müşteri runtime | Ayrı non-owner, NOINHERIT, NOBYPASSRLS login; yalnız gereken tablo/kolon/sequence yetkileri | Organizasyon API sorguları; geçerli oturum ve org kapsamında |
| Worker runtime | Ayrı non-owner, NOINHERIT, NOBYPASSRLS login (`--worker-role`, `WORKER_DATABASE_URL`); yalnız iş yürütme tablo/kolon yetkileri | Kuyruk işlerinin yürütülmesi (`WorkerStore`); canlı `job_id` + `claim_token` + `connection_id` + `organization_id` kapsamında |

Runtime hesapları superuser/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS, başka DB rolüne üyelik veya nesne sahipliği taşıyamaz. Public/yazılabilir schema ve TEMP yetkileri reddedilir. Müşteri hesabında beklenmeyen tablo, kolon, sequence veya gözden geçirilmemiş SECURITY DEFINER fonksiyon erişimi açılışı durdurur. Yalnız tablo bazlı SELECT kontrol edilmez; örneğin session tablosunun tek `token_hash` kolonuna verilen erişim de reddedilir.

Operatör hesabının global veriye erişimi ayrı ve açık yetkidir; müşteri rolü bu hesaba SET ROLE yapamaz veya korunan rol kaydını değiştiremez. Aynı API süreci hâlâ operatör/login sırlarına sahiptir; süreç/host ele geçirilmesine karşı bağımsız servis ve secret erişim sınırı VF-020/081–085 kapsamında ayrıca ele alınmalıdır. Buradaki testler bu tür bir tam süreç ihlalinin engellendiği iddiası değildir.

## Kurulum ve upgrade

Yalnız **VulnForge'a ayrılmış bir PostgreSQL veritabanında** çalıştır. Migration, public schema'nın PUBLIC CREATE yetkisini ve uygulama tablolarının PUBLIC izinlerini kaldırır; provisioning DB'nin PUBLIC TEMP yetkisini kaldırır. Ortak veritabanında başka uygulamaların izinlerini etkileyebileceğinden bu kurulum ortak DB'ye uygulanmaz. Gerçek müşteri DB'sinde bu geliştirmede hiçbir işlem yapılmadı.

1. Tutarlı yedek al, API/worker yazıcılarını durdur. [Taşıma rehberindeki](DATABASE_MIGRATION_TR.md) cutover ve rollback kurallarını uygula.
2. DBA ayrı migration hesabını ve ona ait uygulama DB/schema'sını oluşturur. Runtime login'lerini ayrı, yeni hesaplar olarak hazırlar. Örnek nitelikler:

   ```sql
   CREATE ROLE vf_operator_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   CREATE ROLE vf_customer_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   ```

   Parolaları terminal geçmişine/sohbete koymadan DBA'nın güvenli parola atama mekanizmasıyla belirle. Üretimde SCRAM/TLS ve özel ağ bağlantısını yapılandır. Geçici test cluster'ındaki Unix-socket trust ayarı üretim örneği değildir. Migration hesabının bu login'leri oluşturması gerekmez; araç rol veya parola oluşturmaz. PostgreSQL 14'te yeni DB'nin `public` schema sahibi ayrıca doğru migration hesabına atanmalıdır.
3. Korunan işlem ortamında `DATABASE_URL`, doğrudan migration hesabının bağlantısı olmalı. Sır değerini komuta/issue'ya gömmeyin. Sürümlü şemayı uygula ve mevcut runtime rollerine yetki ver:

   ```bash
   python -m vulnforge.rls --operator-role vf_operator_runtime
   python -m vulnforge.rls --customer-role vf_customer_runtime
   ```

   İlk komut migrations'ı uygular; iki komut da kendi yetki değişikliklerini transaction içinde yapar. Başarılı çıktı sadece durum bildirir. CLI, runtime için yapılmış `DATABASE_AUTO_MIGRATE=false` ayarından bağımsız olarak migration yetkisi ister; bu bir runtime startup komutu değildir. Rol isimleri basit lowercase identifier olmalıdır. Mevcut customer rolü operator'e veya tersi moda dönüştürülemez.
4. API/worker ortamını ayrı runtime sırlarıyla ayarla:

   ```dotenv
   DATABASE_URL=<operator-runtime-postgresql-uri>
   DATABASE_AUTO_MIGRATE=false
   CUSTOMER_DATABASE_URL=<customer-runtime-postgresql-uri>
   CUSTOMER_API_PREVIEW=false
   ```

   Migration hesabının sırrını çalışan API/worker ortamına bırakma. `DATABASE_AUTO_MIGRATE=false`, migration geçmişini sadece doğrular; eksik/eski/değişmiş şemayla çalışmaz. Müşteri bağlantısı migration yapmayı denemez; private helper üzerinden migration checksum'larını doğrular.
5. Yerel önizleme testinde bile PostgreSQL müşteri API'si için iki ayrı runtime bağlantısı zorunlu. Müşteri URL'si boşsa operatör bağlantısına geri dönülmez. Operatör veya müşteri URL'sinde owner/superuser hesabı varsa müşteri API'si açılmaz. Gerçek App/HTTPS ve tam tenant kapıları tamamlanmadan public erişimi etkinleştirme.

Eski self-hosted geliştirmede otomatik migration varsayılanı korunur; bu URL'nin migration sahibi olması mevcut davranıştır. Ancak bu owner bağlantısıyla PostgreSQL müşteri önizlemesi başlatılması engellenir. SQLite yalnız yerel uygulama kapsamı kontrollerini sunar; RLS varmış gibi gösterilmez ve üretim müşteri DB'si sayılmaz.

## DB'nin doğruladığı oturum

Müşteri DB rolünün kimliği `session_user` ile belirlenir. DB private registry'sini yalnız migration yetkilisi yönetir; `SET vulnforge.internal=true` gibi kullanıcı ayarları operatör yetkisi oluşturmaz.

Her müşteri işlemi transaction içinde `set_config(..., true)` ile organizasyon ve doğrulanmış session'ın SHA-256 özetini taşır. Bu özet bir erişim kanıtıdır ve sır gibi korunmalıdır. PostgreSQL, özel `user_sessions` tablosunda gerçek kullanıcıyı, 8 saatlik mutlak süreyi ve 30 dakikalık idle sınırını kontrol eder. `user_id` veya `role` GUC/header beyanından kimlik türetilmez. Müşteri rolü session tablolarını veya özetlerini doğrudan okuyamaz/değiştiremez. Oturumu bilmeyen kişi yalnız organizasyon kimliğini ayarlayarak erişemez.

Transaction scope dışındaki proje sorguları boş sonuç verir. Commit/rollback sonrasında aynı fiziksel bağlantıda local ayarların temizlendiği test edildi; yeni scope, geçersiz veya revoke edilmiş kanıtla kurulamaz. İç içe scope veya işlem ortasında scope değiştirme helper tarafından reddedilir. Henüz connection pool kullanılmaz; gelecekteki pool entegrasyonu bu testleri tekrar geçmelidir.

Özetleri, OAuth kodlarını ve session cookie'lerini DB/proxy/APM loglarına yazma. PostgreSQL parametre loglarını da gözden geçir; özellikle `log_parameter_max_length` ve `log_parameter_max_length_on_error` için sır içermeyen ayarlar kullan. Uygulama DB hata metninde DSN veya row/parametre değerlerini geri yansıtmaz; dış altyapı loglarına tek başına hükmetmez.

## Politika kapsamı

24 uygulama tablosunda ENABLE + FORCE RLS vardır; davet, repo düzeltme politikası ve üç runner identity tablosu customer rolüne kapalıdır. Repo, finding, inventory, scan ve alt bulgular, remediation, advisory/alias/impact, ownership ve audit politikaları organizasyon/üyelik sınırını uygular. Ortak public advisory'nin müşteriyle ilişkili kayıtları yalnız görünür impact üzerinden erişilebilir. Users/organizasyon/üyelik erişimi mevcut aktöre bağlıdır; gerekli olmayan users tablosuna müşteri GRANT'i verilmez.

Findings güncellemesinde yalnız `status` kolonuna izin verilir. Org Admin/Maintainer süreli risk kabulü yapabilir; Analyst open/resolved ile sınırlıdır. Viewer/Auditor normal triage yapamaz. Süresi dolmuş kendi bulgusunun yalnız open'a dönmesi, sınırlı system expiry istisnasıdır. Audit'e yalnız yetkili triage/export isteği veya bu expiry kaydı eklenebilir; aktör/org/ilgili kayıt kontrol edilir. Audit read sadece Org Admin/Auditor'dadır. Bu kontrol operatör audit'ini tümüyle immutable yapmaz; VF-085 açık kalır.

Jobs, deliveries ve karantina raporlarında müşteri politikası yoktur; müşteri rolüne bu tablolara erişim verilmez. Auth state/session ve migration/role metadata'sı ayrı ACL/private helper sınırındadır. Worker'a bağlantı/organizasyon/claim doğrulaması, repo/scan kapsamlı uygulama arayüzü ve iş başına cache eklendi. Worker DB bağlantısı hâlâ global operatördür; DB seviyesinde iş kanıtı ve özel katalog namespace'i bitmediğinden VF-018 açık kalır. [İlerleme ve sınırlar](QUEUE_ISOLATION_TR.md).

SECURITY DEFINER helper'ları kontrollü SQL kullanır, tablo isimlerini schema ile belirtir, güvenli search_path ve sınırlandırılmış EXECUTE izinleriyle kurulur. Helper sahibi superuser olduğunda da olmadığında da test edildi. Superuser/DBA kasıtlı olarak policy veya rol değiştirebilir; RLS, DB yöneticisinin kontrolünü ortadan kaldıran bir şifreleme sistemi değildir.

## Kanıt ve kalan işler

Gerçek geçici PostgreSQL 14.23 üzerinde ham SQL testleri; WHERE filtresi olmadan iki org ayrımı, diğer org'a UPDATE, sahte role/user/org/internal ayarları, row_security=off, SET ROLE/SESSION AUTHORIZATION, RLS kapatma, TRUNCATE, schema/temp oluşturma, sahiplik/üyelik değiştirme, session hash kolonu sızıntısı, fazla grants, rol üyeliği ve unsafe definer kontrollerini kapsar. Beş rolün DB izin matrisi uygulamayla karşılaştırılır. API testi iki ayrı non-owner runtime hesabını kullanır; root/migration hesabıyla müşteri API'si açılmaz.

Migration/parser testleri dollar-quoted SQL gövdelerini ve literal/comment içindeki noktalı virgülleri korur. SQLite→PostgreSQL aktarımı yeni RLS şemasıyla da doğrulanır. DB rol registry'si kaynak SQLite'dan kopyalanmaz; hedefteki onaylı hesaplarla yeniden kurulur. Üretim restore ve credential rotasyonu VF-083/089 kapsamında ayrıca prova edilmelidir.

Canlı GitHub/gerçek müşteri trafiği, başka PostgreSQL major sürümleri, yönetilen DB sağlayıcıları, yük testi ve bağımsız güvenlik değerlendirmesi yapılmadı. Sıradaki VF-018 worker/queue/cache sınırıdır; `tenant_isolation_ready=false` kalır.

Resmi mekanizma referansları: [PostgreSQL RLS](https://www.postgresql.org/docs/17/ddl-rowsecurity.html), [SECURITY DEFINER güvenliği](https://www.postgresql.org/docs/current/sql-createfunction.html), [transaction/session ayarları](https://www.postgresql.org/docs/current/config-setting.html). Bunlar uygulamanın bütününe güvenlik onayı değildir.
