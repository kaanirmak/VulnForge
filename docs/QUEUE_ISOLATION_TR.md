# Kuyruk bağlantısı ve iş sınırı — VF-018 kaydı

29 Ekim 2026. VF-018 tamamlanmıştır: uygulama düzeyindeki iş/bağlantı sınırı, ayrı PostgreSQL `WorkerStore` (`--worker-role`) çalışma hesabı, iş kanıtına (`job_id`, `claim_token`, `connection_id`, `organization_id`, `catalog_scope`) bağlı FORCE RLS politikaları ve organizasyon-bazlı (`org:<org_id>`) özel OSV katalog namespace'i uygulanmıştır. Canlı GitHub/müşteri kabul kapıları tamamlanana kadar `tenant_isolation_ready=false` korunur.

## Tamamlanan kontroller

- [x] Her repo bağlantısına rastgele, kalıcı `connection_id` atanır. Kurulum değişirse, repo silinip tekrar eklenirse veya sahiplik kaydı eklenir/değişir/silinirse kimlik yenilenir. Sadece varsayılan dal değişmesi yeni bağlantı oluşturmaz.
- [x] Aynı repo adı farklı installation ile kaydedilirse eski sahiplik ve repo verileri temizlenir; yeni bağlantı eski organizasyona otomatik atanmaz. İlk kayıtların eşzamanlı gelmesi de transaction içinde sıralanır.
- [x] Kuyrukta organizasyon, kurulum ve bağlantı kimliği sunucu kayıtlarından alınır; payload içindeki benzer alanlar yetki kanıtı değildir. Kayıtsız repo için iş üretilemez. Tekrarlı iş anahtarı bağlantıya özeldir.
- [x] Her claim yeni rastgele `claim_token` üretir. İşin başlangıcında, yerel okuma/yazmalarında, sağlayıcı çağrılarından önce/sonra ve tamamlanırken canlı bağlantı, sahiplik, iş durumu ve lease tekrar doğrulanır. Geçersiz sonuçlar yazılamaz; eski claim yeni worker'ın işini tamamlayamaz veya iptal edemez.
- [x] Yerel işlemler kısa transaction içinde repo ve job kilitlerini tutar. Ağ beklenirken DB transaction'ı tutulmaz. PostgreSQL sahiplik trigger'ı aynı repo kilidiyle sıralanır; SQLite yazmaları transaction ile sıralanır. Harici sisteme zaten gönderilmiş bir isteği geri almak mümkün değildir; sonraki çağrılar ve yerel sonuç yazımı durdurulur.
- [x] Worker'ın uygulama veri arayüzü yalnız işin reposuna ve onun scan kayıtlarına erişir. Global listeleme, ham SQL, kurulum değiştirme ve başka repo için alt iş üretme bu arayüzde kapalıdır.
- [x] GitHub, OSV ve KEV istemcileri her işte yeniden oluşturulur; bitiş/hata/iptalde kapatılır. Token, advisory ve HTTP cookie önbellekleri temizlenir. Repo içeriği yalnız işin belleğinde işlenir; repo klonlama, geçici kaynak dosyası veya diskte kaynak cache'i oluşturulmaz. Bu, işlem belleğinin kriptografik silindiği garantisi değildir.
- [x] İşe bağlı GitHub installation token isteği yalnız ilgili repository adını ister. Repo/kurulum dışında sağlayıcı isteği reddedilir; önbellekte token olsa da yetki yeniden kontrol edilir. Mekanizma: [GitHub installation token kapsamı](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app). Gerçek GitHub App kabul testi yapılmadı.
- [x] Kuyruk hata kaydı ve worker hata logu dış servis hata mesajını içermez; yalnız hata sınıfı kaydedilir.
- [x] 005 migration, eski kapsam kanıtı olmayan pending/running işleri `cancelled` yapar. Yeni sürüme geçişte bu işler mevcut organizasyona sessizce bağlanmaz. Güncel repo için yeniden tarama planlanmalıdır.
- [x] Worker için ayrı DB rolü (`WorkerStore`, `python -m vulnforge.rls --worker-role <role>`, `WORKER_DATABASE_URL`) ve iş kanıtıyla (`vulnforge.job_id`, `vulnforge.claim_token`, `vulnforge.connection_id`, `vulnforge.organization_id`, `vulnforge.catalog_scope`) PostgreSQL FORCE RLS politikaları (`011_worker_isolation.postgresql.sql`). Ayrıcalıklı tablolara (`users`, `user_sessions`, `organizations`, `invitations`, `deliveries`, `runner_reports`, `schema_migrations`) hiç erişim verilmez; `audit_events` üzerinde yalnız `INSERT` izni vardır; `repositories` üzerinde yalnız `default_branch`, `last_sha`, `evidence_invalidated_at`, `updated_at` kolonları güncellenebilir (`connection_id` ve `installation_id` değiştirilemez).
- [x] Özel OSV (`private_osv`) advisory katalogları `org:<organization_id>` (`catalog_scope`) ve `org:<organization_id>:<canonical_id>` birincil anahtarıyla organizasyon bazında izole edilir. Sahipliği olmayan repolar için `private_osv` kuyruk işi reddedilir. Upgrade sırasında kaynağı `OSV` veya `GitHub webhook` olmayan eski ortak kayıtlar `quarantined_legacy` olarak sınıflandırılır ve müşteri/genel sorgulardan çıkarılır.
- [x] Worker kaynak dosyası veya kalıcı yerel artifact yazmaz; tüm analiz bellek içinde yürütülür.

Lease yenileme, uzun iş timeout ve dead-letter akışı VF-086 kapsamında tamamlandı. [İşletim rehberi](QUEUE_OPERATIONS_TR.md). Lease 300 saniyedir; süre dolarsa eski iş fail closed durur. İzolasyon testi yük/performans veya üretim kabulü yerine geçmez.

## Kanıt

Son doğrulama: **659 test geçti, skip yok**; bunlara geçici yerel PostgreSQL 14.23 testleri dahildir. Tek uyarı mevcut Starlette/httpx deprecation uyarısıdır. Canlı GitHub kabulü yapılmadı.

`tests/test_job_scope.py` ve `tests/test_rls.py`: SQLite ve gerçek geçici PostgreSQL üzerinde uninstall/reinstall, installation değişimi, sahiplik bağlama/silme/yeniden bağlama, lease süresinin dolması, işin yeniden alınması, başka repo/scan/global işlem reddi, ağ beklerken iptal, iş kapsamının hata sonrası temizlenmesi, iş başına istemci kapanışı, token'ın repo ile sınırlandırılması, cache temizliği, eski kuyruk migration'ı, `private_osv` organizasyon katalog izolasyonu, legacy advisory karantinası ve `WorkerStore` ham SQL / RLS sınırları (non-superuser migration sahibi dahil) test edilir.

SQLite → PostgreSQL aktarımı, boş hedefte yalnız migration hesabıyla bağlantı kimliklerini birebir korur. Aktarım transaction'ında sadece sahiplik kimliği yenileme trigger'ı geçici devre dışıdır ve commit öncesi tekrar açılır; hata rollback'i bu değişikliği de geri alır. Runtime hesaplarında trigger değiştirme izni yoktur. Kaynakta zaten eski bağlantıya ait olan bir iş aktarım sonrasında da geçersiz kalır.
