# Kuyruk bağlantısı ve iş sınırı — VF-018 ilerleme kaydı

27 Ekim 2026. VF-018'in ilk bölümü uygulanmıştır; maddenin tamamı henüz bitmemiştir. Müşteri alımı ve `tenant_isolation_ready` kapalı kalır.

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

## Açık kalan kabul koşulları

- [ ] Worker için ayrı DB rolü ve job kanıtıyla PostgreSQL politikası. Şimdiki scheduler/worker operatör bağlantısı global yetkilidir; `JobStore` uygulama sınırıdır, keyfi SQL çalıştırabilen ele geçirilmiş bir worker'a karşı DB izolasyonu değildir.
- [ ] Özel OSV advisory kataloglarını organizasyon/bağlantı namespace'ine ayır. Mevcut ortak advisory kataloğu bu garantiyi vermez. Bu nedenle `private_osv` modundaki kuyruk taraması, kaynak okumadan ve scan oluşturmadan açık hata ile reddedilir. Public OSV için mevcut paylaşım izni ve paket allowlist kontrolleri sürer. Eski özel katalog kayıtları için sınıflandırma/taşıma da gereklidir.
- [ ] Yeni çıktı/indirilebilir rapor veya disk cache'i eklendiğinde aynı kapsamı uygula ve silme testlerini ekle. Şu an worker kaynak dosyası/artifact yazmaz; karantina runner raporları hâlâ ayrı operatör alımındadır.

Lease yenileme, uzun iş timeout ve dead-letter akışı VF-086 kapsamında tamamlandı. [İşletim rehberi](QUEUE_OPERATIONS_TR.md). Lease 300 saniyedir; süre dolarsa eski iş fail closed durur. İzolasyon testi yük/performans veya üretim kabulü yerine geçmez.

## Kanıt

Son doğrulama: **522 test geçti, skip yok**; bunlara geçici yerel PostgreSQL 14.23 testleri dahildir. Tek uyarı mevcut Starlette/httpx deprecation uyarısıdır. Wheel paketi yeniden oluşturuldu; 16 migration kaynağı ve iki HTML ekranı paket içeriğinde doğrulandı. Canlı GitHub kabulü yapılmadı.

`tests/test_job_scope.py`: SQLite ve gerçek geçici PostgreSQL üzerinde uninstall/reinstall, installation değişimi, sahiplik bağlama/silme/yeniden bağlama, lease süresinin dolması, işin yeniden alınması, başka repo/scan/global işlem reddi, ağ beklerken iptal, iş kapsamının hata sonrası temizlenmesi, iş başına istemci kapanışı, token'ın repo ile sınırlandırılması, cache temizliği, eski kuyruk migration'ı ve özel katalog kapısı test edilir. Mevcut RLS, aktarım ve uygulama testleri birlikte tekrar çalıştırılır.

SQLite → PostgreSQL aktarımı, boş hedefte yalnız migration hesabıyla bağlantı kimliklerini birebir korur. Aktarım transaction'ında sadece sahiplik kimliği yenileme trigger'ı geçici devre dışıdır ve commit öncesi tekrar açılır; hata rollback'i bu değişikliği de geri alır. Runtime hesaplarında trigger değiştirme izni yoktur. Kaynakta zaten eski bağlantıya ait olan bir iş aktarım sonrasında da geçersiz kalır.
