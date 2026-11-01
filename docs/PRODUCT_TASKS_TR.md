# VulnForge — GitHub + Supabase Ürün Görevleri

Tarih: 1 Kasım 2026

Bu dosya hedef ürünün uygulanabilir görev listesidir. Kutular canlı kabul kanıtı olmadan tamamlandı sayılmaz. Mevcut kodda karşılığı olan özellikler yeniden yazılmadan incelenip doğrulanır. Eski teknik görevlerin ayrıntıları için `TASKS_TR.md` korunur; bu dosya yeni ürün kapsamını ve teslim sırasını belirler.

## 1. Kesinleşen kapsam

- Kullanıcı yalnız GitHub ile giriş yapar; VulnForge kendi sunucu oturumunu yönetir.
- Supabase Auth kullanılmaz.
- Supabase PostgreSQL; kullanıcı, kuruluş, bağlantı, commit, tarama ve bulgu geçmişini saklar.
- Supabase Storage özel raporları saklar. Canlı ekran güncellemeleri yetkilendirilmiş API üzerinden iletilir; doğrudan Realtime erişimi ayrıca doğrulanır.
- İlk tarama ortamı GitHub Actions'tır. Kaynak kod geçici runner ortamında incelenir.
- İlk sürüm GitHub depolarını destekler. GitLab, Bitbucket, yerel agent, Kubernetes runner ve projeye gömülen Swagger benzeri panel sonraki kapsamdır.
- Arayüz kurumsal, modern, koyu temalı ve ölçülü glassmorphism kullanır.
- Kullanıcı depo adlarını görür; yalnız seçip onayladığı depolar çalışma alanına eklenir.
- Push/PR taramaları, manuel tarama ve zamanlanmış bağımlılık kontrolü desteklenir.

## 2. Mevcut durumun doğrulanması — P0

Önceki panelde çalışan sayaç, tarama çalıştığının kanıtı değildir. Kuyruğa ekleme, runner başlangıcı ve rapor kabulü ayrı olaylardır. Mevcut metadata-only App ve customer_runner modu, kaynak erişimi isteyen managed worker ile birbirinin yerine kullanılamaz. PostgreSQL kurmak tek başına bu uyuşmazlığı çözmez. CI testlerinin geçmesi de müşteri deposu güvenlik taramasının tamamlandığı anlamına gelmez.

- [ ] Mevcut branch, API, veritabanı, App izinleri ve workflow'ların envanterini çıkar.
- [ ] GitHub login, kuruluş ve repo bağlama akışını canlı doğrula.
- [ ] `/scans/run` hatasını gerçek HTTP durumu ve sunucu kaydıyla yeniden üret; kök nedeni kaydet.
- [ ] Tarama başlatmada yalnız `project.read` yetkisinin yeterli olması sorununu gider; açık `scan.start` rol politikası tanımla.
- [ ] İlk listedeki repoyu sessizce seçmek yerine proje/branch seçimi ekle.
- [ ] İş kabul edilmeden başlayan sayacı ve kanıtsız “çalışmaya başladı” mesajını kaldır.
- [ ] Runner hazır değilse nedeni ve kurulum adımını göster.
- [ ] Mevcut testleri ve açık ürün kapılarını yeni görevlerle eşleştir; tamamlanmış kodu yeniden yazma.

Kabul: bir başlatma hatası gerçek nedenine göre görüntülenir; panel sunucunun bildirmediği çalışma durumunu göstermez.

## 3. Mimari ve veri sözleşmesi — P0

```text
GitHub login → VulnForge API ve güvenli session → çalışma alanı
GitHub olayları → doğrulama + kalıcı olay/outbox → tarama kuyruğu
Kuyruk → dispatcher → GitHub Actions → doğrulanmış rapor kabulü
Rapor → Supabase PostgreSQL/özel Storage → yetkili canlı API → panel
Zamanlayıcı → son doğrulanmış bağımlılık envanteri → yeni advisory eşitlemesi
```

- [ ] Mevcut Python API'yi koruyan dağıtım kararını yaz; frontend barındırma ile API/runner barındırmayı ayır.
- [ ] Queue için tek kaynak seç: mevcut PostgreSQL jobs veya Supabase Queues; iki bağımsız kuyruk oluşturma.
- [ ] GitHub App kurulum kimliği, GitHub kullanıcı kimliği ve workspace üyeliği arasındaki sınırları tanımla.
- [ ] Mevcut organizations/repositories tablolarını hedef workspace/project kavramlarıyla eşleştir.
- [ ] Rapor şema sürümü, boyut sınırları ve desteklenen tarama profillerini tanımla.
- [ ] Durum geçişlerini ve hangi bileşenin hangi geçişe yetkili olduğunu yaz.
- [ ] İlk sürüm için desteklenen dilleri, manifestleri ve scanner'ları açıkça listele.

## 4. Supabase kurulumu ve taşıma — P0

Hedef proje URL'si: `https://xsnivuaurhwezlaxuvro.supabase.co`.
Publishable anahtar kullanıcı tarafından sağlandı; bu dosyada çoğaltılmaz. Proje şeması veya bağlantısının doğrulandığı henüz iddia edilmez.

- [ ] Supabase proje erişimini mevcut bağlantı araçlarıyla doğrula.
- [ ] Backend için PostgreSQL bağlantısını güvenli ortam ayarına ekle; public anahtarı DB parolası olarak kullanma.
- [ ] Geliştirme, staging ve production ortamlarını ayır.
- [ ] Mevcut migration'ların Supabase PostgreSQL uyumunu incele.
- [ ] Migration sahibi, API müşteri erişimi ve worker rollerini ayır; mevcut RLS modelini koru.
- [ ] GitHub session'ının DB'de workspace yetkisine nasıl dönüştüğünü doğrula.
- [ ] Supabase Auth olmadığı için `auth.uid()` varsayımına dayanan politikalar oluşturma.
- [ ] Frontend veri erişimini VulnForge API üzerinden yap; public anahtarın tek başına müşteri yetkisi sağlamadığını doğrula.
- [ ] Publishable anahtarın gerekip gerekmediğini erişim modeline göre belirle.
- [ ] Açık şema/table grant'lerini ve RLS politikalarını doğrula.
- [ ] SQLite verisini yedekle; dry-run taşıma, satır sayısı ve ilişki doğrulaması yap.
- [ ] Oturum taşıma/yeniden giriş kararını ve geri dönüş planını yaz.
- [ ] Rapor bucket'ını private oluştur; kısa ömürlü indirme bağlantıları ekle.
- [ ] Bağlantı havuzu ve transaction scope uyumunu doğrula.
- [ ] Yedekleme, restore denemesi ve retention görevlerini tamamla.

Kabul: iki workspace'in kullanıcıları birbirinin kayıtlarını API, SQL rolü, canlı olay ve Storage yollarından okuyamaz.

## 5. Veri modeli — P0

Mevcut tabloları aşağıdaki ihtiyaçlara eşleştir; gereksiz ikinci kullanıcı/kuruluş modeli oluşturma.

- [ ] Kullanıcılar: kalıcı GitHub numeric ID, değişebilir login, oluşturma zamanı.
- [ ] Oturumlar: hash, son kullanım, sona erme ve iptal bilgisi.
- [ ] Kuruluşlar ve üyelikler: owner/admin/analyst/viewer görev eşlemesi.
- [ ] GitHub bağlantıları: installation/account numeric ID, izinler, durum, son kontrol.
- [ ] Projeler: repo numeric ID, bağlantı, workspace, default branch, güncel head SHA.
- [ ] Commit/PR gözlemleri: SHA, ref, PR/base SHA, olay ve alınma zamanı.
- [ ] Webhook teslimleri: delivery ID, işlenme durumu, tekrar işleme kanıtı.
- [ ] Tarama işleri: trigger, profil/sürüm, SHA, durum, attempt, lease ve idempotency.
- [ ] Tarama denemeleri: runner run/attempt ID, kapsam, sonuç ve hata kodu.
- [ ] İlerleme olayları: sıra numarası, aşama, sunucu zamanı ve heartbeat.
- [ ] Bulgular ve gözlemler: fingerprint, kural, önem, geçmiş ve tarama ilişkisi.
- [ ] Bağımlılık envanterleri: paket, sürüm, ekosistem, kapsam ve güncellik.
- [ ] Advisory/alias ve proje etkileri: kaynak, değişiklik zamanı ve yeniden değerlendirme.
- [ ] Triage geçmişi: aktör, gerekçe, süre ve manuel durum.
- [ ] Rapor kayıtları: private storage yolu, digest, format, boyut ve şema sürümü.
- [ ] Tarama politikaları/zamanlamaları: timezone, sonraki tetik ve kota.
- [ ] Audit/outbox kayıtları: güvenli olay içeriği ve teslim durumu.
- [ ] Foreign key, tenant kapsamı, unique index, sayfalama ve sorgu indekslerini doğrula.

## 6. GitHub giriş ve depo bağlantısı — P0

- [ ] GitHub App kullanıcı yetkilendirmesini mevcut callback/session akışıyla tamamla.
- [ ] State, PKCE, callback issuer, CSRF ve güvenli cookie kontrollerini doğrula.
- [ ] Login değişse bile kullanıcıyı numeric GitHub ID ile eşleştir.
- [ ] Oturum sona erme, iptal, çıkış ve yeniden giriş ekranlarını tamamla.
- [ ] Kişisel hesap ve GitHub organization installation seçimlerini destekle.
- [ ] Depo adlarını sayfalı getir; arama ve çoklu seçim sun.
- [ ] Repo ekleme yetkisini canlı GitHub erişimiyle doğrula.
- [ ] Bağlanmış projeleri işaretle; workspace sahiplik çakışmasını açık göster.
- [ ] Installation kaldırılması, askıya alınması, repo transferi/ad değişimini işle.
- [ ] Bağlantı sağlık ekranında son doğrulama zamanını göster.
- [ ] Yetki kaybında bekleyen işleri iptal et; geç raporların yazmasını engelle.

## 7. GitHub Actions izinleri ve kurulum — P0

- [ ] Metadata-only App'in workflow dispatch ve push aboneliği için yeterli olmadığını gerçek izin matrisiyle belgeleyip gereken minimum izinleri belirle.
- [ ] Login izinleri, olay abonelikleri, Actions dispatch/durum erişimi ve kaynak erişimini ayrı değerlendir.
- [ ] Depoya workflow ekleme için incelenebilir kurulum yönergesi/PR akışı hazırla.
- [ ] Reusable workflow/Action sürümünü immutable commit SHA ile sabitle.
- [ ] Dispatch sırasında hedef branch'in beklenen workflow dosyasını içerdiğini doğrula.
- [ ] Manuel işlemde repo, ref ve taranacak SHA'yı açık göster.
- [ ] Kalıcı paylaşılan runner secret yerine GitHub OIDC ve kısa ömürlü iş token'ı kullan.
- [ ] Runner'ın `GITHUB_TOKEN` izinlerini checkout ve gereken işler için daralt.
- [ ] GitHub Checks yayını opsiyonelse ayrı izin ve ayar olarak tanımla.

Kabul: test deposunda workflow kurulur, bir manuel iş doğru SHA ile başlatılır ve gerçek run ID kaydedilir.

## 8. Webhook ve kuyruk — P0

- [ ] HTTPS webhook endpoint'ini ve ham gövdeden imza doğrulamasını kur.
- [ ] Installation, repository numeric ID, workspace ve izinleri birlikte doğrula.
- [ ] Push, PR, installation ve installation_repositories olaylarını destekle.
- [ ] PR fork güven modelini tanımla; güvenilmeyen kodla ayrıcalıklı token kullanma.
- [ ] Delivery ID dedup ve kalıcı olay/outbox kaydını atomik yap.
- [ ] Aynı repo/SHA/profil/sürüm için job dedup oluştur; açık yeniden tarama denemesini ayrıca modelle.
- [ ] Hızlı commit akışında debounce/coalescing ve eski iş iptal politikasını belirle.
- [ ] Claim token, lease, heartbeat ve stale-worker yazma engelini doğrula.
- [ ] Workspace kotası, eşzamanlı iş sınırı ve adil sıra uygula.
- [ ] Retry/backoff, dead-letter, iptal ve timeout uygula.
- [ ] Dispatch başarısını `running` sayma; runner başlangıç kanıtını bekle.
- [ ] Kayıp webhook/run olayları için periyodik uzlaştırma ekle.

## 9. Scanner ve güvenli sonuç kabulü — P0

- [ ] Exact SHA checkout ve kontrollü tarama kapsamını uygula.
- [ ] Kod, dependency ve secret tarayıcılarını destek matrisiyle çalıştır.
- [ ] İlk sürümde container/IaC taramasının dahil olup olmadığını belirle.
- [ ] Paket envanteri çıkarma ile advisory sorgulamasını ayrı aşamalar yap.
- [ ] Kaynak/secret/snippet sızdırmadan rapor normalizasyonu yap.
- [ ] CPU, bellek, dosya/boyut, ağ ve toplam süre limitlerini uygula.
- [ ] Tarama sırasında repo build/install scriptlerini varsayılan çalıştırma.
- [ ] OIDC issuer/audience/repo ID/workflow/ref/run/attempt/SHA kontrollerini yap.
- [ ] İş token'ını job ve connection'a bağla; expiry/replay kontrolleri koy.
- [ ] SARIF/JSON/SBOM şemasını, boyutu ve içerik sınırlarını doğrula.
- [ ] Raporu private Storage'a yaz; digest ve veritabanı kaydını tutarlı tamamla.
- [ ] Güvenilir sonuç ile doğrulanmamış/eksik raporu ayır.
- [ ] İlk tam raporun baseline kabul koşullarını uygula.
- [ ] Runner çalışma alanını ve geçici credential'ları temizle.

## 10. Bulgu ve yeni güvenlik açığı eşitlemesi — P0/P1

- [ ] SAST/secret ve dependency bulguları için ayrı kararlı fingerprint kuralları tanımla.
- [ ] Satır kayması, dosya taşıma ve scanner sürümü değişimini test et.
- [ ] Yeni, devam eden, yeniden açılan ve çözülen bulguları gözlem geçmişiyle tut.
- [ ] Yalnız aynı kapsamda başarılı ve yeterli tarama sonrası kayıp bulguyu resolved yap.
- [ ] Eksik/başarısız taramada veya eski commit raporunda mevcut bulguları kapatma.
- [ ] PR bulgularını default branch baseline'ından ayrı tut.
- [ ] Triage gerekçe/sürelerini koru; süresi dolan suppression için politika uygula.
- [ ] Default branch'in en güncel geçerli raporunu atomik olarak seç.
- [ ] CVE/GHSA/OSV alias'larını birleştir; kaynak ve veri güncelliğini göster.
- [ ] Yeni commit olmasa da son doğrulanmış dependency envanterini düzenli advisory verisiyle karşılaştır.
- [ ] Paket verisinin dış servise paylaşım politikasını ve kullanıcı onayını uygula.
- [ ] Eski envanter, advisory withdrawal ve değişen severity durumlarını işle.
- [ ] Paket güncelleme önerisini desteklenen ekosistemlerde doğrula.

## 11. Canlı durum ve süreler — P0

- [ ] Sunucu durumları: queued, dispatched, runner_waiting, running, uploading, completed, failed, timed_out, cancelled.
- [ ] Queue bekleme süresi, gerçek çalışma süresi ve toplam süreyi ayrı hesapla.
- [ ] Süreleri kalıcı sunucu timestamp'lerinden üret; refresh sonrası koru.
- [ ] Worker'ın bildirdiği aşamayı göster; ölçüm yoksa yüzde uydurma.
- [ ] Son heartbeat ve son durum güncellemesini göster.
- [ ] Runner sessiz kalırsa belirlenen sürede timeout'a geçir; sayacı sonlandır.
- [ ] Kendi GitHub session modelimizle API üzerinden SSE/polling erişimini uygula.
- [ ] Doğrudan Supabase Realtime kullanılacaksa desteklenen JWT/özel kanal yetkisini doğrula; service role'u tarayıcıya verme.
- [ ] Canlı bağlantı koparsa yeniden bağlanma ve sınırlı polling ekle.
- [ ] Sayfa/kuruluş değişiminde abonelik ve timer temizliğini yap.
- [ ] Sonuç yükleme ve bulgu eşitleme bitmeden completed gösterme.

## 12. Modern kurumsal arayüz — P1

- [ ] Tasarım token'ları: renk, tipografi, boşluk, radius, gölge, blur ve katmanlar.
- [ ] Koyu tema, emerald vurgu, ölçülü saydam yüzeyler ve okunaklı kontrast.
- [ ] Blur desteklemeyen cihazlar için düz yüzey alternatifi.
- [ ] Responsive sidebar, workspace seçici, breadcrumb ve mobil gezinme.
- [ ] Klavye erişimi, focus, dialog davranışı, ekran okuyucu etiketleri ve reduced motion.
- [ ] Login: tek GitHub giriş düğmesi ve izin açıklaması.
- [ ] Onboarding: workspace → GitHub installation → repo → workflow → ilk rapor.
- [ ] Overview: gerçek tarama kapsamı, kritik bulgular, bağlantı sağlığı ve son aktivite.
- [ ] Projeler: repo arama, branch, commit, son tarama, bağlantı ve kapsam.
- [ ] Bağlantılar: installation, izin, workflow hazırlığı, son kontrol ve yeniden doğrulama.
- [ ] Taramalar: proje/ref seçimi, başlatma, zaman çizelgesi, süreler ve tekrar deneme.
- [ ] Tarama detayı: run bağlantısı, aşamalar, kapsam, hata ve rapor indirme.
- [ ] Bulgular: önem/proje/durum filtreleri, arama, sayfalama ve triage.
- [ ] Bulgu detayı: kanıt, commit, rule, geçmiş, öneri ve atama.
- [ ] Proje etkisi: paket/CVE/GHSA, güncel envanter ve önerilen sürüm.
- [ ] Ekip: üyeler, davet, roller ve son yönetici koruması.
- [ ] Ayarlar: tarama profili, zamanlama, retention ve bildirimler.
- [ ] Audit ekranı ve rapor indirme yetkileri.
- [ ] Her sayfa için loading, empty, error, stale ve permission durumları.
- [ ] Gerçek kanıt ve metodoloji olmadan güvenlik skoru veya “güvenli” iddiası gösterme.

## 13. Zamanlama ve bildirimler — P1

- [ ] Push/PR, manuel ve periyodik tarama politikaları.
- [ ] Timezone, next_run_at ve last_run_at gösterimi.
- [ ] Scheduler kesintisi, çakışan işler ve duplicate tetik kontrolü.
- [ ] Panel bildirimleri: kritik yeni bulgu, sonuç, hata ve bağlantı kaybı.
- [ ] E-posta bildirim tercihleri ve güvenli içerik özeti.
- [ ] Bildirim dedup, susturma ve workspace yetki kontrolü.
- [ ] Slack/Teams ve diğer kanalları sonraki sürüme ayır.

## 14. Yayın ve işletim — P1

- [ ] Staging domain/HTTPS ve erişilebilir API/runner callback adresi.
- [ ] GitHub App production callback/webhook ayarları ve gerekirse dağıtım erişimi.
- [ ] API container ve dispatcher çalışma ortamı seçimi; mevcut Python API uyumluluğu.
- [ ] Production sır yönetimi, anahtar rotasyonu ve log maskeleme.
- [ ] CI testleri, migration kontrolü, paket/Action sürümü ve kontrollü yayın.
- [ ] Kuyruk yaşı, tarama başarı oranı, heartbeat ve rapor kabul metrikleri.
- [ ] Alarm, hataya ait request/job ID ve müdahale yönergeleri.
- [ ] Rate limit, rapor boyutu, kota ve maliyet sınırları.
- [ ] Restore testi, servis kesintisi ve rollback provası.
- [ ] Gizlilik/veri saklama açıklaması ve pilot müşteri destek akışı.

## 15. Kabul testleri — P0/P1

- [ ] Ayrı test deposunda sahte secret ve kontrollü SAST örnekleriyle ilk tam tarama.
- [ ] Bilinen advisory örnekli dependency envanteri; harici sorgu politikası doğrulaması.
- [ ] Commit → iş → gerçek runner → rapor → bulgu ekranı uçtan uca testi.
- [ ] Manuel seçimde doğru repo/branch/SHA; iki projenin karışmaması.
- [ ] Aynı webhook/rapor tekrarında duplicate oluşmaması.
- [ ] Eski raporun yeni baseline'ı ezmemesi; eksik taramanın bulgu kapatmaması.
- [ ] Açığı düzeltip yeniden taramada uygun bulgunun resolved olması.
- [ ] Yeni commit olmadan yeni advisory'nin mevcut envanterde etki oluşturması.
- [ ] Runner kapanması, API kesintisi, retry, timeout ve iptal testleri.
- [ ] Installation iptali/rol kaybı sonrası iş ve rapor reddi.
- [ ] OIDC yanlış repo/SHA/run/attempt, replay ve büyük/bozuk rapor testleri.
- [ ] İki workspace için API/DB/Storage/canlı olay izolasyon testleri.
- [ ] Mobil, klavye, kontrast ve gerçek loading/error ekranı kontrolü.
- [ ] Ürün kapasitesine göre yük hedefi belirle; ölçüm olmadan eşzamanlı tarama kapasitesi iddia etme.

## 16. Teslim sırası ve tamamlanma tanımı

1. Mevcut hataları kanıtla; sahte ilerlemeyi düzelt ve tarama yetkisini sınırla.
2. Supabase bağlantısı, migration ve workspace veri izolasyonunu tamamla.
3. Tek GitHub test deposuna workflow kur; manuel exact-SHA taramasını çalıştır.
4. OIDC rapor kabulü ve ilk güvenilir baseline'ı tamamla.
5. Commit/PR olayları, kuyruk ve bulgu eşitlemesini tamamla.
6. Gerçek aşama/süre/timeout durumlarını canlı panele bağla.
7. Yeni advisory eşitlemesi ve zamanlamayı ekle.
8. Kurumsal arayüzü gerçek verilerle tamamla.
9. Staging ortamında iki workspace ile pilot kabulünü yap.
10. Yayın, izleme ve geri dönüş provasından sonra sınırlı müşteri pilotunu aç.

İlk teslim, yalnız düğmenin görünmesiyle tamamlanmış sayılmaz: seçilen depoda gerçek runner çalışmalı, doğrulanmış rapor saklanmalı, bir bulgu bulunmalı, düzeltildiğinde doğru kapsamda kapanmalı ve kesintide ekran gerçek hata durumuna geçmelidir.
