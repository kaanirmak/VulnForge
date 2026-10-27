# Kuyruk işletimi

Her işin bağlantı/organizasyon snapshot'ı ve tek kullanımlık claim kanıtı vardır; [izolasyon sınırları](QUEUE_ISOLATION_TR.md) ayrıca geçerlidir. Claim 300 saniye geçerlidir; çalışırken 60 saniyede bir yalnız canlı claim DB transaction'ında yenilenir. Eski bağlantı, başka claim veya süresi zaten geçmiş lease yenilenemez. Yenileme hatası işi iptal eder; yerel/provider kapıları da bir sonraki işlemde yeniden kontrol edilir.

Her iş için toplam 1800 saniye timeout vardır. İş bitince, iptal/hata/timeout olunca heartbeat ve coroutine iptal edilip beklenir; HTTP istemcileri ve cache'ler kapatılır. İşlem SIGKILL/crash ile durursa heartbeat biter, 300 saniyelik lease sonrasında yeni claim işi alabilir. Süre dolmuş eski worker sonuç yazamaz. Bu tek süreç işleyicisinin CPU/bloklayan dış kod için ayrı process kill sandbox'ı olduğu iddia edilmez.

Hata sonrası 15 × 2^attempt saniye, en çok 300 saniye backoff uygulanır. 4 deneme sonrasında durum `failed` olur ve dead-letter listesine girer. Provider hata mesajları yerine yalnız hata sınıfı log/DB kaydına girer. Otomatik sonsuz retry yoktur.

Operatör API'si:

- GET `/api/v1/operator/jobs/dead-letters?limit=50&cursor=0`: payload/claim token içermeyen, cursor'lu liste.
- POST `/api/v1/operator/jobs/{id}/retry`: yalnız failed işi yeni kimlikle kuyruğa alır. İşin bağlantı, kurulum ve organizasyonu hâlâ aynı olmalıdır; eski tenant payload'ı yeni bağlantıda oynatılamaz. İşlem audit'e yazılır; aynı orijinal iş tekrar tekrar retry edilemez. Yeni denemenin de 4 denemelik bütçesi vardır.

Dead-letter müdahalesi insan kontrolündedir. Repo bağlantısı değiştiyse eski işi retry etmek yerine güncel repo için yeni scan başlatılmalıdır. 005 migration öncesi kapsamı bilinmeyen işler iptal edilir. Tenant başına kota/adalet, ayrı DB worker rolü ve metrik/alert işletimi VF-018/087/088'de açık kalır.

SQLite ve gerçek geçici PostgreSQL testleri yenileme, iptal, timeout cleanup, eski claim/organizasyon reddi, backoff/deneme sınırı, tek kullanımlık retry ve API yetkisini kapsar.
