# VulnForge veri işleme bildirimi — teknik taslak

27 Ekim 2026. Bu metin mevcut teknik davranışı açıklar; yayımlanmış müşteri sözleşmesi, DPA veya mevzuata uygunluk onayı değildir. Hizmeti sunan tüzel kişi, iletişim, veri bölgesi, uygulanacak hukuk ve gerçek retention uygulaması seçilmeden genel müşteri metni olarak kullanılmamalıdır.

## İşlenen veriler

Varsayılan customer_runner modunda sunucu kaynak dosyalarını GitHub'dan almaz. Operatör karantinasına repo adı, commit SHA, paket adı/sürümü/ekosistemi, manifest digest'i, hash'lenmiş yollar, izinli kural kimlikleri, severity, satır ve kapsam sayaçları yüklenebilir. Ham kod, diff, snippet ve token alanları kabul edilmez. Hash'lenmiş yol anonimleştirme sayılmaz. Operatör raporu güvenilir scan veya otomatik düzeltme yetkisi üretmez.

Managed mode açıkça etkinleştirilirse seçilen repo dosyaları analiz için sunucu belleğine alınır. Dosya yolları, paketler ve bulgu metadata'sı DB'ye kaydedilebilir; normal akışta tam kaynak dosyası DB'ye yazılmaz. Bellek/swap/core dump/APM ve altyapı logları için kalan kontroller tamamlanmadan kaynak gizliliği garantisi verilmez.

GitHub webhook'ları sağlayıcının gönderdiği metadata'yı bellekte taşır. Tam webhook gövdesi normal DB akışına yazılmaz; delivery/job kimlikleri ve gerekli sınırlı iş bilgisi saklanır. Yerel müşteri API önizlemesinde rol/org sorgu kapsamı uygulanır; müşteri kapısı varsayılan kapalıdır ve public origin ile açılamaz. PostgreSQL müşteri verisi için RLS ve ayrı runtime hesapları eklendi; tam worker/queue/cache tenant izolasyonu henüz yoktur.

GitHub hesap girişi ayrıca yapılandırılırsa GitHub numeric kullanıcı ID'si ve login saklanır; provider access/refresh token'ı yalnız giriş isteğinin belleğinde kullanılır, DB/cookie'ye yazılmaz. Yerel oturum ve state değerlerinin yalnız özetleri DB'de saklanır. GitHub girişi henüz canlı kabulden geçmedi ve müşteri proje verilerine erişim vermez.

## Dış servisler

OSV sorguları varsayılan olarak kapalıdır. Public OSV ancak açık paylaşım ayarı ve tam paket allowlist'i ile kullanılabilir; onaysız veya private pattern'e uyan paket varsa istek gönderilmez. Sorguda ekosistem, paket adı ve sürüm paylaşılır. Bu bilgiler teknoloji yığını veya özel paket isimleri hakkında ipucu verebilir. Operatör kendi HTTPS OSV uyumlu servisini seçebilir; ağ izolasyonu ayrıca sağlanmalıdır. LLM sağlayıcısına kaynak kodu gönderilmez; model entegrasyonu yoktur.

## Kontrol ve silme

Operatör kaynak erişimini ve public metadata paylaşımını kapatabilir. GitHub kurulumunu kaldırma ve repo silme mevcut repo kayıtlarını temizler; yedek TTL, çalışan iş iptali ve müşteri bazlı silme portalı henüz tamamlanmadı. Saklama hedefleri `DATA_RETENTION_TR.md` dosyasındadır; bugün otomatik uygulanıyor sayılmaz.

## İzinler ve sorumluluk sınırı

Tarama yalnız yetki verilen repolarda yapılmalıdır. Güncelleme önerileri insan incelemesi gerektirir; yayımlanmış sürüm, build/uyumluluk ve test sonucu garanti edilmez. Üretim dağıtımı veya otomatik merge yapılmaz. Özel müşteri repolarını kullanan genel hizmet, tenant ve koşucu güvenliği kabul kapıları tamamlanmadan açılmaz.
