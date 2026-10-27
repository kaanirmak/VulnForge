# Veri saklama, silme ve bağlantı kaldırma politikası

VF-009 — 27 Ekim 2026. Bu bir uygulama sözleşmesi ve saklama hedefidir. Otomatik TTL, tenant bazlı silme, yedeklerin yaşam döngüsü ve silme SLA'sı henüz uygulanmış değildir; müşteri hizmetinde bunlar varmış gibi vaat edilmez.

| Veri | Hedef varsayılan | Bugünkü durum |
|---|---|---|
| Ham müşteri kaynak kodu | Customer runner modunda servise yüklenmez | Rapor sözleşmesi kaynak alanlarını reddeder; uçtan uca Action henüz yok |
| Managed kaynak metni | Yalnız analiz süresince bellek | Normal DB kaydına yazılmaz; swap/core/APM izolasyonu henüz doğrulanmadı |
| Operatör karantina raporu | 7 gün | Güvenilmeyen metadata; manuel temizleme/backup gerekir; TTL worker yok |
| Giriş state / yerel oturum | State 10 dk; oturum en fazla 8 saat, idle 30 dk | State tüketimi/erişim expiry uygulanır; genel TTL worker ve yedek silme yok |
| Kullanıcı/org/üyelik | Hesap bağlıyken, silme politikasına tabi | Repo uninstall hesabı silmez; hesap silme akışı açık iş |
| Snapshot ve scan metadata | 30 gün | Otomatik süre temizliği yok |
| Son geçerli dependency inventory | Repo bağlıyken; yenisiyle değiştirilir | Mevcut davranış; disconnect sonrası temizlenir |
| Webhook delivery/job metadata | 90 gün | Payload kaydı sınırlı SHA/ref/kimlikler; otomatik TTL yok |
| Finding/impact/öneri geçmişi | 90 gün veya müşteri politikası | Repo çıkarılana kadar saklanabilir |
| Audit | 365 gün; kaynak/sır içermez | Operasyonel audit sınırlı; uninstall repo kayıtlarını da siler; immutable audit yok |
| Yedek | En fazla 30 günlük geri dönüş penceresi hedefi | Otomatik yedek/şifreleme/silme henüz yok |
| Public advisory kataloğu | Kaynak/provenance gerektikçe | Repo kaldırılması public advisory'leri silmez |

Süreler ürün önerisidir; bir yasal zorunluluk veya mevcut otomasyon iddiası değildir. Veri bölgesi ve tenant gereksinimleri yayın öncesi sözleşmeye bağlanmalıdır.

## Bağlantı kaldırma

1. Yeni source işi/rapor kabulü ve yeni installation token kullanımı durdurulur. Mevcut revoke/cache/job iptali tamamlaması VF-028–029'dadır.
2. Repo çıkarma/uninstall mevcut SQLite/PostgreSQL akışında repo, inventory, job, finding, remediation, scan, suppression, impact, repo audit, sahiplik bağı ve karantina raporlarını siler. Kullanıcı/organizasyon hesap temeli korunur; bunların silme akışı henüz yoktur.
3. Public advisory metadata'sı müşteriye ait kaynak kodu olmadığı için katalogda kalabilir.
4. Çalışan işlerin silme sonrasında veri yeniden oluşturmaması, tenant sahipliği ve stale-worker önleme ile doğrulanmalıdır; mevcut sürüm bunun tam kanıtını sağlamaz.

## Yedeklerden silme ve geri yükleme hedefi

Yayın sürümünde silme isteği kimliği, kapsam, aktif veri silme zamanı ve son yedek bitişi tutulmalıdır. Geri yükleme sonrası silme işaretleri yeniden uygulanmalı; geri yüklenen job veya installation erişimi otomatik etkinleşmemelidir. Yedekler şifreli olmalı; anahtar erişimi operatör rolünden ayrılmalıdır. Bu işler VF-084 ve VF-089'da açık kalır.

## Müşteri talebi ve kanıt

Giriş/oturum kodu yerelde test edildi; canlı kabul ve müşteri yetkilendirmesi henüz tamamlanmadı. Otomatik kişisel veri talebi/silme portalı yoktur. Kullanıcı/organizasyon tabloları bir uygulama temelidir; gerçek müşteri onboarding'i değildir. Şimdilik self-hosted operatör kendi DB/yedek politikasından sorumludur. Müşteriye açılmadan önce kapsamı doğrulanan silme API'si, retention ayarı, tamamlanma kanıtı ve destek süreci gerekir. Doğrulanmamış SLA veya hukuki uygunluk beyanı yayımlanmaz.
