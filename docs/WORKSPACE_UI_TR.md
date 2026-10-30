# Çalışma alanı ve GitHub depo seçimi

30 Ekim 2026. Mevcut Python uygulamasının yerel `/account` ekranı yenilendi; ayrı bir Supabase servisi veya veritabanı eklenmedi.

## Kullanım

1. GitHub ile giriş yap; ilk kullanımda bir çalışma alanı oluştur.
2. **Proje ekle → GitHub depolarını getir** seçeneğiyle aynı GitHub hesabını doğrula.
3. App'in kurulu olduğu, Metadata read iznine sahip ve GitHub'da yöneticisi olduğun depolar listelenir. Diğer depoları GitHub kurulum ayarından ayrıca ekle.
4. Depoyu ara ve listeden seç; metadata bağlantısı onayını vererek bağla. Bağlantıda kullanıcı kimliği, repo yöneticiliği ve App metadata kanıtı yeniden doğrulanır.

Proje adına tıklanınca bağlantı, varsayılan dal, son tarama ve kapsam ayrıntıları açılır. Sol menüde genel bakış, projeler, taramalar, bulgular, proje etkisi, düzeltmeler ve erişim ayarları bulunur. Tarama kaydı varsa SARIF ve uygun bağımlılık taramaları için SBOM mevcut yetkili API üzerinden indirilir. Bulgu başlığı kanıt ayrıntılarını açar. Taramasız projelerin sayaçları güvenli/temiz sonucu ima etmez.

## Veri ve yetki sınırı

Depo keşfi mevcut session/state/PKCE akışını kullanır. Yalnız repo adları, oturum ve kuruluş çiftine bağlı, beş dakikalık süreç belleği önbelleğine alınır. Provider tokenları saklanmaz. Önbellek en fazla 128 seçim ve toplam 5.000 repo adı tutar; keşif başına 2.000 repo üst sınırı vardır. Sayfalama tamamlanamazsa kısmi liste başarı sayılmaz. Yetki callback sonrasında ve liste okunurken tekrar kontrol edilir; çıkışta o oturumun önbelleği temizlenir. Yeniden başlatma veya farklı sunucu süreci listeyi kaybedebilir; kullanıcı yeniden getirebilir. Bu önbellek bağlantı yetkisi değildir.

Kaynak erişimi, dış paket paylaşımı, runner baseline promotion ve genel müşteri kabulü açılmadı. GitHub App hâlâ hesaba özel; bu çalışma onu herkese kurulabilir bir App'e dönüştürmez. Production hizmeti ve ilk güvenilir koşucu raporu ayrı açık işlerdir.

Sağlayıcı sözleşmesi: [GitHub installation ve repository API'leri](https://docs.github.com/en/rest/apps/installations).

## Doğrulama

- PostgreSQL dahil `python scripts/check.py --postgres`: **903 test geçti, atlama yok**.
- Gerçek GitHub hesabıyla giriş, depo keşfi, listeden seçim, bağlantı ve çıkış/yeniden giriş başarılı.
- Masaüstü ekranı ve uygulama içi tarayıcıda 390 piksel mobil görünüm kontrol edildi; yatay taşma saptanmadı.
- JavaScript sözdizimi kontrolü ve yerel wheel paketi oluşturma başarılı.
- CI'nin [82. çalışması](https://github.com/kaanirmak/VulnForge/actions/runs/41064039060), YAML satır 18 hatası yüzünden iş başlatamıyordu. `--only-binary=:all:` içeren komut blok scalar içine alındı; YAML ayrıştırması ve komut türleri doğrulandı. Değişiklikler henüz GitHub'a gönderilmediğinden yeni uzak CI sonucu yoktur.
