# Kaan'ın yapacağı ilk kurulum adımları

28 Ekim 2026. Bu liste **yalnız senin kontrolündeki test reposuyla yerel GitHub kabulü** içindir. Alan adı satın alman veya production'a açman şu aşamada gerekmiyor. Gerçek müşteri reposu, otomatik düzeltme, kaynak erişimi ve runner baseline kapıları henüz açılmadı.

## 1. Yerel test için özel bir GitHub App oluştur

[GitHub Apps / New GitHub App](https://github.com/settings/apps/new) sayfasında:

- İstediğin benzersiz bir App adı seç. Homepage URL: `http://127.0.0.1:8000`.
- Kullanıcı authorization callback adreslerini **iki ayrı kayıt** olarak ekle:
  - `http://127.0.0.1:8000/auth/github/callback`
  - `http://127.0.0.1:8000/auth/github/connect/callback`
- Callback wildcard eşleşmesini kapalı tut. Setup URL, authorization callback yerine geçmez.
- Repository izinlerinde yalnız **Metadata: read** bırak. Contents, Pull requests, Checks, Actions, Organization ve Account izinleri isteme.
- App'i yalnız kendi hesabına kurulabilir/private tut. İlk yerel testte webhook'u **Active kapalı** bırak; GitHub internetteki sunucudan bilgisayarındaki 127.0.0.1 adresine webhook gönderemez. Webhook/uninstall kabulü sonraki HTTPS aşamasıdır.
- App'i kendi hesabındaki, hassas veri içermeyen **tek bir test reposuna** kur. “All repositories” seçme. Test reposunda yönetici olmalısın.

GitHub'ın [yerel login örneği](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-a-login-with-github-button-with-a-github-app) localhost callback kullanımını; [callback belgesi](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url) çoklu callback ve wildcard sınırlarını açıklar. Bu adresler production adresi değildir.

## 2. Dört alanı korumalı yerel dosyaya yaz

Projede `.env` dosyası hazırlandı; yalnız dosya sahibi okuyabilir ve Git tarafından dışlanır. Webhook ve yerel operatör için bağımsız rastgele sırlar üretildi; sohbete veya Git'e yazılmadı. OAuth alanları sen doldurana kadar başlatma kontrolü eksik kurulum gösterir.

App ayarlarından aşağıdaki alanları `.env` içine ekle:

| Alan | Nereden alınır? |
|---|---|
| `GITHUB_APP_ID` | App ID; sayısal değer. |
| `GITHUB_OAUTH_CLIENT_ID` | Aynı GitHub App'in Client ID değeri; App ID değildir. |
| `GITHUB_OAUTH_CLIENT_SECRET` | Aynı App'te Generate a new client secret ile üretilen değer. |
| `GITHUB_PRIVATE_KEY_PATH` | Generate a private key ile indirilen PEM dosyasının bilgisayarındaki tam yolu. PEM içeriğini buraya yapıştırma. Dosyayı proje klasörünün dışında sakla. |

Sırları, PEM içeriğini veya `.env` ekran görüntüsünü sohbete gönderme. Hazırlanan dosyada yerel origin, customer-runner modu ve local preview ayarları yer alır; diğer güvenlik kapılarını değiştirme. İzin kontrolü dosyayı yeterince özel bulmazsa kabulden önce düzelteceğiz.

Bitince yalnız **“App kuruldu, .env hazır, test repom: sahip/proje”** yazman yeterli. Repo adı hassassa onu da yereldeki bağlantı formuna girebilirsin.

## Sonrasında birlikte yapacağımız doğrulama

Sırları göstermeyen `python -m vulnforge.setup_check --env-file .env` kontrolünü çalıştıracağız. Bu araç `.env`'i komut olarak çalıştırmaz; yalnız sınırlı literal alanları okur. Provider isteği ve DB yazması yapmaz. “Local configuration ready” production veya canlı kabul kanıtı değildir.

Ardından yerel uygulamada senin GitHub girişin, kuruluş oluşturma, açık metadata onayı ve test projesini bağlama akışını gerçek sağlayıcıyla deneyeceğiz. Repo yetkisi olmayan hesap, iptal/tekrar kullanım ve bağlantı değişimi reddini de kontrol edeceğiz. Kaynak kod okunmayacak; proje önce koşucu raporu bekleyecek.

## Benden kalan işler; bunları sana yaptırmıyorum

Tüm P0 görevleri bitmiş değildir. Worker için job-scoped DB rolü/private katalog, doğrulanmış runner envanterinin baseline'a alınması, immutable Action dağıtımı, ingress/kota, secret store ve backup/restore, HTTPS webhook yaşam döngüsü ve bağımsız kabul kapıları hâlâ açık. Bunlar [ana görev listesinde](TASKS_TR.md) boş tutulur; alan adı/hesap bilgisi sağlamak kod eksiklerini otomatik kapatmaz.

Production alan adı, staging/production sağlayıcısı, özel PostgreSQL ve secret store seçimlerini **daha sonraki dağıtım adımında** netleştireceğiz. Şimdi altyapı satın alma veya gerçek müşteri verisi yükleme adımı yoktur.
