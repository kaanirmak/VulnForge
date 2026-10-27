# GitHub giriş ve oturum akışı

VF-013–014 — 27 Ekim 2026. Kod ve yerel protokol testleri eklendi; **gerçek GitHub App ile canlı kabul bekliyor**, bu yüzden bu iki iş henüz tiklenmedi. Proje bağlama, müşteri yetkilendirme ve tenant izolasyonu hâlâ kapalı/açık işlerdir.

## Kurulum

Giriş için GitHub App'in **client ID/client secret** değerleri gerekir; bunlar installation App ID ve PEM anahtarından ayrıdır. Kaynak erişimi istemeyen ayrı metadata App tasarımını kullan. Mevcut managed App'in geniş izinleri bir login parametresiyle azaltılamaz; App izin ayrımı VF-021–029 kapsamında tamamlanacaktır.

Gerçek değerleri sohbete/issue'ya yazmadan yerel korunan `.env` veya secret manager üzerinden birlikte yapılandır:

```dotenv
GITHUB_OAUTH_CLIENT_ID=<metadata-app-client-id>
GITHUB_OAUTH_CLIENT_SECRET=<local-secret>
PUBLIC_ORIGIN=https://your-vulnforge-domain.example
ALLOW_INSECURE_LOCAL_AUTH=false
```

`PUBLIC_ORIGIN` sabit HTTPS origin olmalı; path, trailing slash, userinfo, query ve fragment kabul edilmez. App kaydının Callback URL alanı **tam olarak** `https://your-vulnforge-domain.example/auth/github/callback` olmalı. Kullanıcı yönlendirme adresi Host/X-Forwarded-Host veya `next` parametresinden üretilmez. Bu akış public GitHub issuer'ına sabittir; GitHub Enterprise Server desteği yoktur. `GITHUB_API_URL` ayarı kimlik doğrulama hedefini değiştirmez.

HTTP geliştirme istisnası yalnız localhost/127.0.0.1/::1 ve `ALLOW_INSECURE_LOCAL_AUTH=true` ile kullanılabilir. Bu durumda production `__Host-` cookie adlarından ayrı `vf_local_` adları kullanılır. İstisna genel internete açık bir hostname için çalışmaz. HTTPS arkasında uygulamanın gördüğü scheme/host sabit origin ile eşleşmelidir; reverse proxy yalnız güvenilen bağlantılardan forwarded header kabul etmelidir. İnternete açılmadan rate limit, TLS ve ingress kontrolleri VF-082/087 ile tamamlanmalıdır.

## Girişte ne olur?

1. `/account` giriş durumunu gösterir. Yapılandırma boşsa giriş kapalıdır; `/auth/github/login` 503 döndürür.
2. Login, 10 dakika geçerli rastgele state ve ayrı PKCE verifier üretir. DB'ye yalnız state/verifier SHA-256 özetleri yazılır. Verifier tarayıcıda HttpOnly cookie'dedir; authorize isteğine yalnız S256 challenge gider. Tarama anahtarı kullanılmaz.
3. Callback sabit origin, tekil parametreler, state, süre ve tarayıcı cookie'sini doğrular. Yanlış tarayıcı/bozuk state sağlayıcıya istek göndermez. Geçerli state transaction içinde bir kez tüketilir; PostgreSQL satır kilidi eşzamanlı tekrar kullanımı engeller.
4. Sunucu kodu, client secret ve verifier'ı sabit GitHub token endpoint'ine POST eder; ardından token ile sabit `/user` endpoint'inden kimliği doğrular. Redirect izlenmez. Yanıtlar boyut/tip/tekrarlanan JSON alanı bakımından sınırlanır; hatalar kod, token, sır veya provider metnini geri yansıtmaz.
5. Yalnız immutable GitHub numeric ID ve login yerel kullanıcı modeline yazılır. Provider access/refresh token'ları DB, cookie veya log'a bilinçli olarak yazılmaz; login isteğinin belleğinde kullanılıp bırakılır. Bu, provider token'ının GitHub tarafında revoke edildiği veya bellekten kriptografik olarak silindiği anlamına gelmez. Repo bağlantısı için gelecekteki doğrulanmış akış ayrıca tasarlanacaktır.
6. Rastgele yerel oturum ve CSRF değeri üretilir; DB'de yalnız özetleri tutulur. Aynı tarayıcının önceki oturumu silinir. Sabit `/account` adresine dönülür; sorgudan gelen dönüş URL'si kabul edilmez.

Provider sözleşmeleri: [GitHub App kullanıcı yetkilendirmesi](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), [PKCE desteği](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/), [doğrulanmış kullanıcı endpoint'i](https://docs.github.com/en/rest/users/users#get-the-authenticated-user).

## Oturum sınırı

- HTTPS cookie'leri Secure, Path=/, Domain'siz ve SameSite=Lax; oturum ve verifier ayrıca HttpOnly. CSRF cookie'si sayfanın çıkış isteği için okuyabildiği ayrı rastgele değerdir.
- En fazla 8 saat; 30 dakika işlem yapılmazsa geçersiz. `/api/v1/me` yalnız oturum sahibinin iç ID, login, mutlak süre sonu ve `customer_access_ready=false` bilgisini döndürür. Oturumun yenilenmesi mutlak süre sonunu uzatmaz.
- `POST /auth/logout`, tam eşleşen Origin, header/cookie CSRF eşleşmesi ve DB'deki CSRF özeti ister; başarılı çıkış oturumu sunucuda siler ve cookie'leri temizler. Çıkış sadece yerel oturumu kapatır; GitHub hesabından çıkış yapmaz.
- Cookie müşteri oturumudur. Eski `/api/*` operatör verilerine veya runner karantinasına erişim sağlamaz; bunlar hâlâ ayrı bearer credential ister. Rol ve organization sorgu kapsamı VF-015/016 ile yalnız yerel müşteri API önizlemesinde eklendi. Default kapalı `CUSTOMER_API_PREVIEW` public origin ile açılamaz; VF-017 PostgreSQL DB izolasyonu ayrı runtime hesaplarıyla eklendi; worker/queue ve diğer VF-018–020 kontrolleri henüz tamamlanmadı. [Erişim sınırı](ORGANIZATION_ACCESS_TR.md).
- Auth/account/me yanıtları no-store ve no-referrer kullanır, frame içine alınmaz. Callback query uygulama girişinde çıkarılıp özel request state'te işlenir; standart Uvicorn access log'unda code/state query'sinin kalmadığı scope testi vardır. Dış proxy/CDN/APM logları bu kontrolün dışında kalır; callback query'leri oralarda da kaydedilmemelidir.

Süresi dolmuş state/oturumlar yeni giriş oluşturulurken temizlenir; erişilen süresi dolmuş oturum anında kaldırılır. Kesintisiz TTL worker, bütün cihazlardan çıkış, authorization revoke webhook'u, davet/üyelik kaybında iptal ve abuse kotası henüz tamamlanmadı. Yedeklere giren session hash'leri için restore/revoke politikası VF-084/089 gerektirir.

## Kanıt ve bekleyen canlı kabul

40 yerel auth testi: PKCE/cookie, state replay, başka tarayıcı, expiry, duplicate query, açık redirect/installation ID parametresini reddetme, provider redirect/bozuk-büyük yanıt/time-out, minimal kimlik kaydı, token saklamama, admin erişim ayrımı, oturum döndürme, logout CSRF, yeniden başlatma ve callback query temizliği. Gerçek PostgreSQL ayrıca aynı state'in eşzamanlı yalnız bir kez tüketilmesini ve session revoke'u test eder. SQLite→PostgreSQL testi auth state/session satırlarını da kapsar.

Canlı kabul için gerçek metadata App kaydı, HTTPS origin ve client credentials gerekir. Yetkili hesapla giriş→callback→me→çıkış, reddetme ve tekrar kullanım akışı gerçek GitHub üzerinde doğrulanmadan VF-013/014 kapanmaz. Bu aşamada yerel `.env` içinde bu üç OAuth ayarı bulunmadığı doğrulandı; sır değerleri okunabilir çıktıya alınmadı. Kullanıcı HTTPS adresinin henüz olmadığını bildirdi; canlı aşama bekler; bu durum hazır olmayan tenant erişimini açmak için gerekçe değildir.

## GitHub App kayıt hazırlığı — VF-021

`python -I -m vulnforge.github_app --origin https://YOUR_REAL_HOST --mode customer_runner` kayıt ayarlarını ve GitHub'ın resmî kayıt sayfasına önceden doldurulmuş bağlantıyı üretir. Bu komut App oluşturmaz, canlı sisteme yazmaz veya gizli anahtar üretmez. HTTPS adresi henüz olmadığı için kullanıcı adına kayıt yapılmadı. Kaynak: [GitHub'ın URL parametreli App kaydı](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-using-url-parameters).

Üç ayrı kayıt profili vardır: customer_runner yalnız metadata read; managed_read contents/pull_requests read; remediation_write contents/pull_requests write. Checks write yalnız kaynak erişimi olan profilde ayrıca istenir. App varsayılan olarak public değildir; genel kurulum ancak açık `--public` ile hazırlanır. Callback mevcut OAuth rotasına, webhook mevcut imzalı intake rotasına bağlanır. Kurulum sırasında kontrolsüz OAuth callback başlatılmaz; oturuma bağlı kendi login/state akışı korunur. Installation olayları otomatik gelir; push/PR aboneliği yalnız managed profillerde istenir. Security advisory ingestion/subscribe ve tam installation ownership akışı sonraki görevlerdir.

Hazırlanan ayarlar, gerçek App'in izinlerinin onaylandığı veya kurulum dönüşünün güvenli olduğu kanıtı değildir. VF-022–028/094 canlı hazırlık ve kabulünü gerektirir. Worker installation token'ı her işte ilgili repo adına daraltır, cache'i iş sonunda siler ve yaşam süresini GitHub cevabındaki expiry'den takip eder; 90 saniyeden az ömrü kalan token yeniden alınır. Bağlı worker'da PR yayın kapısı kapalı olduğu için token contents/pull_requests write istemez. [Repo izin ve yayın kapısı](ACCOUNT_OPERATIONS_TR.md), [GitHub token kapsamı](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).
