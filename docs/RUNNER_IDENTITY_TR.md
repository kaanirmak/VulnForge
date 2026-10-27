# GitHub kimliğiyle rapor kabulü — yerel önizleme

Bu akış GitHub Actions kimliğini doğrular, raporu doğru repo/organizasyon bağlantısına bağlar ve **yalnız `identity_verified_quarantined`** durumunda saklar. Gerçek proje envanteri, finding, scan veya düzeltme işi üretmez. `baseline_ready=false`, `customer_ingestion_ready=false` ve `tenant_isolation_ready=false` kalır. Operatörün eski karantina endpoint'i ve onun credential'ı ayrıdır.

## Kimlik ve sınır kontrolleri

- İmza yalnız RS256 ve GitHub'ın sabit HTTPS JWKS adresindeki RSA anahtarıyla doğrulanır. Issuer ve audience tam eşleşir. Token/header içinden URL, `jku`, `jwk`, `x5u` veya algoritma seçilmez. Duplicate JSON, unsigned/HMAC token, yanlış imza ve kritik header reddedilir.
- exp/iat/nbf integer olmalıdır; token geçerli ve en çok 600 saniyelik olmalıdır. Clock leeway yoktur; sunucu saati senkron tutulmalıdır. Ham token, jti veya request credential DB/log'a yazılmaz. Jti yalnız SHA-256 özetiyle tekrar kullanım kontrolüne girer.
- Platformun onayladığı reusable workflow **tam 40 karakter commit SHA'sıyla** sabitlenir. Token'daki `job_workflow_ref` ve `job_workflow_sha` eşleşir; repo yöneticisi platform listesinin dışındaki bir workflow'u yetkilendiremez.
- İmzalı repository ID, owner ID, repo adı, ref, SHA, caller workflow, run ID/attempt ve event kontrol edilir. Legacy ve yeni immutable `sub` biçimleri metin parçalanarak yetki verilmesinde kullanılmaz; açık immutable claim'ler ve DB politikası esas alınır.
- Yalnız protected branch üzerinde push/schedule/workflow_dispatch kabul edilir; ref canlı DB'deki ve GitHub metadata'sındaki varsayılan dal olmalıdır. `pull_request`, `pull_request_target`, Dependabot `dynamic`, tag, fork/head/base PR bağlamı ve bilinmeyen event reddedilir. `ref_protected` yoksa veya false ise kapalı kalır. PR tarama profili yerelde çalışabilir; ayrıcalıklı yükleme izni vermez.
- Gönderilen raporun repo ve SHA'sı imzalı claim'lerle aynı olmalıdır. Organizasyon rapor alanından veya token içindeki kullanıcı beyanından alınmaz; mevcut repository ownership kaydından türetilir.

GitHub'ın güncel [OIDC referansı](https://docs.github.com/en/actions/reference/security/oidc), [reusable workflow kimliği](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows) ve [issuer discovery bilgisi](https://token.actions.githubusercontent.com/.well-known/openid-configuration) esas alındı. Canlı sağlayıcı token'ıyla kabul testi yapılmadı; bu referanslar uygulama için güvenlik sertifikası değildir.

## GitHub repository doğrulaması

`GitHubMetadata`, yalnız sabit `api.github.com` adresindeki installation ve repository metadata endpoint'lerini kullanır. App JWT'siyle installation/App/suspend durumunu doğrular; kurulumun izinleri tam olarak `metadata:read` değilse reddeder. Kaynak erişimli managed App bu akışta kullanılamaz. Ardından yalnız seçili repo için **metadata:read** token ister ve cevabın izinlerini de denetler. İçerik, diff, branch içeriği veya kod endpoint'i çağrılmaz. Credential cache'i/persist'i yoktur; request token'ı ve OIDC token birbirine karıştırılmaz.

Repo ID/owner ID/default branch değerleri API müşterisinden alınmaz; bu doğrulamadan türetilir. Policy kurulurken ve her upload'da yeniden kontrol edilir. Kurulum kaldırılmış/suspend edilmiş, repo taşınmış/yeniden adlandırılmış veya metadata doğrulaması başarısızsa sonuç yazılmaz. Provider URL'leri, redirects ve proxy ortam değişkenleri credential gönderme hedefini değiştiremez.

Bu kontrol **GitHub kullanıcı hesabının installation bağlama yetkisini doğrulayan VF-024 akışının yerine geçmez**. Yerel ownership kaydı hâlâ yetkili sunucu koduyla kurulmaktadır. Bu nedenle production açılmaz ve VF-035/036 canlı kurulum/kimlik kabulü tamamlanmış sayılmaz.

## Politika kurulumu

Önizleme yalnız mevcut loopback müşteri önizlemesiyle açılır:

- `CUSTOMER_API_PREVIEW=true`, mevcut local auth ayarları;
- `SCAN_MODE=customer_runner` ve `RUNNER_OIDC_PREVIEW=true`; managed kaynak erişimiyle birlikte açılamaz;
- `RUNNER_TRUSTED_WORKFLOWS`: platformun incelediği ve yayımladığı exact `owner/repo/.github/workflows/file.yml@40_CHARACTER_SHA` referansları; wildcard/branch/tag kabul edilmez;
- metadata doğrulaması için gerçek App ID/PEM; OAuth client credential'larından ayrıdır.

Gerçek alan adı/App/incelemiş yayın henüz yokken bu ayarlar boş/kapalı kalmalıdır. Sahte prod origin veya GitHub App kaydı oluşturulmadı. Genel hostta müşteri önizlemesi config tarafından reddedilir; route'un bulunması production kabulünün açık olduğu anlamına gelmez.

Org Admin, mevcut session + Origin/CSRF ile PUT `/api/v1/organizations/{org}/runner-policy` çağırır: `repo`, `workflow_ref`. Yalnız kendi mevcut repo bağlantısı ve platform allowlist'i kabul edilir; installation metadata'sı sunucudan doğrulanır. DELETE aynı route, `repo` query'siyle politikayı iptal eder. Kaynak okuma veya yazma izni eklenmez.

Policy güncel connection ID'ye, org'a, immutable GitHub ID'lere, varsayılan dala ve onaylayan yöneticinin mevcut rolüne bağlıdır. Onaylayan kişi yetkisini kaybederse, bağlantı/dal değişirse veya workflow platform listesinden çıkarılırsa geçersizdir. Policy yenilemeden **önce** üretilen token kabul edilmez; yeni workflow job'u/token gereklidir. Saniye çözünürlüğü nedeniyle policy kurulumuyla aynı saniyede mint edilen token da reddedilebilir; sonraki saniyede başlayan job kullan.

## Upload ve tekrar teslim

POST `/api/v1/runner/reports` yalnız JSON ve Authorization Bearer GitHub OIDC token'ı kabul eder. Cookie, operatör token'ı, query credential veya serbest organization_id yetki oluşturmaz. Body 1 MB, v1 nested allowlist, kaynak/bilinmeyen alan/bilinen sır pattern reddi aynen korunur. Paket metadata'sı hassas olabilir; şema gizli kanal engeli veya anonimleştirme garantisi değildir.

Receipt anahtarı bağlantı + run ID + attempt + scan kind + canonical rapor özetine bağlıdır. JSON obje key sırası değişse de aynı rapor duplicate olur. Aynı run/kind için farklı içerik önceki kanıtın üzerine yazılamaz. Aynı jti farklı raporda kullanılamaz; tekrar teslim aynı kanıt için idempotent'tir. Yeni token'la aynı kanıt tekrar gelirse onun jti özeti de tüketilir. Code/dependency için farklı job/token kullanılır.

Doğrulama ağı beklenirken DB kilidi tutulmaz. Ardından kısa transaction'da org/repo/connection/policy ve token zamanı tekrar kontrol edilir; nonce, receipt ve audit atomik yazılır. Aynı anda gelen teslimatlar tek receipt oluşturur. İptal/kurulum değişimi/provider hatası sonrası yarım veya yeni tenant'a ait sonuç yazılmaz.

008 migration üç private tablo ekler: runner_policies, runner_receipts, runner_token_uses. PostgreSQL'de FORCE RLS ve yalnız onaylı operator runtime erişimi vardır; customer DB rolü bunları okuyamaz. Role provisioning migration sonrası yeniden çalıştırılmalıdır. SQLite→PostgreSQL aktarımı içerik/kimlik/nonce bariyerini korur. Repo kaldırılması FK cascade ile bu kayıtları da temizler; yeni bağlantının policy zamanı eski token'ı yeniden kullanmayı engeller.

## Koşucu istemcisi ve workflow

`python -I -m vulnforge.runner_upload --report ... --server FIXED_HTTPS_ORIGIN --consent-metadata-upload`, raporu önce yerelde v1 şemasıyla doğrular. Sonra yalnız GitHub'a ait Actions token endpoint'inden belirtilen audience için kısa ömürlü OIDC token ister ve yalnız onaylanan servis adresine gönderir. Runtime request token'ı servise, rapor GitHub token endpoint'ine gönderilmez. Kaynak veya ortak server secret'ı taşınmaz. Redirect yoktur; credential içeren URL reddedilir. Local HTTP yalnız ayrıca `--allow-loopback-preview` ile denenebilir. Her çağrı en fazla 15 saniye, installation doğrulaması toplam 30 saniye ağ bütçesiyle sınırlıdır.

`examples/workflows/identity-verified-runner.yml` reusable workflow **yayın şablonudur**. Aktif değildir: sabit server origin'i, incelenmiş immutable workflow commit'i ve onaylı scanner dağıtımı yoktur. Origin çağıranın input'u değildir; yayımlanacak güvenilen workflow'da sabitlenir. Kaynak kod kurulum/build/test için çalıştırılmaz; scanner checkout dışındaki ayrı runtime'dan `-I` ile çağrılır. Matrix iki ayrı job/token ile code/dependency üretir; cleanup trap'i raporları temizler. Yakalanamayan host/SIGKILL durumları için ephemeral-runner/retention sınırı devam eder.

## Kanıt ve kalan kabul

Yerel testler gerçek RSA imzası/JWKS formatı, key rotation/cooldown/timeout, yanlış issuer/audience/kid/imza/zaman, protected branch ve PR/fork bağlamı, repo/SHA/workflow eşleşmesi, API Origin/CSRF/role, kaynak/secret payload, tekrar/replay/conflict, eşzamanlı kabul, provider beklenirken erişim kaybı, non-owner operator, customer SQL reddi ve veri taşımasını kapsar. CLI → OIDC upload → ASGI intake → karantina zinciri sahte iki kimlik/metadata sağlayıcısıyla ve ağ mock'larıyla test edildi. Gerçek GitHub job'u veya private müşteri verisi kullanılmadı.

VF-037'nin privilege reddi ve VF-038'in şema/limit/filtre/dedup kod kabulü bu kapsamda tamamlandı. VF-035/036 gerçek provider/installation/workflow kabulü, VF-039 immutable dağıtım, VF-018 worker/catalog izolasyonu, kapsam/baseline promotion ve VF-094 canlı uçtan uca kabul açıktır. Quota/adalet/abuse kontrolleri ve bağımsız değerlendirme de production öncesi gereklidir; kimliği doğru bir rapor tek başına taramanın doğru/güncel olduğu kanıtı değildir.
