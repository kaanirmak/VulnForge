# GitHub Actions koşucusu kurulumu

Bu yönerge, VulnForge'un GitHub App kimliğinden ayrı olan tarama koşucusunu
kurar. App yalnız seçilen depoların metadata bilgilerine erişir; kaynak kodu
GitHub Actions çalışma alanından dışarı çıkarılmaz.

## Ön koşullar

- VulnForge API, sabit bir HTTPS origin üzerinden erişilebilir olmalıdır.
- Hedef depo VulnForge çalışma alanına bağlanmış olmalıdır.
- Organizasyon yöneticisi, workflow için kullanılacak self-hosted runner'ı
  yönetiyor olmalıdır.
- Runner etiketleri `self-hosted`, `linux`, `vulnforge` olmalıdır. PR'lar için
  kalıcı/ayrıcalıklı runner kullanılmaz.
- Runner üzerinde incelenmiş VulnForge dağıtımı `/opt/vulnforge` altında
  bulunmalıdır; checkout içindeki kod tarama aracını değiştiremez.

## Workflow'u depoya ekleme

1. `examples/workflows/identity-verified-runner.yml` dosyasını hedef depoya
   `.github/workflows/vulnforge.yml` olarak bir inceleme PR'ı ile ekleyin.
2. `VF_SERVER` değerini yalnız VulnForge'un sabit HTTPS adresiyle değiştirin.
   Caller input, repository variable veya yönlendirilebilir bir URL kullanmayın.
3. Checkout Action referansını ve kullanılacak reusable workflow referanslarını
   tam commit SHA ile sabitleyin. Dal, tag veya `@main` kabul edilmez.
4. Workflow'a yalnız gerekli izinleri verin: `contents: read` ve OIDC rapor
   kimliği için `id-token: write`. `contents: write`, `pull-requests: write`,
   secret erişimi ve `pull_request_target` eklemeyin.
5. Workflow dosyasını varsayılan branch'e bir yönetici incelemesiyle birleştirin.

## VulnForge tarafında doğrulama

1. Çalışma alanındaki proje ayrıntılarında GitHub bağlantısının **Bağlı**
   olduğunu doğrulayın.
2. OIDC runner policy'sini yalnız platform tarafından onaylanan, commit-pinned
   workflow referansı için etkinleştirin.
3. Workflow dispatch'i seçilen branch ve exact SHA üzerinde başlatın.
4. VulnForge, GitHub OIDC token'ındaki repo numeric ID, owner ID, workflow,
   ref, run/attempt ve SHA'yı doğrular. Eşleşmeyen raporlar baseline'a yazılmaz.
5. İlk raporu yalnız kapsamı yeterliyse baseline kabul edin. Eksik veya başarısız
   rapor eski bulguları kapatmaz.

## Güvenlik sınırları

- `GITHUB_TOKEN`, VulnForge API'ye gönderilmez.
- Kalıcı bir paylaşılmış upload secret kullanılmaz; runner kısa ömürlü OIDC
  kimliğiyle rapor yollar.
- Raporlar önce doğrulanır; ham kaynak, secret veya source artifact yüklenmez.
- Rapor kabulü ve baseline'a terfi ayrı olaylardır. Kimliği doğrulanmış rapor,
  tek başına taramanın tamamlandığı anlamına gelmez.

## Canlı kabul kanıtı

Kurulum ancak şu kanıtlarla tamamlanmış sayılır: GitHub Actions run URL'si,
doğru SHA, doğrulanmış runner receipt ID, kaydedilmiş scan attempt ve panelde
görünen kapsam/bulgular. Bu kanıtlar yoksa panel “ilk koşucu raporu bekleniyor”
durumunda kalmalıdır.
