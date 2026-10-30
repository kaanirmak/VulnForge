# VulnForge Müşteri Kurulum, İzin, Koşucu, Kaldırma ve Sorun Giderme Rehberi

Bu kılavuz, kuruluşunuzun VulnForge platformunu GitHub depolarınızda güvenli bir şekilde kurması, çalıştırması, yönetmesi ve gerektiğinde tüm verileriyle kaldırması için gereken adımları ve izin gerekçelerini açıklar.

---

## 1. GitHub App Kurulumu ve İzin Açıklamaları

VulnForge, en az yetki (least-privilege) ilkesine sıkı sıkıya bağlıdır. Kuruluşunuzun kod gizliliği politikalarına göre iki farklı çalışma modu desteklenir:

### 1.1. İzin Matrisi ve Gerekçeler

| İzin | Seviye | Kullanım Amacı ve Gerekçe |
|---|---|---|
| **Metadata** | `Read-only` | Zorunlu. Depo adı, varsayılan dal ve kurulum kimliğini doğrulamak için kullanılır. Kaynak koda erişim sağlamaz. |
| **Pull Requests** | `Read & Write` | Güvenlik açığı tespit edildiğinde doğrulanmış otomatik düzeltme (patch) PR'ı açmak ve PR durumunu güncellemek için. |
| **Checks / Commit Statuses** | `Read & Write` | PR kontrollerinde güvenlik durumunu (`success` / `failure`) ve bulgu özetini bildirmek için. |
| **Repository Contents** | `No Access` (Müşteri Koşucusu Modu) | Kaynak koda **erişim istenmez**. Tarama tamamen sizin GitHub Actions ortamınızda gerçekleşir. |
| **Repository Contents** | `Read-only` (Yönetilen Bulut Modu) | Sadece `requirements.txt`, `package-lock.json`, `go.mod` gibi manifest dosyalarını okumak için kullanılır. |

---

## 2. Müşteri Koşucusu (Customer Runner) Entegrasyonu

Kaynak kodunuzun VulnForge sunucularına asla çıkmasını istemiyorsanız, **Müşteri Koşucusu Modu**'nu kullanın. Bu modda bağımlılık tespiti ve SBOM çıkarımı tamamen kendi GitHub Actions koşucunuz üzerinde çalışır ve VulnForge'a sadece izin verilen JSON Schema v1 formatındaki metadata iletilir.

### 2.1. Örnek GitHub Actions İş Akışı (`.github/workflows/vulnforge.yml`)

```yaml
name: VulnForge Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  vulnforge-scan:
    name: Dependency & Vulnerability Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run VulnForge Isolated Runner Action
        uses: vulnforge/action-scan@v1
        with:
          api_endpoint: 'https://api.vulnforge.com'
          connection_id: ${{ secrets.VULNFORGE_CONNECTION_ID }}
          upload_metadata_only: 'true'
```

---

## 3. Depo Bağlantısını Kesme ve Kaldırma (Uninstallation)

### 3.1. GitHub Üzerinden Kaldırma
1. GitHub kuruluşunuzda **Settings -> GitHub Apps -> VulnForge** sayfasına gidin.
2. **Uninstall** butonuna tıklayın.
3. VulnForge anında `installation.deleted` webhook'unu alır, depo sahipliklerini geçersiz kılar ve tarama kuyruklarını durdurur.

### 3.2. Müşteri Verilerini Tamamen Temizleme (GDPR / Purge)
Kuruluşunuza ait tüm tarama geçmişini, bağımlılık envanterini ve bulguları kalıcı olarak silmek için:

```bash
curl -X DELETE "https://api.vulnforge.com/api/v1/organizations/{organization_id}/data" \
  -H "Authorization: Bearer <ORGANIZATION_ADMIN_TOKEN>"
```

Bu işlem:
- Depolara ait tüm `findings`, `scans`, `dependency_inventory` kayıtlarını fiziksel olarak siler (`DELETE`).
- Şifrelenmiş yedeklerden müşteri anahtarı imha edilir.
- İşlem değişmez audit günlüğünde kayıt altına alınır.

---

## 4. Sorun Giderme (Troubleshooting)

### Soru 1: Webhook teslimatı "403 Invalid webhook signature" hatası veriyor.
- **Neden**: GitHub App Webhook Secret ile VulnForge üzerindeki `WEBHOOK_SECRET` uyuşmuyor.
- **Çözüm**: Secret rotasyonu sırasında grace-period kullanın veya VulnForge kasa (`SecretVault`) ayarlarından webhook secret'ını güncelleyin.

### Soru 2: Webhook yanıtında "429 Ingress rate limit exceeded" alıyorum.
- **Neden**: Belirli bir IP veya depodan kısa sürede aşırı sayıda burst webhook gönderildi.
- **Çözüm**: HTTP yanıtındaki `Retry-After` başlığında belirtilen saniye kadar bekleyin; GitHub Webhook altyapısı otomatik olarak yeniden deneyecektir.

### Soru 3: Müşteri koşucusu raporu "400 Schema validation failed" ile reddedildi.
- **Neden**: Rapor yükünde bilinmeyen alanlar veya yetkilendirilmemiş dosya yolları tespit edildi.
- **Çözüm**: `runner_report.py` JSON Schema v1 kurallarına uyun; yolların mutlak sistem yolları yerine göreli pseudonym yollar içerdiğinden emin olun.

### Soru 4: Oturum sona erdiğinde arayüz yanıt vermiyor.
- **Neden**: 8 saatlik oturum süresi dolmuş olabilir.
- **Çözüm**: Sağ üst köşedeki "Giriş Yap" düğmesini kullanarak GitHub OAuth ile oturumu yenileyin.

