# VulnForge Felaket Kurtarma, Yedekleme ve Dağıtım Rollback Runbook'u

Bu doküman, VulnForge altyapısının olağanüstü durumlarda, veri kaybı veya hizmet kesintisi senaryolarında kurtarılmasını, RPO/RTO hedeflerini, yedekleme/şifre çözme tatbikatlarını ve güvenli dağıtım rollback prosedürlerini tanımlar.

---

## 1. RPO ve RTO Hedefleri

| Metrik | Hedef Süre | Tanım ve Garanti |
| :--- | :--- | :--- |
| **RPO (Recovery Point Objective)** | **$\le$ 15 Dakika** | Felaket durumunda tolere edilebilecek azami veri kaybı süresi. Veritabanı WAL/PITR ve 15 dakikalık şifreli snapshot'lar ile sağlanır. |
| **RTO (Recovery Time Objective)** | **$\le$ 30 Dakika** | Kesinti başlangıcından sistemin standby ortamda tam doğrulanmış şekilde tekrar yayına girmesine kadar geçen azami süre. |

---

## 2. Şifreli Yedekleme Mimarisi

- **Şifreleme Algoritması**: AES-256-GCM (`VFENC1\x00` formatı, 12-byte rastgele nonce ve 16-byte cryptographic authentication tag).
- **Anahtar Ayrımı**: Yedek şifreleme anahtarları müşteri veritabanında saklanmaz; izole KMS / Vault veya çevrimdışı yedek anahtarlığı (`VF_BACKUP_ENCRYPTION_KEY`) üzerinden yönetilir.
- **WORM / Immutable Depolama**: Yedekler, değiştirilemez ve silinemez nesne kilidi (Object Lock / WORM) etkin bucket'larda 90 gün saklanır.

---

## 3. Adım Adım Felaket Kurtarma Prosedürü

1. **Olay İlanı (Incident Declaration)**:
   - Kritik altyapı arızası veya ana bölge kesintisinde Incident Commander tarafından felaket modu ilan edilir.
2. **Yedek Alma ve Doğrulama**:
   - En son doğrulanmış şifreli yedek paketi çekilir.
   - SHA-256 hash ve bütünlük doğrulaması yapılır.
3. **Şifre Çözme ve Geri Yükleme**:
   - `vulnforge.encryption.restore_encrypted_backup` çalıştırılarak yeni izole PostgreSQL veya SQLite örneğine yüklenir.
4. **Şema ve RLS Doğrulaması**:
   - `python -m vulnforge.migrate` çalıştırılarak şemanın güncelliği ve RLS politikalarının devrede olduğu (`ENABLE ROW LEVEL SECURITY`) teyit edilir.
5. **Veri Bütünlüğü ve Tenant İzolasyon Kontrolü**:
   - Tenant sayısı, açık bulgular, son tarama zamanları ve audit olayları doğrulanır.
6. **Trafik Değişimi**:
   - Ingress/DNS yönlendirmesi yeni doğrulanmış kümeye çevrilir.
   - Kaçırılan GitHub webhook'ları için `deliveries` tablosu kontrol edilerek backfill tetiklenir.

---

## 4. Dağıtım Rollback (Deployment Rollback) Runbook'u

VulnForge, kesintisiz geri alma için **N-1 Geriye Dönük Şema Uyumluluğu (Expand & Contract)** politikasını zorunlu kılar.

### 4.1. Şema Değişiklik Kuralları
- **Yasak İşlemler**: Tek adımda kolon silme, kolon tipi daraltma veya mevcut versiyonun yazamayacağı zorunlu (NOT NULL default'suz) kolon ekleme.
- **Kural**: Her şema değişikliği en az bir sürüm boyunca hem mevcut ($N$) hem de önceki ($N-1$) kod versiyonuyla çift yönlü çalışabilir olmalıdır.

### 4.2. Rollback Adımları
1. **İmaj Geri Alma**:
   - Konteyner orkestratöründe (Kubernetes/Cloud Run) anında önceki stabil imaj tag'ine dönülür:
     ```bash
     kubectl rollout undo deployment/vulnforge-api
     kubectl rollout undo deployment/vulnforge-worker
     ```
2. **Sağlık Kontrolleri**:
   - `/health` ve `/api/v1/organizations/{org_id}/health` endpoint'leri üzerinden 200 OK yanıtları ve DB bağlantı havuzu izlenir.
3. **Kuyruk Temizliği / Güvenliği**:
   - Hatalı sürüm tarafından işlenirken başarısız olmuş veya `lease_until` süresi dolmuş işler (`Store.claim`) otomatik olarak geri alınır ve dead-letter logları operatör tarafından gözden geçirilir.

---

## 5. Otomatik Felaket Kurtarma Tatbikatı (Drill Automation)

Tatbikatlar aylık periyotlarla otomatik olarak çalıştırılır:
- Canlı veritabanından şifreli anlık görüntü alınır.
- Boş bir geçici ortama geri yüklenir.
- Tenant izolasyonu, bulgu sayıları ve veri tutarlılığı test edilir.
- RPO ve RTO süreleri ölçülerek standartlara uyum raporlanır.

