# VulnForge Güvenlik Olayı Müdahale ve Alarm Runbook'u (Incident Response Playbook)

Bu doküman, kritik güvenlik olaylarında (anahtar sızıntısı, yetkisiz erişim, tehdit istihbaratı kesintisi, PR spam / kötüye kullanım) izlenecek standart operasyon prosedürlerini (SOP), acil durum kapatma anahtarlarını (killswitch) ve alarm akışlarını tanımlar.

---

## 1. Olay Sınıflandırması ve Müdahale Süreleri (SLA)

| Seviye | Tanım | İlk Müdahale SLA | Örnek Olay |
| :--- | :--- | :--- | :--- |
| **SEV-0 (Kritik)** | Doğrulanmış veri sızıntısı, anahtar sızıntısı, RCE, RLS izolasyon ihlali. | **$\le$ 15 Dakika** | GitHub App private key veya DB şifresinin sızması, çapraz müşteri verisi görme. |
| **SEV-1 (Yüksek)** | Olay zinciri kesintisi, yetkisiz erişim denemeleri, PR spam saldırısı. | **$\le$ 30 Dakika** | Webhook imza doğrulama bypass denemesi, otomatik PR flooder. |
| **SEV-2 (Orta)** | Tehdit feed'i kesintisi, tekil müşteri oturum tutarsızlığı. | **$\le$ 2 Saat** | OSV API 4 saattir erişilemiyor, bayat istihbarat alarmı. |

---

## 2. Senaryo Bazlı Müdahale Akışları

### 2.1. Senaryo A: Anahtar / Sır Sızıntısı (Secret Compromise)
1. **Tespit**: GitHub Secret Scanning, operatör bildirimi veya log taraması ile tespit edilir.
2. **İptal ve Çift Anahtarlı Rotasyon**:
   - `SecretVault.rotate_secret` ve `IncidentManager.rotate_compromised_credential` kullanılarak yeni anahtar devreye alınır.
   - Eski anahtar grace-period sonrası tamamen iptal edilir.
3. **Adli Bilişim (Forensics)**:
   - Sızan anahtarın kullanıldığı zaman aralığındaki tüm `audit_events` kayıtları filtrelenir (`SELECT * FROM audit_events WHERE created_at >= ?`).
   - Yetkisiz bir işlem (veri çekme, PR açma, yetki artırma) yapılıp yapılmadığı incelenir.
4. **Müşteri Bildirimi**:
   - Müşteri verisini etkileyen bir durum varsa 72 saat içinde şeffaf ihlal bildirimi yayınlanır.

### 2.2. Senaryo B: Yetkisiz Erişim ve Hesap İhlali
1. **Oturum İptali (Session Revocation)**:
   - `IncidentManager.revoke_compromised_sessions` çağrılarak şüpheli kullanıcının tüm aktif oturumları anında sonlandırılır.
2. **Yetki Düşürme / Askıya Alma**:
   - Organizasyon üyeliği geçici olarak `suspended` veya `viewer` durumuna çekilir.
3. **IP ve Aktör Engelleme**:
   - Kötü niyetli IP adresleri `TenantQuotaManager.record_abuse_violation` üzerinden blok listesine alınır ve WAF/Ingress düzeyinde kesilir.

### 2.3. Senaryo C: Tehdit İstihbaratı / Feed Kesintisi (Feed Outage)
1. **Belirti**: `freshness.assess_scan` bayat uyarısı verir (`intelligence_stale`).
2. **Otomatik Koruma**:
   - VulnForge, bayat veya doğrulanamayan feed ile bulgu kapatmayı (`finding_resolved`) reddeder.
   - Yeni taramalar `incomplete_intelligence` bayrağı ile işaretlenir, yanıltıcı "güvendesiniz" raporu verilmez.
3. **Operatör Müdahalesi**:
   - Alternatif ayna (mirror) veya önbellek sunucularına geçiş yapılır (`OSV_API_URL` fallback).

### 2.4. Senaryo D: PR Spam / Otomasyon Taşkını (PR Flood Attack)
1. **Acil Durdurma Anahtarı (Emergency Killswitch)**:
   - `IncidentManager.trigger_emergency_killswitch("auto_pr", "PR spam alert", operator_actor)` çağrılarak otomatik PR oluşturma tüm sistemde veya ilgili organizasyonda anında durdurulur.
2. **Kuyruk Temizliği**:
   - Bekleyen `remediation_publish` işleri iptal edilir (`Store.discard_job`).
3. **GitHub API Limiti Koruma**:
   - GitHub App rate limit durumu kontrol edilir; taşkına neden olan repo bağlantısı askıya alınır.

---

## 3. Otomatik Alarm Sinyalleri ve Eşikleri

- **Stale Feed Alarmı**: Son başarılı OSV/GHSA ingestion üzerinden $> 86400$ saniye (24 saat) geçtiğinde tetiklenir.
- **PR Flood Alarmı**: 1 saat içinde bir organizasyonda $> 20$ otomatik PR oluşturulmaya çalışıldığında tetiklenir.
- **Brute-Force / Abuse Alarmı**: 5 dakika içinde 15'ten fazla 401/403/CSRF hatası alındığında aktör geçici olarak bloklanır.
