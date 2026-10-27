# Hesap, operatör ve repo politikası

Ana adres `/account` müşteri giriş ekranına yönlenir. `/operator` tüm instance'ı görebilen ayrı operatör konsoludur; müşteri session cookie'si hiçbir operatör API'sine yetki sağlamaz. İki ekran ayrı kimlik mekanizması kullanır. Token'lar tarayıcı storage'ına kaydedilmez.

## Operatör

`OPERATOR_CREDENTIALS`, operatör kimliği → bağımsız rastgele token biçiminde JSON nesnesidir. Kimlik 2–64 güvenli karakter; token 32–128 URL-safe karakter olmalıdır. Gerçek değerleri sohbete, loga veya Git'e koyma; deployment sır yönetiminden sağla. Named credentials varsa `ADMIN_TOKEN` boş olmalıdır. Tekrarlı kimlik/token, rapor intake anahtarıyla aynı token ve geçersiz yapı reddedilir. Legacy ADMIN_TOKEN yalnız eski yerel operatör kullanımına uyumluluk içindir; müşteri kimliği değildir.

Her doğrulanan operatör isteği aktör, HTTP yöntemi ve route şablonuyla audit'e yazılır. Header, token, query veya payload yazılmaz. Anahtar döndürme: ilgili değeri değiştir/kaldır ve bütün API instance'larını yeniden başlat; eski değer yeni instance'ta reddedilir. Merkezi secret store, canlı rotasyon tatbikatı, MFA/SSO ve immutable audit ayrı açık işlerdir. Global operatör DB yetkisi müşteri yetkisi değildir; erişimini dar tut.

## Davet ve üyelik

Yerel müşteri önizlemesi session + Origin/CSRF kontrolleri ister. Yalnız Org Admin davet eder, rol değiştirir veya üyelik siler. Son yönetici silinemez/düşürülemez. Üyelik PATCH'i yeni kullanıcı eklemez; önce davet gerekir.

- POST `/api/v1/organizations/{org}/invitations`: `github_id`, `role`. Doğrulanmış kullanıcıyla eşleşmesi için immutable GitHub sayısal ID kullanılır. Tek kullanımlık token yalnız bu cevapta görünür; DB yalnız özetini tutar. 7 gün geçerli, org başına 100 aktif davet sınırı vardır. Aynı hedefe yeni davet eskisini iptal eder. Uygulama daveti kendiliğinden göndermez.
- POST `/api/v1/organizations/invitations/accept`: `token`. Yalnız hedef GitHub ID'siyle giriş yapan kişi kabul eder. Süre, iptal, önceki kabul ve davet eden yöneticinin güncel yetkisi tekrar kontrol edilir.
- DELETE `/api/v1/organizations/{org}/invitations/{id}`: daveti iptal eder.
- PATCH/DELETE `/api/v1/organizations/{org}/memberships/{user_id}`: mevcut rolü değiştirir veya üyeliği kaldırır.

Rol değişimi ve üyelik silme, hedef kullanıcının **bütün yerel session'larını** sonlandırır. Bu muhafazakâr politika diğer kuruluşlar için de tekrar giriş gerektirir. Üyelik sorgusu/RLS her istekte yeniden uygulanır. Eski yöneticinin bekleyen davetleri ve silinen üyeye ait açık davetler iptal edilir. Token'lar audit'e yazılmaz.

Repo/installation kaldırılması veya başka installation'a taşınması eski repo sahipliğini ve kayıtlarını kaldırır; önceki kullanıcı oturumu o projeye erişemez, eski kuyruk sonucu geri yazılamaz. GitHub'daki kişi/ekip erişimi değişikliğinin bütün yerel üyeliklerle otomatik uzlaştırılması için doğrulanmış installation/organization bağlantısı ve provider akışı hâlâ gereklidir (VF-024/025/028). VF-019 bu yüzden tamamen kapatılmadı.

## Repo bazlı düzeltme izni

PUT `/api/v1/organizations/{org}/remediation-policy`, `repo`, `enabled`, `packages` ve `paths` alır. Org Admin + session/CSRF zorunludur. Yalnız kendi organizasyonunun güncel repo bağlantısı seçilebilir. Paket ve dosya listeleri exact allowlist'tir; wildcard, dot-directory veya requirements.txt dışındaki hedefler reddedilir. İzin güncel bağlantı kimliğine ve onaylayan yöneticinin mevcut rolüne bağlıdır; kurulum değişimi veya yetki kaybı izni geçersiz yapar.

Repo opt-in'i tek başına yayın kanıtı değildir. Worker'ın eski doğrulanmamış PR oluşturma yolu kaldırıldı; VF-063–069 izole resolver/build/test ve güncel SHA+diff'e bağlı insan onayı sağlanana kadar `publication_ready=false` kalır. Bağlı worker token'ları global ENABLE_AUTO_PR açık olsa da contents/pull_requests read ister; gerekiyorsa checks write ayrı seçenektir. Client merge, non-draft PR ve desteklenmeyen yazma yollarını reddeder. Hiçbir otomatik merge yolu eklenmedi.

## Müşteri ekranı

Yerel önizlemede kuruluş seçimi, rol, proje sayıları, son scan, SHA, bulgular, severity filtresi, etkilenen projeler ve güncelleme adayları gösterilir. Boş liste, eksik yetki, session süresi sonu, hata ve sınırlı liste durumları ayrı metin taşır. Diğer org'un verisi response veya DOM'a gelmez. API verisi HTML olarak çalıştırılmaz; `textContent` ile gösterilir. Kurulum/bağlantı ve rapor yüklemesi genel kullanıma açılmadı; bu ekran bunlar tamamlanmış gibi davranmaz. VF-071–080'in tamamı kapatılmadı.
