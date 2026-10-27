# Kullanıcı, organizasyon, üyelik ve repo sahipliği temeli

VF-012 — 27 Ekim 2026. SQLite/PostgreSQL migration 002 ve `vulnforge/identity.py` kalıcı model sağlar. **GitHub giriş/oturum kodu eklendi ve yerelde test edildi; canlı kabul bekliyor. Müşteri API önizlemesinde rol/org sorgu sınırı vardır; PostgreSQL DB sınırı da eklendi; worker/cache/queue genelinde tenant izolasyonu henüz tamamlanmadı.** [Giriş sınırı](GITHUB_LOGIN_TR.md). Kimlik metotları yalnız güvenilen sunucu kodundan çağrılır; müşteri tarafından gönderilen user/org ID'sini yetki kabul eden HTTP endpoint eklenmedi.

| Varlık | Kimlik ve ilişki | Kural |
|---|---|---|
| User | İç UUID + unique immutable GitHub numeric ID | Login değişebilir; aynı GitHub ID aynı iç kullanıcıyı korur. Giriş callback'i sunucuda doğrulanmış OAuth kullanıcı yanıtından kaydeder. |
| Organization | UUID + ad + oluşturan kullanıcı | Kurucu kayıtlı olmalı; oluşturma ve ilk admin üyeliği atomiktir. Bu iç çalışma alanı bir GitHub organizasyonuyla aynı varlık varsayılmaz. |
| Membership | Organization/user birleşik anahtar | org_admin, maintainer, analyst, viewer, auditor. Üyelik atamasını yalnız mevcut org_admin yapabilir. |
| Repository ownership | Kayıtlı repo → tek organization | Yalnız org_admin, önceden kayıtlı repo ve sunucu doğrulama referansı. Başka org'a ait repo sahiplenilemez; uninstall ile bağ silinir. |

Son admin'in rolünü düşürmek engellenir. PostgreSQL transaction advisory lock aynı organizasyondaki eşzamanlı rol değişimlerini sıralar; SQLite yazma transaction'ı aynı korumayı sağlar. Testte iki admin aynı anda kendini düşürmeye çalıştığında yalnız biri başarılı olur ve organizasyonda bir admin kalır.

`verification_reference`, gelecekteki VF-024 GitHub kurulum sahipliği doğrulamasının audit korelasyonudur; doğrulamayı kendisi gerçekleştirmez. Kullanıcının uydurduğu bir referansla repo bağlanamaz. Bu yüzden müşteri repo bağlama endpoint'i bu aşamada açılmadı. GitHub ID, repo adı veya installation_id beyanı tek başına sahiplik kanıtı değildir.

Üyelik/sahiplik değişimleri mevcut audit tablosuna aktör ve organization bilgisiyle yazılır. Yeni müşteri audit sorgusu org kapsamlıdır; eski operatör audit'i global, kayıt deposu ise henüz immutable değildir. Bağlantı kaldırma repo sahiplik ilişkisini de siler; kullanıcı/organizasyon kayıtlarını kendiliğinden silmez. Kişisel veri silme ve üyelikten çıkarma akışları ayrıca gerekir.

## Tamamlanmamış erişim katmanı

- VF-013–014: State/PKCE/callback, süreli oturum ve cookie/CSRF kodu mevcut; gerçek GitHub App ile canlı kabul bekliyor.
- VF-015–016: [Yerel müşteri API önizlemesinde rol ve org kapsamı](ORGANIZATION_ACCESS_TR.md) uygulandı/test edildi. VF-017 PostgreSQL DB izolasyonu/RLS [ayrı runtime bağlantılarıyla](DATABASE_ISOLATION_TR.md) eklendi; SQLite yalnız geliştirme kapsamındadır.
- VF-018–020: Queue/cache/worker sınırı, davet/revoke ve müşteri yolundan ortak admin token'ın çıkarılması.
- VF-024: Gerçek GitHub yetkisi doğrulanmış kurulum/ownership bağlama.
- VF-092: İki müşteri arasında negatif erişim testleri.

`/api/v1/privacy` hâlâ `tenant_isolation_ready=false` ve `customer_ingestion_ready=false` döndürür. Eski admin API'leri operatör kapsamındadır; bu model eklendi diye dış müşterilere açılmaz.

## Doğrulama

`tests/test_identity.py`: immutable ID/login değişimi, bozuk kimlikler, kayıtlı aktör zorunluluğu, üyelik görünürlüğü, admin rol ataması, son admin kuralı, kayıtlı repo gereksinimi, organization'lar arası sahiplenme engeli ve uninstall/FK temizliği. Gerçek PostgreSQL testleri identity tablolarının SQLite'tan aktarımını ve eşzamanlı son-admin korumasını da doğrular. Canlı OAuth/kurulum kabulü yapılmadı. İki sahte organizasyonun müşteri API yetkilendirmesi ayrıca SQLite ve gerçek yerel PostgreSQL üzerinde test edildi; bu tam sistem/queue izolasyonunun yerini tutmaz.
