# Yerel GitHub kurulum durumu

30 Ekim 2026 — yalnız yerel test kurulumu.

- `VulnForge-Kaan-Local` adlı private GitHub App oluşturuldu.
- Başlangıçta yalnız `kaanirmak/VulnForge` deposuna Metadata read izniyle kuruluydu; kullanıcı onayıyla GitHub App kapsamı tüm mevcut ve gelecekteki depoların yalnız ad/metadata görünümüne genişletildi. Kaynak kod ve yazma izni yok, webhook kapalı.
- App/OAuth bilgileri korumalı, Git tarafından dışlanan `.env` dosyasına kaydedildi. RSA özel anahtarı repo dışında tutuluyor; yalnız dosya sahibi okuyabilir.
- `python -m vulnforge.setup_check --env-file .env`: `local_configuration_ready=true`.
- `http://127.0.0.1:8000/account` üzerinden gerçek GitHub giriş → callback → hesap ekranı başarılı; doğrulanan kullanıcı `kaanirmak`.
- Canlı GitHub dönüşündeki `iss` alanı için hem giriş hem bağlantı callback'inde tam `https://github.com/login/oauth` eşleşmesi eklendi. Yanlış/boş/tekrarlanan issuer reddedilir; mevcut state, PKCE ve tek kullanım kontrolleri korunur. [GitHub issuer belgesi](https://docs.github.com/en/apps/github-authentication-discovery-endpoints).
- İlgili doğrulama: `tests/test_auth.py`, `tests/test_connections.py`, `tests/test_setup_check.py`: **100 geçti, 2 atlandı**. Atlanan PostgreSQL testleri bu çalıştırmada doğrulanmadı.

- Açık kullanıcı onayıyla `Kaan VulnForge` kuruluşu oluşturuldu ve `kaanirmak/VulnForge` gerçek kullanıcı/App metadata doğrulamasıyla bağlandı. Callback sonucu `connected`, panelde proje `Bağlı (Aktif)`; ilk koşucu raporu bekleniyor.
- Panelden çıkış ve yeniden GitHub girişi başarılı; kuruluş ve depo bağlantısı yeni oturumda korunuyor.
- Proje ekleme ekranında `kaanirmak` hesabından 39 depo adı listeleniyor. Listeleme otomatik bağlantı kurmuyor; kullanıcı depo seçip metadata onayını işaretlediğinde ayrıca bağlama işlemini başlatıyor.

İlk tarama henüz tamamlanmadı. Mevcut sunucu `runner_baseline_promotion=false` ve `customer_ingestion_ready=false` bildiriyor; koşucu raporlarını güvenilir proje envanterine alma yolu ayrıca geliştirme/kabul gerektiriyor. Tam canlı kabul, iptal/bağlantı yaşam döngüsünün olumsuz senaryoları, koşucu kabulü ve üretim kapıları bu kurulum kaydıyla tamamlanmış sayılmaz. Genel müşteri erişimi ve GitHub Pages yayını açılmadı.
