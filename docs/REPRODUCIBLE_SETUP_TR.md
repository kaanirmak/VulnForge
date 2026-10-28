# Sabit bağımlılıklar ve doğrulanan kurulum

28 Ekim 2026. Test edilen mevcut sürümler yükseltilmeden sabitlendi: 24 runtime, 29 geliştirme/build paketi. PyPI release metadata'sındaki non-yanked wheel SHA-256 değerleri runtime.lock, development.lock ve build.lock içine yazıldı. lock-metadata.json kaynak, sürüm ve hash envanteridir; özel müşteri paketi içermez.

Desteklenen kilit hedefi CPython 3.11/3.12, Linux/macOS'tur. Windows/PyPy veya başka Python sürümüne uyumluluk iddiası yoktur. Farklı platform wheel'lerinin hash'leri metadata'dan alınır; her platformda çalıştırılmış kabul testi sayılmaz.

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements/development.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
python scripts/check.py --postgres
```

Build backend de sabittir; kurulum sırasında habersiz build isolation bağımlılığı indirilmez. CI 3.11/3.12 Ubuntu 24.04 matrisiyle aynı kilitleri ve gerçek geçici PostgreSQL testini kullanır. Checkout/setup-python action referansları önceki incelenmiş commit SHA'larında tutulur. GitHub CI sonucu ayrıca kaydedilmeden uzaktaki iş başarılı sayılmaz.

Yerel kanıt: resmi PyPI hash'leriyle wheel indirme, ağsız temiz environment kurulumu, pip dependency kontrolü ve tüm PostgreSQL testleri. Değiştirilmiş bir wheel hash enforcement tarafından kurulumdan önce reddedildi. Linux CPython 3.12 wheel indirmesi execution kanıtından ayrıdır.

Dockerfile aynı runtime/build kilitlerini kullanır. Default Compose yalnız API'yi başlatır; App anahtarı bağlamaz ve kaynak worker'ı oluşturmaz. Local onboarding için ayrı preview overlay, managed tarama için açık kaynak erişim onayı isteyen ayrı managed overlay vardır. Managed worker'a GitHub OAuth client secret, müşteri DB credential'ı, session/operatör/karantina sırları aktarılmaz. Worker App anahtarı ve iş DB yetkisi hâlâ ayrı izolasyon/secret-store çalışması gerektirir.

Güncelleme: yalnız incelenmiş geliştirme ortamında `python scripts/lock_dependencies.py --refresh`. Araç yeni sürüm seçmez; kurulu paketlerin uyumlu closure'ını ve resmi PyPI hash'lerini tekrar çıkarır. Çıktıyı diff/test/uyumluluk ve ayrı güvenlik değerlendirmesiyle incelemeden dağıtma. Hash sabitlemesi, registry'nin güvenilirliğinin veya pakette güvenlik açığı bulunmadığının kanıtı değildir.

Docker base image ayrıca gözlenen `python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159` digest'ine sabitlendi. Python interpreter/pip bootstrap, OS paketleri ve uzak build provenance Python kilitlerinin dışındadır. İmaj ve immutable Action/CLI yayını tamamlanmadan VF-039/091'in bütün kabul koşulları kapanmaz.

28 Ekim kabulü: temiz kilitli ortamda **642 test, sıfır skip**; gerçek PostgreSQL 14.23. Docker build ve UID 10001/ağsız/read-only açılış geçti. Bu açılış testi patch sandbox kabulü değildir.

`python scripts/build_package.py --output /tmp/vulnforge-dist` temiz kaynak commit’i, sabit build backend ve commit zamanına bağlı SOURCE_DATE_EPOCH ile wheel, SHA256SUMS ve build-manifest.json üretir. İki bağımsız yerel preview derlemesi byte düzeyinde eşleşti. `--allow-dirty` yalnız preview içindir; source_revision null kalır. Manifestte published/signed false tutulur; araç yayın yapmaz.
