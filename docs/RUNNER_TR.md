# Müşteri ortamında tarama ve Action

Kaynak kod müşteri koşucusunda kalır. Scanner CLI yalnız dosya okur, AST/regex ve manifest parser'ı çalıştırır; repository kodunu import etmez, paket yöneticisi/build/test/subprocess başlatmaz, ağ çağrısı veya rapor yüklemesi yapmaz. Bu araç Semgrep/Gitleaks veya tam dependency resolver değildir.

## Kurulum ve kullanım

Python 3.11+ ve POSIX koşucu gerekir. İncelenmiş VulnForge dağıtımını checkout dışındaki ayrı bir ortama kur. Repo içindeki Python ortamı, `PYTHONPATH` veya değiştirilmiş bir komutla tarama yapma. Paket yayımlama, bütün bağımlılıkların hash ile kilitlenmesi ve dağıtım provenance'ı VF-039/091 kapsamında açıktır; şu an genel bir registry sürümü yayımlanmadı.

Kurulmuş paket iki eşdeğer giriş sağlar:

```sh
/opt/vulnforge/bin/vulnforge-scan --root /workspace/project --repo organization/project --sha EXACT_40_CHARACTER_SHA --kind code --output /tmp/code-report.json
/opt/vulnforge/bin/python -I -m vulnforge.cli --root /workspace/project --repo organization/project --sha EXACT_40_CHARACTER_SHA --kind dependencies --output /tmp/dependency-report.json
```

SHA ve repo CLI'da beyan edilen metadata'dır. CLI checkout/SHA veya workflow kimliğini kriptografik olarak ispatlamaz. Sunucu bunları güvenilir OIDC/installation kanıtıyla doğrulamadan raporlar proje baseline'ı sayılamaz (VF-035–038). Operatör intake'i ve yeni loopback OIDC önizlemesi yalnız karantinaya alır; production müşteri upload API'si ve baseline promotion açılmadı. [Kimlik/provenance protokolü](RUNNER_IDENTITY_TR.md).

`--fail-on high` belirtilen ve daha yüksek önem derecesindeki kod bulgularında 1 döndürür. `--require-complete` eksik analizde 3 döndürür. Kullanım/tarama/çıktı hatası 2, başarılı rapor üretimi 0 döndürür. Varsayılan 0, projenin güvenli olduğu anlamına gelmez. Rapor her zaman coverage durumunu taşır. Özet çıktıda kaynak, dosya adı veya sır değeri bulunmaz.

## Tarama kapsamı

Kod profili Python, JavaScript/TypeScript, JSX/TSX, env, JSON, YAML ve TOML dosyalarında mevcut temel kuralları uygular. Dependency profili requirements.txt, package-lock.json, poetry.lock, Cargo.lock, composer.lock ve go.mod dosyalarını işler. Diğer diller/dosyalar bu profilin kapsamı dışındadır. `.git`, `.hg`, `.svn`, node_modules, .venv, venv, __pycache__ ve .tox dizinleri kapsam dışıdır. İç içe Git depoları/submodule'lar ve symlink'ler takip edilmez; belirsizlik raporu eksik yapar.

Her dosya bileşeni descriptor-relative `NOFOLLOW` ile açılır; dosya türü ve okuma sırasındaki değişiklik kontrol edilir. Binary, geçersiz UTF-8, aşırı boyut/derinlik, bozuk parser girdisi ve erişim hataları temiz sonuç sayılmaz. Sınırlar: dosya başına 300 KB/10.000 satır, toplam 50 MB okuma, 20.000 ağaç girdisi, 32 derinlik, 120 saniye keşif bütçesi, 80 manifest, 1.500 dependency, 5.000 bulgu, 1 MB rapor. Süre kontrolü best effort'tır; işletim sistemi seviyesinde CPU/bellek sandbox'ı değildir.

requirements.txt transitive graph kanıtı oluşturmaz; go.mod resolved build listesi değildir. Böyle envanterler `declared/incomplete` kalır. Tamamlanma yalnız seçili profilin kapsamına aittir; bütün repo/dil veya güvenlik garantisi değildir.

Raporlar v1 allowlist'ine uyar. Yollar SHA-256 pseudonym'i olur; hash anonimleştirme değildir. Bulgu rule/severity/line/fingerprint içerir; kaynak/snippet/sır değeri içermez. Dependency ad ve sürümleri metadata'dır ve hassas olabilir; raporu paylaşma kararı ayrıca gerekir.

## Action ve workflow profilleri

Kök `action.yml`, yöneticinin önceden kurduğu scanner Python'unu `-I` ile çağırır. Action müşteri projesinden scanner veya bağımlılık kurmaz. Runtime checkout dışında olmalıdır. `examples/workflows/customer-runner.yml` varsayılan dal push, günlük ve elle çalıştırma; `customer-runner-pr.yml` PR head profili sağlar.

Şablonlar doğrudan aktif workflow değildir. `OWNER/VulnForge@COMMIT_SHA` yerine incelenmiş Action deposu ve tam değişmez commit SHA'sı, runner label'ı ve scanner yolu yerleştirilmelidir. `main` yerine gerçek korunmuş varsayılan dal yazılmalıdır. GitHub'da Action çalıştırma kabulü henüz yapılmadı. Örnek checkout referansı upstream commit'te doğrulandı; bu en yeni sürüm veya bağımsız güvenlik değerlendirmesi iddiası değildir.

PR profili tek işten sonra silinen, sırsız ve özel ağa erişimsiz runner ister. Persistent/ayrıcalıklı self-hosted koşucuda fork PR çalıştırma. Şablon `pull_request_target`, sır, `id-token: write`, repo yazma, kaynak artifact'i veya upload kullanmaz. Kaynak checkout token'ı saklanmaz; submodule çekilmez. Yeni OIDC yayın şablonu protected varsayılan dal için ayrı bir profildir; gerçek sağlayıcı kabulünde bu izinler/bağlam ayrıca yeniden değerlendirilmeli; bu şablonun bugünkü yetkisiz raporu trusted baseline'a terfi etmez.

Raporlar yalnız `RUNNER_TEMP` altında owner-only dosyalarda atomik yazılır. Hata/SIGINT/SIGTERM durumlarında ara rapor dizini temizlenir; workflow'un son `always()` adımı başarılı raporları da temizler. `runner_cleanup` yalnız kendi rapor adlarını ve geçerli temp dizinini kabul eder, kaynak checkout'unu veya beklenmedik dosyaları silmez. SIGKILL/host çökmesi gibi yakalanamayan durumlarda ephemeral runner imhası veya koşucu yöneticisinin temp-retention politikası gerekir. Scanner kaynak dosyası kopyası oluşturmaz.

Yerel testler: kötü niyetli setup/conftest/shadow module çalıştırmama, sır/kaynak/yol sızıntısı reddi, CLI çıkış kodları, coverage, symlink/submodule/binary/limit, gerçek isolated Action giriş noktası, iptal ve güvenli cleanup. Gerçek GitHub koşucu trafiği ve yükleme kabulü VF-093/094 kapsamında açıktır.
