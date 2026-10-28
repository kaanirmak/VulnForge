# Yeni açık → etkilenen proje → güncelleme önerisi

VulnForge artık bir güvenlik duyurusunun hangi kayıtlı projelere değdiğini kalıcı olarak eşler ve paket bazında güncelleme önerisi sunar. Öneri üretimi `ENABLE_AUTO_PR` ayarından bağımsızdır; projeye yazma veya otomatik güncelleme yapmaz.

27 Ekim gizlilik değişikliği: varsayılan kaynak erişimi ve OSV sorguları kapalıdır. Aşağıdaki mevcut akış, açık onaylı managed tarama ve ayrıca etkin intelligence politikasıyla çalışır. Public OSV için tam paket allowlist'i ve metadata paylaşım izni gerekir; özel paket engeli önce gelir. Müşteri koşucusu envanterinin doğrulanmış kabulü henüz yoktur. [Modlar ve veri paylaşımı](PRIVACY_ARCHITECTURE_TR.md).

28 Ekim tazelik kontrolü: eksik/eski snapshot veya sorgu kanıtı, yeni varsayılan dal push'u ve değişmiş advisory hash'i eski önerinin güncel sürüm olarak gösterilmesini engeller. Tarihsel `not_affected`, geçerli kanıt yoksa etkili `under_investigation` olur. API, müşteri/operatör ekranı ve exportlar aynı değerlendirmeyi kullanır. [Süreler, filtre anlamı ve sınırlar](EVIDENCE_FRESHNESS_TR.md).

## Nasıl işler?

1. İmzalı GitHub `security_advisory` olayı alınır. Duyuru, CVE/GHSA alias'ları, kaynak özeti ve hash'i saklanır. Inventory'de eşleşen ve inventory'si eksik/bilinmeyen projeler yeniden değerlendirme kuyruğuna alınır. Önceden etkilendiği bilinen projeler de güncellenen duyurularda yeniden kontrol edilir.
2. Aday proje **etkileniyor** sayılmaz; ilk durum `under_investigation` olur. İşçi varsayılan dalın sabit SHA'sında paket/sürüm envanteri çıkarır.
3. OSV paket + ekosistem + sürüm sorguları etkilenmeyi doğrular. Yeni duyuru henüz OSV'ye yansımamışsa imzalı GitHub duyurusunun desteklenen açık sürüm karşılaştırmaları da kullanılır. Paket adı benzerliği yeterli değildir.
4. Etkilenen her paket için ilgili duyuruların fixed sürümleri değerlendirilir. En az gerekli hedeflerden başlanır. Aynı hedef birden fazla manifestte bulunuyorsa sorgusu birleştirilir; farklı paketler toplu OSV sorgusuyla kontrol edilir.
5. Hedef hem yeni GitHub duyurusundaki aralığın dışında olmalı hem de OSV paket/sürüm sorgusunda başka bilinen açığa takılmamalıdır. İlk hedef hâlâ etkileniyorsa diğer belgelenmiş fixed sürümler denenir; paket başına en fazla 20 aday değerlendirilir.
6. Panelde **açık, proje, paket/ekosistem, dosya, mevcut sürüm, önerilen sürüm, patch/minor/major türü ve SHA kanıtı** gösterilir. Öneriler insan incelemesi gerektirir.
7. Güncelleme sonrasındaki tam taramada eski risk saptanmazsa etki `not_affected` olur. Eksik/başarısız tarama güvenli kabul edilmez; eski öneriler geçerliymiş gibi tutulmaz.

Yeni commit gelmesi gerekmez: işçi kayıtlı projeleri düzenli OSV taramasına alır. Varsayılan `SCAN_INTERVAL_SECONDS=900` (15 dakika) oldu. Mevcut `.env` içinde 3600 gibi açık bir değer varsa o değer geçerlidir; değiştirmek ve API/worker'ı yeniden başlatmak gerekir. Kuyruk yoğunluğu ve dış servis gecikmesi nedeniyle bu aralık tamamlanma garantisi/SLO değildir. Küresel GHSA/NVD veri tabanının tamamını indiren ayrı bir feed servisi eklenmedi.

## Etki durumları

| Durum | Anlamı |
|---|---|
| `affected` | Gözlemlenen kesin paket/sürüm OSV veya imzalı GitHub aralığıyla eşleşiyor. Uygulamada istismar ya da kod erişilebilirliği kanıtlanmış değildir. |
| `not_affected` | Güncel tam taramada önceki risk saptanmadı veya ilgili duyurunun sürüm aralığı dışında/ilgili paket mevcut değil. Tüm güvenlik risklerinin yokluğu iddiası değildir. |
| `under_investigation` | Kontrol bekliyor; sürüm aralığı desteklenmiyor; inventory eksik veya kaynak erişimi başarısız. |
| `withdrawn` | Kaynak duyuruyu geri çekti. İlgili öneriler kaldırılır; ilgili bulgular çözülür ve audit geçmişi korunur. Eski OSV yanıtı geri çekilmiş duyuruyu yeniden etkinleştiremez. Daha yeni tarihli açık bir GitHub olayı yeniden değerlendirebilir. |

GitHub karşılaştırmalarında açık `>`, `>=`, `<`, `<=`, `=`, `==`, virgülle AND ve `||` ile OR desteklenir. `^`, `~`, joker, pre-release ve bilinmeyen sürüm biçimleri tahmin edilmez; sonuç unknown/under_investigation kalır. PyPI için PEP 440 kararlı sürümler; npm, Rust, Go ve Composer için desteklenen kararlı üç bileşenli sürümler karşılaştırılır. Diğer ekosistemler için güncelleme sürümü uydurulmaz.

## Öneri durumları

| Durum | Anlamı |
|---|---|
| `update_available` | Hedef mevcut sürümden yüksek; gerekli bilinen fixed sınırlarını karşılıyor ve OSV yeniden sorgusunda bilinen açık dönmedi. |
| `no_known_fix` | Duyurulardan uygun fixed sürüm çıkarılamadı; upstream mitigasyonu/izleme gerekir. |
| `target_still_affected` | Belgelenmiş adayda hâlâ açık var veya yeni duyurunun aralığı dışında olduğu kanıtlanamadı. |
| `verification_failed` | Hedef OSV'de kontrol edilemedi; doğrulanmış sürüm önerilmez. |
| `unsupported_version` | Sürüm biçimi güvenle karşılaştırılamıyor; manuel inceleme gerekir. |

`update_available` bir güvenlik veya uyumluluk garantisi değildir. `release_verified`, `tests_verified`, `compatibility_verified` alanları false; `requires_review` true'dur. Hedefin paket kaydında yayımlandığı/yank edilmediği, çözümleyici uyumluluğu, lockfile yenilemesi, build ve test sonuçları bu özellikte doğrulanmaz. Panel de bunu belirtir. Otomatik PR'ın önceki inventory/policy kapıları korunur.

## Kullanım

GitHub App için `security_advisory` aboneliği, uygulamanın imza sırrı ve çalışan worker gerekir. OSV erişimi ve metadata politikası açıkça etkin olmalıdır. Dashboard'da admin token ile Refresh yaptıktan sonra **Yeni açıklar ve etkilenen projeler** bölümünü kullanın. Projeye (`org/repo`) ve açık kimliğine (CVE/GHSA/OSV alias) göre filtrelenebilir; **Daha fazla göster** sonraki sayfayı getirir. **Açıkları şimdi kontrol et**, seçili projeyi veya tüm kayıtlı projeleri kuyruğa alır; sonucu işçi tamamladıktan sonra Refresh ile alın.

Tüm uçlar admin bearer ister:

| Yol | İşlev |
|---|---|
| `GET /api/v1/advisories?limit=50` | Son duyurular, alias'lar, etkilenen/incelemedeki proje sayıları |
| `GET /api/v1/impacts?repo=org/repo&advisory_id=...&state=affected&limit=50&cursor=0` | `{items,next_cursor}`; proje etkisi, snapshot kanıtı ve paket bazlı öneriler; en fazla 100 kayıt |
| `POST /api/v1/intelligence/refresh?repo=org/repo` | Tek proje için yeniden kontrol; repo verilmezse tüm kayıtlı projeler; dakika bazında aynı istek dedup edilir |

SQLite/PostgreSQL migration'larıyla eklenen tablolar `advisories`, `advisory_aliases`, `advisory_impacts` mevcut verileri silmeden eklenir. Repo çıkarıldığında projeye bağlı etkiler de kaldırılır. Genel/public advisory metadata'sı katalogda kalabilir.

## Doğrulama

Güncel yerel test paketi gerçek geçici PostgreSQL testleri dahil **301 test** ile geçti (27 Ekim 2026). Yeni testler beş ekosistemde önerileri, yeni GHSA'nın OSV indekslenmeden eşleşmesini, aynı isim/güvenli sürüm ayrımını, başka açığa takılan hedefi, doğrulama hatasını, sürüm aralığı belirsizliğini, withdrawal/reinstatement durumlarını, toplu hedef sorgularını, API kimlik doğrulamasını ve sayfalamayı kapsar. GitHub/OSV çağrıları mock'tur; canlı GitHub App/OSV kabul testi yapılmadı.

Sözleşme kaynakları: [OSV şeması](https://ossf.github.io/osv-schema/), [OSV paket/sürüm sorgusu](https://google.github.io/osv.dev/post-v1-query/), [GitHub global advisory alanları](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub advisory webhook'u](https://docs.github.com/en/webhooks/webhook-events-and-payloads#security_advisory).
