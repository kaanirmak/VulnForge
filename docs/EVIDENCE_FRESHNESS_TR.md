# Envanter, açık verisi ve öneri tazeliği

28 Ekim 2026 — VF-054. Müşteri ve operatör API'leri, ekranları ve scan/SBOM/SARIF çıktıları eksik veya eski kanıtı güncel sonuç olarak sunmaz. Karar okuma anında hesaplanır; saat ilerlediğinde bir arka plan temizleme işinin çalışması gerekmez. Saklanan gözlem ve eski öneri silinmez.

## Yerel politika

- Envanter: bitmiş snapshot en çok 24 saatlik olmalıdır. Sınırın kendisinde eski sayılır.
- Açık verisi: aynı taramadaki başarılı paket/sürüm sorgusu en çok 1 saatlik olmalıdır. Hedef sürümün sorgu doğrulaması da bu sınır içindedir.
- Null, bool, gelecekteki, negatif, NaN/sonsuz veya zaman sırası tutarsız kanıt geçerli zaman sayılmaz. Sunucu saatinin senkron tutulması işletim gereğidir.

Bu değerler kodda sabit ihtiyatlı önizleme politikasıdır; ölçülmüş SLO veya kaynak feed'inin senkronizasyon garantisi değildir. `intelligence_checked_at`, o snapshot'ın başarılı sorgu zamanıdır; OSV/GHSA'nın dünyadaki en yeni duyuruyu içerdiğini kanıtlamaz. Bağımsız feed cursor/backfill/tazelik izlemesi VF-051–053'te açıktır.

## Tam ve bağlı kanıt

Yalnız `dependencies` türündeki, geçerli SHA'ya ve mevcut varsayılan dal adına bağlı, complete durumlu, manifest kanıtı ve tutarlı pozitif dosya sayımları bulunan tarama bu değerlendirmeye adaydır. Atlanan dosya/coverage sorunu veya tanınmayan kaynak modu varsa güncel sayılmaz. Commit ve PR taraması varsayılan dal envanteri değildir. Yeni worker kayıtlarında kaynak modu, sorgu zamanı ve taranan varsayılan dal saklanır; eski kayıtlara geriye dönük kanıt uydurulmaz.

Repo başına son dependency taraması doğrudan sorgulanır; panelin 50 kayıtlık karma scan listesinden seçilmez. Son tarama failed/incomplete/running ise eski complete taramanın sonucuna geri dönülmez. Başlama zamanı aynı iki taramanın sırası UUID'ye bakılarak tahmin edilmez.

İmzalı varsayılan dal push'u (silme dahil) ve varsayılan dal değişikliği repository kaydındaki `evidence_invalidated_at` alanını ilerletir. Customer-runner modunda bu işlem kaynak işi veya ham push yükü oluşturmaz. Scan başladıktan sonra değişiklik bildirilmişse yeni snapshot gerekir. Geç veya ters sıralı webhook gereksiz bir tekrar tarama gerektirebilir; eski kanıtı yeniden güncel hale getiremez. Kaçırılan webhook'u bu kontrol keşfedemez; backfill ve bağlantı sağlığı VF-028/030'da açıktır. `current_head_verified=false` kalır.

## API anlamı

Repository, dependency satırı ve scan yanıtındaki `evidence_status`; impact'teki `freshness`, `fresh_snapshot`, `needs_review` veya `missing` durumunu ve makinece okunabilir nedenleri taşır. `snapshot_only=true`, `history=not_verified` ve `safe=false` bütün durumlarda korunur. Yakın tarihli tam snapshot geçmişin tamamının tarandığı veya uygulamanın güvenli olduğu anlamına gelmez. İlk kurulum ve baseline promotion VF-027/034/035–036 kapsamında açık kalır.

Impact ayrıca aynı scan'e ve advisory'nin güncel kaynak hash'ine bağlı olmalıdır. Yeni advisory revision, başarısız son scan, kapsam eksikliği veya süre aşımı durumunda eski `not_affected`, yanıtta `under_investigation` olur. `state` ve eşdeğeri `assessment_state` bu etkili gösterimdir; `observed_state` veritabanındaki tarihsel gözlemdir. Etkilendiğine dair eski pozitif kanıt görünür kalır ve tazelik uyarısı taşır. Geri çekilmiş duyurunun önerileri görünümden kaldırılır.

Mevcut `state` sorgu filtresi kalıcı tarihsel gözlemi seçer; yanıt bunu `filter_scope=observed_state` ile belirtir. Bu nedenle `state=not_affected` filtresinin sonucu, kanıtı eskimişse etkili `state=under_investigation` olabilir. Cursor kalıcı ID üzerinden ilerler. Tazelikten bağımsız advisory/overview sayaçları tarihsel gözlem sayılarıdır; güncel güvenlik skoru değildir.

Yeniden doğrulama gereken öneride `recommended_version=null`, `status=needs_reverification` olur. `previous_recommended_version` ve `previous_status` tarihsel inceleme için tutulur. Bu kural impact, bulgu listeleri, scan detayları ve SARIF içindeki bulgu kanıtına da uygulanır. Paket kaydında yayımlanma, yank/deprecation, uyumluluk ve testler bu kontrolle doğrulanmaz; VF-057/058/063–065 açık kalır. Hiçbir PR/merge izni açılmaz.

## Veritabanı ve kabul

009 migration iki dialect'te repository'ye bir nullable timestamp ekler. Mevcut kayıtlar korunur; checksum geçmişi değişmez. Yeni tablo/grant yoktur; mevcut repository RLS politikası uygulanır. Customer rolleri bu alanı değiştiremez, ancak audit okuma izni olmayan Viewer/Maintainer/Analyst de kendi reposunun geçersizleşmesini görebilir. Operator audit kaydını müşteriye açma gereği yoktur. SQLite→PostgreSQL aktarımı timestamp'i aynen korur.

`tests/test_freshness.py`, süre sınırları, kaynak/kapsam/zaman kanıtı, failure/running/PR ayrımı, ters sıralı değişikliklere ihtiyatlı yaklaşım, source hash değişimi, tüm API/export yüzeylerinde öneri kaldırılması, geçmişin korunması, beş müşteri rolü ve gerçek PostgreSQL taşımasını kapsar. UI iki ayrı sahte proje ve ayrı organizasyon verisiyle yerel tarayıcıda incelendi. Gerçek müşteri verisi veya canlı sağlayıcı kullanılmadı; production müşteri kabulü ve worker tenant izolasyonu kapalı kalır.
