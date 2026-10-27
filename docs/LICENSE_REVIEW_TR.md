# Lisans ve veri kaynağı değerlendirmesi

VF-010 — 27 Ekim 2026. Bu çalışma mevcut metadata ve resmi metinler üzerinden teknik ön değerlendirmedir; ürün lisansı seçimi veya hukuki dağıtım onayı değildir.

## Ürün ve paket lisansları

Depoda henüz ürün lisansını belirleyen bir LICENSE dosyası yok. Buna dayanarak müşteriye veya katkı verene MIT/Apache/açık kaynak hakları vaat edilmez. Ürün sahibinin seçimi yayın öncesi VF-091/100 kapsamında açıkça kaydedilmelidir; bu değişiklikte lisans ataması yapılmadı.

Olası seçeneklerin kısa değerlendirmesi:

- MIT: İzin ve telif bildirimi koşuluyla geniş kullanım/dağıtım yetkileri tanımlar; seçilirse ilgili bildirimler korunmalıdır. [Resmi MIT metni](https://opensource.org/license/mit).
- Apache-2.0: Dağıtım/bildirim şartları ve patent hükümleri içerir; seçilirse NOTICE ve değişiklik bildirimleri ayrıca değerlendirilmelidir. [Resmi Apache metni](https://www.apache.org/licenses/LICENSE-2.0).
- Kapalı kaynak/ticari dağıtım: Ürün sözleşmesi ayrıca hazırlanır; kullanılan açık kaynak paketlerin yükümlülüklerini ortadan kaldırmaz.

`DEPENDENCY_LICENSES.md`, yerel geliştirme ortamındaki kurulu 30 üçüncü taraf paketin sürüm/lisans metadata'sını kaydeder. MIT/BSD/Apache gibi farklı ifadeler, certifi için MPL-2.0, psycopg ve psycopg-binary için LGPL-3.0-only metadata'sı bulunur. PostgreSQL optional grubu binary paket içerir; ilgili lisans/bildirim ve binary içeriğin kendi bileşen lisansları dağıtım öncesinde ayrıca incelenmelidir. Lisans dosyaları ve dağıtılan bileşenler sürüm kilidiyle tekrar incelenmelidir. Listede bulunması, her paketin nihai üründe dağıtılacağı anlamına gelmez.

Semgrep/Gitleaks ve gelecekteki modeller henüz bu dağıtıma eklenmedi. Bunların kullanılacak motor/sürüm, kurallar, model ağırlıkları ve ticari özellik lisansları entegrasyondan önce ayrı incelenmelidir; bu paketlerin tamamının aynı lisansa sahip olduğu varsayılmaz.

## Advisory ve servis verileri

GitHub Advisory Database deposunun lisans dosyası CC BY 4.0 koşullarına yönlendirir; yeniden dağıtımda kaynak/atıf ve değişiklik bildirimleri değerlendirilmelidir. [Kaynağın lisansı](https://github.com/github/advisory-database/blob/main/LICENSE.md).

OSV, farklı vulnerability veri tabanlarını birleştiren bir servistir; API erişimi bütün kaynak kayıtlarına tek bir veri lisansı atandığı anlamına gelmez. Her kaynağın kullanım/atıf koşulu korunmalıdır. [OSV açıklaması](https://google.github.io/osv.dev/).

Güncel kayıt modeli source, ID/alias, zaman ve hash tutar. Kaynak lisansı/atıf alanlarının bütün export'lara aktarılması ve feed bazlı kullanım limitleri VF-049/051–053 kapsamında tamamlanmalıdır. Public servise metadata paylaşımı izni, veriyi yeniden dağıtma hakkı veya müşteri sözleşmesinin yerine geçmez.

## Yayın öncesi açık kararlar

Ürün lisansı, lisans/telif sahibi, dağıtım modeli, hizmeti sunan kişi/kurum, gizlilik iletişimi, veri bölgesi, DPA ve gerçek retention taahhütleri ürün sahibi tarafından kesinleştirilmelidir. Teknik taslaklar mevcut davranışı açıklar; bu kararlar alınmadan yayımlanmış yasal metin veya sertifika olarak gösterilmez.
