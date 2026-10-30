# VulnForge On-Premises ve Air-Gapped (Dışa Kapalı) Kurulum Rehberi

Bu kılavuz, VulnForge platformunun tamamen internet erişiminden yalıtılmış (air-gapped / offline) veri merkezlerinde, savunma sanayii ve kurumsal kapalı ağlarda kurulması ve işletilmesi için gereken adımları açıklar.

---

## 1. Mimari ve Ağ İzolasyonu Prensipleri

1. **Sıfır Giden Ağ Çıkışı (Zero External Egress)**:
   - VulnForge air-gapped modunda çalıştığında (`AIRGAPPED=true`), dış internet adreslerine (OSV.dev, GitHub public API, harici NTP/DNS) giden tüm soket çağrıları engellenir.
   - Sadece RFC 1918 özel IP blokları (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) ve güvenilen yerel alan adları (`.internal`, `.local`, `.corp`, `.lan`) kabul edilir.

2. **İzole Docker Ağı**:
   - Dağıtılan `docker-compose.onprem.yml` içerisinde tanımlanan `vf_internal` köprüsü `internal: true` bayrağı ile dış dünya ağ geçidine (default gateway) kapatılmıştır.

---

## 2. Docker Compose ile On-Premises Kurulum

```bash
# Kurulum dosyasını oluştur
python -c "from vulnforge.onprem import generate_onprem_compose; print(generate_onprem_compose(db_password='your_strong_password'))" > docker-compose.onprem.yml

# Servisleri başlat
docker-compose -f docker-compose.onprem.yml up -d
```

---

## 3. Çevrimdışı Tehdit İstihbaratı (Advisory Bundle) Yükleme

Dışa kapalı ortamlarda yeni CVE ve GHSA verileri "veri diyotu" (data diode) veya güvenli taşınabilir medya ile JSON bundle formatında aktarılır:

```bash
# Çevrimdışı paketi içeri aktar
python -c "from vulnforge.db import Store; from vulnforge.onprem import load_offline_advisories_bundle; \
  store = Store('postgresql://vulnforge:pass@localhost:5432/vulnforge'); \
  count = load_offline_advisories_bundle(store, '/path/to/advisories_bundle_20261030.json'); \
  print(f'{count} adet güvenlik duyurusu içe aktarıldı.')"
```

---

## 4. Teftiş ve İzolasyon Doğrulaması

Ağ sınırlarını doğrulamak için:
```python
from vulnforge.onprem import AirgappedConfig, validate_airgapped_isolation

config = AirgappedConfig(airgapped=True)
# Bu çağrı harici internet adreslerinde ValueError fırlatır:
validate_airgapped_isolation(config, ["https://git.internal.corp", "https://db.internal"])
```

