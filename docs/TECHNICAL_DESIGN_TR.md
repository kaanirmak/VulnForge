# VulnForge — Teknik tasarım

> **0.3.0 güncellemesi:** Bu dosya önceki MVP anlatımını içerir. Güncel davranışlar ve gereksinim durumları için [uygunluk raporunu](REQUIREMENTS_COMPLIANCE_TR.md) okuyun. Worker PR yayını, repo opt-in olsa da izole doğrulama ve SHA/diff onay kapıları tamamlanana kadar kapalıdır. Yalnız `ENABLE_AUTO_PR=true` yeterli değildir.

Bu belge, 23 Ekim 2026 tarihli SentinelAI tasarımının metin aktarımıdır. SentinelAI projesinin güncel adı VulnForge’dur. Belge hedef mimariyi anlatır; v0.2.0 uygulama kapsamı ve sınırları için README.md esas alınmalıdır. Kaynak bağlantılarına ilişkin doğrulama tarihleri özgün belgeye aittir.

TEKNİK ÜRÜN TASARIMI  /  SÜRÜM 1.0

SentinelAI

Autonomous Repository Security & Vulnerability Remediation Platform

GitHub / GitLab • Commit bazlı güvenlik analizi • CVE istihbaratı • Etki analizi • Kontrollü otomatik yamalama

Alan

Tanım

Belge türü

Ürün Gereksinimleri + Yüksek Seviyeli ve Detaylı Teknik Tasarım

Sürüm / tarih

1.0 / 23 Ekim 2026

Kapsam

MVP, üretim mimarisi, güvenlik politikaları, veri modeli, test ve yol haritası

Varsayım

Yetki verilmiş organizasyon repoları; otomatik birleştirme varsayılan olarak kapalı

Hedef kullanıcı

Yazılım ekipleri, DevSecOps, AppSec, güvenlik operasyon merkezleri

Tasarım ilkesi: Otomasyon hız sağlar; değişiklik yetkisi her zaman doğrulanmış politika, izlenebilirlik ve test kapılarıyla sınırlandırılır.

1. Yönetici özeti

SentinelAI, kaynak kod havuzlarını sürekli koruyan iki tetikleyicili bir güvenlik platformudur: (A) her push / pull request için değişen kodun güvenlik analizini yapar; (B) bağımsız olarak yeni yayımlanan güvenlik duyurularını takip eder ve mevcut bağımlılık envanterini yeniden değerlendirir. Yalnızca bulgu üretmez; uygun düzeltmeyi hazırlar, doğrular, geliştiriciye raporlar ve politika izin verirse otomatik birleştirir.

Ana değer önerisi: “Yeni kod yeni risk getirmesin; dün güvenli olan kod bugün yeni bir CVE yüzünden savunmasız kalmasın.”

1.1. Hedefler

Her commit ve PR için düşük gecikmeli, tekrarlanabilir ve gerekçeli tarama.

Yeni CVE / GHSA / OSV kaydı geldiğinde etkilenen repo, dal, paket ve çözülmüş sürümün belirlenmesi.

Otomatik düzeltme: önce güvenli sürüm yükseltmesi, gerekirse kısıtlı AI kod yaması.

Güvenli dağıtım: PR, CI kontrolleri, onay politikası, geri alma ve denetim izi.

Yanlış pozitiflerin azaltılması, aynı bulgunun tekrar üretilmemesi ve anlaşılır risk açıklaması.

1.2. MVP dışında tutulacaklar

Varsayılan olarak üretim sunucularına doğrudan müdahale, korumalı main/master dalına doğrudan push, kapsamlı otomatik penetrasyon testi, kimlik bilgisi olmadan özel depoların taranması ve tespit edilen her güvenlik açığının kesin olarak istismar edilebilir olduğunun iddiası kapsam dışıdır.

1.3. İki bağımsız tetikleyici

Akış

Tetikleyici

Çıktı

CodeGuard

push, pull_request, manuel tarama

Commit check, kod bulgusu, düzeltme PR’ı

ThreatWatch

Yeni advisory, Dependabot alarmı, periyodik feed

Etkilenen proje listesi, risk, acil uyarı

AutoRemediate

Doğrulanmış bulgu + uygun düzeltme

Patch branch, PR, test raporu, opsiyonel merge

2. Kapsam ve kullanıcı senaryoları

2.1. Roller

Rol

Yetki / kullanım

Platform admin

GitHub App kurulumu, kurum politikaları, veri saklama ve onay matrisi

Repo maintainer

Bulgu inceleme, PR onayı, repo risk eşikleri, yanlış pozitif yönetimi

Security analyst

CVE etkisi, önceliklendirme, olay bildirimleri, istisnalar

Developer

Commit geri bildirimi, neden ve nasıl düzeltileceğini görme

2.2. Kullanıcı hikâyeleri

Geliştirici olarak, gönderdiğim commit güvenlik riski getiriyorsa ilgili dosya/satır ve önerilen çözümü PR üzerinde görmek istiyorum.

Güvenlik uzmanı olarak, yeni bir CVE yayımlandığında hangi repolarımızda hangi sürümlerin etkilendiğini dakikalar içinde öğrenmek istiyorum.

Bakım sorumlusu olarak, testleri geçen düşük riskli bağımlılık yamasının isteğe bağlı olarak otomatik birleştirilmesini istiyorum.

Yönetici olarak, hangi düzeltmenin ne zaman, hangi kanıta dayanarak ve hangi yetkiyle yapıldığını denetlemek istiyorum.

3. Fonksiyonel gereksinimler

Kimlik

Gereksinim

Öncelik

FR-01

GitHub App üzerinden repo seçerek kurulabilme; ileride GitLab adaptörü

P0

FR-02

push/PR olaylarını imzayla doğrulayıp kuyruğa alma

P0

FR-03

Her commit SHA için diff ve değişen dosya taraması; planlı tam tarama

P0

FR-04

SAST, secrets, SCA ve container/IaC tarayıcılarını standardize etme

P0

FR-05

Lockfile + SBOM tabanlı repo/paket/sürüm envanteri

P0

FR-06

OSV/GHSA/Dependabot/CISA KEV kaynaklarını ingest etme

P0

FR-07

CVE ile paket + çözülmüş sürümü eşleştirme, belirsizliği belirtme

P0

FR-08

Bulguları önem, uygulanabilirlik ve güven düzeyine göre sıralama

P0

FR-09

Patch branch oluşturup bağımlılık güncelleme PR’ı açma

P0

FR-10

İzole test, re-scan ve politika kapılarıyla doğrulama

P0

FR-11

Github Checks, PR yorumları ve dashboard bildirimleri

P0

FR-12

İsteğe bağlı, koşullu auto-merge ve rollback mekanizması

P1

FR-13

AI destekli uygulama kodu yaması ve açıklanabilir diff

P1

FR-14

Audit log, istisna/false-positive yönetimi, RBAC, metrikler

P0

4. Mimari ve bileşenler

4.1. Önerilen teknoloji yığını

Katman

Seçim

Gerekçe

API / webhook

FastAPI (Python 3.12+)

Güçlü asenkron API ve tarayıcı/AI entegrasyonları

Frontend

Next.js + TypeScript

Çok kiracılı dashboard, olay listesi ve PR bağlantıları

Agent orchestration

LangGraph veya deterministik workflow motoru

State, retry, insan onayı ve araç çağrı denetimi

Queue / jobs

Redis Streams / Celery veya RabbitMQ

Webhook’ta hızlı ack; uzun analizleri worker’da yürütme

Relational DB

PostgreSQL

Tenant, advisory, scan, remediation ve audit kayıtları

Artifact storage

S3 uyumlu nesne deposu

SARIF, SBOM, raporlar, test logları

SAST / secrets

Semgrep + Gitleaks

Yaygın güvenlik kalıpları + credential taraması

SCA / image / IaC

OSV-Scanner + Trivy

Bilinen paket, container, yapılandırma açıkları

Patch engine

Renovate entegrasyonu + paket yöneticileri

Mevcut güvenilir sürüm yükseltme mekanizmalarını yeniden kullanma

LLM

Değiştirilebilir model adaptörü; tercihen özel ortam

Kod bağlamı ve açıklanabilir patch önerileri

Observability

OpenTelemetry + Prometheus + Grafana

Latency, maliyet, başarısızlık, güvenlik olayları

4.2. Servis sorumlulukları

Integration Gateway: GitHub/GitLab uygulama yetkilendirmesi; webhook imzası, delivery ID, event şeması, minimum izinler.

Commit Analyzer: Git diff + per-commit SHA kontrolü; SAST, secrets, SCA; SARIF normalize etme.

Asset Inventory: Paket URL (purl), lockfile çözümlemesi, dependency graph, SBOM, image digest ve commit snapshot.

Threat Intelligence Hub: OSV/GHSA/Dependabot/KEV/EPSS kayıtlarını normalize etme, alias eşleme, güncelleme ve withdrawn durumları.

Impact Correlator: Repo, paket, ekosistem, resolved version, branch, runtime ve ulaşılabilirlik ile etki eşlemesi.

Remediation Engine: Fix stratejisi seçme, patch branch, PR, sandbox doğrulama, geri alma.

Policy & Approval: Risk eşiği, otomatik birleştirme, onaylar, korumalı dallar, denetim izi.

Notification & Portal: GitHub Checks, PR yorum, Slack/email kanalları (isteğe bağlı), gösterge paneli.

4.3. Mimari ilkeler

Event-driven + idempotent: delivery_id ve (repo_id, SHA, scan_profile) kombinasyonlarıyla yinelenen görevleri bastır.

Tek gerçeklik kaynağı: analizler her zaman sabit SHA / dependency snapshot üzerinde yapılır.

Çok kiracılı izolasyon: tenant_id her veri satırında ve sorgu sınırında; ayrı token, worker ve isteğe göre ayrı VPC.

LLM kararı = öneri; merge veya geniş yetkili eylemler = deterministik politika sonucu.

5. Commit tarama akışı

GitHub App kurulumunda seçilen depolar için push ve pull_request olayları dinlenir.

Webhooks, X-Hub-Signature-256 ile HMAC-SHA256 doğrulanır; teslim kimliği kaydedilir; işlem kuyruğa alınarak 2xx yanıtı verilir.

push içindeki before/after SHA temel alınır; tek push birden fazla commit içeriyorsa tüm SHA’lar hesaplanır. Büyük push, force push ve ref silinmesi ayrı ele alınır.

Her SHA için değişen dosyalar analiz edilir; belirlenen aralıkta tam repo taraması drift ve önceki eksikleri yakalar.

Semgrep, Gitleaks, OSV-Scanner, Trivy bulguları ortak şemaya dönüştürülür; dosya yolu/satır/sürüm/kanıt saklanır.

Triage modeli, bulguları kod bağlamıyla açıklar; kritik bulgu durumunda zorunlu GitHub Check fail olabilir.

Bir düzeltme mümkünse kısa ömürlü dal ve PR açılır; test, yeniden tarama ve onay politikası uygulanır.

5.1. Taramaların sınırı

PR diff taraması hızlıdır ama geçmişten gelen açıkları kaçırabilir. Bu nedenle kurulumda tam baseline tarama, varsayılan dal için planlı tarama ve yeni advisory tetikleyicisinde yeniden eşleme birlikte zorunludur. Commit taraması bir push içindeki her SHA için rapor üretse de kapsamlı kod bağlamı/entegrasyon testleri PR head üzerinde yürütülebilir.

5.2. GitHub App asgari izinleri

İzin

Düzey / amaç

Metadata

Read; temel repo kimliği

Contents

Read; clone/diff; patch modu açılırsa Write

Pull requests

Read; patch PR oluşturmak için Write

Checks

Write; SHA üstüne check-run yayımlamak

Dependabot alerts

Read; repo güvenlik alarmlarını takip etmek

Issues

Sadece issue açma özelliği etkinse Write

Permissions, kurulum profiline göre ayrıştırılmalı; read-only monitoring ile patch-authoring aynı zorunlu yetki setini kullanmamalıdır. GitHub Actions workflow dosyaları varsayılan otomatik patch kapsamına alınmamalıdır.

6. Vulnerability Intelligence & Impact Engine

6.1. Kaynak stratejisi

Kaynak

Veri

Tetikleme

OSV API / OSV-Scanner

Ekosistem + sürüm / commit düzeyinde bilinen açıklar

Yeni kayıtlar için delta polling + paket bazlı yeniden sorgu

GitHub GHSA / Dependabot

GitHub duyuruları ve repo özel uyarıları

dependabot_alert webhook + periyodik API reconciliation

CISA KEV

Sahada istismar edildiği bilinen CVE listesi

Katalog farkı; eşleştirilen CVE için öncelik artırımı

FIRST EPSS

30 günlük istismar olasılığı tahmini

Günlük öncelik zenginleştirmesi

NVD / CVE kayıtları

CVE metaverisi, sürümler, referanslar

Zenginleştirme; tek başına eşleme kanıtı sayılmaz

6.2. Eşleştirme algoritması

Her repo için varsayılan dal snapshot’ı oluştur: manifest + lockfile + SBOM + container base image + direct/transitive dependencies.

Advisory kimliklerini normalize et: CVE, GHSA, OSV alias; duplicate kayıtları canonical advisory altında birleştir.

Advisory paket koordinatlarını purl/ecosystem/name ile eşleştir; isim benzerliğini tek başına kesin kanıt olarak alma.

Gerçek resolved sürümü vulnerable range içine düşüyor mu kontrol et. Kilit dosyası yoksa “potansiyel etki” işaretle.

Direct/transitive, prod/dev, derleme/runtime ve reachability kanıtlarını ekle; kanıt bulunmaması otomatik “güvenli” sonucu doğurmaz.

Fix version yayımlandıysa en dar güvenli güncellemeyi seç; yayımlanmadıysa mitigation, config guard ve kritik bildirim yolu işlet.

Teyit, yayımlanma, geri çekilme (withdrawn) veya yeni fix çıktığında repo eşlemesini yeniden değerlendir.

6.3. Önceliklendirme

Öncelik sırası önerisi: doğrulanmış etki → CISA KEV’de bulunma → internet erişimi / kritik varlık → CVSS ağırlığı → EPSS → ulaşılabilirlik kanıtı → çözümün varlığı. CVSS, EPSS ve LLM güven puanı farklı kavramlardır; tek sayıya indirgemek için kör toplama yapılmaz. Ürün, neden “Critical” verdiğini kanıt alanlarıyla göstermelidir.

Gerçek zamanlılık uyarısı: Webhook’lar ve veri kaynakları anlık teslim garantisi vermez. Hedef “olay geldikten sonra hızlı işlem + periyodik uzlaştırma” olarak tanımlanır; bütün dünyadaki yeni CVE’lerin sıfır gecikmeyle tespit edildiği iddia edilmez.

7. Otonom düzeltme (Remediation) politikası

7.1. Düzeltme hiyerarşisi

Paket yükseltme: etkilenen sürümü kaldıracak en düşük uyumlu güvenli sürüm; lockfile yeniden oluştur.

Bağımlılık değiştirme / transitive override: yalnızca uyumluluk ve kaynak güveni doğrulandığında.

Kısa kod yaması: doğrulanmış kod bulgusu için dar kapsamlı AI patch; değişiklik dışı dosyalara dokunma.

Fix yoksa: acil uyarı, geçici mitigation önerisi, kayıt altına alınmış risk kabulü; sahte “düzeltildi” durumu oluşturma.

7.2. Değişiklik karar matrisi

Değişiklik türü

Otomatik PR

Otomatik merge (opt-in)

Patch seviyesinde bağımlılık güvenlik güncellemesi

Evet

Uygun test ve politika ile evet

Minor dependency güncellemesi

Evet

Yalnız izinli paketlerde / güçlü CI ile

Major dependency / breaking change

Evet, açıklamalı

Hayır; insan onayı

Uygulama kaynak koduna AI yaması

Evet, sandbox testliyse

MVP’de hayır; insan onayı

Auth, crypto, ödeme, altyapı, workflow değişikliği

Evet, incelemeyle

Hayır; ek güvenlik onayı

Henüz yamalanmamış kritik CVE

Mitigation önerisi

Hayır; yalnız alarm/onay

7.3. Merge güvenlik kapıları

PR hedef dalı protected; doğrudan main/master push kapalı; onay ve branch protection bypass edilmez.

Paket kaynağı beklenen registry ve imza/provenance kontrolünden geçer; ilk kez gelen paket/sahip değişimi yükseltilmiş inceleme ister.

Build, unit/integration testleri, güvenlik re-scan, policy ve gerekiyorsa smoke test başarılı olur.

Bulgu düzeltildiği teyit edilir; yeni High/Critical bulgu, secret sızıntısı veya test kaybı oluşmaz.

Rollback stratejisi hazırlanır ve deploy sonrası smoke/health kontrolleri için sahip belirlenir.

AI modelinden gelen prompt, repo README veya tarayıcı bulgusu yönetici yetkisi yaratamaz.

8. AI agent tasarımı

8.1. Önerilen agent rolleri

Agent

Girdi

Çıktı

Scan Coordinator

Webhook, repo, SHA

Tarama planı, job DAG

Finding Triage

SARIF/bulgu + kod bağlamı

CWE, güven kanıtı, kullanıcı açıklaması

Threat Correlator

Advisory + SBOM + lock

Etkilenen sürüm, kapsam, etki gerekçesi

Patch Planner

Bulgu + sürüm çözümleri + politika

Düzeltme stratejisi, dar kapsamlı değişiklik

Patch Generator

Yalnız izinli dosyalar

Git diff / dependency update

Patch Verifier

Patch + test planı

İzole test ve re-scan sonucu

PR Reporter

Onaylanmış kanıtlar

PR özeti, risk, doğrulama, rollback notu

8.2. Araç sınırları

Agent yalnızca tanımlı tool API’lerini çağırır: get_diff, read_file_at_sha, get_sbom, query_advisory, plan_dependency_upgrade, prepare_patch, run_isolated_tests, create_pull_request, attach_check. Doğrudan shell erişimi, serbest network çıkışı, kalıcı admin token ve rastgele repo yazma yetkisi verilmez. Her tool invocation kayıt ve tenant-policy kontrolünden geçer.

Repo içeriği, commit mesajları, PR yorumları ve CVE açıklamaları güvenilmeyen veri olarak ele alınır. İçlerine gömülü “kuralları yok say / token’ı dışarı gönder” türü komutlar agent talimatı kabul edilmez. LLM’e gönderilen kod minimum bağlamla ve secret maskesiyle sınırlandırılır.

8.3. Workflow state

NEW -> VALIDATED -> INVENTORIED -> SCANNED -> CORRELATED

 -> PLANNED -> PATCH_PREPARED -> TESTING

 -> {READY_FOR_REVIEW | ELIGIBLE_FOR_AUTOMERGE | FAILED}

 -> {MERGED | REJECTED | ROLLED_BACK | CLOSED_NO_FIX}

9. Veritabanı ve olay modeli

Tablo

Önemli alanlar / amaç

organizations

id, name, settings, policy_version

installations

tenant_id, provider, installation_id, encrypted_ref

repositories

id, tenant_id, provider_repo_id, default_branch, state

repo_snapshots

repo_id, commit_sha, sbom_uri, lock_digest, scanned_at

components

snapshot_id, purl, resolved_version, direct, scope, path

advisories

canonical_id, aliases, ranges, fixed_versions, published, withdrawn

impacts

advisory_id, repo_id, snapshot_id, matched_component, confidence, status

scans / findings

repo_sha, engine, rule_id, severity, file, line, fingerprint, status

remediations

finding_id/impact_id, strategy, branch, pr_id, validation, approval

audit_events

actor, action, tenant_id, object, policy_decision, timestamp

9.1. Event sözleşmeleri

event_type: advisory.matched | commit.scan.completed | remediation.pr.created

idempotency_key: <tenant>/<repo>/<sha-or-advisory>/<workflow_version>

metadata: {tenant_id, repo_id, source, event_time, correlation_id}

payload: {advisory_id?, commit_sha?, finding_ids?, severity?, policy_result?}

9.2. API taslağı

POST /api/v1/integrations/github/webhook

GET  /api/v1/repos

GET  /api/v1/repos/{repo_id}/findings?status=open

GET  /api/v1/repos/{repo_id}/sbom

GET  /api/v1/advisories/impacts?severity=critical

POST /api/v1/findings/{id}/remediate

GET  /api/v1/remediations/{id}

POST /api/v1/remediations/{id}/approve

POST /api/v1/remediations/{id}/cancel

GET  /api/v1/audit?repo_id=...

10. Yapılandırma örneği

Repo düzeyindeki örnek sentinelai.yml; kurumsal merkezi politikalar buna üst sınır koyar:

version: 1

scan:

  on_push: true

  on_pull_request: true

  weekly_full_scan: true

  engines: [semgrep, gitleaks, osv, trivy]

intelligence:

  sources: [osv, ghsa, cisa_kev, epss]

  reconciliation_interval_minutes: 30

remediation:

  create_pr: true

  auto_merge: false

  allow_dependency_patch_updates: true

  allow_ai_code_patch: false

  block_direct_default_branch_write: true

  require_checks: [build, unit-tests, security-rescan]

policy:

  block_new_severities: [critical, high]

  auth_crypto_workflow_changes_require_review: true

notification:

  critical: immediate

  others: digest

Kurumsal politikalar ve runtime yapılandırması ayrıca tutulmalıdır. Örneğin webhook secret veya GitHub App private key dosyaları repodaki YAML içine yazılmaz.

11. Güvenlik ve tehdit modeli

Tehdit

Kontrol

Sahte webhook / replay

HMAC-SHA256 + delivery ID dedupe + replay penceresi + audit

Kötü niyetli PR/CI kodu

Ephemeral sandbox, ağ kapalı varsayılanı, secret’sız worker, CPU/RAM/time limit

Agent prompt injection

Repo/advisory = untrusted data; tool allowlist + policy engine + output verification

Dependency supply chain attack

Trusted registry, lock/digest, provenance, şüpheli release / ownership tespiti

Token sızıntısı

GitHub installation token kısa ömürlü, KMS/Vault, secret redaction, scope limit

Cross-tenant veri erişimi

Tenant-scoped authorization, DB RLS opsiyonu, ayrı worker cache namespace

Yanlış otomatik düzeltme

PR, korumalı dal, test+re-scan, retry limit, rollback, audit

Webhook veya feed kesintisi

Dead-letter queue, retry/backoff, periyodik reconciliation, health alarmı

11.1. Gözlemlenebilirlik

Olay alım gecikmesi (webhook event -> queue), tarama süresi, advisory -> matched impact süresi.

Açık bulgular, kritik etkilenen repo sayısı, doğru/yanlış pozitif geri bildirimi.

Otomatik oluşturulan PR sayısı, test başarısı, merge oranı, revert oranı, MTTR.

Feed staleness, webhook başarısızlıkları, DLQ birikimi, token/API kota tüketimi.

LLM token maliyeti ve model çıktı belirsizliği; repo başına maliyet ve rate limit.

12. Örnek olay - yeni güvenlik duyurusu

Örnek tamamen kurgusaldır. “example-http 2.4.0” kütüphanesinde bir güvenlik açığı duyuruluyor; 2.4.3 sürümü düzeltme içeriyor.

ThreatWatch yeni advisory’yi alır ve kimlikleri normalize eder.

Inventory, Repo-A içindeki çözülmüş example-http 2.4.0 sürümünün advisory aralığında olduğunu doğrular.

Impact Engine bu paketin prod bağımlılığı olduğunu ve uygulamanın ilgili HTTP özelliğini kullandığını raporlar.

Policy Engine, en düşük güvenli sürümün 2.4.3 olduğunu seçer.

Patch engine manifest/lockfile günceller; “security/example-http-2.4.3” dalı ve PR oluşturur.

CI: build + test + re-scan başarılı olur. Varsayılan politika nedeniyle PR insan onayına gider; auto-merge açık ve tüm kapılar uygunsa otomatik birleştirilebilir.

PR açıklaması etki, kanıt, CVE/GHSA bağlantıları, test sonuçları, değişen dosyalar ve rollback adımını içerir.

13. MVP teslim planı ve kabul kriterleri

Faz

Teslimatlar

Çıkış koşulu

Faz 1 - İskelet

GitHub App, webhook, queue, Postgres, repo dashboard

Gerçek push için doğrulanmış check run

Faz 2 - Tarama

Diff/baseline, Semgrep, Gitleaks, OSV, Trivy

Yeni kritik örnek bulgu commit ile eşleşir

Faz 3 - İstihbarat

SBOM/lockfile, OSV/GHSA/KEV, alias normalizasyonu

Yeni advisory ilgili repo sürümünü bulur

Faz 4 - Patch

Renovate/paket yöneticisi, PR, izole CI, onay akışı

Güvenli sürüm için doğrulanmış patch PR

Faz 5 - Sertleştirme

RBAC, audit, retry/DLQ, güvenlik testleri, pilot

Kritik güvenlik testlerini ve operasyon SLO’larını geçer

13.1. Ölçülebilir kabul testleri

AT-01: Geçerli imzasız webhook reddedilir; geçerli imzalı olay kabul edilir.

AT-02: Aynı delivery iki kez geldiğinde tek mantıksal tarama oluşturulur.

AT-03: Bir push içindeki birden çok SHA kayıpsız izlenir; her SHA’ya durum bağlanır.

AT-04: Commit’te yeni secret örneği güvenilir test fixture’ı ile yakalanır; secret raporda maskelenir.

AT-05: Yeni advisory, etkilenen çözülmüş sürümü bulur; etkilenmeyen sürümü eşlemez.

AT-06: Fix bulunmayan advisory için PR başarısı uydurulmaz, mitigation alarmı üretilir.

AT-07: Patch PR test başarısızsa otomatik birleşmez.

AT-08: Korumalı dal bypass’ı ve workflow/credential değişiklikleri politika tarafından engellenir.

AT-09: Kötü niyetli repo metni (prompt injection) agent’ın tool sınırını aşamaz.

AT-10: Reconciliation job gecikmiş/advisory withdrawn kayıtları doğru günceller.

13.2. Ölçü hedefleri (başlangıç hedefi, garanti değildir)

MVP için öneri: webhook alma isteğine hızlı 2xx dönüş; sıraya alma p95 < 5 sn (kendi servisimiz için), küçük commit taraması p95 < 3 dk (yük/engine bağımlı), webhook sonrası etkilenmiş repo listesi p95 < 5 dk (olay alındıktan sonra), %100 patch PR için test/re-scan sonucu ve audit kaydı. Bunlar gerçek pilotta baz çizgisi alınarak revize edilir.

14. Riskler ve mühendislik kararları

Karar / risk

Öneri

Tüm CVE’leri LLM ile yorumlamak

Önce sürüm eşleştirmesini deterministik yap; LLM yalnız bağlam ve açıklama için

Kendi dependency patch motorunu yazmak

İlk sürümde Renovate/paket yöneticisini orkestre et

Tüm security güncellemelerini auto-merge etmek

Varsayılan kapalı, kapsam + CI + politikaya bağlı ve dar izinli

Sürekli tam repo taramak

PR/diff taraması + periyodik baseline; cache + öncelik kuyruğu

CVE yayımlandı ama fix henüz yok

Durumu açık göster; mitigation ve owner bildirimleri

AI kodu dış modele göndermek

Hassas repolar için self-hosted model / veri politikası, minimal bağlam

15. Kaynaklar / teknik doğrulama

Aşağıdaki resmi kaynaklar bu tasarımın API ve mekanizma seçimlerine temel olur. 23.10.2026 itibarıyla kontrol edilmiştir:

01. GitHub webhook event payloadshttps://docs.github.com/en/webhooks/webhook-events-and-payloads

02. GitHub webhook signatureshttps://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

03. GitHub Checks REST APIhttps://docs.github.com/en/rest/checks/runs

04. GitHub Dependabot alert event change 2026-10-13https://github.blog/changelog/2026-10-13-improved-detection-for-withdrawn-dependabot-alerts/

05. GitHub Dependabot alerts version field 2026-10-20https://github.blog/changelog/2026-10-20-dependabot-alerts-rest-api-now-includes-dependency-versions/

06. OSV APIhttps://google.github.io/osv.dev/api/

07. OSV Scanner / source and SBOMhttps://github.com/google/osv-scanner/blob/main/docs/scan-source.md

08. CISA KEV official datahttps://github.com/cisagov/kev-data

09. Renovate security updateshttps://docs.renovatebot.com/configuration-options/

10. Renovate automergehttps://docs.renovatebot.com/key-concepts/automerge/

16. Üretime alma kontrol listesi

16.1. Pilot öncesi

GitHub App sadece pilot depolara kurulmuş; installation ID ve izinleri en az ayrıcalıkla sınırlandırılmış olmalı.

İmzalı webhook doğrulaması, olay tekrar işleme/idempotency ve webhook kesintisi telafisi test edilmiş olmalı.

Repo gizlilik sınıfları belirlenmiş; özel kodun harici LLM servislerine çıkışı politika ile kapatılabilmeli.

Patch runner internete kontrollü çıkan, kısa ömürlü bir sandbox içinde ve kalıcı credential olmadan çalışmalı.

Politika sahibi, acil onay nöbetçisi ve repo bakım sorumlusu tanımlanmış olmalı.

Rollback, PR kapatma ve yanlış açılmış güvenlik alarmını geri çekme senaryoları denenmiş olmalı.

16.2. Pilot sonrası

False-positive oranı ve tespit doğruluğu gerçek örnekler üzerinden etiketlenerek ölçülmeli.

Patch PR başarısızlık nedenleri ve dependency ecosystem uyumluluğu raporlanmalı.

Auto-merge yalnız kapsamı dar ve CI güvenilirliği kanıtlanmış repolarda kontrollü açılmalı.

Aylık kaynak feed gecikmesi, GitHub API kotası, worker maliyeti ve kritik olay süresi gözden geçirilmeli.

Son not: Bu belge bir geliştirme tasarımıdır; gerçek GitHub App izinleri, tarayıcı lisansları ve kurum güvenlik politikası kurulum esnasında ayrıca gözden geçirilmelidir.
