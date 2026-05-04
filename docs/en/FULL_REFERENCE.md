# Eresus Sentinel — Tam Referans Kılavuzu

> **Sürüm:** 0.1.0 · 25 input + 25 output = 50 firewall scanner · 39 artifact scanner · 2132+ kural

---

## İçindekiler

1. [Genel Bakış](#1-genel-bakış)
2. [Global Flagler](#2-global-flagler)
3. [Ortak Flagler (tüm alt komutlar)](#3-ortak-flagler)
4. [CLI Komutları — Tam Referans](#4-cli-komutları)
   - 4.1 [scan — tam tarama](#41-scan)
   - 4.2 [artifact — model artefakt tarama](#42-artifact)
   - 4.3 [sast — statik kod analizi](#43-sast)
   - 4.4 [secrets-scan — gizli bilgi tarama](#44-secrets-scan)
   - 4.5 [firewall — prompt güvenlik duvarı](#45-firewall)
   - 4.6 [codeguard — agent/araç kodu denetimi](#46-codeguard)
   - 4.7 [notebook — Jupyter güvenlik taraması](#47-notebook)
   - 4.8 [diff — git farkı tarama](#48-diff)
   - 4.9 [hf-scan — HuggingFace model tarama](#49-hf-scan)
   - 4.10 [hf-artifact — HuggingFace artefakt tarama](#410-hf-artifact)
   - 4.11 [hf-guard — HuggingFace repo koruma](#411-hf-guard)
   - 4.12 [aibom — AI Malzeme Listesi](#412-aibom)
   - 4.13 [dep-scan — bağımlılık güvenlik açığı tarama](#413-dep-scan)
   - 4.14 [supply-chain — tedarik zinciri tarama](#414-supply-chain)
   - 4.15 [agent — agent kodu tarama](#415-agent)
   - 4.16 [mcp — MCP protokol tarama](#416-mcp)
   - 4.17 [a2a — Agent-to-Agent tarama](#417-a2a)
   - 4.18 [rag — RAG embedding tarama](#418-rag)
   - 4.19 [red-team — kırmızı takım saldırısı](#419-red-team)
   - 4.20 [playbook — playbook çalıştırma](#420-playbook)
   - 4.21 [evaluate — LLM değerlendirme](#421-evaluate)
   - 4.22 [compliance — uyumluluk denetimi](#422-compliance)
   - 4.23 [llm-judge — LLM ile bulgu sınıflandırma](#423-llm-judge)
   - 4.24 [provenance — model köken doğrulama](#424-provenance)
   - 4.25 [reverse — model tersine mühendislik](#425-reverse)
   - 4.26 [watch — dosya izleme modu](#426-watch)
   - 4.27 [rules — kural yönetimi](#427-rules)
   - 4.28 [policy — politika yönetimi](#428-policy)
   - 4.29 [serve — REST API sunucusu](#429-serve)
   - 4.30 [Bilgi & sistem komutları](#430-bilgi--sistem)
5. [Çıktı Formatları](#5-çıktı-formatları)
6. [Artifact Tarayıcılar — 39 Format](#6-artifact-tarayıcılar)
7. [Firewall Tarayıcılar — 50 Scanner](#7-firewall-tarayıcılar)
8. [Python API](#8-python-api)
9. [REST API Endpoints](#9-rest-api-endpoints)
10. [Exit Kodları](#10-exit-kodları)
11. [CI/CD Entegrasyonu](#11-cicd-entegrasyonu)

---

## 1. Genel Bakış

```
sentinel <global-flags> <komut> [komut-flagleri] <argümanlar>
```

Eresus Sentinel, ML/AI sistemleri için kapsamlı güvenlik tarama aracıdır:

| Katman | Ne Tarar |
|---|---|
| **Artifact** | 39 format: Pickle, ONNX, GGUF, SafeTensors, Keras, CNTK... |
| **SAST** | Python/JS/TS/Java/Go/Ruby/C#/Rust kaynak kodu |
| **Secrets** | Hardcode edilmiş API key, token, şifre |
| **Firewall** | LLM prompt injection, jailbreak, veri sızdırma |
| **Supply Chain** | Bağımlılık CVE, tedarik zinciri |
| **Compliance** | OWASP LLM Top-10, EU AI Act, NIST AI RMF |

---

## 2. Global Flagler

Bu flagler **her komuttan önce** gelir:

```bash
sentinel [GLOBAL] <komut> ...
```

| Flag | Kısa | Açıklama |
|---|---|---|
| `--version` | | Sürüm numarasını göster ve çık |
| `--help` | `-h` | Yardım mesajını göster |
| `-v` | | Ayrıntılı (verbose) çıktı |
| `-q` | | Sessiz mod (sadece hatalar) |
| `-f FORMAT` | | Çıktı formatı (aşağıya bak) |
| `-o FILE` | | Çıktıyı dosyaya yaz |

```bash
# Örnekler
sentinel --version
sentinel -v scan ./models
sentinel -q -f json scan ./models -o results.json
```

---

## 3. Ortak Flagler

Çoğu alt komut bu flagleri destekler:

| Flag | Değerler | Açıklama |
|---|---|---|
| `-f FORMAT` | Aşağıda | Çıktı formatı |
| `-o FILE` | dosya yolu | Çıktıyı dosyaya yaz |
| `--min-severity SEV` | `INFO LOW MEDIUM HIGH CRITICAL` | Bu seviyenin altındaki bulguları gizle |
| `--fail-on SEV` | `info low medium high critical` | Bu seviyede veya üstünde bulgu varsa çık kodu 1 |

---

## 4. CLI Komutları

### 4.1 `scan`

**Tüm katmanları birden çalıştıran ana tarama komutu.**

```bash
sentinel scan <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--profile PROFILE` | `fast` `balanced` `deep` `paranoid` — tarama derinliği |
| `--fast` | Sadece SAST + secrets (artifact/supply-chain atlar) |
| `--ci` | CI modu: makine okunabilir çıktı + `--fail-on` politikası |
| `--fail-on SEV` | Belirtilen seviyede bulgu varsa exit 1 |
| `--min-severity SEV` | Filtreleme seviyesi |
| `--plan` / `--explain-plan` | Hangi scanner'ların çalışacağını göster, tarama yapma |
| `--stdin-files` | Ek dosya yollarını stdin'den oku (pre-commit için) |
| `-f FORMAT` | Çıktı formatı |
| `-o FILE` | Çıktı dosyası |

```bash
# Temel kullanım
sentinel scan ./models

# CI pipeline — yüksek+ bulgu varsa fail
sentinel scan . --ci --fail-on high -f sarif -o results.sarif

# Hızlı sadece SAST+secrets
sentinel scan . --fast --profile fast

# Hangi scanner'lar çalışacak?
sentinel scan . --explain-plan

# Paranoid mod — fuzzing dahil
sentinel scan ./models --profile paranoid -f json -o deep.json
```

---

### 4.2 `artifact`

**Model artefaktlarını deserialize etmeden tarar.**

```bash
sentinel artifact scan [path] [flagler]
sentinel artifact metadata <dosya>
sentinel artifact scan --list-scanners
```

#### `artifact scan` flagleri

| Flag | Açıklama |
|---|---|
| `--list-scanners` | 39 kayıtlı scanner'ı listele |
| `--scanners LIST` | Virgülle ayrılmış scanner izin listesi (id, class, ya da uzantı) |
| `--exclude-scanner LIST` | Virgülle ayrılmış scanner engel listesi |
| `--dry-run` | Dosyaları ve scanner'ları önizle, tarama yapma |
| `--strict` | Desteklenmeyen format ve scanner hatalarını da bul olarak işaretle |
| `--stream` | Uzak URL'yi geçici dosyaya indirerek tara |
| `--max-size BOYUT` | Bu boyutu aşan artefaktları atla (örn. `10GB`) |
| `--trust-loaders` | Pickle/Torch/Joblib için deserializasyon izni (opt-in) |
| `--sbom DOSYA` | CycloneDX SBOM JSON dosyasına yaz |
| `--show-skipped` | Atlanan dosyaları göster |
| `--fail-on SEV` | |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

```bash
# Tek dosya
sentinel artifact scan model.pkl

# Dizin, sadece pickle ve onnx scanner'ları
sentinel artifact scan ./models --scanners pickle,onnx

# Pickle hariç tüm scanner'lar
sentinel artifact scan ./models --exclude-scanner pickle

# Uzak URL tarama
sentinel artifact scan --stream https://huggingface.co/.../model.pkl

# SBOM üret
sentinel artifact scan ./models --sbom bom.json -f cyclonedx

# Güvenilir loader ile (dikkat: deserialize eder)
sentinel artifact scan model.pt --trust-loaders

# JSON çıktı
sentinel artifact scan evil.pkl -f json -o bulgu.json

# Önizleme
sentinel artifact scan ./models --dry-run
```

---

### 4.3 `sast`

**Python ve çok dilli kaynak kodu statik analizi.**

```bash
sentinel sast <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--multi-lang` | JS/TS/Java/Go/Ruby/C#/Rust için de LLM güvenlik pattern'larını tara |
| `--langs LANG[,LANG]` | `--multi-lang` ile hangi diller: `javascript,typescript,go,java,ruby,csharp,rust` |
| `--min-severity SEV` | |
| `-f FORMAT` / `-o FILE` | |

```bash
# Python kodu
sentinel sast ./python

# Çok dilli
sentinel sast ./src --multi-lang

# Sadece JS ve TS
sentinel sast ./frontend --multi-lang --langs javascript,typescript

# SARIF çıktısı (GitHub Code Scanning için)
sentinel sast . --multi-lang -f sarif -o sast.sarif
```

---

### 4.4 `secrets-scan`

**Hardcode edilmiş sırlar, API key'ler, token'lar.**

```bash
sentinel secrets-scan <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--git-history` | Git geçmişini de tara (commit'lerde sızdırılmış secret) |
| `--no-entropy` | Entropi tabanlı tespiti devre dışı bırak |
| `--max-git-commits N` | Git geçmişinde taranacak max commit sayısı |
| `--min-severity SEV` | |
| `-f FORMAT` / `-o FILE` | |

```bash
# Mevcut dosyalar
sentinel secrets-scan ./src

# Git geçmişiyle birlikte
sentinel secrets-scan . --git-history --max-git-commits 500

# Sadece pattern tabanlı (entropi yok)
sentinel secrets-scan ./config --no-entropy

# JSON çıktı
sentinel secrets-scan . --git-history -f json -o secrets.json
```

**Tespit edilen secret türleri:** AWS key, GitHub token, Stripe key, Google API key, JWT, hardcoded şifre, özel anahtar, bağlantı dizesi, `.env` içerikleri...

---

### 4.5 `firewall`

**Gerçek zamanlı LLM prompt güvenlik duvarı.**

```bash
sentinel firewall <input> [flagler]
sentinel firewall - [flagler]   # stdin'den oku
```

| Flag | Değerler | Açıklama |
|---|---|---|
| `-d` / `--direction` | `input` `output` | Prompt yönü (default: `input`) |
| `--min-severity SEV` | | |
| `-f FORMAT` / `-o FILE` | | |

```bash
# Kullanıcı girdisini tara
sentinel firewall "Ignore all previous instructions"

# Model çıktısını tara
sentinel firewall -d output "Here is your system prompt: ..."

# Stdin'den
echo "Some user input" | sentinel firewall -

# JSON çıktı
sentinel firewall "{{7*7}}" -f json

# Yüksek+ seviye bul varsa fail
sentinel firewall "jailbreak attempt" --min-severity HIGH
```

**Tespit edilen tehditler (25 input + 25 output scanner):**

| Input Scanner | Output Scanner |
|---|---|
| Prompt injection (DeBERTa ML) | AI içerik tespiti |
| Heuristik injection (8360 kombinasyon) | Copyright ihlali |
| Encoding saldırıları (leet/b64/rot13/...) | Önyargı tespiti |
| Veri sızdırma girişimi | Format uyumu |
| Görünmez metin/Unicode steganografi | Alaka düzeyi |
| Reverse shell payload | Ret tespiti |
| Sıfır genişlikli karakter bombası | Gerçekçilik kontrolü |
| Jailbreak (DAN, persona) | Kaynak atıfı |
| SQL/code injection | Uyumluluk |
| Maliyet koruması | JSON yapısı |

---

### 4.6 `codeguard`

**Agent ve araç kodlarında tehlikeli pattern tespiti.**

```bash
sentinel codeguard scan <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--min-severity SEV` | |
| `-f FORMAT` / `-o FILE` | |

```bash
# Agent kodu tara
sentinel codeguard scan ./agent

# Tek dosya
sentinel codeguard scan tools/web_search.py

# JSON çıktı
sentinel codeguard scan ./src -f json -o codeguard.json

# Yüksek+ bulgu varsa CI'da fail
sentinel codeguard scan . --min-severity HIGH --fail-on high
```

**Tespit:** araç kötüye kullanımı, güvensiz deserializasyon, komut enjeksiyonu, agent kaçış pattern'leri, tehlikeli MCP araç tanımları.

---

### 4.7 `notebook`

**Jupyter Notebook (.ipynb) güvenlik taraması.**

```bash
sentinel notebook <path> [flagler]
```

```bash
sentinel notebook research.ipynb
sentinel notebook ./notebooks -f json -o nb_scan.json
sentinel notebook . --min-severity MEDIUM
```

**Tespit:** tehlikeli kod hücreleri, `os.system`, `eval`, gizlenmiş payload, zararlı import'lar.

---

### 4.8 `diff`

**Git değişikliklerini tarar — pre-commit için.**

```bash
sentinel diff [target] [flagler]
sentinel diff HEAD~1
sentinel diff --staged
```

| Flag | Açıklama |
|---|---|
| `--staged` | Index'e eklenmiş (staged) değişiklikler |
| `--unstaged` | Henüz staged olmayan değişiklikler |
| `--all` | Tüm git değişiklikleri |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

```bash
sentinel diff --staged                    # commit öncesi kontrol
sentinel diff HEAD                        # son commit
sentinel diff HEAD~3                      # son 3 commit
sentinel diff --unstaged -f json          # çalışma dizini değişiklikleri
sentinel diff main..feature-branch        # branch karşılaştırma
```

---

### 4.9 `hf-scan`

**HuggingFace model repo'sunu tüm katmanlarla tarar.**

```bash
sentinel hf-scan <org/model> [flagler]
```

```bash
sentinel hf-scan bert-base-uncased
sentinel hf-scan microsoft/phi-2 -f json -o phi2_scan.json
sentinel hf-scan suspicious-org/model --min-severity LOW
```

---

### 4.10 `hf-artifact`

**HuggingFace repo'sunun artefaktlarını tarar.**

```bash
sentinel hf-artifact <org/model> [flagler]
```

```bash
sentinel hf-artifact TheBloke/Llama-2-7B-GGUF
sentinel hf-artifact org/model -f sarif -o hf_artifacts.sarif
```

---

### 4.11 `hf-guard`

**HuggingFace repo güvenlik politikası uygular.**

```bash
sentinel hf-guard <org/model> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--deep` | Dosyaları indir ve derin tara |
| `--block-pickle` | Pickle içeren repo'yu reddet |
| `--require-safetensors` | Sadece SafeTensors'a izin ver |
| `--offline` | HuggingFace Hub ağ çağrısını atla |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

```bash
# Derin tarama + pickle reddet
sentinel hf-guard org/model --deep --block-pickle

# SafeTensors zorunlu
sentinel hf-guard org/model --require-safetensors

# Offline (önceden indirilmiş)
sentinel hf-guard ./local_model --offline --deep
```

---

### 4.12 `aibom`

**AI Malzeme Listesi (AI Bill of Materials) oluşturur.**

```bash
sentinel aibom [path] [flagler]
```

| Flag | Açıklama |
|---|---|
| `--format FORMAT` | `cyclonedx json spdx sarif html csv junit markdown` |
| `--output FILE` / `-o` | Çıktı dosyası |
| `--ci` | CI uyumlu mod |
| `--list-scanners` | AIBOM scanner kaydını listele |
| `--diff OLD NEW` | İki AIBOM JSON dosyasını karşılaştır |
| `--container-extraction-tier` | `auto runtime tarball metadata` |
| `--discover-repos DIR` | Alt repo'ları keşfet |
| `--skip-unchanged` | HEAD değişmemiş repo'ları atla |
| `--parallel-repos N` | Paralel repo tarama sayısı |
| `--once` | Watch modunda tek tarama yap |

```bash
# Temel AIBOM oluştur
sentinel aibom ./models

# CycloneDX formatında
sentinel aibom ./models --format cyclonedx -o sbom.json

# İki AIBOM karşılaştır
sentinel aibom --diff old_bom.json new_bom.json

# Tüm alt repo'ları keşfet
sentinel aibom --discover-repos ./org-root --format json -o org_bom.json
```

---

### 4.13 `dep-scan`

**Bağımlılıklardaki CVE ve güvenlik açıklarını tarar.**

```bash
sentinel dep-scan <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--no-osv` | OSV.dev sorgulamalarını devre dışı bırak |
| `--no-pip-audit` | pip-audit'i devre dışı bırak |
| `--offline` | Canlı güvenlik açığı sorgularını atla |
| `--ecosystem` | `pypi` ya da `npm` |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

```bash
sentinel dep-scan .
sentinel dep-scan . --ecosystem npm
sentinel dep-scan . --offline                # ağ yok
sentinel dep-scan . --no-pip-audit --no-osv  # sadece yerel analiz
sentinel dep-scan . -f json -o vuln.json --min-severity HIGH
```

---

### 4.14 `supply-chain`

**Model tedarik zinciri bütünlüğü taraması.**

```bash
sentinel supply-chain <path> [flagler]
```

```bash
sentinel supply-chain ./models
sentinel supply-chain . -f json -o supply_chain.json
```

---

### 4.15 `agent`

**Agent kodu ve araç tanımlarını tarar.**

```bash
sentinel agent <path> [flagler]
```

```bash
sentinel agent ./agent_src
sentinel agent tools/ -f sarif -o agent_findings.sarif
sentinel agent . --min-severity MEDIUM
```

---

### 4.16 `mcp`

**MCP (Model Context Protocol) güvenlik taraması.**

```bash
sentinel mcp scan [target] [flagler]
sentinel mcp transports
sentinel mcp fingerprint
```

#### `mcp scan` flagleri

| Flag | Açıklama |
|---|---|
| `--manifest DOSYA` | MCP JSON/YAML manifest dosyası |
| `--url URL` | MCP HTTP JSON-RPC endpoint |
| `--stdio-command ...` | MCP stdio sunucu komutu |
| `--timeout N` | Bağlantı zaman aşımı (saniye) |
| `-f FORMAT` / `-o FILE` | |

```bash
# Manifest dosyası tara
sentinel mcp scan mcp.json

# HTTP endpoint
sentinel mcp scan --url http://localhost:8080/mcp

# Stdio komut
sentinel mcp scan --stdio-command python -m my_mcp_server

# Transport desteği görüntüle
sentinel mcp transports

# Sunucu yeteneklerini parmak izi al
sentinel mcp fingerprint --url http://localhost:8080
```

---

### 4.17 `a2a`

**Agent-to-Agent (A2A) protokol güvenlik taraması.**

```bash
sentinel a2a scan <path> [flagler]
```

```bash
sentinel a2a scan agent_manifest.json
sentinel a2a scan ./agent_configs -f json -o a2a_scan.json
```

---

### 4.18 `rag`

**RAG embedding dosyalarında hubness anomalisi ve near-duplicate tespiti.**

```bash
sentinel rag scan <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--k N` | k-NN komşu sayısı (hubness skoru için) |
| `--hubness-threshold Z` | Hubness anomali eşiği (z-skoru, default 3.0) |
| `--near-dup-threshold SIM` | Near-duplicate eşiği (cosine, default 0.995) |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

```bash
sentinel rag scan embeddings/
sentinel rag scan ./vectors --k 20 --hubness-threshold 2.5
sentinel rag scan embeddings.npy --near-dup-threshold 0.98 -f json
```

---

### 4.19 `red-team`

**Otomatik kırmızı takım saldırı simülasyonu.**

```bash
sentinel red-team [target] [flagler]
```

| Flag | Açıklama |
|---|---|
| `--target URL` | Hedef LLM API endpoint |
| `--vertical SEKTÖR` | Sektöre özel probe paketi |
| `--strategy STRATEJİ` | Saldırı stratejisi: `autodan` `meta_agent` `adaptive` |
| `-f FORMAT` / `-o FILE` | |
| `--min-severity SEV` | |

**Desteklenen dikey sektörler:** `financial` `healthcare` `telecom` `ecommerce` `insurance` `realestate` `medical` `pharmacy` `policy` `agentic` `teenSafety` `codingAgent` `compliance` `all`

```bash
# Finansal sektör probe paketi
sentinel red-team http://localhost:8000 --vertical financial

# Tüm sektörler + adaptif strateji
sentinel red-team http://api/chat --vertical all --strategy adaptive

# JSON rapor
sentinel red-team --target http://localhost:8000 -f json -o redteam.json
```

---

### 4.20 `playbook`

**YAML tabanlı güvenlik playbook'larını çalıştırır.**

```bash
sentinel playbook <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `--report-format FORMAT` | `json html sarif text` |
| `--report-output DOSYA` | Rapor çıktı dosyası |
| `--fail-fast` | İlk başarısızlıkta dur |
| `--fail-on-critical` | CRITICAL probe başarısız olursa exit 1 |
| `--fail-on-failed-probes` | Herhangi probe başarısız olursa exit 1 |
| `--fail-on-grade HARF` | Bu not veya altında ise exit 1 (`A B C D F`) |

```bash
sentinel playbook playbooks/mcp_injection_suite.yaml
sentinel playbook ./playbooks --report-format html -o report.html
sentinel playbook suite.yaml --fail-on-critical --fail-fast
sentinel playbook . --fail-on-grade B  # B veya altı → fail
```

---

### 4.21 `evaluate`

**LLM çıktı kalitesi ve güvenlik değerlendirmesi.**

```bash
sentinel evaluate [config] [flagler]
```

| Flag | Açıklama |
|---|---|
| `--fail-on-threshold N` | Geçme oranı bu değerin altında ise exit 1 (0.0–1.0) |
| `--concurrency N` / `-j` | Paralel eval işçi sayısı (default 1) |
| `--summary-only` | Satır satır değil sadece özet göster |

```bash
sentinel evaluate eval_config.yaml
sentinel evaluate eval.json -j 4 --fail-on-threshold 0.9
sentinel evaluate config.yaml --summary-only -f json -o eval_results.json
```

---

### 4.22 `compliance`

**Uyumluluk çerçevesi denetimi.**

```bash
sentinel compliance check [path] [flagler]
```

| Flag | Değerler | Açıklama |
|---|---|---|
| `--framework` | `owasp-llm` `eu-ai-act` `nist-ai-rmf` `owasp-agentic-top10` `eresus` `all` | Hangi çerçeve |
| `-f FORMAT` | `table json html` | |
| `-o FILE` | | |

```bash
sentinel compliance check .
sentinel compliance check . --framework owasp-llm
sentinel compliance check ./models --framework eu-ai-act -f html -o report.html
sentinel compliance check . --framework all -f json -o compliance.json
```

---

### 4.23 `llm-judge`

**Bulguları LLM ile sınıflandırır (false positive / doğrulama).**

```bash
sentinel llm-judge classify <findings_json> [flagler]
sentinel llm-judge consensus ...
```

| Flag | Açıklama |
|---|---|
| `--provider PROVIDER` | `openai` `anthropic` `ollama` (default: `openai`) |
| `--model MODEL` | Model id (default: `gpt-4o-mini`) |
| `--min-severity SEV` | Sadece bu seviye ve üstü bulguları sınıflandır |
| `-o FILE` | Zenginleştirilmiş bulgu JSON dosyası |

```bash
# OpenAI ile sınıflandır
sentinel llm-judge classify findings.json --provider openai

# Anthropic + yüksek seviye bulgu
sentinel llm-judge classify scan.json --provider anthropic --model claude-3-haiku-20240307 --min-severity HIGH

# Yerel Ollama
sentinel llm-judge classify findings.json --provider ollama --model llama3.2

# Çıktıyı kaydet
sentinel llm-judge classify scan.json -o enriched.json
```

---

### 4.24 `provenance`

**Model köken ve parmak izi doğrulama.**

```bash
sentinel provenance scan <model>
sentinel provenance compare <model1> <model2>
sentinel provenance db-info
sentinel provenance download-fingerprints
```

```bash
# Modeli referans DB ile karşılaştır
sentinel provenance scan model.safetensors

# İki modeli karşılaştır
sentinel provenance compare original.pt finetuned.pt

# Kurulu referans DB durumu
sentinel provenance db-info

# Tohum parmak izi DB'sini indir
sentinel provenance download-fingerprints
```

---

### 4.25 `reverse`

**Model dosyasını tersine mühendislik eder — kendi detaylı çıktısı var.**

```bash
sentinel reverse <path>
```

```bash
sentinel reverse model.pkl
sentinel reverse suspicious.onnx
sentinel reverse model.pt
```

> **Not:** Bu komut kendi zengin çıktı formatına sahiptir, `-f` flag'i desteklenmez.

---

### 4.26 `watch`

**Dizini izler ve değişimleri otomatik tarar.**

```bash
sentinel watch <path> [flagler]
```

| Flag | Açıklama |
|---|---|
| `-i N` / `--interval N` | Kontrol aralığı (saniye) |

```bash
sentinel watch ./models
sentinel watch ./src -i 5       # 5 saniyede bir kontrol
```

---

### 4.27 `rules`

**Kural yönetimi ve denetimi.**

```bash
sentinel rules list
sentinel rules test <rule_id>
sentinel rules explain <rule_id>
sentinel rules audit
```

```bash
# Yüklü tüm kuralları listele (2132+)
sentinel rules list

# Kural test et
sentinel rules test ARTIFACT-002
sentinel rules test FIREWALL-INPUT-005

# Kural açıkla
sentinel rules explain ATR-019
sentinel rules explain SEC-AWS-001

# Tüm kural ID ve regex'leri denetle
sentinel rules audit
```

---

### 4.28 `policy`

**Güvenlik politikası yönetimi.**

```bash
sentinel policy init
sentinel policy show
sentinel policy validate
```

```bash
sentinel policy init        # sentinel.toml oluştur
sentinel policy show        # mevcut politikayı göster
sentinel policy validate    # politika dosyasını doğrula
```

---

### 4.29 `serve`

**REST API ve web dashboard sunucusu.**

```bash
sentinel serve [flagler]
```

| Flag | Default | Açıklama |
|---|---|---|
| `--host HOST` | `127.0.0.1` | Dinleme adresi |
| `--port PORT` | `8000` | Dinleme portu |
| `--policy DOSYA` | | Politika YAML dosyası |
| `--ui` | | React SPA web dashboard'u da sun |
| `--open` | | `--ui` ile açılışta tarayıcı aç |

```bash
sentinel serve                          # localhost:8000
sentinel serve --host 0.0.0.0 --port 9000
sentinel serve --ui --open              # dashboard ile
sentinel serve --policy sentinel.toml
```

---

### 4.30 Bilgi & Sistem

```bash
sentinel version          # Sürüm + scanner sayısı
sentinel config           # Mevcut yapılandırmayı göster
sentinel doctor           # Bağımlılıkları ve kurulumu doğrula
sentinel debug            # Debug bilgisi
sentinel scanners         # Firewall scanner listesi (50 scanner)
sentinel plugins          # Yüklü plugin'ler
sentinel stats <path>     # Dizin/dosya istatistikleri
sentinel cache stats      # Önbellek durumu
sentinel cache cleanup    # Önbelleği temizle
sentinel audit query      # Denetim kaydı sorgula
```

---

## 5. Çıktı Formatları

| Format | Açıklama | Kullanım |
|---|---|---|
| `table` | Renkli terminal tablosu (default) | İnsan okuma |
| `json` | Ham JSON | API, parse etme |
| `sarif` | SARIF 2.1 | GitHub Code Scanning, SAST araçları |
| `csv` | Virgülle ayrılmış | Excel, veri analizi |
| `markdown` | Markdown rapor | Dokümantasyon |
| `html` | HTML rapor | Tarayıcıda görüntüleme |
| `junit` | JUnit XML | Jenkins, test raporlama |
| `otlp` | OpenTelemetry | Observability platformları |
| `splunk` | Splunk HEC formatı | SIEM entegrasyonu |
| `plaintext` | Sade metin | Log'lama |
| `summary` | Kısa özet | Hızlı bakış |
| `cyclonedx` | CycloneDX BOM | SBOM araçları |
| `spdx` | SPDX BOM | Tedarik zinciri |
| `webhook` | Webhook payload | Slack/Teams/PagerDuty |
| `modelcard` | Model kartı | HuggingFace model card |

```bash
# Format ve çıktı dosyası
sentinel scan . -f sarif -o results.sarif
sentinel scan . -f json -o results.json
sentinel scan . -f html -o report.html
```

---

## 6. Artifact Tarayıcılar

39 kayıtlı tarayıcı — `sentinel artifact scan --list-scanners` ile görüntüle.

| ID | Sınıf | Uzantılar | Unsafe* |
|---|---|---|---|
| `pickle` | PickleScanner | `.pkl .pickle .p .dill .dat .joblib` | ✓ |
| `torch` | TorchScanner | `.pt .pth .bin .ckpt` | ✓ |
| `safetensors` | SafetensorsValidator | `.safetensors` | |
| `gguf` | GGUFAnalyzer | `.gguf .ggml .ggmf .ggjt .ggla .ggsa` | |
| `tensorflow` | TensorFlowScanner | `.pb` | |
| `tf_metagraph` | TFMetaGraphScanner | `.meta` | |
| `torchscript` | TorchScriptScanner | `.torchscript .ptc` | ✓ |
| `tflite` | TFLiteScanner | `.tflite` | |
| `torchmobile` | TorchMobileScanner | `.ptl` | ✓ |
| `llamafile` | LlamaFileScanner | `.llamafile .exe` | |
| `onnx` | ONNXScanner | `.onnx` | |
| `keras` | KerasScanner | `.keras .h5 .hdf5` | ✓ |
| `xgboost` | XGBoostScanner | `.xgb .bst .ubj .model` | |
| `numpy` | NumpyScanner | `.npy .npz` | ✓ |
| `archive` | ArchiveSlipDetector | `.zip .tar .tar.gz .tgz .tar.bz2 .tar.xz` | |
| `7z` | SevenZipScanner | `.7z` | |
| `yaml` | YamlScanner | `.yaml .yml` | |
| `catboost` | CatBoostScanner | `.cbm` | |
| `coreml` | CoreMLScanner | `.mlmodel .mlpackage` | |
| `flax` | FlaxScanner | `.msgpack .orbax .flax .jax .checkpoint` | |
| `lightgbm` | LightGBMScanner | `.lgb .lightgbm` | |
| `mxnet` | MXNetScanner | `-symbol.json .params` | |
| `nemo` | NeMoScanner | `.nemo` | ✓ |
| `openvino` | OpenVINOScanner | `.xml` | |
| `paddle` | PaddleScanner | `.pdmodel .pdiparams .pdparams` | |
| `pmml` | PMMLScanner | `.pmml` | |
| `rknn` | RKNNScanner | `.rknn` | |
| `cntk` | CNTKScanner | `.dnn .cmf` | |
| `r-serialized` | RSerializedScanner | `.rds .rda .rdata` | ✓ |
| `skops` | SkopsScanner | `.skops` | |
| `torchserve` | TorchServeScanner | `.mar` | ✓ |
| `torch7` | Torch7Scanner | `.t7 .th .net` | ✓ |
| `rar` | RARScanner | `.rar` | ✓ |
| `compressed` | CompressedWrapperScanner | `.gz .bz2 .xz .lz4 .zlib` | ✓ |
| `executorch` | ExecuTorchScanner | `.pte` | |
| `tensorrt` | TensorRTScanner | `.engine .plan .trt` | |
| `oci` | OCIScanner | `.oci .manifest` | |
| `jinja2` | Jinja2InjectionScanner | `.jinja .jinja2 .j2 .template` | |
| `mlmanifest` | MLManifestScanner | `.json` | |

> **\*Unsafe:** `--trust-loaders` flag'i gerektiren deserializasyon yapan tarayıcılar.

---

## 7. Firewall Tarayıcılar

`sentinel scanners` ile tam listeyi göster.

**25 Input Scanner** — kullanıcı girdilerini analiz eder:

| Scanner | Tespit |
|---|---|
| `injection` (ML) | DeBERTa tabanlı prompt injection (eşik: 0.85) |
| `heuristic_injection` | 8360 kombinasyon: verb×adj×obj×prep |
| `encoding_attack` | base64/hex/rot13/leet/url/morse/unicode steganografi |
| `invisible_text` | Sıfır genişlikli karakter, Unicode tag bombaları |
| `data_exfiltration` | Veri sızdırma girişimleri |
| `code` | Tehlikeli kod pattern'leri |
| `ban_substrings` | Yasaklı substring'ler |
| `ban_code` | Yasaklı kod pattern'leri |
| `ban_competitors` | Rakip marka referansları |
| `language` | Dil tespiti ve kısıtlama |
| `cost_guard` | Aşırı token maliyeti koruması |
| `gibberish` | Anlamsız metin tespiti |
| `layered_defense` | Çok katmanlı savunma koordinatörü |
| `ml_classifier` | Genel ML sınıflandırıcı |
| `policy_engine` | Politika tabanlı kural motoru |

**25 Output Scanner** — model çıktılarını analiz eder:

| Scanner | Tespit |
|---|---|
| `ai_content` | AI tarafından oluşturulmuş içerik |
| `ban_code_output` | Çıktıda yasaklı kod |
| `copyright` | Telif hakkı ihlali |
| `bias` | Önyargı ve ayrımcı içerik |
| `factual_consistency` | Gerçekçilik kontrolü |
| `relevance` | Soru-cevap alaka düzeyi |
| `format_enforcer` | Format uyumu (JSON, şema vb.) |
| `citation` | Kaynak atıf zorunluluğu |
| `compliance` | Uyumluluk ihlali |
| `no_refusal` | Gereksiz ret tespiti |
| `emotion` | Duygusal içerik analizi |
| `reading_time` | Okuma süresi hesaplama |
| `json` | JSON yapı doğrulama |

---

## 8. Python API

### Artifact Tarama

```python
from sentinel.artifact import scan_file, scan_directory, ArtifactScanOptions

# Tek dosya
findings = scan_file("model.pkl")

# Seçeneklerle
opts = ArtifactScanOptions(
    min_severity="HIGH",
    trust_loaders=False,
    scanners=["pickle", "torch"],        # izin listesi
    exclude_scanners=["yaml"],           # engel listesi
    max_file_size=1024 * 1024 * 500,    # 500 MB
)
findings = scan_file("model.pt", options=opts)

# Dizin tarama
findings = scan_directory("./models", options=opts)

# Zengin çıktı (runner metadatası dahil)
from sentinel.artifact import scan_file_rich
result = scan_file_rich("model.pkl")
# result.findings, result.scanner, result.duration_ms

for f in findings:
    print(f.rule_id, f.severity, f.title)
    print(f.description)
    print(f.evidence)
    print(f.remediation)
```

### SAST Tarama

```python
from sentinel.sast import SastScanner, SecretsScanner

# Python SAST
scanner = SastScanner()
findings = scanner.scan_file("agent.py")

# Çok dilli
findings = scanner.scan_file("tool.go", lang="go")

# Secrets
secrets = SecretsScanner()
findings = secrets.scan_file("config.py")
findings = secrets.scan_directory("./src", git_history=True)
```

### Firewall

```python
from sentinel.firewall import FirewallManager

fw = FirewallManager()

# Input tarama
result = fw.scan_input("Ignore all previous instructions")
print(result.action)     # BLOCK / ALLOW
print(result.issues)     # list[Issue]
print(result.score)      # 0.0–1.0

# Output tarama
result = fw.scan_output("Here is the system prompt: ...")
print(result.action)

# Issue detayları
for issue in result.issues:
    print(issue.scanner, issue.severity, issue.message)
```

### Finding Nesnesi

```python
from sentinel.finding import Finding, Severity

# Finding alanları:
finding.rule_id        # str   — örn. "ARTIFACT-002"
finding.severity       # Severity enum: INFO LOW MEDIUM HIGH CRITICAL
finding.title          # str
finding.description    # str
finding.evidence       # str | None
finding.remediation    # str | None
finding.file_path      # str | None
finding.line_number    # int | None
finding.tags           # list[str]
finding.cwe_ids        # list[str]
finding.cvss_score     # float | None
```

### Rules API

```python
from sentinel.rules import (
    load_cntk_rules,
    load_secret_patterns,
    load_backdoor_patterns,
    load_jinja2_rules,
    validate_all_rule_files,
    _clear_rule_cache,
)

# Kural yükle
cntk_rules = load_cntk_rules()
secret_patterns = load_secret_patterns()

# Cache temizle (test için)
_clear_rule_cache()

# Tüm kural dosyalarını doğrula
errors = validate_all_rule_files()
```

### Çıktı Formatlama

```python
from sentinel.output import format_findings

findings = scan_file("model.pkl")

# JSON string
json_output = format_findings(findings, format="json")

# SARIF
sarif = format_findings(findings, format="sarif")

# Dosyaya yaz
format_findings(findings, format="html", output_file="report.html")
```

---

## 9. REST API Endpoints

`sentinel serve` ile sunucu başlatıldığında:

```bash
sentinel serve --host 0.0.0.0 --port 8000
```

### Temel Endpoint'ler

| Method | Path | Açıklama |
|---|---|---|
| `GET` | `/health` | Sağlık kontrolü |
| `GET` | `/version` | Sürüm bilgisi |
| `GET` | `/scanners` | Kayıtlı scanner listesi |
| `GET` | `/rules` | Yüklü kural listesi |

### Tarama Endpoint'leri

| Method | Path | Açıklama |
|---|---|---|
| `POST` | `/scan` | Tam tarama (çok katman) |
| `POST` | `/artifact/scan` | Artifact tarama |
| `POST` | `/sast` | SAST tarama |
| `POST` | `/secrets` | Secrets tarama |
| `POST` | `/firewall/input` | Input güvenlik duvarı |
| `POST` | `/firewall/output` | Output güvenlik duvarı |
| `POST` | `/codeguard` | Agent kodu tarama |
| `POST` | `/notebook` | Notebook tarama |

### Örnek İstekler

```bash
# Firewall input
curl -X POST http://localhost:8000/firewall/input \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions"}'

# Artifact tarama (dosya yolu)
curl -X POST http://localhost:8000/artifact/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/model.pkl", "min_severity": "HIGH"}'

# Sağlık kontrolü
curl http://localhost:8000/health
```

### Web Dashboard

```bash
sentinel serve --ui --open    # React SPA dashboard'unu aç
# → http://localhost:8000/dashboard
```

---

## 10. Exit Kodları

| Kod | Anlam |
|---|---|
| `0` | Temiz — bulgu yok (ya da `--min-severity` altında) |
| `1` | Bulgu tespit edildi |
| `2` | Yanlış kullanım / geçersiz argüman |
| `3` | Yapılandırma hatası |
| `127` | Komut bulunamadı |

```bash
sentinel scan ./models --fail-on high
echo $?   # 0=temiz, 1=bulgu var
```

---

## 11. CI/CD Entegrasyonu

### GitHub Actions

```yaml
- name: Sentinel Security Scan
  run: |
    uv run python -m sentinel scan . \
      --ci \
      --fail-on high \
      --min-severity medium \
      -f sarif \
      -o sentinel.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: sentinel-diff
        name: Sentinel Security
        entry: sentinel diff --staged --fail-on high
        language: system
        pass_filenames: false
```

### GitLab CI

```yaml
sentinel:
  script:
    - sentinel scan . --ci --fail-on critical -f json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Docker

```bash
# Sentinel ile dizin tara
docker run --rm -v $(pwd):/workspace \
  eresus/sentinel:latest \
  scan /workspace --fail-on high -f json
```

---

*Bu dokümantasyon `sentinel 0.1.0` sürümü için otomatik oluşturulmuştur.*
*Son güncelleme: 2026-05-03*
