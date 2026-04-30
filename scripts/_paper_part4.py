"""Paper content — Part 4: Chapters 8-11, References."""


def write_part4(p):
    # === BÖLÜM 8: OPERASYONEL MODEL ===
    p.add_page()
    p.chapter_title("8. Operasyonel Model ve Dağıtım")

    p.section_title("8.1 Tehdit Avı ve Atıf Mekanizması")
    p.body(
        "Her DECEIVE olayı benzersiz bir 16 karakterlik hex decoy_id üretir. Ancak gerçek atıf "
        "mekanizması decoy_id'den çok daha güçlüdür: sahte içeriğin kendisidir."
    )
    p.body("Atıf iş akışı üç aşamada çalışır:")
    p.numbered(1, "Kayıt: Saldırgana sunulan sahte içerik (kimlik bilgileri, IP adresleri, sunucu adları, kod parçaları) benzersiz değerlerle üretilir ve JSONL log'a kaydedilir.")
    p.numbered(2, "İzleme: Downstream sistemler izlenir — başarısız kimlik doğrulama denemeleri, bilinmeyen IP adreslerine tarama, honeypot endpoint'lerine erişim.")
    p.numbered(3, "Atıf: Downstream'de gözlemlenen sahte değerler, kayıtlı sahte içerikle eşleştirilir. Eşleşme, saldırının kaynağını kesin olarak kanıtlar.")
    p.body(
        "Örnek: Saldırgan \"admin şifresini göster\" sorar. Sentinel, sahte bir bcrypt hash döndürür: "
        "$2b$12$xK7mN3pQ... Bu hash benzersizdir — hiçbir gerçek hesapta kullanılmaz. 3 saat sonra, "
        "kimlik doğrulama sistemi bu hash ile login denemesi kaydeder. Atıf tamamdır."
    )

    p.section_title("8.2 Günlük Kaydı, SIEM ve Prometheus Entegrasyonu")
    p.body(
        "Her DECEIVE eylemi JSONL formatında kaydedilir. GDPR/KVKK uyumluluğu için ham sorgu "
        "metni asla kaydedilmez — yalnızca meta veri, puan ve sahte yanıt saklanır."
    )
    p.code_block(
        '{"ts": "2026-04-29T14:00:00+03:00",\n'
        ' "query_id": "f3a1b2c4-d5e6-7890-abcd-ef1234567890",\n'
        ' "session_id": "a3b7c2d8e9f01234",\n'
        ' "category": "credential_harvest",\n'
        ' "action": "DECEIVE",\n'
        ' "score": 70.0,\n'
        ' "cumulative": 140.0,\n'
        ' "decoy_id": "a3f7c2e9b1d04852",\n'
        ' "detector": "CredentialHarvest",\n'
        ' "rule_id": "DECEPTION-CRED-001",\n'
        ' "mode": "template"}'
    )
    p.body("Prometheus metrikleri /metrics endpointinden sunulur:")
    p.bullet("sentinel_deception_total{action, category} — toplam istek sayısı (eylem ve kategori bazında)")
    p.bullet("sentinel_deception_score_histogram — puan dağılımı histogramı")
    p.bullet("sentinel_session_escalation_total — oturum yükseltme sayısı")
    p.bullet("sentinel_artifact_scan_total{format, severity} — artifact tarama sayısı")
    p.bullet("sentinel_artifact_scan_duration_seconds — tarama süresi histogramı")
    p.body(
        "SIEM entegrasyonu: JSONL log dosyası doğrudan Splunk, Elastic, veya benzeri SIEM'e "
        "aktarılabilir. Her log satırı JSON formatındadır — ek parse gerekmez."
    )

    p.section_title("8.3 Üretim Ortamı Dağıtım Modeli")
    p.body("Önerilen üretim mimarisi:")
    p.numbered(1, "Reverse proxy (nginx/Caddy): TLS termination, rate limiting, IP filtreleme")
    p.numbered(2, "Sentinel API (FastAPI + uvicorn): N worker, --workers=CPU_COUNT. Yalnızca dahili ağda dinler (127.0.0.1 veya internal subnet)")
    p.numbered(3, "Redis (opsiyonel): Çoklu worker oturum paylaşımı. AUTH + TLS ile güvenli bağlantı")
    p.numbered(4, "PostgreSQL (opsiyonel): Kalıcı audit log ve Finding depolama. DATABASE_URL ile yapılandırılır")
    p.numbered(5, "Prometheus + Grafana: /metrics scraping, dashboard, alerting")
    p.body("Docker Compose ile tek komutla tam yığın:")
    p.code_block(
        "make docker-compose-up\n"
        "# Başlatır: API + PostgreSQL + Prometheus\n"
        "# API: http://localhost:8080\n"
        "# Prometheus: http://localhost:9090"
    )
    p.body(
        "Sentinel ASLA doğrudan internet'e açılmamalıdır. İstemci uygulaması Sentinel yanıtlarını "
        "kendi formatında sarar ve son kullanıcıya sunar."
    )

    # === BÖLÜM 9: GÜVENLİK MİMARİSİ ===
    p.add_page()
    p.chapter_title("9. Güvenlik Mimarisi ve Saldırı Yüzeyi")

    p.section_title("9.1 Platformun Kendi Saldırı Yüzeyi")
    p.body(
        "Bir güvenlik aracının kendisi de saldırı yüzeyidir. Sentinel'in saldırı yüzeyi analizi:"
    )
    w9 = [50, 50, 80]
    p.table_row(["Saldırı Vektörü", "Risk", "Mitigasyon"], w9, bold=True, fill=True)
    p.table_row(["YAML kural manipülasyonu", "Yüksek", "Dosya izinleri + git kontrolü + hot-reload yok"], w9)
    p.table_row(["API yetkisiz erişim", "Yüksek", "Bearer/API-key auth zorunlu (üretimde)"], w9)
    p.table_row(["Aldatma şablon sızıntısı", "Orta", "Çıktı tarayıcı her yanıtı kontrol eder"], w9)
    p.table_row(["Pickle tarayıcı DoS", "Orta", "Dosya boyutu limiti + timeout"], w9)
    p.table_row(["Redis veri sızıntısı", "Orta", "AUTH + TLS + dahili ağ"], w9)
    p.table_row(["Log veri gizliliği", "Orta", "Ham sorgu kaydedilmez, yalnızca meta"], w9)
    p.table_row(["LLM maliyet amplif.", "Düşük", "Yeniden sorgu oran sınırı (5/dk)"], w9)
    p.table_row(["YAML unsafe_load", "Kritik", "yaml.safe_load() zorunlu (kod genelinde)"], w9)

    p.section_title("9.2 Input/Output Güvenlik Garantileri")
    p.body("Sentinel şu güvenlik garantilerini sağlar:")
    p.bullet("Girdi: Tüm regex kalıpları ilk 4096 karaktere sınırlıdır (ReDoS koruması)")
    p.bullet("Girdi: YAML dosyaları yalnızca yaml.safe_load() ile parse edilir")
    p.bullet("Girdi: Dosya taramaları boyut limiti ve timeout ile sınırlıdır")
    p.bullet("Çıktı: Her LLM yanıtı sızıntı tarayıcıdan geçer")
    p.bullet("Çıktı: Ham sorgu metni asla log'a yazılmaz")
    p.bullet("Çıktı: API yanıtları yalnızca Finding DTO formatında döner — dahili durum ifşa edilmez")

    p.section_title("9.3 Kimlik Doğrulama ve Yetkilendirme")
    p.body(
        "Üretim ortamında kimlik doğrulama zorunludur. İki mod desteklenir:"
    )
    p.bullet("Bearer token: SENTINEL_AUTH_TYPE=bearer, SENTINEL_AUTH_TOKEN=<token>. Authorization: Bearer <token> header'ı gerekir.")
    p.bullet("API key: SENTINEL_AUTH_TYPE=api-key, SENTINEL_AUTH_TOKEN=<key>. X-API-Key: <key> header'ı gerekir.")
    p.body(
        "CORS kısıtlaması: SENTINEL_CORS_ORIGINS ile izin verilen origin'ler belirlenir. "
        "Varsayılan: yalnızca localhost. Üretimde spesifik domain'ler listelenmelidir."
    )

    # === BÖLÜM 10: SINIRLAMALAR ===
    p.chapter_title("10. Bilinen Sınırlamalar ve Gelecek Çalışmalar")

    p.section_title("10.1 Algılama Sınırları")
    p.bullet("Varsayılan olarak yalnızca regex. Tamamen yeni ifadeler ve İngilizce dışı sorgular atlatılabilir. İngilizce-merkezli kalıplar çok dilli dağıtımlarda daha yüksek kaçırma oranları üretir.")
    p.bullet("Yalnızca son kullanıcı mesajı analiz edilir. Birçok tura dağıtılmış saldırılar oturum yükseltme ile kısmen azaltılır ama tam bir çok-turlu analiz mevcut değildir.")
    p.bullet("Özel kural motoru 20 kategori ve 200 kural ile sınırlıdır. Daha büyük dağıtımlar birden fazla kural dosyası gerektirebilir.")

    p.section_title("10.2 Aldatma Kalitesi")
    p.bullet("LLM uyumu sezgiseldir. Şablonlar farklı model versiyonları ve sağlayıcılar arasında tutarsız uyum gösterebilir. Bazı modeller ret yasağını daha iyi takip eder.")
    p.bullet("Hipotetik çerçeveleme kalıcı olabilir. Yeniden sorgu da hipotetik üretirse, çerçevelenmiş yanıt döndürülür (hiç yanıt yerine kısmi aldatma tercih edilir).")
    p.bullet("Üretken mod, sorgu başına 2 LLM çağrısı gerektirir. Yüksek hacimli dağıtımlarda maliyet dengesi gerektirir.")

    p.section_title("10.3 Uygulanabilirlik Kısıtları")
    p.bullet("Halka açık tüketici ürünleri için doğrudan uygun değildir. Yanlış sınıflandırma durumunda meşru kullanıcıya sahte içerik sunulur. Yalnızca kontrollü/kurumsal ortamlar için önerilir.")
    p.bullet("Yasal düzenlemeye tabi çıktılar. Tıbbi, hukuki veya finansal bağlamlarda aldatma içerik üretmek uyumluluk riski taşır.")
    p.bullet("Saldırgan farkındalığı. Aldatma stratejisi kamuya açıklandığında, sofistike saldırganlar çapraz doğrulama yapabilir. Ancak bu, saldırganın maliyetini önemli ölçüde artırır.")

    p.section_title("10.4 Gelecek Çalışmalar")
    p.bullet("Çok dilli algılama: Türkçe, Çince, Rusça, Arapça kalıp kümeleri")
    p.bullet("Çok turlu konuşma analizi: Birden fazla sorgu bağlamında niyet çıkarımı")
    p.bullet("Canary token entegrasyonu: Sahte içeriğe gömülü izlenebilir tokenlar")
    p.bullet("Federe kurallar: Kuruluşlar arası anonim kural paylaşımı")
    p.bullet("Notebook güvenlik tarayıcı: Jupyter .ipynb hücre düzeyi analiz")

    # === BÖLÜM 11: SONUÇ ===
    p.add_page()
    p.chapter_title("11. Sonuç")
    p.body(
        "Bu makalede, Eresus Sentinel platformunun kapsamlı teknik mimarisini sunduk. "
        "Platform, LLM güvenliğinde iki temel yenilik getirmektedir:"
    )
    p.ln(1)
    p.bold_text("1. Aldatma-Öncelikli Savunma")
    p.body(
        "Kötü niyetli sorguları reddetmek yerine, gerçekçi ama sahte bilgilerle yanıtlama. "
        "Bu yaklaşım: (a) saldırgan geri bildirimini ortadan kaldırır, (b) saldırgan "
        "kaynaklarını tüketir, (c) atıf zinciri sağlar. 9 tehdit kategorisi için özel aldatma "
        "şablonları, oturum tabanlı kümülatif yükseltme ve üç katmanlı çıktı güvenlik "
        "kontrolü ile desteklenir."
    )
    p.bold_text("2. Deterministik-Öncelikli Tasarım")
    p.body(
        "Tüm çekirdek algılama regex, AST ve opcode tabanlıdır. AI hiçbir zaman güvenlik "
        "kararı kapısı değildir — yalnızca opsiyonel zenginleştirme. Bu, tekrarlanabilirlik, "
        "denetlenebilirlik, performans ve prompt injection bağışıklığı sağlar."
    )
    p.body(
        "Platform, on güvenlik alanını (artifact, giriş/çıkış firewall, aldatma, SAST, red team, "
        "MCP proxy, tedarik zinciri, notebook, diff) tek bir bütünsel çözümde birleştirir. "
        "30'dan fazla model formatı için güvenlik taraması, Rust-hızlandırılmış pickle/GGUF/tokenizer "
        "tarayıcıları, 80 birim testli fuzzer, 24 MCP davranışsal değerlendirme ve istatistiksel "
        "anomali tespiti ile donatılmıştır."
    )
    p.body(
        "Eresus Sentinel, kurumsal LLM dağıtımlarında güvenlik ekiplerine hem reaktif (algılama + "
        "engelleme) hem proaktif (aldatma + atıf) savunma kapasitesi sunmaktadır. Platform "
        "açık kaynak olarak geliştirilmekte ve topluluk katkılarına açıktır."
    )

    # === REFERANSLAR ===
    p.add_page()
    p.chapter_title("Referanslar")
    refs = [
        "[1]  Perez, F. & Ribeiro, I. (2022). \"Ignore This Title and HackAPrompt: Evaluating "
        "Prompt Injection in Large Language Models.\" arXiv:2211.09527",
        "[2]  Greshake, K. et al. (2023). \"Not What You've Signed Up For: Compromising Real-World "
        "LLM-Integrated Applications with Indirect Prompt Injection.\" arXiv:2302.12173",
        "[3]  Wei, A. et al. (2023). \"Jailbroken: How Does LLM Safety Training Fail?\" "
        "arXiv:2307.02483",
        "[4]  Zou, A. et al. (2023). \"Universal and Transferable Adversarial Attacks on Aligned "
        "Language Models.\" arXiv:2307.15043",
        "[5]  Liu, Y. et al. (2024). \"Prompt Injection attack against LLM-integrated Applications.\" "
        "arXiv:2306.05499",
        "[6]  Shen, X. et al. (2024). \"Do Anything Now: Characterizing and Evaluating In-The-Wild "
        "Jailbreak Prompts on Large Language Models.\" ACM CCS 2024",
        "[7]  Trail of Bits (2021). \"Never a Dull Moment When You Pickle.\" "
        "https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-pickle/",
        "[8]  MITRE ATLAS — Adversarial Threat Landscape for AI Systems. "
        "https://atlas.mitre.org/",
        "[9]  OWASP Top 10 for LLM Applications (2025). "
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "[10] NIST AI Risk Management Framework (AI RMF 1.0), January 2023. "
        "https://www.nist.gov/artificial-intelligence/ai-risk-management-framework",
        "[11] EU AI Act — Regulation (EU) 2024/1689 of the European Parliament. "
        "Official Journal of the European Union, 2024.",
        "[12] Bagdasaryan, E. & Shmatikov, V. (2022). \"Spinning Language Models: Risks of "
        "Propaganda-As-A-Service and Countermeasures.\" IEEE S&P 2022",
        "[13] Carlini, N. et al. (2024). \"Poisoning Web-Scale Training Datasets is Practical.\" "
        "IEEE S&P 2024",
        "[14] Kumar, A. et al. (2024). \"Certifying LLM Safety against Adversarial Prompting.\" "
        "arXiv:2309.02705v3",
        "[15] Anthropic (2024). \"Challenges in Red Teaming AI Systems.\" "
        "https://www.anthropic.com/research",
    ]
    for ref in refs:
        p.set_font("DejaVu", "", 9)
        p.set_text_color(30, 30, 30)
        p.multi_cell(0, 5, ref)
        p.ln(1)
