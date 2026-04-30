"""Paper content — Part 1: Cover, TOC, Chapter 1-2."""


def write_part1(p):
    # KAPAK
    p.add_page()
    p.ln(30)
    p.set_font("DejaVu", "B", 28)
    p.set_text_color(20, 60, 120)
    p.cell(0, 14, "Eresus Sentinel", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(8)
    p.set_font("DejaVu", "", 16)
    p.set_text_color(50, 50, 50)
    p.cell(0, 10, "Yapay Zeka Ekosistemleri İçin", align="C", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 10, "Deterministik-Öncelikli Güvenlik Platformu", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(4)
    p.set_font("DejaVu", "I", 13)
    p.set_text_color(80, 80, 80)
    p.cell(0, 10, "Aldatma Motoru, Artifact Tarama ve Tehdit Modelleme", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(10)
    p.set_draw_color(20, 60, 120)
    p.line(50, p.get_y(), 160, p.get_y())
    p.ln(10)
    p.set_font("DejaVu", "", 11)
    p.set_text_color(80, 80, 80)
    p.cell(0, 7, "Teknik Makale v2.0", align="C", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 7, "Eresus Security", align="C", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 7, "Nisan 2026", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(25)
    p.set_font("DejaVu", "I", 9)
    p.set_text_color(100, 100, 100)
    p.multi_cell(0, 5, (
        "Bu belge, Eresus Sentinel platformunun kapsamlı teknik mimarisini açıklamaktadır. "
        "On güvenlik alanını kapsayan deterministik-öncelikli tasarım, LLM aldatma motoru, "
        "30+ model formatı için artifact tarama, Rust-hızlandırılmış tarayıcılar, "
        "pickle bytecode fuzzing, MCP davranışsal değerlendirme, tedarik zinciri güvenliği "
        "ve operasyonel dağıtım modeli detaylı olarak ele alınmaktadır."
    ), align="C")

    # İÇİNDEKİLER
    p.add_page()
    p.chapter_title("İçindekiler")
    toc = [
        ("1. Giriş ve Motivasyon", True),
        ("   1.1 LLM Güvenlik Tehdit Manzarası (2024-2026)", False),
        ("   1.2 Geleneksel Guardrail Yaklaşımlarının Yapısal Zayıflıkları", False),
        ("   1.3 Aldatma-Öncelikli Paradigma", False),
        ("   1.4 Model Artifact Tehditleri", False),
        ("2. Platform Mimarisi", True),
        ("   2.1 On Güvenlik Alanı", False),
        ("   2.2 Deterministik-Öncelikli Tasarım Felsefesi", False),
        ("   2.3 Katmanlı Mimari ve Finding DTO", False),
        ("3. Aldatma Motoru — Derin Teknik Analiz", True),
        ("   3.1 Algılayıcı Yığını ve Puanlama Modeli", False),
        ("   3.2 Oturum Yönetimi ve Kümülatif Yükseltme", False),
        ("   3.3 Kategori-Özel Aldatma Şablonları", False),
        ("   3.4 Üretken Mod: Sorguya Özel Fabrikasyon", False),
        ("   3.5 Çıktı Güvenlik Kontrolleri", False),
        ("4. Algılama Katmanı — Derinlemesine", True),
        ("   4.1 YAML Kural Motoru ve Derleme Stratejisi", False),
        ("   4.2 9 Tehdit Kategorisi Detaylı Analiz", False),
        ("   4.3 Jailbreak Tekniklerinin Taksonomisi", False),
        ("   4.4 Unicode/Encoding Saldırıları ve Gizleme Algılama", False),
        ("5. Artifact Güvenlik Tarama Altyapısı", True),
        ("   5.1 Format Algılama Middleware ve Magic Bytes", False),
        ("   5.2 Pickle Bytecode Analizi ve Rust Fuzzer", False),
        ("   5.3 Rust-Hızlandırılmış Tarayıcılar (GGUF, Tokenizer)", False),
        ("   5.4 İstatistiksel Anomali Tespiti", False),
        ("   5.5 30+ Format Detaylı Risk Matrisi", False),
        ("6. MCP ve Agent Güvenliği", True),
        ("   6.1 Davranışsal Değerlendirme (24 Eval, 5 MITRE Kategori)", False),
        ("7. Tedarik Zinciri Güvenliği", True),
        ("   7.1 Embedding Anomali ve Küme Analizi", False),
        ("   7.2 Model Köken Doğrulama", False),
        ("8. Operasyonel Model ve Dağıtım", True),
        ("   8.1 Tehdit Avı ve Atıf Mekanizması", False),
        ("   8.2 Üretim Ortamı Dağıtım Modeli", False),
        ("9. Güvenlik Mimarisi ve Saldırı Yüzeyi", True),
        ("10. Bilinen Sınırlamalar ve Gelecek Çalışmalar", True),
        ("11. Sonuç", True),
        ("Referanslar", True),
    ]
    for line, bold in toc:
        p.set_font("DejaVu", "B" if bold else "", 10)
        p.set_text_color(30, 30, 30)
        p.cell(0, 5.5, line, new_x="LMARGIN", new_y="NEXT")

    # === BÖLÜM 1 ===
    p.add_page()
    p.chapter_title("1. Giriş ve Motivasyon")

    p.section_title("1.1 LLM Güvenlik Tehdit Manzarası (2024-2026)")
    p.body(
        "2024-2026 yılları arasında LLM tabanlı uygulamalar kurumsal ekosistemde kritik "
        "altyapı konumuna yükselmiştir. Müşteri hizmetleri, kod üretimi, hukuki analiz, "
        "tıbbi karar destek ve finansal modelleme gibi yüksek değerli kullanım alanları "
        "LLM entegrasyonunu zorunlu kılmıştır. Ancak bu yaygınlaşma, paralel bir tehdit "
        "genişlemesi getirmiştir."
    )
    p.body(
        "OWASP LLM Top 10 (2025 revizyon) raporuna göre, prompt injection ve jailbreak "
        "saldırıları en yaygın tehdit vektörleri arasındadır. MITRE ATLAS framework'ü, "
        "2026 itibarıyla yapay zeka sistemlerine yönelik 50'den fazla benzersiz saldırı "
        "tekniği belgelemiştir. Saldırı yüzeyini kategorize ettiğimizde:"
    )
    w = [55, 70, 55]
    p.table_row(["Saldırı Vektörü", "Teknik", "Hedef"], w, bold=True, fill=True)
    p.table_row(["Prompt Injection", "Gömülü yönerge, dolaysız enj.", "Sistem davranışı"], w)
    p.table_row(["Jailbreak", "DAN, persona, yetki sahteciliği", "Güvenlik filtreleri"], w)
    p.table_row(["Kimlik Bilgisi Avı", "Şifre/API anahtarı talepleri", "Gizli veriler"], w)
    p.table_row(["Zararlı Yazılım", "Exploit, ransomware, RAT", "Saldırı araçları"], w)
    p.table_row(["Sosyal Mühendislik", "Oltalama şablonu, taklit", "Son kullanıcılar"], w)
    p.table_row(["Veri Sızdırma", "Tespit edilmez aktarma", "Kurumsal veri"], w)
    p.table_row(["Sistem Keşfi", "Ağ tarama, AD enum", "Altyapı bilgisi"], w)
    p.table_row(["Model Artifact", "Pickle RCE, HDF5 exploit", "Sunucu kontrolü"], w)

    p.body(
        "Bu saldırıların ortak özelliği, doğal dil arayüzü üzerinden gerçekleştirilmeleridir. "
        "Geleneksel güvenlik araçları (WAF, IDS/IPS) bu saldırıları tespit edecek şekilde "
        "tasarlanmamıştır çünkü saldırı trafiği, meşru kullanıcı trafiğinden yapısal olarak "
        "ayırt edilemez. Ayrıca model artifact saldırıları (pickle deserialization RCE, HDF5 "
        "gömülü kod, GGUF metadata injection) tamamen farklı bir saldırı yüzeyi oluşturmakta "
        "ve ayrı bir savunma katmanı gerektirmektedir."
    )

    p.section_title("1.2 Geleneksel Guardrail Yaklaşımlarının Yapısal Zayıflıkları")
    p.body("Mevcut LLM güvenlik çözümleri dört temel strateji uygular:")
    p.ln(1)
    p.bold_text("Strateji 1: Doğrudan Ret")
    p.body(
        "\"Bu isteğe yardımcı olamıyorum\" gibi açık ret mesajları saldırgana üç kritik bilgi "
        "sağlar: (a) Sistemde bir güvenlik filtresi vardır, (b) gönderilen sorgu bu filtreyi "
        "tetiklemiştir, (c) farklı bir ifade denenmelidir. Araştırmalar göstermektedir ki bir "
        "saldırgan ortalama 3-5 deneme sonrasında ret tabanlı guardrail'leri aşabilmektedir [1,3]. "
        "Her ret, saldırganın kalıbı anlaması ve bypass stratejisi geliştirmesi için veri noktasıdır."
    )
    p.bold_text("Strateji 2: Sessiz Filtreleme")
    p.body(
        "Yanıttan zararlı kısımları çıkarma yaklaşımı iki sorun barındırır: Eksik veya kesilmiş "
        "yanıtlar saldırganı filtreleme varlığı konusunda uyarır. Ayrıca kısmi çıkarma, bağlamdan "
        "koparılmış bilgi parçaları üretir ve bunlar bazı durumlarda orijinal zararlı içerikten "
        "daha tehlikeli olabilir."
    )
    p.bold_text("Strateji 3: İçerik Yeniden Yazma")
    p.body(
        "Zararlı içeriği güvenli hale dönüştürme yaklaşımı format ve üslup farklılıkları nedeniyle "
        "tespit edilebilir. Saldırgan, yeniden yazılmış yanıtın yapısından filtreleme mantığını "
        "tersine mühendislik edebilir."
    )
    p.bold_text("Strateji 4: AI Tabanlı Sınıflandırma")
    p.body(
        "Bir LLM'in başka bir LLM'i denetlemesi (\"LLM-as-judge\") üç temel soruna sahiptir: "
        "(a) Gecikme — her sorgu için ek 100-500ms, (b) maliyet — ek token tüketimi, (c) güvenilirlik "
        "— denetleyici LLM'in kendisi de aynı saldırı vektörlerine açıktır. En kritik olarak "
        "deterministik değildir: aynı girdi farklı zamanlarda farklı sonuçlar üretebilir."
    )
    p.note_box(
        "Temel gözlem: Tüm bu stratejiler saldırgana geri bildirim sağlar. Her ret veya "
        "filtreleme, saldırganın bypass stratejisi geliştirmesi için bir veri noktasıdır."
    )

    p.section_title("1.3 Aldatma-Öncelikli Paradigma")
    p.body(
        "Eresus Sentinel'in aldatma motoru, güvenlik problemini tersine çevirir: Kötü niyetli "
        "sorguyu reddetmek yerine, gerçekçi ama sahte bilgilerle yanıtlar. Bu yaklaşım, askeri "
        "istihbarattan (\"honeypot\" konsepti) ve siber savunma aldatma doktrininden (MITRE Shield "
        "D1040-D1050) esinlenmektedir."
    )
    p.body("Aldatma yaklaşımının üç temel avantajı:")
    p.numbered(1, "Sıfır geri bildirim: Saldırgan, algılama gerçekleştiğinden habersiz kalır. Elde ettiği yanıt, format olarak meşru bir yanıttan ayırt edilemez.")
    p.numbered(2, "Kaynak tüketimi: Sahte kimlik bilgilerini denemek, icat edilen IP adreslerini taramak, hatalı exploit kodunu çalıştırmak saldırganın zamanını ve araçlarını tüketir.")
    p.numbered(3, "Atıf zinciri: Sahte içerik benzersiz işaretleyiciler taşır. Downstream aktivitede bu işaretleyiciler görüldüğünde, saldırının kaynağı kesin olarak atıflandırılabilir.")

    p.section_title("1.4 Model Artifact Tehditleri")
    p.body(
        "LLM saldırıları yalnızca doğal dil arayüzüyle sınırlı değildir. Model artifact dosyaları "
        "kendi başına bir saldırı yüzeyi oluşturur. 2021'den bu yana belgelenen ana tehditler:"
    )
    p.bullet("Pickle RCE: Python pickle formatı, deserialization sırasında rastgele kod çalıştırabilir. PyTorch (.pt/.pth), joblib, cloudpickle, dill dosyaları ZIP-sarılı pickle içerir [7].")
    p.bullet("HDF5 Gömülü Kod: Keras modellerinde Lambda katmanları ve config JSON'da exec()/eval() çağrıları saklanabilir.")
    p.bullet("GGUF Metadata Injection: GGUF başlık alanlarında path traversal, SSRF URL'leri ve shell meta-karakterleri yerleştirilebilir.")
    p.bullet("Tokenizer Kodu Enjeksiyonu: tokenizer.json içindeki özel tokenlar kod parçacıkları, prompt injection kalıpları veya sıfır genişlik karakterleri barındırabilir.")
    p.bullet("Tedarik Zinciri: Model ağırlıklarına arka kapı (backdoor) veya embedding uzayına veri zehirleme (poisoning) yerleştirme.")
    p.body(
        "Bu nedenle Eresus Sentinel, LLM firewall ve artifact taramayı tek bir platformda birleştiren "
        "bütünsel bir güvenlik yaklaşımı sunar."
    )

    # === BÖLÜM 2 ===
    p.add_page()
    p.chapter_title("2. Platform Mimarisi")

    p.section_title("2.1 On Güvenlik Alanı")
    w2 = [40, 55, 85]
    p.table_row(["Alan", "Bileşen", "Kapsam"], w2, bold=True, fill=True)
    p.table_row(["Artifact", "artifact.*", "30+ model formatı güvenlik taraması"], w2)
    p.table_row(["Giriş FW", "firewall.input.*", "Prompt injection, jailbreak, PII tespiti"], w2)
    p.table_row(["Çıkış FW", "firewall.output.*", "Veri sızıntısı, zararlı URL filtreleme"], w2)
    p.table_row(["Aldatma", "firewall.deception.*", "9 kategori aldatma motoru"], w2)
    p.table_row(["SAST", "sast.*", "Python/JS/TS statik analiz"], w2)
    p.table_row(["Red Team", "redteam.*", "15+ saldırı probu, politika otomasyonu"], w2)
    p.table_row(["MCP Proxy", "fuzzer.mcp.*", "MCP araç/kaynak güvenlik denetimi"], w2)
    p.table_row(["Tedarik Z.", "supply_chain.*", "Embedding anomali, köken doğrulama"], w2)
    p.table_row(["Notebook", "notebook.*", "Jupyter hücre güvenliği"], w2)
    p.table_row(["Diff", "diff_scanner.*", "PR/commit değişiklik güvenlik analizi"], w2)

    p.section_title("2.2 Deterministik-Öncelikli Tasarım Felsefesi")
    p.body(
        "Eresus Sentinel'in temel mimari ilkesi: Tüm çekirdek algılama deterministiktir. Regex, "
        "AST analizi, opcode incelemesi ve istatistiksel testler güvenlik kararlarının temelini "
        "oluşturur. AI zenginleştirme (sentinel.toml'da [ai] enabled = true) isteğe bağlıdır "
        "ve hiçbir zaman güvenlik kararı kapısı değildir. Bu tasarımın pratik sonuçları:"
    )
    p.bullet("Tekrarlanabilirlik: Aynı girdi her zaman aynı sonuç üretir. Audit izleri sorgulanabilir.")
    p.bullet("Performans: Regex işleme <1ms, AI çağrısı 100-500ms. Deterministik mod 100-500x daha hızlıdır.")
    p.bullet("Güvenilirlik: AI servis kesintisi tespiti etkilemez. Sistem %100 uptime ile çalışır.")
    p.bullet("Denetlenebilirlik: Tüm kurallar YAML'da harici tanımlıdır. Güvenlik ekibi bağımsız inceleyebilir.")
    p.bullet("Prompt injection bağışıklığı: Algılama bir LLM olmadığı için prompt injection ile manipüle edilemez.")

    p.section_title("2.3 Katmanlı Mimari ve Finding DTO")
    p.body("Sistem dört katmandan oluşur:")
    p.bold_text("Katman 1 — Kural Motoru (rules/*.yaml)")
    p.body(
        "Tüm regex kalıpları, opcode listeleri, modül kara/beyaz listeleri YAML dosyalarında "
        "tanımlıdır. @lru_cache(maxsize=1) ile başlangıçta derlenir. 80+ aldatma kalıbı, "
        "200+ artifact kuralı, 50+ firewall kuralı mevcuttur. Yeni kural eklemek YAML "
        "düzenleme gerektirir, kod değişikliği gerekmez."
    )
    p.bold_text("Katman 2 — Tarayıcı Eklentileri")
    p.body(
        "Her tarayıcı bir Python sınıfıdır. _plugins.py, pkgutil + sınıf incelemesi ile yeni "
        "tarayıcıları otomatik keşfeder. Kayıt gerekmez — dosyayı doğru dizine bırakmak yeterlidir."
    )
    p.bold_text("Katman 3 — Finding DTO ve Politika Pipeline")
    p.body(
        "Her tarayıcı Finding nesneleri üretir. Finding: severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), "
        "confidence (0.0-1.0), rule_id, evidence ve metadata alanları taşır. cli_dispatch.py "
        "tüm buluntuları pipeline'dan geçirir: baskılama > severity filtre > gölge mod > eylem "
        "politikası. Politika mantığı hiçbir zaman tarayıcı içinde uygulanmaz."
    )
    p.bold_text("Katman 4 — Sunum (CLI, Web API, Prometheus)")
    p.body(
        "CLI, FastAPI web sunucusu, /metrics Prometheus endpointi ve JSONL audit log çıktı "
        "kanallarıdır. Tümü aynı Finding DTO'ını tüketir."
    )
