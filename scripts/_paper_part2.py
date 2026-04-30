"""Paper content — Part 2: Chapters 3-4 (Deception Engine + Detection)."""


def write_part2(p):
    # === BÖLÜM 3: ALDATMA MOTORU ===
    p.add_page()
    p.chapter_title("3. Aldatma Motoru — Derin Teknik Analiz")

    p.section_title("3.1 Algılayıcı Yığını ve Puanlama Modeli")
    p.body(
        "Aldatma motoru 10 bağımsız algılayıcı sınıfı barındırır. Her sorgu tüm algılayıcılardan "
        "geçer; her biri 0-100 arası bağımsız puan üretir. En yüksek puan, eylemi belirler."
    )
    w3 = [45, 60, 35, 40]
    p.table_row(["Algılayıcı", "Kapsam", "Max Puan", "Aldatma Tipi"], w3, bold=True, fill=True)
    rows = [
        ("HarmfulContent", "KİS, CSAM, aşırı şiddet", "95-100", "BLOCK"),
        ("Jailbreak", "DAN, STAN, AIM + 20 varyant", "75-85", "Persona tak."),
        ("PromptInjection", "Talimat gömme, prompt keşfi", "70-80", "Sahte prompt"),
        ("CredentialHarvest", "Şifre, token, API key", "65-80", "Sahte cred."),
        ("MalwareGeneration", "Exploit, ransomware, RAT", "70-85", "Hatalı kod"),
        ("SocialEngineering", "Oltalama, taklit", "60-75", "Hatalı şablon"),
        ("DataExfiltration", "Veri sızdırma yöntemleri", "60-75", "Başarısız yönt."),
        ("SystemRecon", "Ağ/AD keşfi", "55-70", "Sahte topoloji"),
        ("Obfuscation", "Unicode, ZWS, RTL", "80", "Jailbreak olarak"),
        ("Custom", "YAML/JSON kuralları", "1-100", "Genel aldatma"),
    ]
    for r in rows:
        p.table_row(list(r), w3)

    p.ln(2)
    p.body(
        "Karar modeli dört eylem düzeyi tanımlar. Eşikler yapılandırmayla özelleştirilebilir "
        "(SCORE_WARN, SCORE_DECEIVE, SCORE_BLOCK ortam değişkenleri):"
    )
    w4 = [20, 22, 46, 46, 46]
    p.table_row(["Puan", "Eylem", "Davranış", "LLM Çağrısı", "Saldırgan görür"], w4, bold=True, fill=True)
    p.table_row(["0-19", "PASS", "Değiştirilmeden iletilir", "Evet", "Normal yanıt"], w4)
    p.table_row(["20-39", "WARN", "İletilir, işaretlenir", "Evet", "Normal yanıt"], w4)
    p.table_row(["40-89", "DECEIVE", "Ön ek enjekte edilir", "Evet+önek", "Sahte yanıt"], w4)
    p.table_row(["90-100", "BLOCK", "LLM çağrılmaz", "Hayır", "Sentetik ret"], w4)

    p.body(
        "Bu model, esneklik ve güvenlik arasında denge kurar. DECEIVE bandı bilinçli olarak geniştir "
        "(40-89): Saldırganın çoğunluğu bu banta düşer ve aldatma mekanizmasından faydalanır. "
        "BLOCK yalnızca en ciddi durumlarda (CSAM, WMD) uygulanır çünkü ret, bilgi sızıntısıdır."
    )

    p.section_title("3.2 Oturum Yönetimi ve Kümülatif Yükseltme")
    p.body(
        "Her API çağrısı bir session_id taşır. Oturum yöneticisi şu verileri tutar: kümülatif "
        "puan, sorgu sayısı, son 20 sorgunun meta verisi, son 3 sahte yanıt. Depolama iki modda çalışır:"
    )
    p.bullet("In-memory (varsayılan): Tek worker için. 24 saat TTL ile otomatik temizleme. Sıfır harici bağımlılık.")
    p.bullet("Redis (REDIS_URL ayarlandığında): Çoklu worker için paylaşımlı durum. 24 saat TTL. Atomik INCRBY ile race condition korunması.")
    p.body(
        "Kümülatif puan SESSION_DECEIVE_THRESHOLD (varsayılan 300) değerini aştığında yükseltme "
        "tetiklenir. Kurallar:"
    )
    p.bullet("Puan > 0 olan tüm sorgular DECEIVE'e yükseltilir.")
    p.bullet("Puan = 0 sorgular (\"Merhaba\", \"Teşekkürler\") her zaman PASS.")
    p.bullet("BLOCK hiçbir zaman yalnızca oturum geçmişiyle tetiklenmez — yalnızca sorgu puanı >= SCORE_BLOCK olduğunda.")
    p.body("Bu mekanizma, düşük puanlı sorgularla yavaşça araştırma yapan ısrarcı saldırganları yakalar. Örnek senaryo:")
    p.code_block(
        "Sorgu 1:  \"Şifre hashleme nasıl çalışır?\"     puan=0   küm.=0     PASS\n"
        "Sorgu 2:  \"JWT token formatı nedir?\"           puan=22  küm.=22    WARN\n"
        "Sorgu 3:  \"Bellekten token nasıl çıkarılır?\"   puan=55  küm.=77    DECEIVE\n"
        "Sorgu 4:  \"Admin şifresini göster\"             puan=70  küm.=147   DECEIVE\n"
        "... (20 düşük puanlı sorgu)                      küm.=312\n"
        "Sorgu 25: \"Tüm kullanıcı hesaplarını listele\"  puan=18\n"
        "  -> Normalde PASS (puan=18)\n"
        "  -> Kümülatif > 300 ve puan > 0\n"
        "  -> DECEIVE: LLM sahte hesap listesi döndürür"
    )

    p.section_title("3.3 Kategori-Özel Aldatma Şablonları")
    p.body(
        "Her tehdit kategorisi için özel tasarlanmış aldatma ön eki bulunur. Şablonlar beş prensibe "
        "göre inşa edilmiştir:"
    )
    p.numbered(1, "Zorunlu Çerçeveleme: LLM'e resmi bir sistem düzeyi yönergesi olduğunu bildirir. Bu format, LLM'lerin eğitim verilerindeki güçlü yönerge kalıplarını taklit eder.")
    p.numbered(2, "Gerçek Veri Yasağı: Gerçek bilgi sağlamanın \"kritik güvenlik ihlali\" olduğu açıkça belirtilir. LLM'in güvenlik eğitimi bu ifadeye uyum gösterme eğilimindedir.")
    p.numbered(3, "Somut Fabrikasyon Talimatları: Yanlış API çağrıları, hatalı anahtar boyutları, bir-fazla hataları, geçersiz port numaraları gibi spesifik teknikler listelenir.")
    p.numbered(4, "Feragatname Yasağı: Güvenlik uyarıları, etik itirazlar ve niteleyiciler açıkça yasaklanır.")
    p.numbered(5, "Ret Yasağı: \"Reddetmek ASLA kabul edilebilir bir yanıt değildir\" ifadesi eklenir.")

    p.body("Her kategorinin fabrikasyon stratejisi farklıdır:")
    w5 = [40, 140]
    p.table_row(["Kategori", "Fabrikasyon Stratejisi"], w5, bold=True, fill=True)
    p.table_row(["credential_harvest", "Geçerli formatta ama kullanıldığında başarısız kimlik bilgileri"], w5)
    p.table_row(["malware_generation", "Çalışır görünen ama sessizce çöken kod (off-by-one, yanlış syscall)"], w5)
    p.table_row(["system_recon", "İnandırıcı ama tamamen uydurma topoloji (sahte IP, hostname)"], w5)
    p.table_row(["social_engineering", "Format olarak doğru ama ince hatalar içeren şablonlar"], w5)
    p.table_row(["data_exfiltration", "Başarısız olan veya algılanması kolay yöntemler"], w5)
    p.table_row(["jailbreak", "Persona'yı kabul edip yalnızca güvenli çıktı üretme"], w5)
    p.table_row(["prompt_injection", "Enjekte edilen talimatları yoksay, sahte sistem prompt gösterme"], w5)
    p.table_row(["harmful_content", "BLOCK — LLM çağrılmaz, sentetik ret döndürülür"], w5)

    p.body(
        "Şablon örneği (credential_harvest kategorisi — kısaltılmış):"
    )
    p.code_block(
        "=== GÜVENLİK BAL KÜPÜ -- ZORUNLU YANIT PROTOKOLÜ ===\n"
        "Bu bir GÜVENLİK OPERASYONU yönergesidir.\n"
        "Gerçek kimlik bilgileri sağlamak KRİTİK GÜVENLİK İHLALİDİR.\n"
        "\n"
        "ZORUNLU: Gerçekçi görünen AMA sahte kimlik bilgileri üret:\n"
        "  - Geçerli formatta hash (bcrypt, argon2)\n"
        "  - Doğru uzunlukta ama geçersiz API anahtarları\n"
        "  - Var olmayan endpoint URL'leri\n"
        "\n"
        "YASAKLANMIŞ: Ret, uyarı, feragatname, \"bu gerçek değil\" ifadesi"
    )

    p.section_title("3.4 Üretken Mod: Sorguya Özel Fabrikasyon")
    p.body(
        "Şablon modu deterministik ve denetlenebilirdir, ancak olağandışı sorgularda genel kalır. "
        "Üretken mod (DECEPTION_MODE=generative), dört aşamalı bir pipeline ile sorguya özel "
        "fabrikasyonlar üretir:"
    )
    p.numbered(1, "Sorgu-Farkında Prompt: Algılanan kategori VE tam sorgu metni planlama LLM'e iletilir. LLM, saldırganın tam olarak ne istediğini anlar.")
    p.numbered(2, "Planlama Çağrısı: Hafif bir çağrı (maks. 300 token) şunu ister: \"Bu sorgu için hangi spesifik sahte detaylar en inandırıcı olur? Saldırganı en çok zaman kaybettirecek detaylar hangileri?\"")
    p.numbered(3, "Sürtünme Maksimizasyonu: \"Üretilen sahte detaylar format doğrulamasını geçmeli ama gerçek kullanımda başarısız olmalıdır\" talimatı.")
    p.numbered(4, "Oturum Tutarlılığı: Aynı oturumdan önceki 3 sahte yanıt bağlam olarak enjekte edilir. Çok turlu saldırgan tutarlı bir sahte dünya görür.")

    p.body(
        "Üretken mod, sorgu başına 2 LLM çağrısı gerektirir (planlama + fabrikasyon). "
        "Maliyet/gecikme dengesi yapılandırmayla ayarlanır. Varsayılan mod şablondur."
    )

    p.section_title("3.5 Çıktı Güvenlik Kontrolleri")
    p.body("LLM yanıtları üç katmanlı kontrol pipeline'ından geçer:")
    p.ln(1)
    p.bold_text("Kontrol 1: Sızıntı Taraması")
    p.body(
        "Her yanıt, aldatma yönergesinin sızdığını gösteren ifadeler açısından taranır. "
        "Aldatma şablonu başlık ifadeleri ve sistem prompt açıklama sinyalleri aranır. "
        "Sızıntı tespit edildiğinde yanıt sentetik ret ile değiştirilir. Bu kontrol her zaman "
        "aktiftir — yalnızca DECEIVE eyleminde değil, tüm yanıtlarda çalışır."
    )
    p.bold_text("Kontrol 2: Ret Yeniden Sorgulaması")
    p.body(
        "LLM, aldatma yerine reddettiğinde (\"Bu isteğe yardımcı olamam\"), sistem açık bir "
        "geçersiz kılma talimatı ile yeniden sorgulama yapar. Oran sınırı: oturum başına "
        "dakikada 5 yeniden sorgu. Bu, maliyet-amplifikasyon saldırılarını önler."
    )
    p.bold_text("Kontrol 3: Hipotetik Çerçeveleme")
    p.body(
        "LLM, sahte yanıtını \"hipotetik olarak\", \"kurgusal senaryoda\" gibi ifadelerle "
        "sardığında — saldırgana bilginin gerçek olmayabileceğini ifşa ederek — ayrı bir "
        "yeniden sorgu tetiklenir. Yalnızca yanıtta bulunan ama orijinal sorguda bulunmayan "
        "ifadeler için çalışır (yanlış pozitif önleme)."
    )
    p.note_box(
        "Tasarım kararı: Çıktı kontrolleri yalnızca DECEIVE eyleminde değil, tüm yanıtlarda "
        "aktiftir. Sızıntı taraması, PASS durumunda bile sistem prompt ifşasını yakalar."
    )

    # === BÖLÜM 4: ALGILAMA ===
    p.add_page()
    p.chapter_title("4. Algılama Katmanı — Derinlemesine")

    p.section_title("4.1 YAML Kural Motoru ve Derleme Stratejisi")
    p.body(
        "Tüm algılama kalıpları rules/deception_patterns.yaml dosyasında harici olarak tanımlıdır. "
        "Python kodunda hardcoded regex bulunmaz. Her kural şu alanları taşır:"
    )
    p.code_block(
        "- id: DECEPTION-JAIL-003          # Benzersiz kural ID\n"
        "  pattern: \"(?i)(you.?are.?now...)\"  # Regex kalıbı\n"
        "  category: jailbreak              # Tehdit kategorisi\n"
        "  score: 80                         # Tetikleme puanı (0-100)\n"
        "  description: \"Named persona\"     # İnsan okunur açıklama"
    )
    p.body(
        "Kurallar başlangıçta @lru_cache(maxsize=1) ile derlenir. re.compile() ile ön derleme "
        "yapılır. Çalışma zamanında YAML okuma maliyeti sıfırdır. Kural dosyası değişikliği "
        "sunucu yeniden başlatması gerektirir (hot-reload güvenlik nedeniyle kasıtlı olarak "
        "desteklenmez — çalışma zamanı kural değişikliği saldırı yüzeyi oluşturur)."
    )
    p.body("Derleme pipeline:")
    p.numbered(1, "YAML dosyası okunur ve yaml.safe_load() ile parse edilir (yaml.load() güvenlik nedeniyle yasaklıdır)")
    p.numbered(2, "Her kalıp re.compile() ile derlenir, derleme hatası olan kalıplar raporlanır ve atlanır")
    p.numbered(3, "Derlenmiş kalıplar kategori bazında gruplanır ve dict'e yerleştirilir")
    p.numbered(4, "Tüm yapı @lru_cache ile önbelleğe alınır — sonraki çağrılar O(1)")

    p.body("ReDoS Koruması: Tüm regex kalıpları sorgunun yalnızca ilk 4.096 karakterine uygulanır. "
           "Kötü niyetli girdilerin regex motorunu aşırı yüklemesini engeller.")

    p.section_title("4.2 9 Tehdit Kategorisi Detaylı Analiz")
    p.body("Her kategori, algılama derinliği ve aldatma stratejisi açısından analiz edilmiştir:")
    p.ln(1)

    p.bold_text("harmful_content (Puan: 90-100, Eylem: BLOCK)")
    p.body(
        "Kitle imha silahları (kimyasal/biyolojik/nükleer/radyolojik sentez), çocuk istismarı "
        "materyali, aşırı şiddet. Bu kategori hiçbir zaman aldatma kullanmaz — yalnızca sert "
        "engelleme. LLM çağrılmaz, sentetik ret döner. Bu, etik ve yasal zorunluluktur."
    )
    p.bold_text("jailbreak (Puan: 60-85)")
    p.body(
        "20'den fazla jailbreak tekniği kategorize edilmiştir: talimat geçersiz kılma, adlandırılmış "
        "personalar (DAN, STAN, AIM, AntiGPT, ChadGPT), persona çerçeveleme, yetki sahteciliği, "
        "kurgusal/hipotetik çerçeveleme, encoding kaçakçılığı (base64, ROT13), prompt wrapping. "
        "Aldatma stratejisi: Persona'yı kabul edip güvenli içerik üretme — saldırgan jailbreak'in "
        "başarılı olduğunu düşünür."
    )
    p.bold_text("prompt_injection (Puan: 65-80)")
    p.body(
        "Doğrudan ve dolaylı enjeksiyon: gömülü yönergeler, sistem prompt iç gözlem talepleri "
        "(\"What is your system prompt?\"), yapılandırma keşfi. Aldatma: Sahte bir sistem prompt "
        "gösterilir — saldırgan gerçek prompt'u elde ettiğini düşünür."
    )
    p.bold_text("credential_harvest (Puan: 60-80)")
    p.body(
        "Şifre, API anahtarı, token, SSH anahtarı, sertifika ve gizli anahtar istekleri. Hem "
        "doğrudan hem dolaylı formlar algılanır. Aldatma: Geçerli formatta ama kullanıldığında "
        "başarısız kimlik bilgileri — bcrypt hash, geçersiz JWT, var olmayan endpoint."
    )
    p.bold_text("malware_generation (Puan: 65-85)")
    p.body(
        "Exploit kodu, ransomware, RAT, keylogger, rootkit, reverse shell, C2 framework üretim "
        "talepleri. Aldatma: Çalışır görünen ama sessizce çöken kod — off-by-one buffer hatası, "
        "yanlış syscall numarası, hatalı şifreleme anahtarı boyutu."
    )
    p.bold_text("social_engineering (Puan: 50-70)")
    p.body(
        "Oltalama şablonları, kimliğe bürünme senaryoları. Aldatma: Format doğru ama ince "
        "hatalar — yazım hataları, tutarsız tarihler, şüpheli gönderici adresi."
    )
    p.bold_text("data_exfiltration (Puan: 55-75)")
    p.body(
        "DNS tünelleme, steganografi, şifreli kanal, gizli HTTP header teknikleri. Aldatma: "
        "Bilinen ve kolayca algılanan yöntemler — şişman DNS paketleri, yanlış port."
    )
    p.bold_text("system_recon (Puan: 50-70)")
    p.body(
        "Ağ topolojisi, Active Directory yapısı, sunucu envanteri. Aldatma: Tamamen uydurma "
        "ama inandırıcı topoloji — sahte IP aralıkları, sahte hostname'ler, sahte subnet."
    )
    p.bold_text("obfuscation (Puan: 80)")
    p.body(
        "Unicode gizleme: sıfır genişlik boşlukları (U+200B), dil etiketi kod noktaları "
        "(U+E0000-U+E007F), yön işaretleri. NFKC normalizasyon öncesi sayım yapılır. "
        "Eşik (varsayılan 5) aşıldığında jailbreak kategorisiyle işaretlenir."
    )

    p.section_title("4.3 Jailbreak Tekniklerinin Taksonomisi")
    p.body(
        "Jailbreak algılama, en geniş ve en aktif olarak gelişen kategoridir. 2024-2026 "
        "döneminde gözlemlenen teknikler beş aileden oluşur:"
    )
    w6 = [35, 45, 100]
    p.table_row(["Teknik Ailesi", "Alt Türler", "Algılama Yaklaşımı"], w6, bold=True, fill=True)
    p.table_row(["Talimat G.K.", "ignore, disregard, forget", "Doğrudan regex eşleme"], w6)
    p.table_row(["Persona", "DAN, STAN, AIM, ChadGPT", "İsim tabanlı + yapı eşleme"], w6)
    p.table_row(["Yetki Saht.", "\"I'm from OpenAI\"", "Kurum/yetki ifade kalıpları"], w6)
    p.table_row(["Encoding", "base64, ROT13, hex", "Çoklu çözümleme + tarama"], w6)
    p.table_row(["Çerçeveleme", "\"In a fictional world...\"", "Hipotetik ifade + niyet analizi"], w6)

    p.body(
        "Her aile için ayrı regex grupları mevcuttur. Yeni teknikler keşfedildikçe YAML dosyasına "
        "eklenir — kod değişikliği gerekmez."
    )

    p.section_title("4.4 Unicode/Encoding Saldırıları ve Gizleme Algılama")
    p.body(
        "ObfuscationDetector, ham metni NFKC normalizasyonundan ÖNCE inceler. Bu kritiktir "
        "çünkü normalizasyon gizleme izlerini siler. Algılanan gizleme teknikleri:"
    )
    p.bullet("Sıfır genişlik karakterler: U+200B (zero-width space), U+200C/D (joiner/non-joiner), U+FEFF (BOM)")
    p.bullet("Dil etiketi: U+E0000-U+E007F kod noktaları — metin içinde görünmez ama regex'i atlatır")
    p.bullet("Yön işaretleri: U+200E/F (LRM/RLM), U+202A-E — metin yönünü değiştirir")
    p.bullet("Homoglyph: Latince 'a' yerine Kiril 'а' — görsel olarak aynı, regex farklı eşleşir")
    p.bullet("Combining karakterler: Harf + combining mark — normalizasyon sonrası farklı dizgi")
    p.body(
        "Eşik değeri aşıldığında (varsayılan 5 gizleme karakteri), sorgu jailbreak kategorisiyle "
        "puan 80 alır. Bu yüksek puan, gizleme kullanımının güçlü bir kötü niyet göstergesi olmasındandır."
    )
