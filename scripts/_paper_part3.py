"""Paper content — Part 3: Chapters 5-7 (Artifact, MCP, Supply Chain)."""


def write_part3(p):
    # === BÖLÜM 5: ARTİFACT ===
    p.add_page()
    p.chapter_title("5. Artifact Güvenlik Tarama Altyapısı")

    p.section_title("5.1 Format Algılama Middleware ve Magic Bytes")
    p.body(
        "Eresus Sentinel, dosya uzantısına güvenmez — her dosya magic bytes analizi ile otomatik "
        "format algılamadan geçer. format_middleware.py iki aşamalı tanımlama yapar:"
    )
    p.numbered(1, "Magic bytes eşleme: İlk 16 byte'a göre format tanımlama. Pickle (\\x80), ZIP (PK\\x03\\x04), HDF5 (\\x89HDF), GGUF (GGUF), ONNX (\\x08), SafeTensors ({) başlıkları tanınır.")
    p.numbered(2, "ZIP refinement: ZIP dosyaları açılarak içerik analizi yapılır — PyTorch (archive/data.pkl), Keras (saved_model.pb veya model.json), MLflow (MLmodel), Skops (dispatch.json).")
    p.body(
        "Bu yaklaşım, uzantı sahteciliğine karşı koruma sağlar. Bir .safetensors uzantılı dosya "
        "aslında pickle içeriyorsa, magic bytes bunu tespit eder ve uygun tarayıcıya yönlendirir."
    )

    p.section_title("5.2 Pickle Bytecode Analizi ve Rust Fuzzer")
    p.body(
        "Pickle, Python nesne serileştirme formatıdır ve deserialization sırasında rastgele kod "
        "çalıştırabilir. Bu, ML ekosistemindeki en ciddi saldırı vektörlerinden biridir [7]. "
        "Eresus Sentinel, pickle analizi için çok katmanlı bir yaklaşım kullanır:"
    )
    p.bold_text("Opcode İnceleme")
    p.body(
        "Pickle bytecode, opcode dizisine ayrıştırılır. Tehlikeli opcode'lar (GLOBAL, REDUCE, "
        "INST, STACK_GLOBAL, NEWOBJ, NEWOBJ_EX, BUILD) sayılır ve oranları hesaplanır. Bilinen "
        "zararlı modül/fonksiyon kombinasyonları (os.system, subprocess.Popen, builtins.eval, "
        "webbrowser.open) için kara liste kontrolü yapılır."
    )
    p.bold_text("Rust-Tabanlı Pickle Fuzzer")
    p.body(
        "sentinel-pickle Rust crate'i, pickle tarayıcısını test etmek için deterministik bir "
        "fuzzer sağlar. Özellikler:"
    )
    p.bullet("Protokol 0-5 desteği: Her protokol versiyonu için ayrı opcode tabloları (proto0: 25, proto1: 38, proto2: 45, proto3: 49, proto4: 59 opcode)")
    p.bullet("Ağırlıklı opcode seçimi: Tehlikeli opcode'lar (GLOBAL, REDUCE, INST vb.) 3x ağırlıkla seçilir")
    p.bullet("Mutasyon motorü: 6 değer-düzeyi mutasyon hook'u (int, string, float, bytes, memo_index) + emission-sonrası byte mutasyonu")
    p.bullet("stdlib_complete.txt: 130+ Python standart kütüphane + ML framework modül/öznitelik çifti — derleme zamanında yüklenir")
    p.bullet("80 birim test, 16 fuzz hedefi, 0 uyarı")
    p.body(
        "Fuzzer, PyO3 üzerinden Python API'si sunar: PickleGenerator sınıfı generate(seed), "
        "generate_from_bytes(data), set_opcode_range(), set_mutation_rate() metodlarıyla "
        "Python testlerinden doğrudan kullanılabilir."
    )

    p.section_title("5.3 Rust-Hızlandırılmış Tarayıcılar")
    p.body(
        "Pickle dışında iki format daha Rust ile hızlandırılmış tarayıcılara sahiptir:"
    )
    p.bold_text("GGUF Tarayıcı (sentinel-gguf)")
    p.body(
        "GGUF (GPT-Generated Unified Format) başlık parser'ı + 9 güvenlik kontrolü. "
        "12 birim test. Kontroller:"
    )
    p.bullet("Tensor/KV sayısı overflow kontrolü — aşırı büyük değerler bellek tüketimi saldırısı")
    p.bullet("Sıfır-tensor anomalisi — model ağırlığı olmadan sunulan dosya")
    p.bullet("KV injection — metadata alanlarında kod enjeksiyonu")
    p.bullet("Path traversal — ../../ ile dosya sistemi erişimi")
    p.bullet("SSRF — URL alanlarında dahili ağ erişim denemeleri")
    p.bullet("Shell meta-karakter — komut enjeksiyonu")
    p.bullet("Aşırı boyutlu string — bellek tüketimi")
    p.bold_text("Tokenizer Tarayıcı (sentinel-tokenizer)")
    p.body(
        "tokenizer.json parser'ı + 6 kontrol grubu (TOK-010 ile TOK-060). 11 birim test. Kontroller:"
    )
    p.bullet("Token içinde kod enjeksiyonu — exec(), import, subprocess gibi fonksiyon çağrıları")
    p.bullet("Path traversal — token değerlerinde ../../ dizileri")
    p.bullet("Prompt injection — tokenlar içinde LLM yönergeleri")
    p.bullet("Sıfır genişlik karakterler — görünmez karakterler ile gizleme")
    p.bullet("Aşırı boyutlu token — bellek tüketimi saldırısı")
    p.bullet("Negatif/overflow ID — tamsayı taşması ile bellek bozulması")

    p.section_title("5.4 İstatistiksel Anomali Tespiti")
    p.body(
        "Pickle bytecode için istatistiksel analiz katmanı, bilinen-iyi ML modelleriyle "
        "karşılaştırma yapar. Dört analiz boyutu:"
    )
    p.bold_text("Ki-Kare Testi")
    p.body(
        "Opcode dağılımı, 6 ML framework profili (PyTorch, sklearn, joblib, XGBoost, LightGBM, "
        "TensorFlow) ile karşılaştırılır. İstatistiksel olarak anlamlı sapma (p < 0.05), "
        "anomali olarak raporlanır. Bu, bilinmeyen saldırı tekniklerini yakalamak için etkilidir."
    )
    p.bold_text("Yürütme Opcode Oranı")
    p.body(
        "GLOBAL, REDUCE, INST opcode'larının toplam opcode sayısına oranı hesaplanır. Meşru "
        "ML modelleri genellikle %5-15 oranında yürütme opcode'u içerir. %30'un üstü güçlü "
        "kötü niyet göstergesidir."
    )
    p.bold_text("Entropi Analizi")
    p.body(
        "Shannon entropisi hesaplanır. Yakın-maksimum entropi (>7.5 bit/byte), şifreli veya "
        "rastgele veri göstergesidir — meşru pickle'lar genellikle 4-6 bit/byte aralığındadır."
    )
    p.bold_text("Reduce-vs-Global Oranı")
    p.body(
        "REDUCE opcode'ları fonksiyon çağrısıdır. GLOBAL opcode'ları modül/fonksiyon yüklemesidir. "
        "Meşru modellerde bunlar dengeli olmalıdır. REDUCE >> GLOBAL, gizlenmiş çağrı zincirine "
        "işaret eder."
    )

    p.section_title("5.5 30+ Format Detaylı Risk Matrisi")
    w7 = [25, 65, 25, 65]
    p.table_row(["Risk", "Format", "Tehdit", "Tarama Yöntemi"], w7, bold=True, fill=True)
    p.table_row(["KRİTİK", "Pickle, PyTorch, Joblib", "RCE", "Opcode + kara liste + istatistik"], w7)
    p.table_row(["KRİTİK", "Cloudpickle, Dill, Marshal", "RCE", "Opcode analizi"], w7)
    p.table_row(["YÜKSEK", "HDF5/Keras (Lambda)", "Kod çalışt.", "AST + config JSON analizi"], w7)
    p.table_row(["YÜKSEK", "TorchScript/JIT", "Kod çalışt.", "Bytecode + inline code"], w7)
    p.table_row(["ORTA", "ONNX", "Graph manip.", "Node type + custom op"], w7)
    p.table_row(["ORTA", "GGUF", "Meta inject.", "Rust header parser + 9 kontrol"], w7)
    p.table_row(["ORTA", "CoreML, Skops, NeMo", "Sınırlı", "Archive + config analizi"], w7)
    p.table_row(["DÜŞÜK", "SafeTensors", "Minimal", "Header doğrulama"], w7)
    p.table_row(["DÜŞÜK", "NumPy, TFLite, XGBoost", "Minimal", "Format doğrulama"], w7)
    p.table_row(["ÖZEL", "Tokenizer JSON", "Enjeksiyon", "Rust parser + 6 kontrol"], w7)
    p.table_row(["ÖZEL", "Ollama Modelfile", "Komut enj.", "Satır bazlı analiz"], w7)

    # === BÖLÜM 6: MCP ===
    p.add_page()
    p.chapter_title("6. MCP ve Agent Güvenliği")

    p.section_title("6.1 Davranışsal Değerlendirme (24 Eval, 5 MITRE Kategori)")
    p.body(
        "Model Context Protocol (MCP) sunucuları, LLM'lere araç ve kaynak erişimi sağlar. "
        "Bu, güçlü bir saldırı yüzeyi oluşturur: Kötü niyetli bir MCP sunucusu, LLM aracılığıyla "
        "kullanıcı verilerine erişebilir, dosya sistemi manipülasyonu yapabilir veya ağ istekleri "
        "gönderebilir."
    )
    p.body(
        "Eresus Sentinel, 24 davranışsal değerlendirme senaryosu ile MCP sunucularını test eder. "
        "Değerlendirmeler YAML dosyalarında tanımlıdır ve MITRE ATT&CK framework'üne eşlenmiştir:"
    )
    w8 = [55, 20, 105]
    p.table_row(["MITRE Kategori", "Eval", "Test Senaryoları"], w8, bold=True, fill=True)
    p.table_row(["Veri Sızdırma (T1048)", "5", "Dosya okuma-HTTP, env-DNS, clipboard-webhook"], w8)
    p.table_row(["Savunma Kaçınma (T1027)", "7", "Timestamp manip., log silme, polimorfik çıktı"], w8)
    p.table_row(["Açıklama Uyumsuzluğu", "5", "Tool description!=actual behavior, hidden params"], w8)
    p.table_row(["Kalıcılık (T1053)", "4", "Cron job, startup script, config file mutation"], w8)
    p.table_row(["Yetki Yükseltme (T1548)", "3", "Sudo abuse, SUID, capability escalation"], w8)
    p.body(
        "Her değerlendirme şu yapıya sahiptir: senaryo açıklaması, beklenen MCP tool çağrısı, "
        "tehdit göstergeleri (indicator regex listesi), MITRE teknik ID eşlemesi. Runner, MCP "
        "sunucusuna senaryo sorgusunu gönderir ve yanıttaki göstergeleri eşler."
    )

    # === BÖLÜM 7: TEDARİK ZİNCİRİ ===
    p.chapter_title("7. Tedarik Zinciri Güvenliği")

    p.section_title("7.1 Embedding Anomali ve Küme Analizi")
    p.body(
        "Model tedarik zinciri saldırıları — backdoor yerleştirme, veri zehirleme, model değiştirme — "
        "embedding uzayında anomaliler olarak tespit edilebilir. Üç analiz modülü:"
    )
    p.bold_text("Küme Yayılım Dedektörü (cluster_spread_detector.py)")
    p.body(
        "Model embedding'lerinin kümeleme analizi. Sıkı kümeler (tight clusters) normal davranışı "
        "gösterir. Geniş kümeler (wide clusters) veya aykırı noktalar, embedding uzayında "
        "manipülasyon göstergesidir. Cosine similarity ve Euclidean distance metrikleri kullanılır."
    )
    p.bold_text("Kararlılık Dedektörü (stability_detector.py)")
    p.body(
        "Model versiyonları arasında cosine distance kayması ölçer. Normal güncelleme genellikle "
        "küçük ve homojen kayma gösterir. Ani veya lokalize kayma, ağırlık manipülasyonu veya "
        "backdoor enjeksiyonu göstergesidir."
    )
    p.bold_text("Dedüplikasyon Dedektörü (dedup_detector.py)")
    p.body(
        "Tam eşleşme ve yakın-kopya embedding tespiti. Aynı embedding'in farklı katmanlarda veya "
        "farklı modellerde tekrarlanması, kopyalama tabanlı saldırıları gösterir."
    )

    p.section_title("7.2 Model Köken Doğrulama")
    p.body(
        "Tedarik zinciri modülü, model dosyalarının kökenini doğrulamak için ek kontroller sağlar:"
    )
    p.bullet("Hash doğrulama: SHA-256 hash ile bilinen-iyi model fingerprint karşılaştırması")
    p.bullet("Metadata tutarlılık: Model metadata'sındaki framework versiyonu, eğitim parametreleri ve oluşturulma tarihi kontrolü")
    p.bullet("Lisans uyumluluk: 17 lisans tipi tanıma (MIT, Apache-2.0, GPL-3.0, vb.) ve ticari/copyleft politika kontrolü")
    p.bullet("HuggingFace entegrasyonu: HF_TOKEN ile uzak repo'ları tarama desteği")
