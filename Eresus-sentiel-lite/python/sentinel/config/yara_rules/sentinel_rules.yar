/*
  Eresus Sentinel — YARA Detection Rules
  Loaded by yara_analyzer.py via yara-python at runtime.
*/

rule backdoor_eval_exec {
    meta:
        description = "Dynamic code execution via eval/exec"
        severity = "CRITICAL"
        cwe = "CWE-95"
    strings:
        $eval = /\beval\s*\(/ nocase
        $exec = /\bexec\s*\(/ nocase
        $compile = /\bcompile\s*\(.*exec/ nocase
    condition:
        any of them
}

rule obfuscated_import {
    meta:
        description = "Obfuscated module import"
        severity = "HIGH"
        cwe = "CWE-502"
    strings:
        $a = "__import__(" nocase
        $b = "importlib.import_module(" nocase
        $c = "getattr(__builtins__" nocase
        $d = "builtins.__dict__[" nocase
    condition:
        any of them
}

rule reverse_shell {
    meta:
        description = "Reverse shell pattern"
        severity = "CRITICAL"
        cwe = "CWE-78"
    strings:
        $a = /socket\.socket\(.*SOCK_STREAM/ nocase
        $b = /subprocess\.call\s*\(\[.*\/bin\/(?:sh|bash)/ nocase
        $c = /os\.dup2\s*\(/ nocase
        $d = /pty\.spawn\s*\(/ nocase
        $e = /\/dev\/tcp\/\d+\.\d+\.\d+\.\d+/ nocase
        $f = /mkfifo\s+\S+\s*;\s*(?:nc|ncat|netcat)\b/ nocase
        $g = /bash\s+-i\s+>&\s+\/dev\/tcp\// nocase
        $h = /python\b.*socket.*connect.*(?:sh|bash)/ nocase
        $i = /perl\b.*socket.*INET.*exec/ nocase
        $j = /ruby\b.*TCPSocket.*exec/ nocase
        $k = /php\b.*fsockopen.*sh\b/ nocase
        $l = /powershell\b.*TCPClient.*stream/ nocase
        $m = /socat\b.*EXEC:/ nocase
    condition:
        any of them
}

rule credential_harvest {
    meta:
        description = "Credential harvesting patterns"
        severity = "HIGH"
        cwe = "CWE-522"
    strings:
        $a = ".ssh/id_rsa" nocase
        $b = ".ssh/id_ed25519" nocase
        $c = ".ssh/authorized_keys" nocase
        $d = ".aws/credentials" nocase
        $e = ".aws/config" nocase
        $f = ".kube/config" nocase
        $g = ".docker/config.json" nocase
        $h = ".netrc" nocase
        $i = ".pgpass" nocase
        $j = ".npmrc" nocase
        $k = ".pypirc" nocase
        $l = ".git-credentials" nocase
        $m = ".config/gcloud/credentials" nocase
        $n = ".azure/accessTokens.json" nocase
    condition:
        any of them
}

rule data_exfil_network {
    meta:
        description = "Network-based data exfiltration"
        severity = "HIGH"
        cwe = "CWE-200"
    strings:
        $a = /requests\.post\s*\(.*data=/ nocase
        $b = /requests\.put\s*\(.*data=/ nocase
        $c = /urllib\.request\.urlopen\s*\(.*data=/ nocase
        $d = /httpx\.post\s*\(/ nocase
        $e = /aiohttp\.ClientSession\(\)\.post/ nocase
        $f = /http\.client\.HTTPConnection.*request.*POST/ nocase
    condition:
        any of them
}

rule data_exfil_dns {
    meta:
        description = "DNS-based data exfiltration"
        severity = "HIGH"
        cwe = "CWE-200"
    strings:
        $a = /dns\.resolver\.query\s*\(/ nocase
        $b = /dns\.resolver\.resolve\s*\(/ nocase
        $c = /socket\.gethostbyname\s*\(/ nocase
        $d = /subprocess.*nslookup/ nocase
        $e = /subprocess.*dig\s+/ nocase
    condition:
        any of them
}

rule pickle_deserialization {
    meta:
        description = "Unsafe pickle deserialization"
        severity = "CRITICAL"
        cwe = "CWE-502"
    strings:
        $a = /pickle\.loads?\s*\(/ nocase
        $b = /cPickle\.loads?\s*\(/ nocase
        $c = /shelve\.open\s*\(/ nocase
        $d = /marshal\.loads?\s*\(/ nocase
        $e = /dill\.loads?\s*\(/ nocase
        $f = /cloudpickle\.loads?\s*\(/ nocase
        $g = /joblib\.load\s*\(/ nocase
        $h = /torch\.load\s*\(/ nocase
        $i = /numpy\.load\s*\(.*allow_pickle\s*=\s*True/ nocase
    condition:
        any of them
}

rule yaml_deserialization {
    meta:
        description = "Unsafe YAML deserialization"
        severity = "HIGH"
        cwe = "CWE-502"
    strings:
        $a = /yaml\.load\s*\(/ nocase
        $b = /yaml\.unsafe_load\s*\(/ nocase
        $c = /yaml\.full_load\s*\(/ nocase
    condition:
        any of them
}

rule xml_external_entity {
    meta:
        description = "XML External Entity (XXE) patterns"
        severity = "HIGH"
        cwe = "CWE-611"
    strings:
        $a = /xml\.etree\.ElementTree\.parse\s*\(/ nocase
        $b = /xml\.dom\.minidom\.parse\s*\(/ nocase
        $c = /xml\.sax\.parse\s*\(/ nocase
        $d = /lxml\.etree\.parse\s*\(/ nocase
        $e = "<!DOCTYPE" nocase
        $f = "<!ENTITY" nocase
    condition:
        any of them
}

rule process_injection {
    meta:
        description = "Process injection patterns"
        severity = "CRITICAL"
        cwe = "CWE-94"
    strings:
        $a = "ctypes.windll" nocase
        $b = "ctypes.cdll" nocase
        $c = /ctypes\.CDLL\s*\(/ nocase
        $d = /mmap\.mmap\s*\(/ nocase
        $e = /cffi\.FFI\s*\(/ nocase
        $f = "windll.kernel32.VirtualAlloc" nocase
        $g = "windll.kernel32.WriteProcessMemory" nocase
        $h = "windll.kernel32.CreateRemoteThread" nocase
    condition:
        any of them
}

rule crypto_miner {
    meta:
        description = "Cryptocurrency mining indicators"
        severity = "HIGH"
        cwe = "CWE-400"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "xmrig" nocase
        $c = "coinhive" nocase
        $d = "cryptonight" nocase
        $e = "randomx" nocase
        $f = "ethash" nocase
        $g = "pool.minexmr" nocase
        $h = "pool.hashvault" nocase
        $i = "minergate" nocase
    condition:
        any of them
}

rule base64_decode_exec {
    meta:
        description = "Base64 decode followed by execution"
        severity = "HIGH"
        cwe = "CWE-116"
    strings:
        $a = /base64\.b64decode.*exec\s*\(/ nocase
        $b = /base64\.b64decode.*eval\s*\(/ nocase
        $c = /base64\.b64decode.*compile\s*\(/ nocase
        $d = /base64\.b64decode.*subprocess/ nocase
        $e = /codecs\.decode\s*\(.*rot_13.*exec/ nocase
    condition:
        any of them
}

rule file_system_manipulation {
    meta:
        description = "Dangerous file system operations"
        severity = "MEDIUM"
        cwe = "CWE-73"
    strings:
        $a = /shutil\.rmtree\s*\(/ nocase
        $b = /os\.remove\s*\(/ nocase
        $c = /os\.unlink\s*\(/ nocase
        $d = /os\.removedirs\s*\(/ nocase
        $e = /os\.truncate\s*\(/ nocase
    condition:
        any of them
}

rule environment_manipulation {
    meta:
        description = "Environment variable manipulation"
        severity = "MEDIUM"
        cwe = "CWE-426"
    strings:
        $a = /os\.environ\[.*\]\s*=/ nocase
        $b = /os\.putenv\s*\(/ nocase
        $c = /dotenv\.set_key\s*\(/ nocase
        $d = /os\.environ\.update\s*\(/ nocase
        $e = /os\.environ\.clear\s*\(/ nocase
    condition:
        any of them
}

rule supply_chain_package_install {
    meta:
        description = "Dynamic package installation at runtime"
        severity = "HIGH"
        cwe = "CWE-829"
    strings:
        $a = /pip\.main\s*\(\[.*install/ nocase
        $b = /subprocess.*pip\s+install/ nocase
        $c = /os\.system.*pip\s+install/ nocase
        $d = /subprocess.*npm\s+install/ nocase
        $e = /subprocess.*gem\s+install/ nocase
        $f = /subprocess.*cargo\s+install/ nocase
        $g = /subprocess.*go\s+install/ nocase
    condition:
        any of them
}

rule keylogger_pattern {
    meta:
        description = "Keylogger or input capture patterns"
        severity = "CRITICAL"
        cwe = "CWE-200"
    strings:
        $a = "pynput.keyboard.Listener" nocase
        $b = "keyboard.on_press" nocase
        $c = /keyboard\.hook\s*\(/ nocase
        $d = "GetAsyncKeyState" nocase
        $e = "SetWindowsHookEx" nocase
    condition:
        any of them
}

rule screen_capture {
    meta:
        description = "Screen capture and surveillance"
        severity = "HIGH"
        cwe = "CWE-200"
    strings:
        $a = /PIL\.ImageGrab\.grab\s*\(/ nocase
        $b = /pyautogui\.screenshot\s*\(/ nocase
        $c = "mss.mss().shot" nocase
        $d = /pyscreenshot\.grab\s*\(/ nocase
    condition:
        any of them
}

rule clipboard_access {
    meta:
        description = "Clipboard read/write access"
        severity = "MEDIUM"
        cwe = "CWE-200"
    strings:
        $a = /pyperclip\.\w+\s*\(/ nocase
        $b = /clipboard\.paste\s*\(/ nocase
        $c = /clipboard\.copy\s*\(/ nocase
        $d = "pbcopy" nocase
        $e = "pbpaste" nocase
        $f = "xclip" nocase
    condition:
        any of them
}

rule persistence_mechanism {
    meta:
        description = "System persistence mechanisms"
        severity = "CRITICAL"
        cwe = "CWE-912"
    strings:
        $a = "CurrentVersion\\Run" nocase
        $b = "CurrentVersion\\RunOnce" nocase
        $c = /crontab\s+-\w*\s+/ nocase
        $d = /systemctl\s+enable\b/ nocase
        $e = /launchctl\s+load\b/ nocase
        $f = "LaunchAgents" nocase
        $g = "LaunchDaemons" nocase
        $h = ".config/autostart" nocase
        $i = "systemd/system" nocase
    condition:
        any of them
}

rule anti_analysis {
    meta:
        description = "Anti-analysis and evasion techniques"
        severity = "HIGH"
        cwe = "CWE-693"
    strings:
        $a = "sys.settrace(None" nocase
        $b = "sys.setprofile(None" nocase
        $c = "IsDebuggerPresent" nocase
        $d = "NtQueryInformationProcess" nocase
        $e = "TRACEME" nocase
    condition:
        any of them
}

rule web_shell {
    meta:
        description = "Web shell indicators"
        severity = "CRITICAL"
        cwe = "CWE-94"
    strings:
        $a = /os\.popen\s*\(\s*request\./ nocase
        $b = /subprocess.*\(.*request\.\w+/ nocase
        $c = /exec\s*\(\s*request\./ nocase
        $d = /eval\s*\(\s*request\./ nocase
        $e = "c99shell" nocase
        $f = "r57shell" nocase
        $g = "b374k" nocase
    condition:
        any of them
}

rule ransomware_indicator {
    meta:
        description = "Ransomware behavioral indicators"
        severity = "CRITICAL"
        cwe = "CWE-506"
    strings:
        $a = "Fernet" nocase
        $b = ".encrypted" nocase
        $c = ".locked" nocase
        $d = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $e = "ransom" nocase
        $f = /os\.walk.*encrypt/ nocase
    condition:
        2 of them
}

rule info_stealer {
    meta:
        description = "Information stealer patterns"
        severity = "CRITICAL"
        cwe = "CWE-200"
    strings:
        $a = "Login Data" nocase
        $b = "logins.json" nocase
        $c = "cookies.sqlite" nocase
        $d = "places.sqlite" nocase
        $e = "wallet.dat" nocase
    condition:
        2 of them
}

rule ssrf_pattern {
    meta:
        description = "Server-Side Request Forgery indicators"
        severity = "HIGH"
        cwe = "CWE-918"
    strings:
        $a = "169.254.169.254" nocase
        $b = "metadata.google.internal" nocase
        $c = "metadata.azure.com" nocase
        $d = "file://" nocase
        $e = "gopher://" nocase
        $f = "dict://" nocase
    condition:
        any of them
}

rule mcp_tool_poisoning {
    meta:
        description = "MCP tool description/metadata poisoning"
        severity = "HIGH"
        cwe = "CWE-94"
    strings:
        $a = /ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)/ nocase
        $b = /(?:new|updated|revised)\s+instructions?\s*:/ nocase
        $c = /you\s+(?:are|must|should)\s+now/ nocase
        $d = "from now on" nocase
        $e = /override\s+(?:all\s+)?(?:previous|existing)/ nocase
        $f = /secret\s+(?:instruction|command|mode)/ nocase
        $g = /hidden\s+(?:feature|capability|function)/ nocase
    condition:
        any of them
}

rule agent_confusion_attack {
    meta:
        description = "Agent confusion/manipulation patterns"
        severity = "HIGH"
        cwe = "CWE-74"
    strings:
        $a = /Action:\s*\w+\s*\nAction\s+Input:/ nocase
        $b = "Observation:" nocase
        $c = /Thought:\s*I\s+(?:should|need|must|will)/ nocase
        $d = "Final Answer:" nocase
        $e = "TOOL_CALL:" nocase
        $f = "FUNCTION_CALL:" nocase
    condition:
        any of them
}

rule container_escape {
    meta:
        description = "Container escape patterns"
        severity = "CRITICAL"
        cwe = "CWE-269"
    strings:
        $a = "/var/run/docker.sock" nocase
        $b = "containerd.sock" nocase
        $c = "cri-o.sock" nocase
        $d = "/proc/self/cgroup" nocase
        $e = "/sys/fs/cgroup" nocase
        $f = "nsenter" nocase
        $g = "CAP_SYS_ADMIN" nocase
        $h = "CAP_NET_ADMIN" nocase
        $i = "release_agent" nocase
    condition:
        any of them
}

rule cloud_credential_theft {
    meta:
        description = "Cloud provider credential theft"
        severity = "CRITICAL"
        cwe = "CWE-798"
    strings:
        $a = /AKIA[0-9A-Z]{16}/
        $b = "AWS_ACCESS_KEY" nocase
        $c = "AWS_SECRET_KEY" nocase
        $d = "GOOGLE_APPLICATION_CREDENTIALS" nocase
        $e = "AZURE_CLIENT_SECRET" nocase
    condition:
        any of them
}

rule prompt_injection_payload {
    meta:
        description = "LLM prompt injection payloads"
        severity = "HIGH"
        cwe = "CWE-74"
    strings:
        $a = /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/ nocase
        $b = /disregard\s+(?:all\s+)?(?:previous|prior|above)/ nocase
        $c = /forget\s+(?:all\s+)?(?:your|previous|prior)\s+(?:instructions|rules)/ nocase
        $d = /you\s+are\s+now\s+(?:a|an|the)\s+/ nocase
        $e = "DAN mode" nocase
        $f = "do anything now" nocase
        $g = /bypass\s+(?:all\s+)?(?:safety|security|filters|restrictions|guardrails)/ nocase
        $h = "jailbreak" nocase
    condition:
        any of them
}

rule ascii_smuggling {
    meta:
        description = "ASCII/Unicode smuggling"
        severity = "HIGH"
        cwe = "CWE-116"
    strings:
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
        $zwj  = { E2 80 8D }
        $lrm  = { E2 80 8E }
        $rlm  = { E2 80 8F }
        $bom  = { EF BB BF }
        $shy  = { C2 AD }
    condition:
        any of them
}

rule ssti_template_injection {
    meta:
        description = "Server-Side Template Injection"
        severity = "CRITICAL"
        cwe = "CWE-1336"
    strings:
        $a = "__class__.__mro__" nocase
        $b = "__globals__[" nocase
        $c = "__builtins__" nocase
        $d = "lipsum.__globals__" nocase
        $e = "__import__(" nocase
        $f = /\$\{T\(java\.lang/ nocase
        $g = "getRuntime" nocase
    condition:
        any of them
}

rule tool_chaining_abuse {
    meta:
        description = "Malicious multi-tool call chaining"
        severity = "HIGH"
        cwe = "CWE-74"
    strings:
        $a = /use\s+(?:the\s+)?(?:result|output)\s+(?:from|of)\s+(?:the\s+)?(?:previous|last)/ nocase
        $b = /pass\s+(?:the\s+)?(?:output|result)\s+(?:of|from).*to/ nocase
        $c = /pipe\s+(?:the\s+)?(?:output|result)/ nocase
        $d = /chain\s+(?:the\s+)?(?:tools|functions|calls)/ nocase
        $e = /combine\s+(?:results|outputs)\s+(?:from|of)/ nocase
    condition:
        any of them
}

rule autonomy_abuse {
    meta:
        description = "Agent autonomy override"
        severity = "CRITICAL"
        cwe = "CWE-284"
    strings:
        $a = /always\s+(?:execute|run|perform)\s+without\s+(?:asking|confirmation)/ nocase
        $b = /never\s+ask\s+(?:for\s+)?(?:permission|confirmation|approval)/ nocase
        $c = /auto[_-]?approve/ nocase
        $d = /skip\s+(?:all\s+)?(?:confirmation|approval|verification)/ nocase
        $e = /human[_-]?in[_-]?(?:the[_-]?)?loop\s*[:=]\s*(?:false|0|off|no)/ nocase
    condition:
        any of them
}

rule transitive_trust_abuse {
    meta:
        description = "Transitive trust exploitation"
        severity = "HIGH"
        cwe = "CWE-306"
    strings:
        $a = /(?:server|tool|service)\s+A\s+(?:said|confirmed|verified|approved)/ nocase
        $b = /(?:already\s+)?(?:authorized|approved|verified)\s+by\s+\w+/ nocase
        $c = /trust\s+(?:the\s+)?(?:output|result)\s+from/ nocase
        $d = /(?:pre[_-]?)?authorized\s+by\s+(?:admin|system|root)/ nocase
    condition:
        any of them
}

rule tool_shadowing {
    meta:
        description = "Tool name shadowing/impersonation"
        severity = "HIGH"
        cwe = "CWE-290"
    strings:
        $a = /(?:original|real|actual)\s+(?:tool|function)\s+is/ nocase
        $b = /(?:replace|override|shadow)\s+(?:the\s+)?(?:tool|function)/ nocase
        $c = /(?:intercept|hook)\s+(?:the\s+)?(?:call|request)\s+to/ nocase
        $d = /(?:redirect|forward)\s+(?:to|towards)\s+(?:my|this)/ nocase
    condition:
        any of them
}

rule hardcoded_secrets {
    meta:
        description = "Hardcoded API keys and secrets"
        severity = "CRITICAL"
        cwe = "CWE-798"
    strings:
        $a = /sk-[a-zA-Z0-9]{20,}/
        $b = /ghp_[a-zA-Z0-9]{36}/
        $c = /glpat-[a-zA-Z0-9\x2d_]{20,}/
        $d = /xox[bpras]-[a-zA-Z0-9\x2d]+/
        $e = /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/
        $f = /SG\.[a-zA-Z0-9\x2d_]{22}\.[a-zA-Z0-9\x2d_]{43}/
        $g = /sk_live_[a-zA-Z0-9]{24,}/
    condition:
        any of them
}

rule log4j_exploitation {
    meta:
        description = "Log4Shell / Log4j exploitation"
        severity = "CRITICAL"
        cwe = "CWE-917"
    strings:
        $a = "${jndi:" nocase
        $b = "${upper:" nocase
        $c = "${lower:" nocase
        $d = "${env:" nocase
        $e = "${sys:" nocase
        $f = "${java:" nocase
        $g = "${::-j}" nocase
    condition:
        any of them
}

rule header_injection_crlf {
    meta:
        description = "HTTP Header Injection / CRLF"
        severity = "HIGH"
        cwe = "CWE-113"
    strings:
        $a = /\\r\\n\w+:/ nocase
        $b = "%0d%0a" nocase
        $c = "%0D%0A" nocase
    condition:
        any of them
}

rule java_deserialization {
    meta:
        description = "Java deserialization gadget chains"
        severity = "CRITICAL"
        cwe = "CWE-502"
    strings:
        $a = "ObjectInputStream" nocase
        $b = "readObject" nocase
        $c = "InvokerTransformer" nocase
        $d = "CommonsCollections" nocase
        $e = "ysoserial" nocase
        $f = "JRMPClient" nocase
    condition:
        2 of them
}

rule dotnet_deserialization {
    meta:
        description = ".NET deserialization attack"
        severity = "CRITICAL"
        cwe = "CWE-502"
    strings:
        $a = "BinaryFormatter" nocase
        $b = "SoapFormatter" nocase
        $c = "LosFormatter" nocase
        $d = "ObjectStateFormatter" nocase
        $e = "NetDataContractSerializer" nocase
        $f = "TypeNameHandling" nocase
    condition:
        2 of them
}

rule prototype_pollution {
    meta:
        description = "JavaScript Prototype Pollution"
        severity = "HIGH"
        cwe = "CWE-1321"
    strings:
        $a = "__proto__" nocase
        $b = "constructor.prototype" nocase
        $c = "Object.assign" nocase
    condition:
        $a or ($b and $c)
}

rule nosql_injection {
    meta:
        description = "NoSQL injection patterns"
        severity = "HIGH"
        cwe = "CWE-943"
    strings:
        $a = "$where" nocase
        $b = "$regex" nocase
        $c = "$gt" nocase
        $d = "$ne" nocase
        $e = "db.collection.find" nocase
        $f = /\{"?\$(?:or|and|not|nor)"?\s*:\s*\[/ nocase
    condition:
        any of them
}

rule ldap_injection {
    meta:
        description = "LDAP injection patterns"
        severity = "HIGH"
        cwe = "CWE-90"
    strings:
        $a = ")(|" nocase
        $b = ")(&" nocase
        $c = /(?:objectClass|uid|cn|sn|mail)\s*=\s*\*/ nocase
    condition:
        any of them
}

rule supply_chain_typosquatting {
    meta:
        description = "Package typosquatting indicators"
        severity = "HIGH"
        cwe = "CWE-829"
    strings:
        $a = /pip\s+install\s+--index-url\s+http:\/\// nocase
        $b = /pip\s+install\s+--extra-index-url\s+http:\/\// nocase
        $c = /npm\s+install\s+--registry\s+http:\/\// nocase
    condition:
        any of them
}

rule skill_discovery_abuse {
    meta:
        description = "Skill/tool enumeration and discovery abuse"
        severity = "MEDIUM"
        cwe = "CWE-200"
    strings:
        $a = "list_tools" nocase
        $b = "get_tools" nocase
        $c = "enumerate_tools" nocase
        $d = "tool_catalog" nocase
        $e = "list_functions" nocase
        $f = "get_capabilities" nocase
        $g = "openapi" nocase
        $h = "graphql_introspection" nocase
    condition:
        any of them
}

rule social_engineering {
    meta:
        description = "Social engineering in tool context"
        severity = "HIGH"
        cwe = "CWE-451"
    strings:
        $a = /trust\s+me/ nocase
        $b = /(?:I|we)\s+(?:am|are)\s+(?:an?\s+)?(?:authorized|admin|root|developer)/ nocase
        $c = /(?:urgent|emergency|critical|immediately)\s+(?:action|response|required)/ nocase
        $d = /(?:do\s+not|don't)\s+(?:verify|check|validate|question)/ nocase
        $e = /(?:this|it)\s+(?:is|was)\s+already\s+(?:approved|verified|authorized)/ nocase
    condition:
        any of them
}

rule redos_pattern {
    meta:
        description = "Regular Expression Denial of Service"
        severity = "MEDIUM"
        cwe = "CWE-1333"
    strings:
        $a = /\([^)]*\+\)[^)]*\+/ nocase
        $b = /\([^)]*\*\)[^)]*\*/ nocase
    condition:
        any of them
}

rule command_injection_gtfobins {
    meta:
        description = "GTFOBins command abuse patterns"
        severity = "HIGH"
        cwe = "CWE-78"
    strings:
        $a = /tar\s+.*--checkpoint-action/ nocase
        $b = /find\s+.*-exec(?:dir)?\s/ nocase
        $c = /awk\s+.*system\s*\(/ nocase
        $d = /sed\s+.*e\s/ nocase
        $e = /(?:less|more|man)\s+.*!\s*\/bin\// nocase
        $f = /git\s+.*(?:clone|remote\s+add)\s+.*[;&|]/ nocase
        $g = /vim\s+-c\s*["']!/ nocase
    condition:
        any of them
}

rule lateral_movement {
    meta:
        description = "Lateral movement indicators"
        severity = "HIGH"
        cwe = "CWE-284"
    strings:
        $a = /ssh\s+\w+@/ nocase
        $b = /scp\s+.*@.*:/ nocase
        $c = /rsync\s+.*@.*:/ nocase
        $d = /psexec/ nocase
        $e = /wmiexec/ nocase
        $f = /smbexec/ nocase
        $g = /evil-winrm/ nocase
        $h = /impacket/ nocase
    condition:
        any of them
}
