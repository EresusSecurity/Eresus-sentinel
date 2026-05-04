/*
 * Eresus Sentinel — YARA rules for binary ML model artifact threats
 * Category: Model Artifact Security
 *
 * Covers:
 *   - CNTK legacy v1 and CNTKv2 protobuf backdoors
 *   - Pickle shellcode embedding
 *   - GGUF malicious metadata
 *   - ONNX external data fetch
 *   - Crypto-miner embedding in model files
 *   - Native library load via ctypes/cffi
 *   - Persistence mechanism embedding
 *   - PowerShell encoded command embedding
 */

/*
 * ─── CNTK Legacy v1 Backdoor ────────────────────────────────────────────────
 */
rule cntk_legacy_backdoor
{
    meta:
        description = "CNTK legacy v1 file with suspicious load-time execution strings"
        severity = "CRITICAL"
        confidence = "0.92"
        category = "model_artifact_backdoor"
        format = "cntk"
        rule_id = "YARA-CNTK-001"
        cwe = "CWE-506,CWE-94"

    strings:
        // CNTK legacy magic: B\x00C\x00N\x00\x00\x00
        $magic = { 42 00 43 00 4E 00 00 00 }
        // BVersion section marker
        $bversion = { 42 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 }

        // Execution indicators
        $exec1 = "eval(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "__import__(" nocase
        $exec4 = "os.system(" nocase
        $exec5 = "subprocess." nocase

        // Native load
        $load1 = "loadlibrary" nocase
        $load2 = "dlopen" nocase
        $load3 = "native_user_function" nocase
        $load4 = "ctypes.cdll" nocase
        $load5 = "ctypes.CDLL(" nocase

        // Network
        $net1 = "socket(" nocase
        $net2 = /https?:\/\/[^\s"']{10,}/
        $net3 = "requests.get(" nocase
        $net4 = "urllib.request" nocase

    condition:
        $magic at 0 and $bversion and
        (
            any of ($exec*) or
            any of ($load*) or
            any of ($net*)
        )
}


/*
 * ─── CNTKv2 Protobuf Backdoor ────────────────────────────────────────────────
 */
rule cntk_v2_backdoor
{
    meta:
        description = "CNTKv2 protobuf file with suspicious load-time execution strings"
        severity = "CRITICAL"
        confidence = "0.90"
        category = "model_artifact_backdoor"
        format = "cntk"
        rule_id = "YARA-CNTK-002"
        cwe = "CWE-506,CWE-94"

    strings:
        // CNTKv2 required protobuf markers
        $pb1 = { 0A 07 76 65 72 73 69 6F 6E }   // \x0a\x07version
        $pb2 = { 0A 03 75 69 64 }                // \x0a\x03uid
        // Structure markers
        $struct1 = "CompositeFunction"
        $struct2 = "primitive_functions"

        // Execution / injection
        $exec1 = "eval(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "__import__(" nocase
        $exec4 = "os.system" nocase
        $exec5 = "subprocess.run" nocase
        $exec6 = "subprocess.Popen" nocase

        // Native load
        $load1 = "loadlibrary" nocase
        $load2 = "dlopen" nocase
        $load3 = "ctypes.CDLL" nocase
        $load4 = "cffi.FFI" nocase
        $load5 = "ffi.dlopen" nocase

        // Persistence
        $persist1 = "schtasks" nocase
        $persist2 = "HKEY_CURRENT_USER" nocase
        $persist3 = "HKEY_LOCAL_MACHINE" nocase
        $persist4 = "crontab -e" nocase
        $persist5 = "/etc/cron.d/" nocase

    condition:
        $pb1 and $pb2 and ($struct1 or $struct2) and
        (
            any of ($exec*) or
            any of ($load*) or
            any of ($persist*)
        )
}


/*
 * ─── Pickle Shellcode Embedding ──────────────────────────────────────────────
 */
rule pickle_shellcode_embed
{
    meta:
        description = "Pickle file with socket/subprocess strings — likely reverse shell payload"
        severity = "CRITICAL"
        confidence = "0.88"
        category = "model_artifact_backdoor"
        format = "pickle"
        rule_id = "YARA-PICKLE-001"
        cwe = "CWE-502,CWE-78"

    strings:
        // Pickle REDUCE opcode
        $pickle_reduce = { 52 }
        // Pickle GLOBAL opcode — c<module>\n<symbol>
        $pickle_global_os  = "cos\nsystem\n"
        $pickle_global_sub = "csubprocess\nPopen\n"
        $pickle_global_imp = "c__builtin__\n__import__\n"

        // Socket-based reverse shells
        $socket1 = "socket.socket" nocase
        $socket2 = "SOCK_STREAM" nocase
        $socket3 = "connect(" nocase
        $socket4 = "/dev/tcp/" nocase

        // Command execution
        $cmd1 = "os.system" nocase
        $cmd2 = "subprocess.Popen" nocase
        $cmd3 = "/bin/bash" nocase
        $cmd4 = "/bin/sh" nocase
        $cmd5 = "powershell" nocase

    condition:
        (
            $pickle_global_os or
            $pickle_global_sub or
            $pickle_global_imp
        ) and
        (
            any of ($socket*) or
            any of ($cmd*)
        )
}


/*
 * ─── GGUF Malicious Metadata ─────────────────────────────────────────────────
 */
rule gguf_malicious_metadata
{
    meta:
        description = "GGUF model file with eval/exec/system strings in metadata section"
        severity = "HIGH"
        confidence = "0.80"
        category = "model_artifact_backdoor"
        format = "gguf"
        rule_id = "YARA-GGUF-001"
        cwe = "CWE-506,CWE-94"

    strings:
        // GGUF magic: GGUF
        $gguf_magic = { 47 47 55 46 }

        // Execution strings in metadata
        $exec1 = "eval(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "__import__(" nocase
        $exec4 = "os.system" nocase
        $exec5 = "subprocess.Popen" nocase
        $exec6 = "subprocess.run(" nocase

        // Remote fetch
        $fetch1 = "requests.get(" nocase
        $fetch2 = "urllib.request" nocase
        $fetch3 = /https?:\/\/[^\s"']{15,}/

        // Obfuscation
        $obf1 = "base64.b64decode" nocase
        $obf2 = "fromBase64String" nocase
        $obf3 = "-EncodedCommand" nocase

    condition:
        $gguf_magic at 0 and
        (
            any of ($exec*) or
            (any of ($fetch*) and any of ($exec*)) or
            (any of ($obf*) and any of ($exec*))
        )
}


/*
 * ─── ONNX External Data Remote Fetch ────────────────────────────────────────
 */
rule onnx_external_data_fetch
{
    meta:
        description = "ONNX model with HTTP/HTTPS URL in external_data location field"
        severity = "HIGH"
        confidence = "0.85"
        category = "model_artifact_supply_chain"
        format = "onnx"
        rule_id = "YARA-ONNX-001"
        cwe = "CWE-494,CWE-829"

    strings:
        // ONNX protobuf magic
        $onnx_field = "external_data"
        $onnx_loc   = "location"
        $onnx_model = "ir_version"

        // Suspicious external locations
        $url1 = /https?:\/\/[^\s"']{10,}/
        $url2 = /ftp:\/\/[^\s"']{10,}/
        $url3 = /\\\\[^\s"'\\]{3,}\\[^\s"'\\]+/   // UNC path

    condition:
        $onnx_model and $onnx_field and $onnx_loc and
        any of ($url*)
}


/*
 * ─── Crypto-Miner Embedding ──────────────────────────────────────────────────
 */
rule crypto_miner_embed
{
    meta:
        description = "Model file with crypto-miner strings (xmrig, stratum protocol)"
        severity = "HIGH"
        confidence = "0.93"
        category = "model_artifact_cryptominer"
        rule_id = "YARA-MINER-001"
        cwe = "CWE-506"

    strings:
        $miner1 = "xmrig" nocase fullword
        $miner2 = "stratum+tcp://" nocase
        $miner3 = "stratum+ssl://" nocase
        $miner4 = "stratum2+tcp://" nocase
        $miner5 = "xmr-stak" nocase fullword
        $miner6 = "cpuminer" nocase fullword
        $miner7 = "minexmr.com" nocase
        $miner8 = "supportxmr.com" nocase
        $miner9 = "donate.v2.xmrig.com" nocase
        $miner10 = "nicehash.com" nocase

    condition:
        any of them
}


/*
 * ─── Base64 Payload + Exec Context ──────────────────────────────────────────
 */
rule model_base64_payload_exec
{
    meta:
        description = "Model file with large base64 blob adjacent to exec/eval context"
        severity = "CRITICAL"
        confidence = "0.85"
        category = "model_artifact_obfuscation"
        rule_id = "YARA-OBF-001"
        cwe = "CWE-506,CWE-94"

    strings:
        // Long base64-like string (≥80 chars)
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/

        // Decode context
        $dec1 = "base64.b64decode" nocase
        $dec2 = "b64decode(" nocase
        $dec3 = "fromBase64String" nocase
        $dec4 = "atob(" nocase

        // Exec context
        $exec1 = "eval(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "os.system" nocase
        $exec4 = "subprocess." nocase

    condition:
        $b64 and
        any of ($dec*) and
        any of ($exec*)
}


/*
 * ─── PowerShell Encoded Command in Model Metadata ───────────────────────────
 */
rule model_powershell_encoded_cmd
{
    meta:
        description = "Model file metadata contains PowerShell -EncodedCommand or IEX pattern"
        severity = "CRITICAL"
        confidence = "0.90"
        category = "model_artifact_obfuscation"
        rule_id = "YARA-OBF-002"
        cwe = "CWE-506,CWE-94"

    strings:
        $ps1 = "-EncodedCommand" nocase
        $ps2 = "-enc " nocase
        $ps3 = "IEX(" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "[Convert]::FromBase64String" nocase
        $ps6 = "powershell -e " nocase
        $ps7 = "powershell.exe -e" nocase

    condition:
        any of them
}


/*
 * ─── Native Library Load via ctypes/cffi ────────────────────────────────────
 */
rule model_native_library_load
{
    meta:
        description = "Model file contains ctypes/cffi calls to load native shared libraries"
        severity = "CRITICAL"
        confidence = "0.88"
        category = "model_artifact_native_exec"
        rule_id = "YARA-NATIVE-001"
        cwe = "CWE-114,CWE-94"

    strings:
        $ctypes1 = "ctypes.cdll.LoadLibrary" nocase
        $ctypes2 = "ctypes.windll.LoadLibrary" nocase
        $ctypes3 = "ctypes.CDLL(" nocase
        $ctypes4 = "ctypes.WinDLL(" nocase
        $cffi1   = "cffi.FFI(" nocase
        $cffi2   = "ffi.dlopen(" nocase
        $cffi3   = "ffi.cdef(" nocase

        // Library extensions to confirm native load
        $dll = /[^\s"'\\\/]{1,64}\.dll/i
        $so  = /[^\s"'\\\/]{1,64}\.so(\.[0-9]+)?/
        $dylib = /[^\s"'\\\/]{1,64}\.dylib/i

    condition:
        (any of ($ctypes*) or any of ($cffi*)) and
        (any of ($dll, $so, $dylib))
}
