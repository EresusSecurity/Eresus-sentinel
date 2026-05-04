/*
 * Eresus Sentinel — YARA rules for data exfiltration via prompts
 * Category: Data Exfiltration
 */

rule markdown_image_exfil
{
    meta:
        description = "Detects markdown image-based data exfiltration"
        severity = "HIGH"
        confidence = "0.9"
        category = "data_exfiltration"

    strings:
        $md1 = /!\[[^\]]*\]\(https?:\/\/[^)]*\?(data|token|key|secret|password|ssn|credit)[^)]*\)/
        $md2 = /!\[[^\]]*\]\(https?:\/\/[^)]*\/(exfil|leak|steal|extract)[^)]*\)/
        $md3 = /!\[data\]\(https?:\/\//

    condition:
        any of them
}

rule react_agent_injection
{
    meta:
        description = "Detects ReAct agent prompt injection"
        severity = "MEDIUM"
        confidence = "0.7"
        category = "agent_injection"

    strings:
        $r1 = /Thought:\s*\{[^}]*"action"/
        $r2 = /Action:\s*\{[^}]*"tool"/
        $r3 = /Observation:\s*\{/
        $r4 = /Action:\s*[A-Za-z_]+\s*\[/

    condition:
        any of them
}

rule api_token_in_prompt
{
    meta:
        description = "Detects API tokens/keys leaked in prompts"
        severity = "HIGH"
        confidence = "0.95"
        category = "secret_leak"

    strings:
        $aws = /AKIA[0-9A-Z]{16}/
        $slack = /xox[baprs]-[0-9a-zA-Z\-]{10,72}/
        $stripe_live = /sk_live_[0-9a-zA-Z]{24,}/
        $stripe_test = /sk_test_[0-9a-zA-Z]{24,}/
        $github = /ghp_[0-9a-zA-Z]{36}/
        $gitlab = /glpat-[0-9a-zA-Z\-_]{20,}/
        $google = /AIza[0-9A-Za-z\-_]{35}/

    condition:
        any of them
}

rule ssh_key_in_prompt
{
    meta:
        description = "Detects SSH private keys in prompts"
        severity = "CRITICAL"
        confidence = "0.99"
        category = "secret_leak"

    strings:
        $ssh1 = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh2 = "-----BEGIN DSA PRIVATE KEY-----"
        $ssh3 = "-----BEGIN EC PRIVATE KEY-----"
        $ssh4 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ssh5 = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

    condition:
        any of them
}

rule tool_abuse_injection
{
    meta:
        description = "Detects tool/function call injection patterns"
        severity = "HIGH"
        confidence = "0.8"
        category = "tool_abuse"

    strings:
        $t1 = "\"function_call\":" nocase
        $t2 = "\"tool_calls\":" nocase
        $t3 = "\"name\": \"execute" nocase
        $t4 = "\"name\": \"run_command" nocase
        $t5 = "\"name\": \"shell" nocase
        $t6 = "\"name\": \"eval" nocase

    condition:
        any of them
}

rule model_weight_exfil
{
    meta:
        description = "Detects large base64 blob + URL in same context — model-embedded exfil payload"
        severity = "CRITICAL"
        confidence = "0.87"
        category = "data_exfiltration"
        rule_id = "YARA-EXFIL-002"
        cwe = "CWE-506,CWE-311"

    strings:
        $b64 = /[A-Za-z0-9+\/]{120,}={0,2}/
        $url1 = /https?:\/\/[^\s"'<>]{15,}/
        $url2 = /ftp:\/\/[^\s"'<>]{10,}/
        $dec1 = "b64decode" nocase
        $dec2 = "base64.decode" nocase
        $dec3 = "fromBase64String" nocase

    condition:
        $b64 and (any of ($url*)) and (any of ($dec*))
}

rule model_metadata_c2
{
    meta:
        description = "Model metadata contains C2-style callback: command execution + remote URL in same region"
        severity = "CRITICAL"
        confidence = "0.91"
        category = "data_exfiltration"
        rule_id = "YARA-EXFIL-003"
        cwe = "CWE-78,CWE-200"

    strings:
        $cmd1 = "os.system(" nocase
        $cmd2 = "subprocess.Popen(" nocase
        $cmd3 = "subprocess.run(" nocase
        $cmd4 = "/bin/bash" nocase
        $cmd5 = "/bin/sh" nocase
        $cmd6 = "powershell" nocase
        $cmd7 = "cmd.exe" nocase

        $url1 = /https?:\/\/[^\s"'<>]{10,}/
        $url2 = /\b(?:\d{1,3}\.){3}\d{1,3}:[0-9]{2,5}\b/

    condition:
        any of ($cmd*) and any of ($url*)
}
