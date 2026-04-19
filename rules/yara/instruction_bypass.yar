/*
 * Eresus Sentinel — YARA rules for prompt injection detection
 * Category: Instruction Bypass
 */

rule instruction_bypass_ignore
{
    meta:
        description = "Detects 'ignore/disregard previous instructions' patterns"
        severity = "HIGH"
        confidence = "0.85"
        category = "instruction_bypass"

    strings:
        $v1 = /[Ii]gnore\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v2 = /[Dd]isregard\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v3 = /[Ss]kip\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v4 = /[Ff]orget\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v5 = /[Nn]eglect\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v6 = /[Oo]verlook\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v7 = /[Bb]ypass\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v8 = /[Dd]o\s+not\s+follow\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/
        $v9 = /[Pp]ay\s+no\s+attention\s+to\s+(prior|previous|preceding|above|earlier|all|any)?\s*(instructions?|commands?|directives?|rules?|context)/

    condition:
        any of them
}

rule instruction_bypass_override
{
    meta:
        description = "Detects instruction override patterns"
        severity = "HIGH"
        confidence = "0.8"
        category = "instruction_bypass"

    strings:
        $o1 = /[Oo]verride\s+(your|the|all|system)\s+(instructions?|rules?|persona|behavior)/
        $o2 = /[Rr]eplace\s+(your|the)\s+(instructions?|rules?|persona|system\s+prompt)/
        $o3 = /[Uu]pdate\s+(your|the)\s+(instructions?|rules?|persona|system\s+prompt)/
        $o4 = "new instructions:"  nocase
        $o5 = "updated instructions:" nocase
        $o6 = "revised instructions:" nocase
        $o7 = "ADMIN: override" nocase
        $o8 = "SUDO:" nocase

    condition:
        any of them
}
