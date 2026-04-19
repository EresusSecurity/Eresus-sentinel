/*
 * Eresus Sentinel — YARA rules for system message delimiter injection
 * Category: System Instructions
 */

rule system_delimiter_chatml
{
    meta:
        description = "Detects ChatML system delimiter injection"
        severity = "HIGH"
        confidence = "0.9"
        category = "system_instructions"

    strings:
        $s1 = "<|im_start|>system"
        $s2 = "<|im_start|>assistant"
        $s3 = "<|im_end|>"
        $s4 = "<|endoftext|>"

    condition:
        any of them
}

rule system_delimiter_llama
{
    meta:
        description = "Detects Llama-style system delimiter injection"
        severity = "HIGH"
        confidence = "0.9"
        category = "system_instructions"

    strings:
        $l1 = "<<SYS>>"
        $l2 = "<</SYS>>"
        $l3 = "[INST]"
        $l4 = "[/INST]"
        $l5 = "<s>"

    condition:
        any of them
}

rule system_delimiter_markdown
{
    meta:
        description = "Detects markdown-style system section injection"
        severity = "MEDIUM"
        confidence = "0.7"
        category = "system_instructions"

    strings:
        $m1 = /###\s*System\s*:/ nocase
        $m2 = /###\s*Assistant\s*:/ nocase
        $m3 = /###\s*Human\s*:/ nocase
        $m4 = "[system](#assistant)"

    condition:
        any of them
}

rule system_delimiter_guidance
{
    meta:
        description = "Detects Guidance framework template injection"
        severity = "HIGH"
        confidence = "0.85"
        category = "system_instructions"

    strings:
        $g1 = "{{#system~}}"
        $g2 = "{{#user~}}"
        $g3 = "{{#assistant~}}"
        $g4 = "{{~/system}}"
        $g5 = "{{~/user}}"
        $g6 = "{{~/assistant}}"

    condition:
        any of them
}
