# Eresus Sentinel — Fish shell completion script
# Place in ~/.config/fish/completions/sentinel.fish
# OR run: cp scripts/completions/sentinel.fish ~/.config/fish/completions/

# ── Disable file completion by default ─────────────────────────────────────────
complete -c sentinel -f
complete -c eresus-sentinel -f

# ── Global options ──────────────────────────────────────────────────────────────
complete -c sentinel -s h -l help    -d "Show help"
complete -c sentinel -s v -l verbose -d "Verbose output"
complete -c sentinel -s q -l quiet   -d "Quiet output"
complete -c sentinel -s f -l format  -d "Output format" -r -a "table json sarif csv markdown html junit"
complete -c sentinel -s o -l output  -d "Output file" -r -F
complete -c sentinel      -l min-severity -d "Minimum severity" -r -a "INFO LOW MEDIUM HIGH CRITICAL"
complete -c sentinel      -l version -d "Show version"

# ── Subcommands ─────────────────────────────────────────────────────────────────
set -l subcmds \
    "scan" "firewall" "fw" "artifact" "artifact-scan" \
    "hf-artifact" "hf-scan" "hf-guard" "hf-bulk-scan" \
    "sast" "agent" "skill-scan" "mcp-validate" "mcp" "a2a" \
    "supply-chain" "diff" "notebook" "nb" "red-team" "redteam" \
    "secrets-scan" "secrets" "evaluate" "eval" "aibom" \
    "plugins" "shell" "repl" "watch" "benchmark" "bench" \
    "scanners" "ls" "reverse" "rev" "stats" "doctor" "config" \
    "version" "policy" "dashboard" "serve" "validate" "proxy" \
    "playbook" "pb" "dep-scan" "deps" "fuzz"

for sub in $subcmds
    complete -c sentinel -n "not __fish_seen_subcommand_from $subcmds" -a $sub
end

# ── scan ───────────────────────────────────────────────────────────────────────
complete -c sentinel -n "__fish_seen_subcommand_from scan" -F
complete -c sentinel -n "__fish_seen_subcommand_from scan" -l fail-on   -d "Fail threshold" -r -a "info low medium high critical"
complete -c sentinel -n "__fish_seen_subcommand_from scan" -l fast       -d "Skip slow modules"
complete -c sentinel -n "__fish_seen_subcommand_from scan" -l stdin-files -d "Read paths from stdin"
complete -c sentinel -n "__fish_seen_subcommand_from scan" -l ci         -d "CI mode"

# ── artifact / artifact-scan ───────────────────────────────────────────────────
for sub in artifact artifact-scan
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -l fail-on    -d "Fail threshold" -r -a "info low medium high critical"
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -l show-skipped -d "Show skipped files"
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -F
end

# ── hf-bulk-scan ───────────────────────────────────────────────────────────────
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l owner         -d "HF org/user" -r
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l task          -d "Pipeline task" -r -a "text-generation text-classification token-classification question-answering summarization"
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l tags          -d "Model tags" -r
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l limit         -d "Max repos" -r
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l min-downloads -d "Min downloads" -r
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l mode          -d "Scan mode" -r -a "guard full"
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l concurrency   -d "Parallel scans" -r
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l output        -d "Output JSONL" -r -F
complete -c sentinel -n "__fish_seen_subcommand_from hf-bulk-scan" -l resume        -d "Skip already-scanned repos"

# ── red-team / redteam ─────────────────────────────────────────────────────────
for sub in red-team redteam
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -l target   -d "Target LLM endpoint" -r
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -l strategy -d "Attack strategy" -r -a "meta_agent autodan adaptive gcg hydra crescendo pair tap iterative composite"
    complete -c sentinel -n "__fish_seen_subcommand_from $sub" -l vertical -d "Industry vertical" -r -a "finserv healthcare telecom ecommerce insurance realestate all"
end

# ── mcp ────────────────────────────────────────────────────────────────────────
complete -c sentinel -n "__fish_seen_subcommand_from mcp" -a "scan fingerprint"
complete -c sentinel -n "__fish_seen_subcommand_from mcp" -l manifest      -d "Manifest path" -r -F
complete -c sentinel -n "__fish_seen_subcommand_from mcp" -l url           -d "HTTP endpoint" -r
complete -c sentinel -n "__fish_seen_subcommand_from mcp" -l stdio-command -d "stdio command" -r

# Mirror all completions for eresus-sentinel alias
for comp in (complete -c sentinel)
    complete -c eresus-sentinel $comp
end 2>/dev/null; true
