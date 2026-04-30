#compdef sentinel eresus-sentinel
# Eresus Sentinel — Zsh completion script
# Place in a directory on your $fpath, e.g.:
#   mkdir -p ~/.zsh/completions
#   cp scripts/completions/sentinel.zsh ~/.zsh/completions/_sentinel
#   echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
#   echo 'autoload -Uz compinit && compinit' >> ~/.zshrc

_sentinel() {
    local -a subcommands
    subcommands=(
        'scan:full project scan'
        'firewall:input/output firewall scan'
        'artifact:model artifact scanner'
        'artifact-scan:scan staged model files (pre-commit)'
        'hf-artifact:scan HuggingFace model artifacts'
        'hf-scan:scan remote HuggingFace repository'
        'hf-guard:pre-download HuggingFace risk assessment'
        'hf-bulk-scan:bulk scan HuggingFace Hub repositories'
        'sast:static analysis'
        'agent:agent/MCP validation'
        'skill-scan:audit SKILL.md files (pre-commit)'
        'mcp-validate:validate MCP manifests (pre-commit)'
        'mcp:MCP live and manifest scanning'
        'a2a:A2A agent-card scanning'
        'supply-chain:supply chain audit'
        'diff:git diff scan'
        'notebook:notebook security scan'
        'red-team:adversarial red team probes'
        'secrets-scan:enterprise secrets scanner'
        'evaluate:evaluate scanners/LLM targets'
        'aibom:generate AI bill of materials'
        'refs:inspect .refs inventory'
        'plugins:list discovered scanner plugins'
        'shell:interactive REPL'
        'watch:watch and auto-scan'
        'benchmark:performance benchmark'
        'scanners:list all scanners'
        'reverse:deep format reverse engineering'
        'stats:scan statistics'
        'doctor:system health check'
        'config:show config as JSON'
        'version:version info'
        'policy:policy management'
        'dashboard:web dashboard'
        'serve:start REST API server'
        'validate:validate YAML rules'
        'proxy:live MCP intercepting proxy'
        'playbook:attack playbook runner'
        'dep-scan:dependency vulnerability scanner'
        'fuzz:AI offensive security fuzzing'
    )

    local -a common_opts
    common_opts=(
        '(-h --help)'{-h,--help}'[show help]'
        '(-v --verbose)'{-v,--verbose}'[verbose output]'
        '(-q --quiet)'{-q,--quiet}'[quiet output]'
        '(-f --format)'{-f,--format}'[output format]:format:(table json sarif csv markdown html junit)'
        '(-o --output)'{-o,--output}'[output file]:file:_files'
        '--min-severity[minimum severity]:severity:(INFO LOW MEDIUM HIGH CRITICAL)'
    )

    local -a severity_vals
    severity_vals=(info low medium high critical)

    _arguments -C \
        '(- :)--version[show version]' \
        "${common_opts[@]}" \
        '1: :->subcommand' \
        '*: :->args'

    case $state in
        subcommand)
            _describe 'subcommand' subcommands ;;
        args)
            case ${words[2]} in
                scan)
                    _arguments \
                        ':path:_files -/' \
                        '--fail-on[fail threshold]:severity:('"${severity_vals[*]}"')' \
                        '--fast[skip slow modules]' \
                        '--stdin-files[read paths from stdin]' \
                        '--ci[CI mode]' ;;
                artifact|artifact-scan)
                    _arguments \
                        '*:model file:_files -g "*.pkl *.pt *.pth *.bin *.safetensors *.gguf *.onnx *.h5"' \
                        '--fail-on[fail threshold]:severity:('"${severity_vals[*]}"')' \
                        '--show-skipped[show skipped files]' ;;
                hf-bulk-scan)
                    _arguments \
                        '--owner[HF org/user]:owner:' \
                        '--task[pipeline task]:task:(text-generation text-classification token-classification question-answering summarization translation)' \
                        '--tags[model tags]:tags:' \
                        '--limit[max repos]:number:' \
                        '--min-downloads[min downloads]:number:' \
                        '--mode[scan mode]:mode:(guard full)' \
                        '--concurrency[parallel scans]:number:' \
                        '--output[output JSONL file]:file:_files' \
                        '--resume[skip already-scanned repos]' ;;
                red-team|redteam)
                    _arguments \
                        ':target:' \
                        '--strategy[attack strategy]:strategy:(meta_agent autodan adaptive gcg hydra crescendo pair tap)' \
                        '--vertical[industry vertical]:vertical:(finserv healthcare telecom ecommerce insurance realestate all)' ;;
                mcp)
                    _arguments \
                        '1: :(scan fingerprint)' \
                        '--manifest[manifest path]:file:_files' \
                        '--url[HTTP endpoint]:url:' \
                        '--stdio-command[stdio command]:' ;;
            esac ;;
    esac
}

_sentinel "$@"
