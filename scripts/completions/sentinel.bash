#!/usr/bin/env bash
# Eresus Sentinel — Bash completion script
# Source this file or place it in /etc/bash_completion.d/ or ~/.bash_completion.d/
#
# Usage:
#   source scripts/completions/sentinel.bash
#   # OR add to ~/.bashrc:
#   source /path/to/scripts/completions/sentinel.bash

_sentinel_completions() {
    local cur prev words cword
    _init_completion || return

    local -r subcommands="scan firewall fw artifact artifact-scan hf-artifact hf-scan hf-guard \
        hf-bulk-scan sast agent skill-scan mcp-validate mcp a2a supply-chain diff notebook nb \
        red-team redteam secrets-scan secrets evaluate eval aibom refs plugins shell repl watch \
        benchmark bench scanners ls reverse rev stats doctor config version policy dashboard \
        serve validate proxy playbook pb dep-scan deps fuzz"

    case "$cword" in
        1)
            COMPREPLY=($(compgen -W "$subcommands --help --version" -- "$cur"))
            return ;;
    esac

    case "$prev" in
        scan)
            COMPREPLY=($(compgen -W "--format --output --min-severity --fail-on --fast --stdin-files --ci --verbose --quiet" -- "$cur"))
            ;;
        artifact|artifact-scan)
            COMPREPLY=($(compgen -W "--format --output --min-severity --fail-on --show-skipped" -- "$cur"))
            [[ "$cur" != -* ]] && _filedir '@(pkl|pickle|pt|pth|bin|safetensors|gguf|onnx|h5|hdf5)' && return ;;
        hf-bulk-scan)
            COMPREPLY=($(compgen -W "--owner --task --tags --limit --min-downloads --mode --concurrency --output --resume" -- "$cur")) ;;
        red-team|redteam)
            COMPREPLY=($(compgen -W "--target --strategy --vertical --format --output --verbose" -- "$cur")) ;;
        --format|-f)
            COMPREPLY=($(compgen -W "table json sarif csv markdown html junit" -- "$cur")) ;;
        --min-severity)
            COMPREPLY=($(compgen -W "INFO LOW MEDIUM HIGH CRITICAL" -- "$cur")) ;;
        --fail-on)
            COMPREPLY=($(compgen -W "info low medium high critical" -- "$cur")) ;;
        --mode)
            COMPREPLY=($(compgen -W "guard full" -- "$cur")) ;;
        --vertical)
            COMPREPLY=($(compgen -W "finserv healthcare telecom ecommerce insurance realestate all" -- "$cur")) ;;
        --strategy)
            COMPREPLY=($(compgen -W "meta_agent autodan adaptive gcg hydra crescendo pair tap iterative composite" -- "$cur")) ;;
        --output|-o)
            _filedir ;;
    esac
}

complete -F _sentinel_completions sentinel
complete -F _sentinel_completions eresus-sentinel
