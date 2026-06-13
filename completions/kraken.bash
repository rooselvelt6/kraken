# Kraken Bash completion

_kraken_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="doctor status init version update help sandbox state config diff export acp prompt skills plugins agents mcp system-prompt dump-manifests bootstrap-plan"

    local opts="--help --version --model --provider --output-format --resume --compact --reasoning-effort --allow-broad-cwd"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands $opts" -- "$cur"))
    elif [[ $cword -eq 2 ]]; then
        case "$prev" in
            --provider)
                COMPREPLY=($(compgen -W "anthropic openai deepseek ollama dashscope openrouter" -- "$cur"))
                ;;
            --output-format)
                COMPREPLY=($(compgen -W "text json" -- "$cur"))
                ;;
            --reasoning-effort)
                COMPREPLY=($(compgen -W "low medium high" -- "$cur"))
                ;;
            *)
                COMPREPLY=($(compgen -W "$opts" -- "$cur"))
                ;;
        esac
    fi
}

complete -F _kraken_completions kraken
