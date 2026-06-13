# Kraken Fish completion

complete -c kraken -f

# Commands
complete -c kraken -n "__fish_use_subcommand" -a doctor -d "Run health check and diagnostics"
complete -c kraken -n "__fish_use_subcommand" -a status -d "Show session and configuration status"
complete -c kraken -n "__fish_use_subcommand" -a init -d "Initialize project configuration"
complete -c kraken -n "__fish_use_subcommand" -a version -d "Print version information"
complete -c kraken -n "__fish_use_subcommand" -a update -d "Check for updates"
complete -c kraken -n "__fish_use_subcommand" -a help -d "Print help information"
complete -c kraken -n "__fish_use_subcommand" -a sandbox -d "Show sandbox status"
complete -c kraken -n "__fish_use_subcommand" -a state -d "Show worker state"
complete -c kraken -n "__fish_use_subcommand" -a config -d "Show configuration"
complete -c kraken -n "__fish_use_subcommand" -a diff -d "Show workspace diff"
complete -c kraken -n "__fish_use_subcommand" -a export -d "Export session"
complete -c kraken -n "__fish_use_subcommand" -a acp -d "ACP status"
complete -c kraken -n "__fish_use_subcommand" -a prompt -d "Run a one-shot prompt"
complete -c kraken -n "__fish_use_subcommand" -a skills -d "List or invoke skills"
complete -c kraken -n "__fish_use_subcommand" -a plugins -d "Manage plugins"

# Options
complete -c kraken -l help -d "Print help"
complete -c kraken -l version -d "Print version"
complete -c kraken -l model -d "Model to use"
complete -c kraken -l provider -d "Provider to use" -xa "anthropic openai deepseek ollama dashscope openrouter"
complete -c kraken -l output-format -d "Output format" -xa "text json"
complete -c kraken -l resume -d "Resume session"
complete -c kraken -l compact -d "Compact mode"
complete -c kraken -l reasoning-effort -d "Reasoning effort" -xa "low medium high"
complete -c kraken -l allow-broad-cwd -d "Allow broad CWD"
