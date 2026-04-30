package sentinel.skill_actions

default allow_action := true

allow_action := false if {
    input.action_type == "file_write"
    not path_allowed(input.target_path)
}

allow_action := false if {
    input.action_type == "network"
    not domain_allowed(input.destination)
}

allow_action := false if {
    input.action_type == "shell_exec"
    input.command_risk in {"blocked", "dangerous"}
}

path_allowed(path) if {
    some allowed in data.allowed_paths
    startswith(path, allowed)
}

domain_allowed(domain) if {
    some allowed in data.allowed_domains
    endswith(domain, allowed)
}

violation[msg] if {
    not allow_action
    msg := sprintf("Skill action denied: %s on %s", [input.action_type, input.target_path])
}
