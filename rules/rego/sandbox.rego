package sentinel.sandbox

default allow_exec := false

allow_exec if {
    input.sandbox_enabled
    input.command_risk != "blocked"
    input.command_risk != "dangerous"
}

allow_exec if {
    input.command_risk == "safe"
}

deny_exec[msg] if {
    input.command_risk == "blocked"
    msg := sprintf("Blocked command: %s", [input.command])
}

deny_exec[msg] if {
    input.command_risk == "dangerous"
    not input.user_approved
    msg := sprintf("Dangerous command requires approval: %s", [input.command])
}
