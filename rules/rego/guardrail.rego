package sentinel.guardrail

default allow_tool_call := true

allow_tool_call := false if {
    input.tool_name in data.sensitive_tools
    not input.user_approved
}

sensitive_tool_warning[msg] if {
    input.tool_name in data.sensitive_tools
    msg := sprintf("Sensitive tool '%s' requires approval", [input.tool_name])
}

rate_limit_exceeded if {
    input.calls_per_minute > data.rate_limit_rpm
}
