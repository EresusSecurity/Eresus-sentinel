package sentinel.firewall

default allow_input := true
default allow_output := true

allow_input := false if {
    some rule in input.firewall_rules
    rule.direction == "input"
    rule.action == "block"
    regex.match(rule.pattern, input.content)
}

allow_output := false if {
    some rule in input.firewall_rules
    rule.direction == "output"
    rule.action == "block"
    regex.match(rule.pattern, input.content)
}

blocked_rules[rule] if {
    some rule in input.firewall_rules
    rule.action == "block"
    regex.match(rule.pattern, input.content)
}
