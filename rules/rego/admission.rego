package sentinel.admission

default allow := false

allow if {
    not any_critical_finding
    not any_blocked_action
}

any_critical_finding if {
    some finding in input.findings
    finding.severity == "CRITICAL"
}

any_blocked_action if {
    some action in input.actions
    action.risk == "blocked"
}

deny[msg] if {
    some finding in input.findings
    finding.severity == "CRITICAL"
    msg := sprintf("CRITICAL finding: %s (%s)", [finding.message, finding.rule_id])
}

warn[msg] if {
    some finding in input.findings
    finding.severity == "HIGH"
    msg := sprintf("HIGH finding: %s (%s)", [finding.message, finding.rule_id])
}
