rule SentinelPickleUnsafeOpcode
{
    strings:
        $global = "GLOBAL"
        $reduce = "REDUCE"
        $build = "BUILD"
        $system = "os.system"
        $subprocess = "subprocess"
    condition:
        any of them
}

rule SentinelAgentSecretReach
{
    strings:
        $env = ".env"
        $aws = "AWS_SECRET_ACCESS_KEY"
        $token = "BEGIN PRIVATE KEY"
        $github = "ghp_"
    condition:
        any of them
}
