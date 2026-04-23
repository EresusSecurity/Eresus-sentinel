"""Per-service secrets detection plugins."""
from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class SecretMatch:
    service: str
    key_type: str
    value: str
    start: int
    end: int
    severity: str = "HIGH"

class BaseSecretsPlugin:
    service: str = ""
    patterns: list[tuple[str, str, str]] = []  # (key_type, regex, severity)

    def scan(self, text: str) -> list[SecretMatch]:
        matches = []
        for key_type, pattern, severity in self.patterns:
            for m in re.finditer(pattern, text):
                matches.append(SecretMatch(self.service, key_type, m.group()[:20]+"...", m.start(), m.end(), severity))
        return matches

class AWSPlugin(BaseSecretsPlugin):
    service = "AWS"
    patterns = [
        ("access_key", r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", "CRITICAL"),
        ("secret_key", r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "CRITICAL"),
        ("session_token", r"(?i)aws_session_token\s*[=:]\s*[A-Za-z0-9/+=]{100,}", "CRITICAL"),
        ("account_id", r"(?i)aws_account_id\s*[=:]\s*\d{12}", "LOW"),
    ]

class OpenAIPlugin(BaseSecretsPlugin):
    service = "OpenAI"
    patterns = [("api_key", r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "CRITICAL"), ("api_key_v2", r"sk-proj-[A-Za-z0-9_-]{40,}", "CRITICAL")]

class AnthropicPlugin(BaseSecretsPlugin):
    service = "Anthropic"
    patterns = [("api_key", r"sk-ant-[A-Za-z0-9_-]{40,}", "CRITICAL")]

class GitHubPlugin(BaseSecretsPlugin):
    service = "GitHub"
    patterns = [
        ("pat", r"ghp_[A-Za-z0-9]{36}", "CRITICAL"), ("oauth", r"gho_[A-Za-z0-9]{36}", "CRITICAL"),
        ("app_token", r"(?:ghu|ghs)_[A-Za-z0-9]{36}", "CRITICAL"), ("fine_grained", r"github_pat_[A-Za-z0-9_]{82}", "CRITICAL"),
    ]

class SlackPlugin(BaseSecretsPlugin):
    service = "Slack"
    patterns = [
        ("bot_token", r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "CRITICAL"),
        ("user_token", r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}", "CRITICAL"),
        ("webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "HIGH"),
    ]

class StripePlugin(BaseSecretsPlugin):
    service = "Stripe"
    patterns = [
        ("secret_key", r"sk_live_[A-Za-z0-9]{24,}", "CRITICAL"), ("publishable", r"pk_live_[A-Za-z0-9]{24,}", "MEDIUM"),
        ("restricted", r"rk_live_[A-Za-z0-9]{24,}", "CRITICAL"),
    ]

class GCPPlugin(BaseSecretsPlugin):
    service = "GCP"
    patterns = [
        ("api_key", r"AIza[0-9A-Za-z_-]{35}", "CRITICAL"),
        ("service_account", r'"type"\s*:\s*"service_account"', "HIGH"),
        ("oauth_secret", r"(?i)client_secret\s*[=:]\s*[A-Za-z0-9_-]{24,}", "HIGH"),
    ]

class AzurePlugin(BaseSecretsPlugin):
    service = "Azure"
    patterns = [
        ("connection_string", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "CRITICAL"),
        ("sas_token", r"(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=[a-z]+&sig=[A-Za-z0-9%+/=]+", "HIGH"),
        ("tenant_id", r"(?i)(?:tenant[_-]?id|AZURE_TENANT_ID)\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "MEDIUM"),
    ]

class DatabasePlugin(BaseSecretsPlugin):
    service = "Database"
    patterns = [
        ("postgres", r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+", "CRITICAL"),
        ("mysql", r"mysql://[^:]+:[^@]+@[^/]+/\w+", "CRITICAL"),
        ("mongodb", r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+", "CRITICAL"),
        ("redis", r"redis://:[^@]+@[^:/]+:\d+", "HIGH"),
    ]

class CloudProvidersPlugin(BaseSecretsPlugin):
    service = "Cloud"
    patterns = [
        ("digitalocean", r"dop_v1_[a-f0-9]{64}", "CRITICAL"),
        ("heroku", r"(?i)heroku.*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "HIGH"),
        ("vercel", r"(?i)vercel_token\s*[=:]\s*[A-Za-z0-9]{24,}", "HIGH"),
        ("netlify", r"(?i)netlify[_-]?(?:auth[_-]?)?token\s*[=:]\s*[A-Za-z0-9_-]{40,}", "HIGH"),
    ]

class CICDPlugin(BaseSecretsPlugin):
    service = "CI/CD"
    patterns = [
        ("circleci", r"(?i)circle[_-]?(?:ci[_-]?)?token\s*[=:]\s*[a-f0-9]{40}", "HIGH"),
        ("gitlab_token", r"glpat-[A-Za-z0-9_-]{20}", "CRITICAL"),
        ("jenkins", r"(?i)jenkins[_-]?(?:api[_-]?)?token\s*[=:]\s*[A-Za-z0-9]{30,}", "HIGH"),
    ]

class MessagingPlugin(BaseSecretsPlugin):
    service = "Messaging"
    patterns = [
        ("twilio_sid", r"AC[a-f0-9]{32}", "HIGH"), ("twilio_token", r"(?i)twilio.*auth.*token\s*[=:]\s*[a-f0-9]{32}", "CRITICAL"),
        ("sendgrid", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "CRITICAL"),
        ("discord_token", r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", "CRITICAL"),
        ("discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", "HIGH"),
    ]

class CryptoPlugin(BaseSecretsPlugin):
    service = "Crypto"
    patterns = [
        ("rsa_private", r"-----BEGIN RSA PRIVATE KEY-----", "CRITICAL"),
        ("ec_private", r"-----BEGIN EC PRIVATE KEY-----", "CRITICAL"),
        ("openssh_private", r"-----BEGIN OPENSSH PRIVATE KEY-----", "CRITICAL"),
        ("pgp_private", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL"),
        ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "HIGH"),
    ]

ALL_PLUGINS = [AWSPlugin(), OpenAIPlugin(), AnthropicPlugin(), GitHubPlugin(), SlackPlugin(), StripePlugin(), GCPPlugin(), AzurePlugin(), DatabasePlugin(), CloudProvidersPlugin(), CICDPlugin(), MessagingPlugin(), CryptoPlugin()]

def scan_all(text: str) -> list[SecretMatch]:
    matches = []
    for plugin in ALL_PLUGINS:
        matches.extend(plugin.scan(text))
    return matches
