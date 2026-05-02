# Community Notes

## Support Channels

- Public bugs and feature requests: GitHub Issues.
- False positives: use the false-positive issue template.
- Vulnerabilities: email `security@eresussec.com`; do not open a public issue.
- Roadmap discussions: use the `phase-roadmap` label.

## Turkish Forum Post

```text
Eresus Sentinel, AI/LLM uygulamaları için deterministic-first güvenlik aracıdır.
Model artifact tarama, prompt firewall, MCP/agent güvenliği, SAST, supply-chain
ve red-team/eval akışlarını tek CLI altında toplar.

Başlangıç:
  pip install -e ".[dev]"
  sentinel doctor
  sentinel scan ./project --profile fast -f json

False positive bildirmek için rule_id, komut ve sanitize edilmiş evidence ile
GitHub false-positive template'ini kullanın. Güvenlik açıklarını public issue
olarak açmayın; security@eresussec.com adresine gönderin.
```
