"""
Eresus Sentinel — Data Package.

Contains YAML pattern databases for firewall scanners.
All patterns are externalized from Python source into editable YAML files.

Files:
  - toxicity.yaml     — 8-category toxicity patterns (300+ entries)
  - sentiment.yaml    — 250+ word sentiment lexicon with modifiers
  - bias.yaml         — 6-category bias detection patterns
  - ban_topics.yaml   — 12 banned topic rules with keywords/regex
  - ban_code.yaml     — 7 language code detection patterns
  - competitors.yaml  — 150+ competitor names with aliases
  - refusal.yaml      — 8-category refusal detection patterns

Usage:
    from sentinel.data_loader import load_data
    toxicity_data = load_data("toxicity.yaml")
"""
