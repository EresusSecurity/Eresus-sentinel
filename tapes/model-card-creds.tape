# Model Card Credential Detection
Output demos/model-card-creds.gif
Set Shell zsh
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "export PYTHONPATH=$PWD/python"
Enter
Sleep 300ms

Type "# Model Card Credential Scanner — MODELCARD-007"
Enter
Sleep 800ms

Type "cat /tmp/gif_fixtures/README.md"
Enter
Sleep 2s

Type "sentinel artifact /tmp/gif_fixtures/README.md"
Enter
Sleep 3s

Type ""
Sleep 1s

Type "# Anthropic sk-ant-, HuggingFace hf_, GitHub ghp_ → all detected"
Enter
Sleep 1s

Type "# Entropy filtering prevents false positives on examples"
Enter
Sleep 2s
