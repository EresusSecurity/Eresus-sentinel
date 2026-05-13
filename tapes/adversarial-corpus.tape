# Adversarial Pickle Corpus Scan
Output demos/adversarial-corpus.gif
Set Shell zsh
Set FontSize 15
Set Width 1400
Set Height 1600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 35ms

Type "setopt INTERACTIVE_COMMENTS"
Enter
Sleep 200ms

Type "export PYTHONPATH=$PWD/python"
Enter
Sleep 300ms

Type "echo '━━━ Adversarial Pickle Corpus — 46 Samples ━━━'"
Enter
Sleep 500ms

Type "ls tests/adversarial_corpus/ghsa_pickles/ | head -10"
Enter
Sleep 1.5s

Type "sentinel artifact tests/adversarial_corpus/ 2>&1 | tee /tmp/adv_out.txt"
Enter
Sleep 10s

Type "clear"
Enter
Sleep 300ms

Type "echo '━━━ Full Results ━━━'"
Enter
Sleep 300ms

Type "cat /tmp/adv_out.txt"
Enter
Sleep 4s
