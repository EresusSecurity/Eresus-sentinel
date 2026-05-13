# SAST Multi-Language Analysis
Output demos/sast-multilang.gif
Set Shell zsh
Set FontSize 15
Set Width 1400
Set Height 1400
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 35ms

Type "setopt INTERACTIVE_COMMENTS"
Enter
Sleep 200ms

Type "export PYTHONPATH=$PWD/python"
Enter
Sleep 300ms

Type "echo '━━━ SAST — 10 Language Static Analysis ━━━'"
Enter
Sleep 500ms

Type "sentinel sast python/sentinel/ --min-severity high 2>&1 | tee /tmp/sast_out.txt"
Enter
Sleep 6s

Type "clear"
Enter
Sleep 300ms

Type "cat /tmp/sast_out.txt"
Enter
Sleep 4s
