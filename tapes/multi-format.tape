# Multi-Format Scan (39 formats)
Output demos/multi-format.gif
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

Type "echo '━━━ Eresus Sentinel — 39 Format Model Artifact Scan ━━━'"
Enter
Sleep 500ms

Type "ls /tmp/gif_fixtures/"
Enter
Sleep 1s

Type "sentinel artifact /tmp/gif_fixtures/ 2>&1 | tee /tmp/scan_all.txt"
Enter
Sleep 6s

Sleep 1s

Type "clear"
Enter
Sleep 300ms

Type "echo '━━━ Scan Results (scroll) ━━━'"
Enter
Sleep 300ms

Type "cat /tmp/scan_all.txt"
Enter
Sleep 4s
