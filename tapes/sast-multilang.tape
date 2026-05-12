# SAST Multi-Language Analysis
Output demos/sast-multilang.gif
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

Type "# SAST — 10 Language Static Analysis + Interprocedural Taint"
Enter
Sleep 800ms

Type "sentinel sast python/sentinel/ --min-severity high"
Enter
Sleep 5s

Type ""
Sleep 2s
