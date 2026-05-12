# Pickle Opcode Chain Analysis (PICKLE-SEQ-003..008)
Output demos/pickle-chain.gif
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

Type "# Pickle Gadget Chain Detection — PICKLE-SEQ-003..008"
Enter
Sleep 800ms

Type "sentinel artifact /tmp/gif_fixtures/gadget_chain.pkl"
Enter
Sleep 3s

Type ""
Sleep 1s

Type "# Chained REDUCE→GLOBAL→REDUCE = gadget chain (CRITICAL)"
Enter
Sleep 1s

Type "# STRING→GLOBAL→REDUCE = code injection (CRITICAL)"
Enter
Sleep 1s

Type "sentinel artifact /tmp/gif_fixtures/newobj_mutation.pkl"
Enter
Sleep 3s

Type ""
Sleep 1s

Type "# NEWOBJ→SETITEMS = attribute injection (HIGH)"
Enter
Sleep 2s
