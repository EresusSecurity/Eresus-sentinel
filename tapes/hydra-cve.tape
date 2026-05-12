# Hydra _target_ CVE-2025-23304 Detection
Output demos/hydra-cve.gif
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

Type "# CVE-2025-23304 — Hydra _target_ RCE Detection"
Enter
Sleep 800ms

Type "cat /tmp/gif_fixtures/hydra_config.yaml"
Enter
Sleep 2s

Type "sentinel artifact /tmp/gif_fixtures/hydra_config.yaml"
Enter
Sleep 4s

Type ""
Sleep 1s

Type "# _target_: os.system → CRITICAL (ARTIFACT-044)"
Enter
Sleep 1s

Type "# _target_: subprocess.Popen → CRITICAL (ARTIFACT-044)"
Enter
Sleep 2s
