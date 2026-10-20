# Run from the repository root with `make demo`.
# Inventories the LOLBin contracts, then validates a command-only WMIExec plan.
# Every command is a dry run; nothing is sent to a target.
Output docs/assets/demo.gif

Require remoteexec
Require bash

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 20ms
Set CursorBlink false

Type "remoteexec exec binaries --output yaml"
Enter
Sleep 3s

Ctrl+L
Sleep 1s

Type `remoteexec exec technique --targets server01 --technique WMIExec --payload-type command --command "whoami.exe /all" --auth token --dry-run --output yaml`
Enter
Sleep 5s
