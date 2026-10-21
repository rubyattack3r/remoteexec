# Run from the repository root with `make demo`.
# Validates a command-only WMIExec plan and shows the shared result schema.
# This is a dry run; nothing is staged or executed on the target.
Output docs/assets/demo.gif

Require remoteexec
Require bash

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 22
Set Width 1800
Set Height 900
Set Padding 40
Set Margin 24
Set MarginFill "#10131c"
Set BorderRadius 20
Set WindowBarSize 72
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set Framerate 10
Set TypingSpeed 25ms
Set CursorBlink false

Hide
Type `unset PROMPT_COMMAND NO_COLOR; export TERM=xterm-256color; PS1='\[\033[38;5;209m\]❯\[\033[0m\] '; clear`
Enter
Sleep 500ms
Show

Type `remoteexec exec technique --targets server01 --technique WMIExec --payload-type command --command "whoami.exe /all" --auth token --dry-run --output yaml`
Enter
Sleep 5s
