# Run from an authorized Windows operator host with `make demo` after placing
# `remoteexec.exe` on PATH and configuring token access to `wks01`.
# Dispatches a benign command through WMIExec and shows the returned evidence.
Output docs/assets/windows-wmiexec-demo.gif

Require remoteexec.exe
Require powershell

Set Shell "powershell"
Set FontFamily "DejaVu Sans Mono"
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
Type `Set-Location C:\; Clear-Host`
Enter
Sleep 500ms
Show

Type `remoteexec.exe exec technique --targets wks01 --technique WMIExec --payload-type command --command "cmd.exe /c whoami.exe" --auth token --output yaml`
Enter
Sleep 5s
