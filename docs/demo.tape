# Run from an authorized Windows operator host with `make demo` after placing
# `remoteexec.exe` on PATH and configuring token access to `wks01`.
# Dispatches a benign command through WMIExec and presents the returned evidence.
Output docs/assets/demo.gif

Require remoteexec.exe
Require powershell

Set Shell "powershell"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 26
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
Type `$env:Path += ";C:\Windows\Temp"; Set-Location C:\; function prompt { "PS C:\> " }; Clear-Host`
Enter
Sleep 500ms
Show

Type "# Live WMI process dispatch using the current Windows token"
Enter
Type "$result = remoteexec.exe exec technique --targets wks01 `"
Enter
Type "  --technique WMIExec --payload-type command `"
Enter
Type "  --command 'cmd.exe /c whoami.exe' --auth token --output json | ConvertFrom-Json"
Enter
Sleep 8s

Type `$result | Select-Object schema_version, technique, target, status | Format-List`
Enter
Sleep 4s
Type `$result.execution.evidence[0] | Select-Object kind, source, outcome, program, process_id, process_id_status | Format-List`
Enter
Sleep 5s

Hide
Type `Remove-Item "$env:TEMP\remoteexec-demo.json" -ErrorAction SilentlyContinue`
Enter
