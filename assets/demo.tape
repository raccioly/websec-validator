# demo.tape — regenerates assets/demo.gif with charmbracelet/vhs.
#
# Render:
#   1. Install websec so `websec` is on PATH (e.g. `pipx install websec-validator`).
#   2. Clone the demo target:  git clone --depth 1 https://github.com/erev0s/VAmPI /tmp/VAmPI
#   3. From the repo root:      vhs assets/demo.tape
#
# Requires: vhs + its ttyd/ffmpeg deps (`brew install vhs`).
# VAmPI is a deliberately-vulnerable API from our proof-harness corpus, so
# scanning it is expected use. `websec run` is read-only recon (no --scan here).

Output assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 640
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Framerate 24
Set Padding 20

# Clean, minimal prompt — hidden from the recording.
Hide
Type "export PS1='$ '" Enter
Type "clear" Enter
Show

# 1) Point it at a repo — deterministic recon maps the whole attack surface in ~1s.
Type "websec run /tmp/VAmPI"
Enter
Sleep 4s

# 2) The product: the marching-orders briefing your AI agent executes.
Type "head -48 websec-out/latest/AGENT-BRIEFING.md"
Enter
Sleep 6s
