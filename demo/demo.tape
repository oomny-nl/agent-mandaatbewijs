# Demo-opname met VHS (https://github.com/charmbracelet/vhs). Maak opnieuw met: make opname
# De keten draait al (make opname start hem eerst met make up); de opname toont make speel.
Output demo/demo.mp4
Require docker
Require make
Set Shell "bash"
Set FontSize 14
Set FontFamily "Menlo"
Set Width 1340
Set Height 900
Set Padding 24
Set TypingSpeed 45ms
Set Theme { "name": "Lindevoort", "background": "#FFFFFF", "foreground": "#1F2933", "cursor": "#0F4C5C", "selection": "#D7E7EA", "black": "#1F2933", "red": "#B3261E", "green": "#2E7D32", "yellow": "#8A6D00", "blue": "#0F4C5C", "magenta": "#6B3FA0", "cyan": "#0F4C5C", "white": "#5F6B73", "brightBlack": "#5F6B73", "brightRed": "#B3261E", "brightGreen": "#2E7D32", "brightYellow": "#8A6D00", "brightBlue": "#0F4C5C", "brightMagenta": "#6B3FA0", "brightCyan": "#0F4C5C", "brightWhite": "#1F2933" }
Hide
Type "export PS1='$ ' DEMO_TEMPO=0.3 DEMO_BREEDTE=138 && clear"
Enter
Sleep 1s
Show
Type "# Uitgever en inkomensregister draaien (make up). Speel de zes scenario's af:"
Enter
Sleep 1s
Type "make speel"
Sleep 600ms
Enter
Wait@180s /^\$\s*$/
Sleep 8s
