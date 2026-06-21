# ftagent terminal demo
Output ftagent-demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 880
Set Height 480
Set Theme "Catppuccin Mocha"
Set Padding 16
Set TypingSpeed 50ms
Set CursorBlink false

# Set up fake ftagent and clean prompt
Hide

Type@0 `export PS1='root@server:~# '`
Enter
Sleep 50ms

Type@0 `alias ftagent='bash .demo-ftagent.sh'`
Enter
Sleep 50ms

Type@0 `alias sudo=''`
Enter
Sleep 50ms

Type@0 `clear`
Enter
Sleep 300ms

Show

# ===== VISIBLE RECORDING =====

Sleep 600ms

# Scene 1: Version check
Type "ftagent --version"
Sleep 300ms
Enter
Sleep 1.5s

# Scene 2: Setup wizard
Type "sudo ftagent --setup"
Sleep 300ms
Enter
Sleep 1.2s

Type "ftk_a1b2c3d4e5f6..."
Sleep 200ms
Enter
Sleep 600ms

Type "nd-8f3a12b7-c4d5-4e6f..."
Sleep 200ms
Enter
Sleep 600ms

# Accept default interface
Enter
Sleep 1.8s

# Scene 3: Agent running
Type "sudo ftagent"
Sleep 300ms
Enter

# Wait for the fake script output
Sleep 12s

# Hold final frame
Sleep 3s
