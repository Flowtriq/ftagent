# ftagent terminal demo
Output ftagent-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 960
Set Height 550
Set Theme "Catppuccin Mocha"
Set Padding 16
Set TypingSpeed 45ms
Set CursorBlink false

# Set up fake ftagent and clean prompt
Hide

Type@0 `export PS1='\[\e[1;32m\]root@nyc-edge-01\[\e[0m\]:\[\e[1;34m\]~\[\e[0m\]# '`
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

Sleep 500ms

# Scene 1: Install
Type "pip install ftagent[full]"
Sleep 200ms
Enter
Sleep 400ms

Hide
Type@0 `echo "Successfully installed ftagent-1.9.27 scapy-2.6.1 psutil-6.1.1 requests-2.32.3 rich-13.9.4 colorama-0.4.6"`
Enter
Sleep 100ms
Show

Sleep 1.5s

# Scene 2: Test connectivity
Type "sudo ftagent --test"
Sleep 200ms
Enter
Sleep 3s

# Scene 3: Start agent - the main show
Type "sudo ftagent"
Sleep 200ms
Enter

# Wait for the full script output
Sleep 25s

# Hold final frame
Sleep 3s
