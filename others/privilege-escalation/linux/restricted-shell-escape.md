# Restricted Shell Escape

A restricted shell is a type of shell that limits the user's ability to execute commands. In a restricted shell, the user is only allowed to execute a specific set of commands or only allowed to execute commands in specific directories

**Command injection**

Imagine that we are in a restricted shell that allows us to execute commands by passing them as arguments to the `ls` command. Unfortunately, the shell only allows us to execute the `ls` command with a specific set of arguments, such as `ls -l` or `ls -a`, but it does not allow us to execute any other commands. In this situation, we can use command injection to escape from the shell by injecting additional commands into the argument of the `ls` command.

```shellscript
ls -l `pwd` 
```

**Command Substitution**

Another method for escaping from a restricted shell is to use command substitution. This involves using the shell's command substitution syntax to execute a command. For example, imagine the shell allows users to execute commands by enclosing them in backticks (\`). In that case, it may be possible to escape from the shell by executing a command in a backtick substitution that is not restricted by the shell.

**Command Chaining**

In some cases, it may be possible to escape from a restricted shell by using command chaining. We would need to use multiple commands in a single command line, separated by a shell metacharacter, such as a semicolon (;) or a vertical bar (|), to execute a command. For example, if the shell allows users to execute commands separated by semicolons, it may be possible to escape from the shell by using a semicolon to separate two commands, one of which is not restricted by the shell.

**Environment Variables**

For escaping from a restricted shell to use environment variables involves modifying or creating environment variables that the shell uses to execute commands that are not restricted by the shell. For example, if the shell uses an environment variable to specify the directory in which commands are executed, it may be possible to escape from the shell by modifying the value of the environment variable to specify a different directory.

**Shell Functions**

In some cases, it may be possible to escape from a restricted shell by using shell functions. For this we can define and call shell functions that execute commands not restricted by the shell. Let us say, the shell allows users to define and call shell functions, it may be possible to escape from the shell by defining a shell function that executes a command.

**Rbash**

```shellscript
# Restriction escape (might have to Ctrl + C for it to work)
ssh <USER>@<IP> -t "bash --noprofile"

# List files in directory
echo *

# Read a file with echo
echo "$(<a.txt )"
```

Cheat sheet

{% embed url="https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf" %}

{% embed url="https://0xffsec.com/handbook/shells/restricted-shells/" %}
