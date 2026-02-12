# IIS

### IIS tilde enumeration

IIS tilde directory enumeration is a technique utilised to uncover hidden files, directories, and short file names (aka the 8.3 format) on some versions of Microsoft Internet Information Services (IIS) web servers. This method takes advantage of a specific vulnerability in IIS, resulting from how it manages short file names within its directories.

```shellscript
# Install a scanner => also need to install Oracle Java
https://github.com/irsdl/IIS-ShortName-Scanner

# Launch the scanner => answer no when prompted for proxy
java -jar iis_shortname_scanner.jar 0 5 <URL>

# The scanner will give us short file names => try to access them 

# If we can't access them, we need to find their full name
# Generate a wordlist for just that file and brute force 
egrep -r ^<SCANNER_OUTPUT_FILE_NAME> /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
gobuster dir -u <URL> -w /tmp/list.txt -x .<EXT>,.<EXT>
```
