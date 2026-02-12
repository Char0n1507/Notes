# User Enumeration

When performing user enumeration with kerbrute, it automatically retrieves AS-REP. It gives `$krb5asrep$18$` instead of `$krb5asrep$23$`, so we need to use GetNPUsers from impacket to AS-REP Roast the user [https://charlti.gitbook.io/pentest-notes/active-directory/kerberos/as-rep-roasting](https://charlti.gitbook.io/pentest-notes/active-directory/kerberos/as-rep-roasting "mention")

```shellscript
# Brute force users through kerberos
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USER_LIST>
```
