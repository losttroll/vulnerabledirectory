# vulnerabledirectory

## Standalone

The script **Deploy-Standalone.ps1** will prepare a Windows 10 client for simple testing.  It add some users, perform some configuration changes, and installed some applications to speed up testing.

### Adds Users
 - lowpriv (Standard User)
 - highpriv (Administrative User)
 - default password - vunwin1!
 
### Configuration Changes
- Whitelists a handful of folders for Windows Defender
- Enables RDP
- Sets Account Lockout Threshold
- Sets Account Lockout Duration
- Sets hostname
- Set Warning Banner

### Downloads
- PSTools
- Notepad++
- Beartail
- Regshot
- Nmap
- Wireshark
- Python 3
- Splunk
- Bitnami WAMP

### Installs
- Sysmon
- Splunk Enterprise (Trial Edition)
- Bitnami Wampstack (vulnerable webshell - http://127.0.0.1/shell.php)
