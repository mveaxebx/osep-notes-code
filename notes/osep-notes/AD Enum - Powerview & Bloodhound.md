F## AD Enum - Powerview & Bloodhound

### Powerview
#powerview #AD #enum

Loading powerview:
```powershell
a
```

Get current user:
```powershell
Get-NetDomain
```

Get Info about the current user domain and the forrest:
```powershell
Get-NetDomain
```

Get All domain from the forrest:
```powershell
Get-NetForestDomain
```

Get the info about DC:
```powershell
Get-NetDomainController
```

Get DACL for object - self: ^f54063
```powershell
Get-ObjectAcl -Identity offsec | more
```

Convert from SID:
```powershell
ConvertFrom-SID <SID>
```

^ea8e3b

Enum Servers with Unconstrained Delegation:
#powerview #ps1 #enum ^660271
``` powershell
Get-DomainComputer -Unconstrained
```


```powershell
a
```

```powershell
a
```

```powershell
a
```




