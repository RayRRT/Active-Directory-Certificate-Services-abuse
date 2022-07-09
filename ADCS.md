During the last week, I wanted to read more in depth about Active Directory Certification Services, so I started to work and read the awesome paper from Specter Ops, as well as other articles which I will refer to through this post.
You won't find anything new here, I simply wanted to understand how this technology works and to try the differents cases of abuse against it.
  
 
 <h3 align="center" id="heading">## Active Directory Certification Services</h3>

                                               
                                               
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


## Certificate Templates:
                                               
                                               
All Enterprise CA servers issue certificates based on one or more of the certificate templates. You cannot create a new template from scratch.
There is only one set of templates, and they are stored in Active Directory for the entire forest. Each Enterprise CA server in the forest uses the same set of templates, regardless of domain or subdomain membership. However, this doesn’t mean you have to enable the same set of templates on all Enterprise CA servers. Instead, you can enable different templates on each Enterprise CA server.

But, what is a certificate template?. **The certificates templates are just collections of enrollment policies and predefined certificate settings.**

In a template you can define things like:
* Validity/ Renewal period
* Who can request a certificate? For whom?
* What actions can be carried out with this certificate?
* How is the subject specified?
* …


![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/CertiTemplate1.png?raw=true)   ![ADCSXMind](https://github.com/RayRRT/ADCS/blob/main/CertiTemplate2.png?raw=true)                                            

Performing a correct configuration, not only on the own CA, also of the properties that define each template is not a easy task, so it is likely to encounter missconfigurations.

In the awesome whitepaper of specter ops, we not only find how to abuse these misconfigurations, but also how to steal the certificates, but in this post I wanted to go to the point and test in my environment each of the attacks to understand them a little better.


## ESC1: Misconfigured Certificate Templates Allows requesters to specify a SA
                                        
In order to be able to abuse this configuration, a series of requirements are needed, before listing them, it is important to define what the SAN is:
Subject  Alternative  Name  (SAN)  is  an  extension  to  X.509  that  allows various identities to be bound to a certificate beyond the subject;

By default during certificate-based authentication, certificates are mapped to Active Directory accounts based on a user principal name (UPN) specified in the SAN;
So, when a certificate template allows requester to specify a SAN, it is possible to request a certificate for another user;

It can be used for privileges escalation if the certificate template defines EKUs that enable domain authentication and can be enrolled by non- privileged user without manager approval.
The certificate template’s AD object specifies if the requester can specify the SAN in its mspki-certificate-name-flag property. The mspki-certificate-name-flag property is a bitmask and if the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag is present, a requester can specify the SAN:
                                        

