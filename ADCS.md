During the last week, I wanted to read more in depth about Active Directory Certification Services, so I started to work and read the awesome paper from Specter Ops, as well as other articles which I will refer to through this post.
You won't find anything new here, I simply wanted to understand how this technology works and to try the differents cases of abuse against it.                  
                                
                                
                                
                                
                                               Active Directory Certification Services
                                
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

![]([http://url/to/img.png](https://github.com/RayRRT/ADCS/blob/main/assets/1AD%20CS.png))




