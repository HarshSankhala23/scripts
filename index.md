![](https://www.volkis.com.au/assets/img/posts/ad-hacking.png)

# Active Directory Overview

## Table of contents
1. [What is Active Directory](#what-is-active-directory)
    - [Pysical Active Directory components](#physical-active-directory-components)
        - [Domain Controllers](#domain-controllers)
        - [AD DS Data Store](#ad-ds-data-store)
    - [Logical Active Directory components](#logical-active-directory-components)
        - [AD DS Schema](#ad-ds-schema)
        - [Domain](#domain)
        - [Trees](#trees)
        - [Forests](#forests)
        - [Organizational Units](#organizational-units)
        - [Trusts](#trusts)
        - [Objects](#objects)
    - [Summary](#summary)
2. [Logging and Monitoring](#logging-and-monitoring)
    - [Event Viewer](#event-viewer)
    - [Resource Monitor](#resource-monitor)
    - [Performance Monitor](#performance-monitor)
3. [Kerberos](#kerberos)
    - [Kerberos components](#kerberos-components)
        - [Transport layer](#transport-layer)
        - [Agents](#agents)
        - [Encryption Keys](#encryption-keys)
        - [Tickets](#tickets)
        - [Privilege Attribute Certificate](#privilege-attribute-certificate)
        - [Messages](#messages)
    - [Authentication Process](#autentication-process)
        - [KRB_AS_REQ](#krb_as_req)
        - [KRB_AS_REP](#krb_as_rep)
        - [KRB_TGS_REQ](#krb_tgs_req)
        - [KRB_TGS_REP](#krb_tgs_rep)
        - [KRB_AP_REQ](#krb_ap_req)
    - [Delegation](#delegation)
        - [Services, Users and Computers](#services\,-users-and-computers)
            - [Users](#users)
            - [Services](#services)
                - [Services delegation](#services-delegation)
            - [Mitigation Measures](#mitigation-measures)
        - [Unconstrained delegation](#unconstrained-delegation)
        - [Constrained delegation and RBCD](#constrained-delegation-and-rbcd)
            - [S4U2Proxy](#s4u2proxy)
            - [S4U2Self](#s4u2self)
4. [Building an AD Lab](#building-an-ad-lab)
    - [Setting up the Domain Controller](#setting-up-the-domain-controller)
    - [Setting up the user machines](#setting-up-the-user-machines)
    - [Setting up Users, Groups and Policies](#setting-up-users\,-groups-and-policies)
    - [Setting up shares](#setting-up-shares)
    - [Setting up Service Principal Names](#setting-up-service-principal-names)
    - [Setting up Group Policies](#setting-up-group-policies)
    - [Joining the clients to the Domain](#joining-the-clients-to-the-domain)
5. [Building an Enterprise AD Network](#building-an-enterprise-ad-network)
6. [Local Enumeration](#local-enumeration)
    - [Interesting Files in a Windows system](#interesting-files-in-a-windows-system)
    - [Windows version](#windows-version)
    - [Vulnerable Drivers](#vulnerable-drivers)
    - [Environment](#environment)
    - [User and Group permissions](#user-and-group-permissions)
    - [Clipboard](#clipboard)
    - [LAPS](#laps)
        - [Identifying whether LAPS is installed](#identifying-whether-laps-is-installed)
        - [LAPS GPOs](#laps-gpos)
        - [Finding computers with LAPS](#finding-computers-with-laps)
        - [Using PowerView](#using-powerview)
        - [LAPS Password Data](#laps-password-data)
        - [Backdooring View LAPS Password Data](#backdooring-view-laps-password-data)
        - [Identifying LAPS Computer Management](#identifying-laps-computer-management)
    - [Watch logging](#watch-logging)
        - [Audit settings](#audit-settings)
        - [Windows Event Forwarding](#windows-event-forwarding)
        - [Antivirus](#antivirus)
    - [Check privileges](#check-privileges)
    - [Network enumeration](#network-enumeration)
        - [Interfaces, routes, ports and dns cache](#interfaces\,-routes\,-ports-and-dns-cache)
        - [Firewall](#firewall)
        - [Shares](#shares)
        - [Wifi](#wifi)
        - [SNMP](#snmp)
    - [Software](#software)
    - [Run at startup](#run-at-startup)
    - [Running processes](#running-processes)
        - [Permissions of the processes binaries](#permissions-of-the-processes-binaries)
    - [Memory password mining](#memory-password-mining)
    - [Services](#services)
        - [Services list](#services-list)
        - [Services permissions](#services-permissions)
7. [AD Enumeration](#ad-enumeration)
    - [SPN Scanning](#spn-scanning)


## What is Active Directory
Active Directory (AD) manages Windows domain networks and stores everything as an object.
It usually uses Kerberos tickets for authentication. Non-Windows devices like Linux machines, firewalls and so forth can also authenticate to Active Directory via RADIUS or LDAP.

Active Directory is the most commonly used identity management service around the world since it's used by the 95% of top 1000 companies.

An Active Directory environment can be exploited without the use of patchable exploits but rather abusing its features such as trusts, components, and more.

The most known AD service is the Active Directory Domain Services, but there are others:
- Active Directory Rigths Management Services (AD RMS): helps with protecting information against unauthorized use of it. It establishes the users identity and provides the authorized users with licenses for the protected information.
- Active Directory Certificate Services (AD CS): used to create certification entities and related role services that allow to manage and issue certificates that are used in different applications.
- Active Directory Federation Services (AD FS): provides protected and simplified identity federation capabilities through a web Single Sign On (SSO). It allows the users in a Domain to login once and access related resources like Azure or 365.


### Physical Active Directory components
#### Domain controllers
A domain controller (DC) is a server with the Active Directory Domain Services (AD DS) server role installed and that has been specifically promoted to a domain controller.

- *A role is just a group of software programs that, once installed, allow the computer to play an specific function for the other users or computers in the network. I.e. FTP server, web server, DNS, DHCP, etc.*
- *Role services are software programs that provide functionality for a specific role. When installing a role, you can choose which services will be installed along. I.e. Resource manager, etc.*
- *Characteristics are programs that complement or increase the functionality of a role. I.e. load balancing, clustering, SNMP, etc.*

Domain Controller characteristics:
- Host a copy of the AD DS directory store (Objects: computers, users, etc)
- Provide authentication and authorization services (Kerberos)
- Replicate updates to other domain controllers in the domain and forest
- Allow administrative access to manage user accounts and network resources

A DC manages the Domain LDAP structure and holds a copy of the AD database (NTDS.dit). A DC can be primary or secondary as well as have copies in order to perform load balancing and have a high disponibility. A DC should never be exposed to the internet, however, a DC needs internet in order to get updates, install new roles and so on, so there must be always behind a well setup firewall.

Since Windows Server 2016, a DC can have interoperability between on premise infrastructure and cloud infrastructure like Azure or Office 365.

It is usually the top target for Red Teams and Pentesters since once it's compromised, virtually the whole enterprise network and its resources would be compromised.

##### Network configuration
A Domain controller must have a static IP so every computer can find it at all times. It usually acts as a DNS too, so the static IP would be the same address as the DNS.

#### AD DS Data Store
The AD DS Data Store (DS) contains the database files and processes that store and manage directory information for users, services and applications, it also contains password hashes.

AD DS Data Store characteristics:
- Consists of the NTDS.dit file
- Is stored by default in %SystemRoot%\\NTDS folder on all domain controllers
- Is accessible only through the domain controller processes and protocols


## Logical Active Directory components
### AD DS Schema
The AD DS is a directory hierarchical structure that stores information about networks and domains in a database. AD DS is designed for network distributed envritonments and can get online information. It uses protocols like LDAP, DNS, DCHP and others.
It also defines what type of objects will be stored enforcing security, authorization and authentication based on rules and permissions defined at the DC level.

<!-- active-directory-diagram -->

All that begins to an AD Domain it's stored as an object:

| Object Types | Function | Example |
|:--------------|:----------|:---------|
| Class Object | What objects can be created in the directory | <ul><li>User</li><li>Computer</li></ul> |
| Attribute Object | Information that can be attached to an object | <ul><li>Display name</li></ul> |

### Domain
Domains are used to group and manage objects in an organization.

Domains characteristics:
- An administrative boundary for applying policies to groups of objects
- A replication boundary for replicating data between domain controllers
- An authentication and authorization boundary that provides a way to limit the scope of access to resources

*Every configuration made through the GUI, can be done with PowerShell.*

### Trees
A domain tree is a hierarchy of domains in AD DS.

All domains in the tree characteristics:
- Share a contiguous namespace with the parent domain
- Can have additional child domains
- By default create a two-way transitive trust with other domains (in the tree)

### Forests
A forest is simply a collection of one or more domain trees.

Forests characteristics:
- Share a common schema
- Share a common configuration partition
- Share a common global catalog to enable searching
- Enable trusts between all domains within the forest
- Share the Enterprise Admins and Schema Admins groups

### Organizational Units
Organizational Units (OUs) are AD containers that can contain users, groups, computers and other OUs.

Organizational Units characteristics:
- Represent your organization hierarchically and logically
- Manage a collection of objects in a consistent way
- Delegate permissions to administer groups of objects
- Apply defined policies

### Trusts
Trusts provide a mechanism for users to gain access to resources in a different domain.

| Types of Trusts | Description |
|:--------------|:----------|
| Directional | <ul><li>The trust direction flows from trusting domain to the trusted domain</li></ul> |
| Transitive | <ul><li>The trust relationship is extended beyond a two-domain trust to include other trusted domains</li></ul> |

- All domains in a forest trust all other domains in the forest
- Trusts can extend outside the forest

### Objects

| Object | Description |
|:--------------|:----------|
| User | <ul><li>Enables network resource for an user</li></ul> |
| InetOrgPerson | <ul><li>Similar to an user account</li><li>Used for compatibility with other directory services</li></ul> |
| Contacts | <ul><li>Used primarily to assign e-mail addresses to external users</li><li>Does not enable network access</li></ul> |
| Groups | <ul><li>Used to simplify the administration of access control</li></ul> |
| Computers | <ul><li>Enables authentication and auditing of computer access to resources</li></ul> |
| Printers | <ul><li>Used to simplify the process of locating and connecting to printers</li></ul> |
| Shared folders | <ul><li>Enables users to search for shared folders based on properties</li></ul> |

#### Groups
A group is a set of user accounts and computers, contacts and other groups that can be managed as a one unit.
The computers and user accounts that belongs to a group are called group members.

The groups are directory objects that belong to a Domain and an Organizational Unit.
Groups can be used to:
- Simplify management of permissions (assign a permission to a group implies that every member will have this permission)
- Delegate administration by assigning user rights to a group
- Create email distribution lists

Groups can have three different scopes:
- Local domain: only permissions within a domain can be assigned to these groups. They can include global groups from any domain, universal groups from any domain, local domain groups within the same domain or a combination of them.
- Global domain: only permissions within the same forest can be assigned.
- Universal

There are also security groups and distribution groups:
- Security groups: permissions for shared resources
- Distribution groups: distribution lists for email

#### Organizational Units
They represent the enterprise structure, for example departments or bussiness areas.
Through OUs, we can manage different policies for different departments by using GPOs.

#### GPOs
Group Policy Objects. It's the simplest way to configure user options and computer in AD based networks.
GPOs complement the OUs implying that the structure must be really well designed in order to make the administration easier.
So, we can link a GPO to a OU that contains groups that, at the same time, contain users and computers.

### Summary
We have domains which are used to group and manage objects in an organization.
If there are multiple domains, then we have a tree, which have a parent domain and one or more child domains.
When we have multiple sets of trees, we have a forest.
Inside these domains, trees and forests, we have the organizational units which consist of objects.
Then across forests and domains, we have trusts, which can be directional or transitive.
Directional trust means that one domain trusts another.
Transitive trust means that one domain trusts another and then trusts everything else that the second domain also trusts.


## Logging and Monitoring
### Event Viewer
The event viewer is in charge of logging every error and warning that occur within the server.
The main section would be the Windows Registry, which have four sub-groups.
- Application: all the errors and warnings thrown by installed applications. It shows the user, the computer, date and time, id, level, etc.
- Security: all the security related events like sessions.
- Installation: all the events related to any installation, updates, applications, roles and so on.
- System: all the errors related to the OS core.

They can be automatically backed up by a script.

### Resource Monitor
It allows to monitor the network (including connections), RAM, HDD, CPU, performance and processes.

### Performance Monitor
It shows data in real time or from a registry file about the performance and stability of the system. It's mainly focused on metrics and it can draw graphs and reporting based on this mentioned metrics.


## Kerberos
Kerberos is an __authentication__ protocol, not __authorization__. It allows to identify each user who provides a secret password but it does not validate which resources or services the user can access.
Kerberos is used in AD to provide information about the privileges of each user, but it's up to each service to determine if the user has access to its resources.

The authentication with kerberos works as shown in the diagram:

<!-- kerberos-diagram -->

### Kerberos components
#### Transport Layer
Kerberos can use either TCP or UDP as transport protocol, which sends data in clear text so Kerberos would be held responsible for adding an encryption layer.
The ports used by Kerberos are UDP/88 and TCP/88.

#### Agents
1. Client or user who wants to access to the service.
2. Application Server (AP) which offers the service required by the user.
3. Key Distribution Center (KDC) which is the main service of Kerberos, responsible for issuing the tickets and it's installed on the Domain Controller (DC). It is supported by the Authentication Service (AS) which issues the TGTs (Ticket Granting Tickets).

#### Encryption Keys
1. KDC or krbtgt key which is derivate from krbtgt account NTLM hash.
2. User key which is derivate from NTLM hash.
3. Service key which is derivate from the NTLM hash of service owner, which can be an user or computer account.
4. Session key which is negotiated between the user and KDC.
5. Service session key to be used between user and service.

#### Tickets
Tickets are the main structure handled by Kerberos. The tickets are delivered to the users so they can perform actions in the Kerberos realm.
1. Ticket Granting Service (TGS) is the ticket which user can use to authenticate against a service. It is encrypted with the service key.
2. Ticket Granting Ticket (TGT) is the ticket presented to the KDC to request for TGS and it is encrypted with the KDC key.

#### Privilege Attribute Certificate
The Privilege Attribute Certificate (PAC) is an structure included in almost every ticket and contains the privileges of the user. It is signed with the KDC key.
The services can verify the PAC by communicating with the KDC, however this does not usually happen.
The PAC verification consists of checking only its signature, without inspecting if privileges inside are correct.
A client can avoid the inclusion of the PAC inside the ticket by specifying it in KERB-PA-PAC-REQUEST field on the ticket request.

#### Messages
The most interesting messages used by Kerberos are:
1. KRB_AS_REQ: used to request the TGT to KDC.
2. KRB_AS_REP: used to deliver the TGT by KDC.
3. KRB_TGS_REQ: used to request the TGS to KDC using the TGT.
4. KRB_TGS_REP: used to deliver the TGS by KDC.
5. KRB_AP_REQ: used to authenticate an user to a service using the TGS.
6. KRB_AP_REP: used by a service to identify itself against an user.
7. KRB_ERROR: message to communicate errors.

<!-- kerberos-messages-exchange -->

### Authentication Process
We will see the authentication process from an user without tickets to an authenticated user.

#### KRB_AS_REQ
First of all, the user must get a TGT from KDC. This can be accomplished by sending a KRB_AS_REQ.
The KRB_AS_REQ has:
1. Encrypted timestamp with the client key to authenticate the user and prevent replay attacks (only if pre-authentication is required: DONT_REQ_PREAUTH flag not set for the user account).
2. Username of the authenticated user.
3. The Service Principal Name (SPN) associated with krbtgt account.
4. A Nonce generated by the user. A nonce is an arbitrary number that can be used once in cryptography.

#### KRB_AS_REP
After receiving the request, the KDC verifies the user identity by decrypting the timestamp. If the message is correct, it responds with a KRB_AS_REP, which includes:
1. Username
2. TGT
    - Username
    - Session key
    - Expiration date
    - PAC
3. Encrypted data with user key
    - Session key
    - Expiration date
    - User nonce

After this process, the user already has the TGT which can be used to request TGSs in order to access the services.

#### KRB_TGS_REQ
In order to request a KRB_TGS_REQ message must be sent to KDC, including:
1. Encryption data with session key
    - Username
    - Timestamp
2. TGT
3. SPN of requested service
4. User nonce

#### KRB_TGS_REP
After receiving the KRB_TGS_REQ, the KDC responds with a KRB_TGS_REP including:
1. Username
2. TGS
    - Service session key
    - Username
    - Expiration date
    - PAC
3. Encrypted data with session key
    - Service session key
    - Expiration date
    - User nonce

#### KRB_AP_REQ
If everything has gone well, the user should have already a TGS to interact with the service so the user must send the KRB_AP_REQ to the application server. The KRB_AP_REQ includes:
1. TGS
2. Encrypted data
    - Username
    - Timestamp

After this process and if the user has the right privileges, the service can be accessed by the user. If the verification is active, the AP would verify the PAC against the KDC. If the mutual authentication is needed it will respond to the user with a KRB_AP_REP message.

### Delegation
There are different kinds of delegation in Kerberos protocol. Delegation allows a service to impersonate the client user to interact with a second service with the privileges and permissions of the client itself.

Delegation types:
1. Unconstrained delegation
2. Constrained delegation
3. Resource Based Constrained Delegation (RBCD)

#### Services, Users and Computers
##### Users
An user is an agent represented by an user account in an Active Directory environment. There can be found different types of user accounts in an AD domain:
- Regular user accounts:
    - physical people that perform daily tasks
    - specific tasks such as back up recovery

- Computer accounts: used by the machines beloging to the domain. Their names end with a dollar sign ($). From an AD point of view, computers are a subclass of users.

##### Services
A service has the following characteristics:
- is identified by a SPN (Service Principal Name) in Active Directory which indicates the service name and class, the owner and the host.
- is executed in a computer as a process but a user can get a TGS for it even if it's not running at that time. As it happens with any other process, an administrator for the host can access the service memory and therefore, the tickets handled by the service.
- is executed in the context of a domain user (the owner). Usually services run in the context of the host computer account, but not always.
- it can be used by many users in the domain and any domain user can get a TGS for any service in the domain.

In summary, a service is running in the context of a user account and therefore it has the privileges of that user account.

That being said, domain users can own services. The SPNs of the services owned by an user are stored in the attribute __ServicePrincipalName__ of that user account.
The permission ValidatedSPN is required to add a SPN to an user account except for the computer accounts, so usually a Domain Admin role is required to modify this value in any user account.

###### Service delegation
- The service can perform delegation only if its owner has permission to do it. Meaning that if an user has delegation capabilities, every service and process owned by this user will have delegation capabilities.
- When a services communicates to the KDC, it adopts the identity of its owner. Actually, KDC only sees the user, not the process. So any process belonging to an user can perform the same actions in kerberos as the user can.

##### Mitigation Measures
- Set the __NotDelegated__ (ADS_UF_NOT_DELEGATED) flag which is stored in the User-Account-Control attribute at user account level. It comes unset by default.
- Add the user to the group Protected Users. By default this group has no members. This group prevents:
    - NTLM authentication
    - DES or RC4 encryption in Kerberos pre-authentication
    - Be delegated with any kind of Kerberos delegation
    - Renew the Kerberos TGTs beyond the initial four-hour time to live

#### Unconstrained delegation
Unconstrained delegation allows a service to impersonate any user that was authenticated without limitations. The service acquires a valid TGT for the client user which is the same as becoming that user in Kerberos and therefore in the domain.

The client sends the TGT to the service. When the client user requests a TGS for a service which has Unconstrained delegation enabled, then the KDC includes a TGT inside the TGS within the encrypted part (encrypted with the service owner key).

KDC includes the TGT in case the __TrustedForDelegation__ (ADS_UF_TRUSTED_FOR_DELEGATION) flag is set for the service owner (user account). This flag is stored in the UAC (User account control) attribute of AD user accoutns.

To modify an user's TrustedForDelegation flag, the __SeEnableDelegationPrivilege__ is required.

<!-- unconstrained-delegation or unconstrained-delegation2 -->

#### Constrained delegation and RBCD
In constrained delegation and RBCD, delegation is restricted to whitelisted third-party services.
Kerberos by itself cannot create special tickets for delegation for specific group of services. This is why Microsoft came up with two Kerberos extensions that allow to implement this behaviour:
- Service for User to Proxy (S4U2Proxy)
- Service for User to Self (S4U2Self)

##### S4U2Proxy
S4U2Proxy is an extension that allows a service to use the TGS sent by the client user to request a new TGS from KDC for a third service in behalf of the client user.

Each user has a list of services that it can request a TGS for stored in the __msDS-AllowedToDelegateTo__ attribute of the user account. The __SeEnableDelegationPrivilege__ is required in the DC to modify this attribute. This list is used in Constrained delegation.

Each user has a list of other users which are allowed to request a TGS for any of its services stored in the __msDS-AllowedToActOnBehalfOfOtherIdentity__ attribute. The user itself can edit his own list of allowed users on demand. This list is used in RBCD.

So the KDC will check the following conditions for applying delegation:
- If the service client is protected against delegation S4U2Proxy fails
- If the requested service is in the __msDS-AllowedToDelegateTo__ list, KDC checks:
    - If the sent TGS is forwardable (the _forwardable_ flag is set), then the KDC returns a forwardable TGS for the requested service (Constrained delegation)
    - Otherwise, S4U2Proxy fails
- If the user requesting the TGS is listed in the __msDS-AllowedToActOnBehalfOfOtherIdentity__ list of the service owner account, the KDC returns a forwardable TGS (RBCD)
- Otherwise S4U2Proxy fails

*Note: in RBCD is not necessary for the sent TGS to be forwardable*

If Constrained delegation and RBCD can be applied for the same service, Constrained delegation has precedence, meaning that if the sent TGS is not forwardable, the S4U2Proxy will fail.
The TGS returned by S4U2Proxy is always forwardable.

<!-- constrained-delegation -->

<!-- RBCD-delegation -->

<!-- S4U2Proxy-delegation -->

It is possible to use the same TGS for any service from the same user just by changing the service name due to:
1. The service name is written in plain text in the ticket, which can be modified by anyone.
2. All the services from the same user share the same Kerberos key, so any service can decrypt correctly a TGS for another service from the same user.

This fact can be used to bypass the white list (msDS-AllowedToDelegateTo) of services used by Constrained delegation.

##### S4U2Self
S4U2Self aims to allow the use of Delegation to services that do not support Kerberos authentication so they cannot get a TGS from the client user.
In order to address this problem, S4U2Self allows a service to request the KDC for a TGS for itself on behalf of another (Protocol Transition).

The KDC will respond differently to a S4U2Self request based on some characteristics of the user account like the services of the account and the flag __TrustedToAuthForDelegation__.

The __TrustedToAuthForDelegation__ (ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) flag is stored in the User Account Control attribute of user accounts. The __SeEnableDelegationPrivilege__ is required to modify this flag.

To make use of S4U2Self, the KDC will follow:
1. If the user account has no services, the KDC will not return a TGS
2. If the target user for impersonation is not allowed to be delegated, the KDC will return a TGS without the forwardable flag set.
3. If the __TrustedToAuthForDelegation__ flag is set for the user, the KDC will return a TGS with the forwardable flag set.
4. If the __TrustedToAuthForDelegation__ flag is not set for the user, the KDC will return a TGS without the forwardable flag set.

<!-- S4U2Self-delegation -->


## Building an AD Lab
*Note: this instructions assume that you know how virtualize and set up an OS in VMWare, Virtualbox or another virtualization software*
The lab consists of a 2019 windows server and 2 windows 10 Enterprise version apart from the attacker machine which can be a Kali, a Parrot or anything you feel comfortable with.
Each virtualized system must have at least 2 GB RAM.

The windows ISOs can be downloaded from Microsoft Evaluation Center. You can take a snapshot once installed each Windows or just bear with the expired license warning.

### Setting up the Domain Controller
Once the Windows Server is installed, we go to View your PC name and click on Rename your PC.
Since it's a Domain Controller, we can call it in a descriptive way like NAME-DC, but it can be anything.
Then restart the Server.

Go to Server Manager, which should pop-up right after the login, and click on the Manage menu (upper right corner) and click on Add Roles and Features.
Next - Select Role-based or feature-based installation - Next - Select Active Directory Domain Services - Add Features and Next - Next - Next - Install.
An alert icon will appear next to the Manage menu and under a flag sign, click on that alert and click on Promote this server to Domain Controller.

Select Add a new forest - type a domain name (NAME.local) - Next
Type a password and confirm it - Next - Next - Next - Install (this will reboot the server).

Now in the login screen, there should appear a NAME\\Administrator since it is a DC now.

### Setting up the user machines
When installing, there will be a screen that asks you to login with the Microsoft account. Well, instead, click in the lower left cornet on the Domain join button.
Set a name for the domain user and a password, then confirm the password and set the security questions for the user account.

Once installed we go again to View your PC name and click on rename your PC, set a name and reboot.

The process is the same for every client in the domain.

### Setting up Users, Groups and Policies
Login to the Domain controller, open Server Manager if it does not pop up automatically and click on the Tools menu next to the Manage menu and select Active Directory Users and Computers.

Under the DOMAIN.local icon will appear all the deafult OUs, i.e. Builtin (built-in security accounts), Domain Controllers under this domain, Users and so on.

Right click on the Domain icon and select New - Organizational Unit and call it Groups.
Then drag all the users but Guest and Administrator to the newly created Groups folder.

Right click inside the Users folder and select New - User. Fill up the required data. And next - finish.
To create another domain admin, right click on the Administrator account and select copy. Fill up the required data. This works for copying normal users too.

### Setting up shares
On the left side of the Server Manager, click on File and Storage Services and then click on Shares. Under the Tasks menu, select New Share..., click on SMB Share Quick, name it and click on Next until Create button appears.

### Setting up Service Principal Names
We will be using this feature for kerberoasting users.

Open a command prompt and type:

```bat
setspn -a COMPUTERNAME-DC/SQLService.DOMAIN.local:60111 DOMAIN\\SQLService
```
And press enter.
Type:

```bat
setspn -T DOMAIN.local -Q \*/\*
```
Existing SPN found should be shown.

### Setting up Group Policies
Go to Group Policy Management (use the search feature) and right click on the icon and select "Run as an administrator".
Under the Domains folder, right click on the DOMAIN.local icon and select Create GPO, set a name.

Right click on the GPO name and select Edit.
There you can configure all the policies for this GPO under the folders.

### Joining the clients to the Domain
Login into the Windows 10 and right click on the network device, open Network Connections and right click on the Ethernet device, double click on the IPv4 and set the DNS with the DC IP.
Search for access work or school, click on connect and click on Join this device to local AD domain, then enter the Admin data.
Type the Domain name (DOMAIN.local).
Enter the account and restart and login as "Other user" and enter the login for a previously created user in the DC.
The new computer object should appear in the DC under the Domain Computers folder.

Log out and log in as the Domain Admin, right click on windows logo and select Computer Management. Once there, click on the Groups folder under the Local Users and Groups icon and double click on Administrator and click on Add. Type username of the domain user to add him to the Local Admins group.


## Building an Enterprise AD Network
*Note: this instructions assume that you know how to virtualize and set up an OS in VMWare, Virtualbox or another virtualization software*
To replicate an enterprise network based on AD, we will be needing two domain controllers, 7 windows clients and two linux clients.
The structure will be as follows:
    - One network for both DCs
    - One network for one domain clients
    - One network for the other domain clients
    - One machine acting as a bridge between both client networks

Each client network will consist of three windows machines simulating they are workers and a linux machine simulating a web server. This web server will have one NIC connected to the internal network and another NIC to the Internet (attacker's network).

The windows bridge machine will have two NICs too, one of them connected to one of the client networks and the other one connected to the other client network.

*Feel free to add Firewalls/IDS/IPS wherever you consider. Also you might consider use PFsense as DCHP server*

Each DC will have two NICs, one connected to the DCs network and the other one connected to its domain's client network.


## Local Enumeration

### Interesting Files in a Windows system
| File | Description |
|:-----|:------------|
| %SYSTEMDRIVE%\boot.ini | Contains information about the bootble systems in NT-based prior to Windows Vista |
| %WINDIR%\win.ini / System.ini | Readable by all users. Usually empty on a fresh installation |
| %SYSTEMROOT%\repair\SAM // %SYSTEMROOT%\System32\config\RegBack\SAM // %SYSTEMROOT%\System32\config\SAM | Store user passwords in LM hash or NTLM hash format. Can be retrieved with shadow copy, ninja copy or reg save |
| %SYSTEMROOT%\repair\system // %SYSTEMROOT%\System32\config\RegBack\SYSTEM // %SYSTEMROOT%\System32\config\SYSTEM | The system registry hive. It's needed to extract the user account password hashes from a Windows system |
| %SYSTEMDRIVE%\autoexec.bat | startup script that executes at startup |
| %SYSTEMDRIVE%\pagefile.sys | Used by the OS when there is not enough RAM. It might contain good information but it's a large file |
| %SYSTEMDRIVE%\inetpub\logs\LogFiles | IIS 7 web server log files |
| %USERPROFILE%\LocalS\~1\Tempor\~1\Content.IES\index.dat | IE web browser history file |
| %USERPROFILE%\ntuser.dat | User level windows registry settings |
| %WINDIR%\System32\drivers\etc\hosts | System hosts file for local DNS translation |
| %WINDIR%\debug\NetSetup.log | Issues when a computer is joined to a domain or try to communicate within the network |
| %WINDIR%\iis[version].log | IIS log files |
| %WINDIR%\system32\CCM\logs\*.log // %Windir%\SysWOW64\CCM\Logs\*.log // %ProgramFiles%\SMS_CCM\Logs\*.log | Windows SCCM log files |
| %WINDIR%\system32\config\AppEvent.evt // %WINDIR%\system32\config\SecEvent.evt| Windows event logs |
| %WINDIR%\system32\config\default.sav // %WINDIR%\system32\config\security.sav // %WINDIR%\system32\config\software.sav // %WINDIR%\system32\config\system.sav | Registry files backup |
| %WINDIR%\system32\logfiles\httperr\httperr1.log | IIS 6 error logs |
| %WINDIR%\system32\system32\logfiles\w3svc1\exYYMMDD.log | Web server log files |
| unattend.txt, unattend.xml, unattended.xml, sysprep.inf | Used for automated deployment of Windows images and may contain user accounts (might be in the %WINDIR%\Panther\ folder) |

Here there is an overview about enumeration in a Windows system.

### Windows version
Search for known vulnerabilities for the Window OS version:

```bat
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

```pwsh
[System.Environment]::OSVersion.Version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}
Get-Hotfix -description "Security update"
```

### Vulnerable Drivers
Search for third party drivers that might have known vulnerabilities

```bat
driverquery
```

### Environment
Search for credentials or other sensitive information in environment variables

```bat
set
```

### User and Group permissions
Check if the user or the groups the user belongs to have permission that can be abused.

```bat
net users %username%
net users
net localgroup
net localgroup Administrators
whoami /all
```

```pwsh
Get-WmiObject -Class Win32_UserAccount
```

### Clipboard
Get the content of the clipboard.

```bat
powershell -command "Get-Clipboard"
```

```pwsh
Get-Clipboard
```

### LAPS
LAPS stands for Local Administrator Password Solution and allows you to manage the Local Admin password on a domain-joined computer. These passwords are stored in AD and restricted to privileged users by using ACLs. The passwords are protected from the client to the server using Kerberos and AES encryption.

#### Identifying whether LAPS is installed
If there is LAPS in use, there will appear two new attributes in the computer objects of the domain: ms-msc-AdmPwd and ms-mcs-AdmPwdExpirationTime. These attributes contain the plain text admin password and the expiration time. So it might come in handy to look for users who can read these attributes.

```bat
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
```

If a host has LAPS installed, it will have AdmPwd.dll on disk.

```pwsh
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-FileHash 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-AuthenticodeSignature 'c:\program files\LAPS\CSE\Admpwd.dll'
```

```pwsh
Get-ADObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=name,DC=name2,DC=dom'
```

#### LAPS GPOs
The LAPS configuration is usually defined in GPOs so in order to find more information, we can search for these GPOs.

```pwsh
Get-DomainGPO -Identity "*LAPS"
```

The specific GPOs for LAPS can be found in Registry.pol which can be parsed to be human readable with Parse-PolFile from [GPRegistryPolicy](https://github.com/PowerShell/GPRegistryPolicy).

```pwsh
Parse-PolFile "\\domain.local\SysVol\domain.local\Policies\{C3801BA8-56D9-4F54-B2BD-FE3BF1A71BAA}\Machine\Registry.pol"
```

Here we can find out the complexity, the length, the duration and admin account name where this is applied.

To find the GPOs that are applied to a specific computer, we run the following command:

```pwsh
Get-DomainGPO -ComputerIdentity computerName -Properties displayname
```

##### Finding computers with LAPS
1. Find the LAPS GPO and grab its GUID name
2. Find which OUs that GPO is applied to
3. Get a list of all computers in those OUs

```pwsh
Get-DomainOU -GPLink "C3801BA8-56D9-4F54-B2BD-FE3BF1A71BAA" -Properties distinguishedname
```
```pwsh
Get-DomainComputer -SearchBase "LDAP://OU=OUName,DC=Domain,DC=local" -Properties distinguishedname
```

#### Using PowerView
Script: [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)

```pwsh
Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object {($_.Objecttype -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID; $_ }
```

```pwsh
Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=testlab,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.A
ctiveDirectoryRights -like "*ReadProperty*" } | Select-Object ObjectDN, SecurityIdentifier

Get-DomainObjectAcl -SearchBase "LDAP://OU=Servers,DC=testlab,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.Activ
DirectoryRights -like "*ReadProperty*" } | Select-Object ObjectDN, SecurityIdentifier

Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=testlab,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.A
ctiveDirectoryRights -like "*ReadProperty*" } | Select-Object ObjectDN, SecurityIdentifier | % { $_ | Add-Member NoteProperty 'ResolvedName' $(Convert-SidToName $
_.SecurityIdentifier); $_ }
```

#### LAPS Password Data
Once the appropriate rights have been acquired, we can get the list of computers and their LAPS passwords.

```pwsh
Get-Adcomputer -Filter {ms-mcs-admpwdexpirationtime -like '*'} -Prop 'ms-mcs-admpwd', 'ms-mcs-admpwdexpirationtime'
```

Reading passwords with AdmPwd module:

```pwsh
Get-AdmPwdPassword -ComputerName computerName | f1
```

With PowerView:

```pwsh
Get-DomainObject -Identity computerId -Properties ms-mcs-admpwd
```

#### Backdooring View LAPS Password Data
If a group is delegated "All Extended Rights" to an OU that contains computers managed by LAPS, it has the ability to view confidential attributes, including the LAPS attribute ms-mcs-admpwd which contains the plain text password.

By using the LAPS PowerShell module, we can enumerate these rights.

```pwsh
import-module admpwd.PS
Find-AdmPwdExtendedRights -Identity "Workstations" | % {$_.ExtendedRightHolders}
```

#### Identifying LAPS Computer Management
Since LAPS computer attribute ms-mcs-AdmPwdExpirationTime is a regular one, authenticated users have read access so we can track LAPS usage in an environment.

```pwsh
Get-ADComputer -filter {ms-Mcs-AdmPwdExpirationTime -like '*'} -properties ms-Mcs-AdmPwdExpirationTime
```

If delegation of the ms-Mcs-AdmPwdExpirationTime is too relaxed, compromising one of these accounts might mean that change the value of the expiration time to a date far in the future so an attacker can get advantage of these passwords not expiring.

```pwsh
Get-ADComputer -filter {ms-Mcs-AdmPwdExpirationTime -like '*'} -properties ms-Mcs-AdmPwdExpirationTime
[datetime]::FromFileTime(attribute value)
```

*Mitigation would be to enable the LAPS GPO setting "Do not allow password expiration time longer than required by policy"*


### Watch logging
#### Audit settings
Here we will see what is being logged.

```bat
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

#### Windows Event Forwarding
See where the logs are sent.

```bat
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

#### Antivirus
Check if there is an antivirus running and which one.

```bat
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more
```

### Check privileges
```bat
whoami /priv
whoami /all
net user [userName]
net localgroup [groupName]
```

### Network enumeration

#### Interfaces, routes, ports and dns cache
```bat
ipconfig /all
route print
arp -A
netstat -ano
type C:\WINDOWS\System32\drivers\etc\hosts
ipconfig /displaydns | findstr "Record" | findstr "Name Host"
```

#### Firewall
```bat
netsh firewall show state
netsh advfirewall firewall show rule name=all
netsh firewall show config
netsh advfirewall show allprofiles
```

#### Shares
```bat
net view
net view /all /domain <domainName>
net use x: \\computer\share #mount share locally
net share
```

#### Wifi
```bat
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

#### SNMP
```bat
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
```

### Software
Check all installed software. Sometimes it's possible to overwrite a binary or perform a DLL Hijacking.

```bat
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
```

```pwsh
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

### Run at startup
Check if some binary executed by another user can be overwritten.

```bat
wmic startup get caption,command 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^

dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul & ^
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul & ^
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
```

```pwsh
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Check which files are executed on computer start and components executed when an user logins.

```bat
autorunsc.exe -m -nobanner -a * -ct /accepteula #sysinternals
```

### Running processes
Check if a running binary can be overwritten or if a memory dump can be performed for a process that contains passwords.

```pwsh
Tasklist /SVC
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOnwer().User}} | ft -AutoSize

Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

#### Permissions of the processes binaries
```bat
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

Looking for dll injection.

```bat
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
```

### Memory password mining
Create a memory dump of a running process using procdump from sysinternals.
```bat
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Services
#### Services list
```bat
net start
wmic service list brief
sc query
```

#### Services permissions
```bat
sc qc <service_name>
```

Check required privilege for each service with sysinternals:
```bat
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Check if Authenticated Users can modify any service:
```bat
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```


<!-- ## AD Enumeration
### Privacy/Anonimity  OPSEC
### SPN Scanning



## AD Privilege Escalation
### Transferring files
### AV/AMSI/IDS/IPS bypass

## AD Lateral Movement
### VLAN Hopping
### Tunneling/Pivoting

## AD Post-Exploitation
### Privacy/Anonimity  OPSEC
### Persistence
#### Backup Servers
### Data Exfiltration
### House Cleaning

## MITRE ATT&CK and Attack mapping

## Hardening AD

## Command & Control Tools -->


## References
- [Tarlogic blog](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [adsecurity LAPS](https://adsecurity.org/?p=3164)
- [harmj0y](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
- [rastamouse](https://rastamouse.me/tags/laps/)
- [0xsp](https://0xsp.com/offensive/active-directory-attack-defense)
- [hacktricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)
- https://docs.microsoft.com/en-us/previous-versions/mt227395(v=msdn.10)?redirectedfrom=MSDN
- [Wagging the Dog](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [MS Protocol Examples](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/03dbd1c5-6617-4276-97ff-d24db65d8154)
- [MS Kerberos Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
- [adsecurity SPN Scanning](https://adsecurity.org/?p=1508)
