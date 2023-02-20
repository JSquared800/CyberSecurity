# Chapter 21 - AD

## Theory

AD has several components, including the **domain controller**.

* **Domain Controller**: The most important one. Acts as the hub of all information traveling through AD and contains valuable information about the service.&#x20;
* **Domain**: Typically something that broadly contains everything, i.e. corp.com. There exist various types of objects, including computer and user objects.
* **Organizational Units**: Similar to file system folders, used to store other objects.&#x20;
* **Objects:** The meat of AD, including computer objects, which are actual computers, or user objects, with **attributes** like first name, last name, username, and password.

## Enumeration

In AD, administrators use groups to assign permissions to member users. Therefore, it follows that attacking high-value groups is the main focus.&#x20;

Another way to gain control is to compromise a domain controller and access domain-joined computers as well as view password hashes.

### Traditional Approach

```
C:\Users\Offsec.corp> net user /domain
The request will be processed at a domain controller for domain corp.com.


User accounts for \\DC01.corp.com

-------------------------------------------------------------------------------
adam                     Administrator            DefaultAccount
Guest                    iis_service              jeff_admin
krbtgt                   offsec                   sql_service
The command completed successfully.
```

This command allows us to enumerate all users in the entire domain. The **jeff\_admin** user looks valuable, we will focus on that user.

```
C:\Users\Offsec.corp> net user jeff_admin /domain
The request will be processed at a domain controller for domain corp.com.

User name                    jeff_admin
Full Name                    Jeff_Admin
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/19/2018 1:56:22 PM
Password expires             Never
Password changeable          2/19/2018 1:56:22 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

We can see that jeff\_admin is a member of the **Domain Admins** group.&#x20;

We can also enumerate all groups in a domain.

```
C:\Users\Offsec.corp> net group /domain
The request will be processed at a domain controller for domain corp.com.


Group Accounts for \\DC01.corp.com

-------------------------------------------------------------------------------
*Another_Nested_Group
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Nested_Group
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Secret_Group
The command completed successfully.
```

We see **Secret\_Group**, which is of interest to us. Note **Nested\_Group** and **Another\_Nested\_Group**. In AD, you can put groups as a member to another group.

### Modern Approach

We can use PowerShell to enumerate AD.&#x20;

The script will query the network for the name of the primary domain controller emulator and the domain, search AD, and filter output.

We will need to use a **DirectorySearcher** object to query AD with **LDAP**, which is essentially an API that allows search functionality with AD. The script will use a very specific LDAP **provider path** that will be the input for DirectorySearcher.&#x20;

```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

To create this path, we need:

* Hostname
* DistinguishedName

We can get both of these with a PowerShell command.

```
PS C:\Users\offsec.CORP> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Forest                  : corp.com
DomainControllers       : {DC01.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner            : DC01.corp.com
RidRoleOwner            : DC01.corp.com
InfrastructureRoleOwner : DC01.corp.com
Name                    : corp.com
```

This tells us that the domain name is "**corp.com**", from the Name field and the primary DC name is "**DC01.corp.com**" from the PdcRoleOwner field. We can use both of these to start our script.

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$SearchString
```

Note that domainObj holds the entire domain objetc, which PDC and DistinguishedName will hold their respective values. SearchString will look like the following:

```
LDAP://DC01.corp.com/DC=corp,DC=com
```

We can now instantiate the DirectorySearcher class with the LDAP path, as well as filter and clean up the output for the final script.

#### Final Script&#x20;

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}
```

We could change the Searcher.filter to something like "name=Jeff\_Admin" if we wanted to just enumerate them.

### Resolving Nested Groups

First we need to locate all the groups and print their names. This can be done by creating a filter for objectClass set to Group and printing the name property.&#x20;

Modified script:

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(objectClass=Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name
}
```

When executed, the script lists all the groups.

Now, we can list the members of Secret\_Group:

```
...

$Searcher.filter="(name=Secret_Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.member
}
...
```

This outputs the names of DistinguishedName group members.

```
CN=Nested_Group,OU=CorpGroups,DC=corp,DC=com
```

Looks like Nested\_Group is a member of Secret\_Group. We can enumerate this group by changing the group name to Nested\_Group.

```
...
$Searcher.filter="(name=Nested_Group)"
...
```

```
CN=Another_Nested_Group,OU=CorpGroups,DC=corp,DC=com
```

We can now enumerate Another\_Nested\_Group with similar methodology.

```
...

$Searcher.filter="(name=Another_Nested_Group)"
...
```

```
CN=Adam,OU=Normal,OU=CorpUsers,DC=corp,DC=com
```

We can see that Adam is the only member.

### Currently Logged on Users

We want to find currently logged in users now, since we can find passwords or other loot in the cache and steal them.

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

If we manage to compromise a Domain Admin, we have essentially compromised the whole domain. However, we can also compromise other accounts or machines. Note in the picture above that we can compromise Bob, then Alice, then Jeff.&#x20;

To discover any logged on users, we can use PowerView.

```
PS C:\Tools\active_directory> Import-Module .\PowerView.ps1
PS C:\Tools\active_directory> Get-NetLoggedon -ComputerName client251 | Format-Table

wkui1_username wkui1_logon_domain wkui1_oth_domains wkui1_logon_server
-------------- ------------------ ----------------- ------------------
offsec         corp                                 DC01
offsec         corp                                 DC01
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp
CLIENT251$     corp 
```

We can retrieve active sessions as well.

```
PS C:\Tools\active_directory> Get-NetSession -ComputerName dc01 | Format-Table

CName           UserName      Time IdleTime ComputerName
-----           --------      ---- -------- ------------
\\172.16.246.10 Administrator    8        0 dc01
```

The Adminstrator has an active session on the domain controller from 172.16.246.10, which is the Windows client. Now we can start compromising accounts.

### Enumeration Through Service Principal Names

Instead of attacking high values groups like the Domain Controller, we can target service accounts. &#x20;

When an application is executed, it will be done through an operating system user. However, services launched by the system use the context of a Service Account.&#x20;

This means that applications can use certain service accounts like **LocalSystem**, **LocalService**, and **NetworkService**.&#x20;

While certain applications are integrated into AD(i.e. SQL), a unique service instance identifier known as an SPN is used to associated services to their respective accounts.

Enumerating all registered SPNs can give us IP addresses and ports to servers integrated with AD.

Let's edit the script to include SPNs with the string http to check for web servers.

```
...
$Searcher.filter="serviceprincipalname=*http*"
...
```

This returns a large block of text.

```
Name                    Value     
----                    -----     
givenname               {iis_service}    
samaccountname          {iis_service}  
cn                      {iis_service}    
...
serviceprincipalname    {HTTP/CorpWebServer.corp.com} 
distinguishedname       {CN=iis_service,OU=ServiceAccounts,OU=CorpUsers,DC=corp,DC=com   
...    
```

One of the attributes, samaccountname is set to iis\_service, which tells us there will likely be a web server. Furthermore, serviceprincipalname is set to HTTP/CorpWebServer.corp.com

## Authentication

### NTLM Authentication

NTLM Authentication is used when a client authenticates to a server by IP instead of hostname. The NTLM authentication protocol has 7 steps:

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

1. The client computer calculates a hash, referred to as the NTLM hash, from the user's password.
2. The client sends the username(stored in plaintext) to the server.
3. The client receives a **nonce** value from the server. The nonce value is randomized.
4. The client will encrypt the nonce with the NTLM hash and send that encryption, referred to as the "response" to the server.
5. The server will forward the username, nonce value, and the encrypted nonce to the Domain Controller.&#x20;
6. The Domain Controller then encrypts the nonce with the NTLM hash of the user(because it knows the NTLM hashes of all users)
7. It is now trivial to validate whether the response and value it encrypted are equal. If so, the authentication request is successful.

### Kerberos Authentication

While NTLM works by challenge and response, Kerberos uses a ticket system. At high level,s Kerberos client authentication to a service in AD uses a domain controller in the role of a key distribution center, or KDC.

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

1. When a user logs on, a request is send to the domain controller. This DC has the role of KDC and maintains the Authentication Server service. This request contains a time stamp that is encrypted use a hash from the username and password of the user.
2. When this is received by the domain controller, it attempts to decrypt the time stamp with the hash. If the decryption process is successful, the authentication is considered successful. It will send an Authentication Server Reply that contains a session key and a Ticket Granting Ticket(TGT). The Ticket Granting Ticket cannot be decrypted by the client.
3. If the user wants to access domain resources, such as a network share, Exchange mailbox, or another application with a registered SPN, it must contact the KDC. The client will generate a Ticket Granting Service Request packet that consists of the current user and timestamp(encrypted with the session key), the SPN of the resource, and the encrypted TGT. The ticket granting service on the KDC receives the request, and if the SPN exists, the TGT is decrypted using the secret key only known by the KDC.  The session key is extracted from the TGT and used to decrypt the username and timestamp of the request. The KDC then performs several checks:
   1. The TGT must have a valid timestamp
   2. The username from the request must match with the TGT
   3. The client IP address must coincide with the TGT IP address
4. If all checks are made, the service responds to the client with a ticket granting server reply packet, made of three parts. The first two parts are encrypted using the session key of creation of the TGT and the service ticket is encrypted using the password hash of the service account registered with the SPN in question.
   1. The SPN to which access has been granted
   2. A session key to be used between the client and the SPN
   3. A service ticket with username and group membership as well as the newly-created session key
5. Once authentication with the KDC is complete and the client has a session key and service ticket, it may continue with authentication. First, it needs to send an **application request**, which includes the username and timestamp encrypted with the session key associated with the service ticket along with the service ticket itself. The application server decrypts the service ticket and extracts the username and session key. It can now decrypt the username from the request and check if the two match.&#x20;
6. The user is authenticated.

### Cached Credential Storage and Retrieval

Password hashes must be stored somewhere to validate TGT requests. In current versions, these are stored in LSASS memory space. &#x20;
