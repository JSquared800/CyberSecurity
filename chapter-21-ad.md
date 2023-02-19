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

We can now instantiate the DirectorySearcher class with the LDAP path.&#x20;

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "corp.com\offsec", "lab")

$Searcher.SearchRoot = $objDomain

```
