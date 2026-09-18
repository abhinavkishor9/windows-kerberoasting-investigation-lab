# Investigation Notes

## 1. Host Role Validation

The Windows computer-system query returned:

    Name             : DESKTOP-9MMM37V
    Domain           : WORKGROUP
    PartOfDomain     : False
    DomainRole       : 0

This establishes that the endpoint is not currently joined to an Active Directory domain.

This is significant because Kerberoasting depends on Active Directory Kerberos infrastructure and SPN-associated service accounts.

## 2. Kerberos Service Validation

The Kerberos-related service check returned:

    Name     Status  StartType
    ----     ------  ---------
    LocalKdc Stopped Manual
    Netlogon Stopped Manual

No local `Kdc` service was returned by the initial query.

The result is consistent with the endpoint not functioning as an Active Directory Domain Controller.

The check was used for environment validation and was not treated as attack evidence.

## 3. Active Directory Database Validation

The following check returned:

    False

for:

    C:\Windows\NTDS\ntds.dit

The absence of this file further supports the conclusion that the workstation is not hosting an Active Directory Domain Controller database.

## 4. Kerberos Ticket Cache

An initial `klist` command produced a Java exception:

    Exception in thread "main" java.lang.NullPointerException

The command was not interpreted as evidence because PowerShell had resolved `klist` to the Java installation.

Command resolution showed:

    C:\Program Files\Java\jdk-23\bin\klist.exe
    C:\Windows\System32\klist.exe

The Windows utility was therefore executed explicitly:

    & "$env:SystemRoot\System32\klist.exe" tickets

The actual Windows result was:

    Current LogonId is 0:0x47dc3

    Cached Tickets: (0)

This establishes that the queried logon session had no cached Kerberos tickets at the time of the check.

It does not establish that Kerberos activity never occurred.

## 5. Security Event ID 4769

The Security log was queried for Event ID `4769`.

Result:

    Get-WinEvent: No events were found that match the specified selection criteria.

The same result was observed when attempting to retrieve and group 4769 events.

No XML event could therefore be extracted.

The failed `$Event.ToXml()` call was a consequence of `$Event` being `$null`; it was not a second investigative finding.

## 6. Authentication Events

Security Event IDs `4624` and `4672` were also queried.

Both searches returned:

    Get-WinEvent: No events were found that match the specified selection criteria.

Therefore, the current Security log did not provide the authentication context required to correlate a hypothetical Kerberos service-ticket request with a user or privileged logon.

## 7. Active Directory User and SPN Validation

The following command could not be executed:

    Get-ADUser -Filter * -Properties ServicePrincipalName

PowerShell returned that `Get-ADUser` was not recognized.

The `setspn` query also failed:

    Ldap Error(0x51 -- Server Down): ldap_connect
    Failed to retrieve DN for domain "" : 0x00000051

This indicates that the current endpoint could not establish the required Active Directory/LDAP context for SPN enumeration.

No service-account or SPN population was therefore assumed.

## 8. Sysmon Process Telemetry

Sysmon was confirmed to be running:

    Status   Name      DisplayName
    ------   --------  -----------
    Running  Sysmon64  Sysmon64

The Sysmon Operational channel was enabled.

Event ID `1` process-creation records were available, including events around the investigation period.

The presence of process telemetry provides useful endpoint context, but no process was automatically classified as a Kerberoasting tool or activity based only on its existence.

## 9. Sysmon Network Telemetry

Sysmon Event ID `3` network connection events were also available.

Multiple network connection records were observed between approximately `06:48` and `07:04` on 18 September 2026.

These records demonstrate that network telemetry was available from the endpoint.

However, the available summarized output did not establish a Kerberos service-ticket request or identify an SPN-related request.

Therefore, the network events were retained as supporting telemetry rather than treated as proof of Kerberoasting.

## 10. Local Network Observation

A separate check showed:

    TCP    127.0.0.1:8080    0.0.0.0:0    LISTENING    4

PID `4` was identified as:

    System

The listener was bound to loopback (`127.0.0.1`), so this observation was not treated as evidence of Kerberoasting.

It is retained as host/network context only.

## 11. Evidence Assessment

| Evidence Source | Result | Investigation Value |
|---|---|---|
| Host role | WORKGROUP | Establishes standalone environment |
| Domain membership | False | No AD domain membership |
| Domain role | 0 | Workstation role |
| Local KDC | Not running | Supports environment limitation |
| Netlogon | Stopped | Consistent with current environment |
| `ntds.dit` | Not present | No local AD database |
| Windows `klist.exe` | 0 tickets | No cached tickets in queried session |
| Security 4769 | Not found | Required telemetry unavailable |
| Security 4624 | Not found | Authentication correlation unavailable |
| Security 4672 | Not found | Privileged-logon correlation unavailable |
| `Get-ADUser` | Unavailable | AD module/domain context unavailable |
| `setspn` | LDAP failure | SPN enumeration unavailable |
| Sysmon EID 1 | Available | Process context available |
| Sysmon EID 3 | Available | Network context available |
| Wazuh | Existing deployment | Additional telemetry source for validation |

