# Investigation Timeline

## Lab 80 — Kerberoasting Investigation

**Date:** 18 September 2026  
**Host:** `DESKTOP-9MMM37V`

The timeline below records only events and observations actually established during the investigation.

| Time | Evidence / Activity | Observation | Significance |
|---|---|---|---|
| 06:51 | Investigation workspace created | `C:\KerberoastingLab\Evidence` created successfully | Evidence collection initialized |
| 06:51 | Host-role validation | `WORKGROUP`, `PartOfDomain: False`, `DomainRole: 0` | Endpoint identified as standalone |
| 06:51 | Kerberos service validation | `LocalKdc` and `Netlogon` were stopped | Consistent with current standalone environment |
| 06:51 | AD database check | `C:\Windows\NTDS\ntds.dit` not present | No local AD database |
| 06:51+ | AD user/SPN query | `Get-ADUser` unavailable | AD enumeration unavailable |
| 06:51+ | SPN query | `setspn -Q */*` returned LDAP error `0x51` | No usable AD/LDAP context |
| 06:53–07:04 | Sysmon Event ID 3 | Multiple network connection events observed | Network telemetry available |
| 06:54+ | Windows `klist.exe` validation | Native utility identified and executed explicitly | Java/Windows command conflict resolved |
| 06:54+ | Kerberos ticket cache | `Cached Tickets: (0)` | No cached tickets in queried session |
| 06:54+ | Security Event ID 4769 search | No matching events found | Required service-ticket telemetry unavailable |
| 06:54+ | Security Event ID 4624 search | No matching events found | Authentication correlation unavailable |
| 06:54+ | Security Event ID 4672 search | No matching events found | Privileged-logon correlation unavailable |
| 07:01–07:03 | Sysmon Event ID 1 | Multiple process creation events observed | Process telemetry available |
| 07:02–07:04 | Sysmon Event ID 3 | Additional network connection events observed | Network context available |
| 07:03 | Sysmon validation | Sysmon service confirmed running | Endpoint telemetry source verified |
| 07:04 | Sysmon network query | Network connection events returned | Supporting telemetry confirmed |

## Key Timeline Interpretation

The timeline establishes that the endpoint generated useful Sysmon telemetry during the investigation period. However, no corresponding Security Event ID `4769` evidence was available.

The most important chronological finding is therefore not an observed Kerberoasting sequence, but the validation that the endpoint lacked the Active Directory/Kerberos telemetry needed to establish such a sequence.

## Investigation Boundary

The following events were **not** added to the timeline because they were not observed:

- Kerberos Event ID `4769`
- A specific SPN request
- A confirmed service-account ticket request
- A Kerberoasting tool execution
- An offline password-cracking event
- A confirmed Domain Controller interaction
- A confirmed Kerberoasting attack

This distinction keeps the timeline evidence-based and prevents expected attack behavior from being presented as events that were actually observed.

## Final Timeline Assessment

The investigation ended with the following evidence state:

    Standalone WORKGROUP host
            ↓
    No local AD database
            ↓
    No cached Kerberos tickets
            ↓
    No Security Event ID 4769
            ↓
    No AD/SPN enumeration
            ↓
    Sysmon process/network telemetry available
            ↓
    Kerberoasting cannot be established from this endpoint
