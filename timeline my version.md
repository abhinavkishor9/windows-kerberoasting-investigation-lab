# Investigation Timeline

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

