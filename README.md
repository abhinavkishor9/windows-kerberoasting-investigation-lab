# Windows Kerberoasting Investigation Lab

## Overview

This lab investigates **Kerberoasting-related telemetry** from a SOC and DFIR perspective. The investigation focuses on validating whether the endpoint can provide the evidence required to analyze Kerberos service-ticket activity rather than assuming that Kerberoasting occurred.

The investigation uses Windows host-role information, Kerberos ticket-cache validation, Security Event ID 4769 checks, Active Directory and SPN validation, authentication telemetry, Sysmon process and network events, and Wazuh visibility.

The lab was performed on a Windows 10 VM that was identified as a standalone **WORKGROUP** system. As a result, the investigation primarily demonstrates how an analyst should identify and document **telemetry and environment limitations** when the expected Active Directory evidence is unavailable.

## Investigation Focus

- Validate whether the endpoint participates in an Active Directory domain.
- Determine whether local Kerberos ticket information is available.
- Check for Security Event ID 4769.
- Validate whether SPN and Active Directory enumeration is possible.
- Review authentication telemetry where available.
- Review Sysmon process and network telemetry for supporting context.
- Understand the difference between collected telemetry and detection alerts.
- Document evidence limitations without fabricating missing events.

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 |
| Hostname | `DESKTOP-9MMM37V` |
| Domain | `WORKGROUP` |
| Domain Member | No |
| Domain Role | `0` |
| Sysmon | Running |
| Sysmon Operational Log | Enabled |
| Wazuh | Installed |
| Kerberos Ticket Cache | 0 cached tickets |
| AD Database | `ntds.dit` not present |

## Investigation Evidence

The host-role check returned:

    Name             : DESKTOP-9MMM37V
    Domain           : WORKGROUP
    PartOfDomain     : False
    DomainRole       : 0

The local Kerberos service checks showed:

    Name     Status  StartType
    ----     ------  ---------
    LocalKdc Stopped Manual
    Netlogon Stopped Manual

The Active Directory database check returned:

    False

for:

    C:\Windows\NTDS\ntds.dit

The native Windows Kerberos utility was executed explicitly after identifying a naming conflict with the Java `klist.exe`.

    Current LogonId is 0:0x47dc3

    Cached Tickets: (0)

No local Security Event ID `4769` events were found.

Authentication checks for Event IDs `4624` and `4672` also returned no matching events in the queried Security log.

## Sysmon Visibility

Unlike the Windows Security log queries, Sysmon was active and producing telemetry.

Sysmon was confirmed as:

    Status   Name      DisplayName
    ------   --------  -----------
    Running  Sysmon64  Sysmon64

The Sysmon Operational log was enabled.

Process creation events (`Event ID 1`) and network connection events (`Event ID 3`) were available. These events provide useful endpoint telemetry, but they do not independently establish Kerberoasting activity.

## Active Directory and SPN Validation

The following Active Directory query was unavailable because the Active Directory PowerShell module and domain context were not present:

    Get-ADUser -Filter * -Properties ServicePrincipalName

`setspn -Q */*` also failed because an LDAP domain target could not be reached:

    Ldap Error(0x51 -- Server Down): ldap_connect
    Failed to retrieve DN for domain "" : 0x00000051

This prevents direct validation of domain users and SPN-associated service accounts from the current endpoint.

## Investigation Result

The investigation did **not** establish Kerberoasting activity.

The available evidence shows that the investigated endpoint is a standalone WORKGROUP system without the Active Directory/Kerberos telemetry required for direct Kerberoasting analysis. No Security Event ID `4769` events were available, the native Windows Kerberos ticket cache contained zero cached tickets, and Active Directory/SPN enumeration could not be performed against a domain.

This is treated as an **environment and telemetry limitation**, not as evidence that Kerberoasting did or did not occur elsewhere.

## Key Takeaways

- Kerberoasting investigations depend heavily on Active Directory and Kerberos telemetry.
- Security Event ID `4769` is important evidence for service-ticket analysis.
- Absence of `4769` on this workstation cannot be interpreted as proof that no Kerberoasting occurred.
- A WORKGROUP endpoint does not provide the same evidence as a Domain Controller or domain-connected investigation host.
- Sysmon process and network telemetry can provide supporting context but cannot replace Domain Controller Kerberos telemetry.
- Missing evidence should be documented as a limitation rather than reconstructed or assumed.
- Tool behavior must also be validated before interpreting results, as demonstrated by the Java/Windows `klist.exe` conflict.

## MITRE ATT&CK Context

This investigation is associated with:

- **T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**

The technique mapping represents the investigation subject. It does not mean that the technique was confirmed on the investigated endpoint.

## Evidence Directory

The investigation evidence was stored under:

    C:\KerberoastingLab\Evidence

Relevant evidence included:

    01-host-role.txt
    02-kerberos-services.txt
    03-windows-klist.txt
    03b-klist-sessions.txt
    04-4769-status.txt

Additional Sysmon and investigation outputs can be added as they are collected.
