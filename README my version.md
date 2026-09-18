# windows-kerberoasting-investigation-lab
## Overview

Kerberoasting targets Active Directory service accounts that have registered Service Principal Names (SPNs).

An attacker typically abuses normal Kerberos functionality to request service tickets for SPN-associated accounts. The resulting ticket can contain material that may be subjected to offline password guessing.

For a SOC investigation, the important telemetry is usually:

Security Event ID 4769 — Kerberos service ticket was requested
Requesting account
Target service account
SPN
Source computer
Timestamp
Ticket encryption information, where available
Process and network context from Sysmon
Wazuh alerts and archived events

The key point is that 4769 alone does not prove Kerberoasting. A normal application can legitimately request service tickets.

This lab investigates **Kerberoasting-related telemetry** from a SOC and DFIR perspective. The investigation focuses on validating whether the endpoint can provide the evidence required to analyze Kerberos service-ticket activity rather than assuming that Kerberoasting occurred.

The investigation uses Windows host-role information, Kerberos ticket-cache validation, Security Event ID 4769 checks, Active Directory and SPN validation, authentication telemetry, Sysmon process and network events, and Wazuh visibility.

The lab was performed on a Windows 10 VM that was identified as a standalone **WORKGROUP** system. As a result, the investigation primarily demonstrates how an analyst should identify and document **telemetry and environment limitations** when the expected Active Directory evidence is unavailable.

##  Lab Objectives

- Validate whether the Windows host has the required Active Directory and Kerberos context for a Kerberoasting investigation.
- Identify the telemetry normally required to investigate Kerberoasting, including Security Event ID 4769, authentication events, Kerberos ticket information, and process activity.
- Examine the availability of Kerberos services, Active Directory components, service accounts, and Service Principal Names (SPNs) without assuming that the host is domain-joined.
- Validate Kerberos ticket activity using the native Windows `klist.exe` utility and distinguish the Windows utility from conflicting executables in the system PATH.
- Review Security Event ID 4769 for evidence of service-ticket requests that could require further investigation for Kerberoasting activity.
- Correlate available Windows Security and Sysmon telemetry to determine whether process or network activity provides supporting evidence.
- Document telemetry gaps, command failures, and environmental limitations that affect the investigation.
- Apply MITRE ATT&CK T1558.003 (Kerberoasting) as an investigative context while avoiding attribution when the available evidence does not establish the technique.
- Produce an evidence-based conclusion that clearly separates confirmed observations, unavailable telemetry, and activity that cannot be determined from the current host. 


## Lab Scenario

A SOC analyst receives a request to investigate potential **Kerberoasting activity** within a Windows environment. The suspected technique involves requesting Kerberos service tickets for accounts associated with Service Principal Names (SPNs) and later attempting to recover service-account credentials from the ticket material. The investigation must determine whether the available host telemetry can support this hypothesis without treating normal Kerberos activity as malicious by default.

The investigation begins by validating the environment before reviewing security events. The analyst checks whether the Windows host is joined to an Active Directory domain, whether Kerberos and Netlogon services are available, whether an Active Directory database is present, and whether service accounts or SPNs can be enumerated. This validation is important because Kerberoasting depends on an operational AD/Kerberos environment, and the absence of that context changes how the available evidence should be interpreted.

The analyst then examines the following areas:

- **Kerberos ticket activity:** Validate the local ticket cache and determine whether Kerberos tickets are present on the investigated host.
- **Security telemetry:** Search for Event ID 4769 and related authentication events that could provide context around service-ticket requests.
- **AD and SPN visibility:** Determine whether domain users, service accounts, and SPNs can be queried from the host.
- **Process activity:** Review Sysmon process-creation events for supporting activity that may correlate with Kerberos-related investigation.
- **Network telemetry:** Examine available Sysmon network events and local network activity for relevant supporting evidence.
- **Telemetry limitations:** Record missing events, unavailable AD functionality, command failures, and other environmental constraints rather than filling gaps with assumptions.

The host is treated as an evidence source rather than proof of the suspected activity. A missing Event ID 4769 on the workstation does not establish that Kerberoasting did not occur, because service-ticket events are most useful from the domain controller/KDC side. Similarly, an empty local Kerberos ticket cache does not by itself establish the absence of Kerberos activity elsewhere in the environment.

The final assessment should determine what can be confirmed from the collected evidence, what remains unknown, and whether the available telemetry is sufficient to support a Kerberoasting conclusion. The investigation follows an evidence-first principle: **an expected artifact that is missing is a telemetry limitation, not evidence that the activity occurred or did not occur.**

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
