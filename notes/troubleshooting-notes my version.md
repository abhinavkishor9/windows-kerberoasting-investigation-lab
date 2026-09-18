# Troubleshooting Notes

## 1. Java `klist` Was Executed Instead of Windows `klist.exe`

### Symptom

Running:

    klist

returned a Java exception:

    Exception in thread "main" java.lang.NullPointerException

### Cause

PowerShell resolved `klist` to the Java JDK installation.

Command discovery showed:

    C:\Program Files\Java\jdk-23\bin\klist.exe
    C:\Windows\System32\klist.exe

The Java JDK directory appeared earlier in the effective PATH.

### Resolution

The Windows utility was executed using its full path:

    & "$env:SystemRoot\System32\klist.exe"

For ticket inspection:

    & "$env:SystemRoot\System32\klist.exe" tickets

### Result

The correct Windows utility returned:

    Current LogonId is 0:0x47dc3

    Cached Tickets: (0)

### Lesson

When Windows and third-party software provide executables with the same name, verify command resolution before interpreting the output.

Useful checks:

    Get-Command klist -All
    where.exe klist

---

## 2. Event ID 4769 Was Not Found

### Symptom

The Security log query returned:

    Get-WinEvent: No events were found that match the specified selection criteria.

### Cause

The endpoint is a standalone WORKGROUP workstation rather than an Active Directory domain system.

Event ID `4769` represents Kerberos service-ticket activity and is primarily useful from the Domain Controller/KDC side of an Active Directory investigation.

### Resolution

No attempt was made to create or simulate 4769 events.

The result was documented as:

    No Security Event ID 4769 events found.

### Lesson

Missing telemetry should be recorded as a telemetry limitation rather than interpreted as proof that the activity did not occur.

---

## 3. `$Event.ToXml()` Failed

### Symptom

The following produced a null-valued expression error:

    $Event.ToXml()

### Cause

The preceding `Get-WinEvent` query returned no events, so `$Event` was `$null`.

### Resolution

Validate the event object before accessing methods or properties.

Example:

    $Event = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4769
    } -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($Event) {
        $Event.ToXml()
    }
    else {
        "No matching event found."
    }

### Lesson

A downstream null-object error does not represent an additional telemetry finding. The root cause was the absence of the requested event.

---

## 4. `Get-ADUser` Was Unavailable

### Symptom

PowerShell returned:

    Get-ADUser: The term 'Get-ADUser' is not recognized

### Cause

The Active Directory PowerShell cmdlet/module was not available in the current environment.

The endpoint also was not joined to an Active Directory domain.

### Resolution

No replacement domain users or SPNs were invented.

The limitation was documented as:

> Active Directory user and SPN enumeration could not be performed from the current endpoint.

### Lesson

SPN-associated service accounts must be obtained from genuine Active Directory evidence.

---

## 5. `setspn -Q */*` Failed

### Symptom

The command returned:

    Ldap Error(0x51 -- Server Down): ldap_connect
    Failed to retrieve DN for domain "" : 0x00000051

### Cause

The current endpoint did not have a usable Active Directory/LDAP domain context.

### Resolution

The command was not repeatedly treated as an attack indicator.

The failure was documented as an environment limitation affecting SPN enumeration.

### Lesson

An LDAP connection failure is not evidence of Kerberoasting.

---

## 6. Security Events 4624 and 4672 Were Also Unavailable

### Symptom

Queries for Security Event IDs `4624` and `4672` returned no matching events.

### Impact

Authentication and privileged-logon context could not be correlated with a hypothetical Kerberos service-ticket request.

### Resolution

The absence was documented rather than reconstructed.

### Lesson

Correlation requires actual telemetry. A missing authentication event cannot be substituted with an assumed user or session.

---

## 7. Sysmon Telemetry Was Available

### Observation

Sysmon was running:

    Status   Name      DisplayName
    ------   --------  -----------
    Running  Sysmon64  Sysmon64

The Operational channel was enabled.

Event IDs `1` and `3` returned records.

### Interpretation

This confirmed that endpoint process and network telemetry was available even though Windows Security and Active Directory telemetry required for the Kerberoasting investigation was unavailable.

### Lesson

Telemetry availability can differ significantly between security data sources on the same endpoint.

---

## 8. Avoiding False Attribution from Sysmon

Sysmon process and network events were not automatically interpreted as Kerberoasting evidence.

The presence of processes such as:

    powershell.exe
    cmd.exe

or network connections around the investigation period does not independently prove Kerberos abuse.

A valid investigation would require correlation with relevant Kerberos and Active Directory evidence.

### Lesson

Temporal proximity is supporting context, not proof of causation.

---

## 9. Local Port 8080 Observation

A local listener was observed:

    127.0.0.1:8080

with PID `4`.

PID `4` was identified as:

    System

The listener was bound to loopback and was not associated with Kerberoasting evidence.

### Lesson

Unexpected-looking network artifacts should be investigated in context rather than automatically connected to the investigation hypothesis.

---

