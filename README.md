**Windows Threat Hunting Lab**

A Python-based threat hunting and investigation tool designed to simulate a small SOC analyst workflow using synthetic Windows security telemetry.

The project searches Windows-style event data for suspicious behaviours, maps findings to MITRE ATT&CK techniques, and provides an investigation interface for pivoting through related events.

**Features**

**PowerShell Hunt*

Detects suspicious PowerShell execution based on:

- Encoded PowerShell commands
- PowerShell launched by Microsoft Office applications

MITRE ATT&CK:

- T1059.001 - PowerShell

**Authentication Hunt**

Detects potential brute-force activity by identifying multiple failed logons from the same source within a five-minute window.

The hunt reports:

- Source IP
- Number of failed logons
- First and last attempts
- Targeted users

MITRE ATT&CK:

- T1110 - Brute Force

**Account Creation Hunt**

Identifies Windows account-creation events and extracts the account that was created.

MITRE ATT&CK:

- T1136.001 - Create Account: Local Account

**LOLBin Hunt**

Detects suspicious use of legitimate Windows binaries, including:

- rundll32.exe
- regsvr32.exe
- mshta.exe
- certutil.exe
- bitsadmin.exe

The detection looks for suspicious command-line patterns rather than flagging the existence of the binaries alone.

Example:

```text
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"