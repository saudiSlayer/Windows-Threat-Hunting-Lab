# Windows Threat Hunting Lab

# Project Overview

Windows Threat Hunting Lab is a Python-based threat hunting and investigation tool designed to simulate a Security Operations Centre (SOC) analyst workflow using synthetic Windows security telemetry.

The project analyses Windows event records to identify suspicious activity, generate security alerts and support further investigation. It also maps detected behaviours to relevant MITRE ATT&CK techniques.

The objective is to demonstrate practical skills in security monitoring, threat detection, event analysis and incident investigation.

# Features

# 1. Suspicious PowerShell Detection

Identifies potentially suspicious PowerShell execution based on:

- Encoded PowerShell commands (`-enc` and `-encodedcommand`).
- PowerShell launched by Microsoft Office applications, including Word, Excel and Outlook.

**MITRE ATT&CK:**
- T1059.001 – PowerShell

# 2. Brute-Force Detection

Identifies potential brute-force activity by monitoring failed Windows logon events.

The detection logic:
- Analyses Windows Event ID 4625 (failed logon).
- Groups attempts by host and source IP address.
- Identifies five or more failed attempts within a five-minute window.
- Reports the number of failed attempts, timestamps and targeted usernames.

**MITRE ATT&CK:**
- T1110 – Brute Force

# 3. Account Creation Detection

Identifies Windows account-creation events and extracts information about newly created accounts.

The detection logic:
- Identifies Event ID 4720.
- Extracts the account creator and newly created username.
- Displays the associated process and command line.

**MITRE ATT&CK:**
- T1136.001 – Create Account: Local Account

# 4. Suspicious LOLBin Detection

Identifies potentially suspicious activity involving legitimate Windows executables that can be abused by attackers.

The tool examines command-line patterns associated with:

| Executable | Detection behaviour | MITRE ATT&CK |
|---|---|---|
| rundll32.exe | JavaScript execution through MSHTML | T1218.011 |
| regsvr32.exe | Suspicious scriptlet execution | T1218.010 |
| mshta.exe | JavaScript or VBScript execution | T1218.005 |
| certutil.exe | URL cache download activity | T1105 |
| bitsadmin.exe | File transfer activity | T1197 |

The tool focuses on suspicious command-line patterns rather than automatically flagging every execution of these legitimate Windows binaries.

## Investigation Module

The `investigate.py` script provides an interactive way to search and examine Windows event records.

An analyst can search using:

- Username
- Source IP address
- Process name
- Event ID
- Timestamp
- Other recorded event information

The investigation module displays matching events, including timestamps, host information, usernames, processes, parent processes, source IP addresses and command-line information.

This supports basic event correlation and investigation.

# Technologies Used

- Python 3
- CSV
- Pytest
- Git and GitHub
- Visual Studio Code

# Python Libraries

The project uses Python's standard libraries:

- `csv` – loading Windows event records.
- `collections` – grouping authentication events.
- `datetime` – processing timestamps and detection windows.
- `pathlib` and `sys` – resolving the test module import path.

Pytest is used for automated testing.

# Project Structure

```text
Windows-Threat-Hunting-Lab/
│
├── data/
│   └── windows_events.csv
│
├── src/
│   ├── hunter.py
│   └── investigate.py
│
├── tests/
│   └── test_hunter.py
│
├── .gitignore
└── README.md
```

# Installation and Usage

# Requirements

- Python 3
- Git
- Pytest

# Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate into the project directory:

```bash
cd Windows-Threat-Hunting-Lab
```

# Install Pytest

```bash
python3 -m pip install pytest
```

# Run the Threat Hunting Tool

From the project root directory:

```bash
python3 src/hunter.py
```

The script analyses the Windows event dataset and displays findings from its four detection modules.

# Run the Investigation Tool

```bash
python3 src/investigate.py
```

When prompted, enter a search value such as a username, source IP, process name or Event ID.

# Run Automated Tests

```bash
python3 -m pytest tests/
```

# Testing and Validation

The project includes an automated test suite containing six tests.

The tests validate:

| Test | Expected behaviour |
|---|---|
| Suspicious PowerShell | Detects encoded PowerShell launched by Word |
| Normal PowerShell | Does not flag ordinary PowerShell activity |
| Brute-force detection | Identifies five failed logons within the configured window |
| Account creation | Identifies a newly created account |
| Suspicious LOLBin | Detects suspicious rundll32 execution |
| Normal LOLBin | Does not flag ordinary rundll32 execution |

# Test Results

The automated tests were executed successfully using Pytest.

```text
collected 6 items

tests/test_hunter.py ......

6 passed in 0.02s
```

The threat hunting and investigation scripts were also executed successfully against the supplied dataset.

#Dataset

The project uses a synthetic Windows security event dataset stored in `data/windows_events.csv`.

The records contain fields such as:

- Timestamp
- Event ID
- Host
- Username
- Process
- Parent process
- Command line
- Source IP
- Event message

The dataset provides sample security telemetry for testing and demonstrating the detection and investigation functionality.

It does not represent live monitoring of an actual Windows endpoint.

# Limitations

- The project analyses CSV files rather than collecting live Windows events.
- Detection relies on predefined rules and command-line patterns.
- Suspicious activity is identified through basic detection logic and requires further analyst investigation.
- The tool does not automatically block processes, terminate sessions or remediate threats.
- The dataset is synthetic and does not represent real-world attack telemetry.

# Future Improvements

Potential enhancements include:

- Integration with live Windows Event Logs.
- Sysmon integration for additional endpoint telemetry.
- Expanded detection rules and behavioural analysis.
- Improved alert severity and risk scoring.
- Automated investigation reports.
- Integration with a SIEM platform
