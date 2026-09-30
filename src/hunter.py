import csv
from collections import defaultdict
from datetime import datetime, timedelta


LOG_FILE = "data/windows_events.csv"

FAILED_LOGON_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def load_events(filename):
    with open(filename, newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def parse_timestamp(timestamp):
    return datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S"
    )


# --------------------------------------------------
# HUNT 1: SUSPICIOUS POWERSHELL
# --------------------------------------------------

def detect_suspicious_powershell(events):

    alerts = []

    for event in events:

        if event["event_id"] != "4688":
            continue

        process = event["process"].strip().lower()
        parent = event["parent_process"].strip().lower()
        command = event["command_line"].lower()

        if process != "powershell.exe":
            continue

        reasons = []

        if "-enc" in command or "-encodedcommand" in command:
            reasons.append("Encoded PowerShell command")

        if parent in [
            "winword.exe",
            "excel.exe",
            "outlook.exe"
        ]:
            reasons.append(
                f"PowerShell launched by {parent}"
            )

        if reasons:

            alerts.append({
                "timestamp": event["timestamp"],
                "host": event["host"],
                "user": event["user"],
                "process": event["process"],
                "parent_process": event["parent_process"],
                "command_line": event["command_line"],
                "reasons": reasons,
                "mitre": "T1059.001 - PowerShell"
            })

    return alerts


# --------------------------------------------------
# HUNT 2: FAILED LOGON CORRELATION
# --------------------------------------------------

def detect_brute_force(events):

    failed_logons = defaultdict(list)
    alerts = []

    for event in events:

        if event["event_id"] != "4625":
            continue

        source_ip = event["source_ip"].strip()

        if not source_ip:
            continue

        failed_logons[
            (event["host"], source_ip)
        ].append({
            "timestamp": parse_timestamp(event["timestamp"]),
            "user": event["user"]
        })

    for (host, source_ip), attempts in failed_logons.items():

        attempts.sort(
            key=lambda attempt: attempt["timestamp"]
        )

        for current_attempt in attempts:

            window_start = (
                current_attempt["timestamp"]
                - timedelta(minutes=TIME_WINDOW_MINUTES)
            )

            window = [
                attempt
                for attempt in attempts
                if window_start
                <= attempt["timestamp"]
                <= current_attempt["timestamp"]
            ]

            if len(window) >= FAILED_LOGON_THRESHOLD:

                alerts.append({
                    "host": host,
                    "source_ip": source_ip,
                    "failed_attempts": len(window),
                    "first_attempt": window[0]["timestamp"],
                    "last_attempt": window[-1]["timestamp"],
                    "targeted_users": sorted({
                        attempt["user"]
                        for attempt in window
                    }),
                    "mitre": "T1110 - Brute Force"
                })

                break

    return alerts


# --------------------------------------------------
# HUNT 3: ACCOUNT CREATION
# --------------------------------------------------

def detect_new_accounts(events):

    alerts = []

    for event in events:

        if event["event_id"] != "4720":
            continue

        command = event["command_line"]
        parts = command.split()

        created_account = "Unknown"

        for index, part in enumerate(parts):

            if part.lower() == "user":

                if index + 1 < len(parts):
                    created_account = parts[index + 1]

                break

        alerts.append({
            "timestamp": event["timestamp"],
            "host": event["host"],
            "creator": event["user"],
            "created_account": created_account,
            "process": event["process"],
            "command_line": command,
            "mitre": "T1136.001 - Create Account: Local Account"
        })

    return alerts


# --------------------------------------------------
# HUNT 4: SUSPICIOUS LOLBIN USAGE
# --------------------------------------------------

def detect_suspicious_lolbins(events):

    alerts = []

    for event in events:

        if event["event_id"] != "4688":
            continue

        process = event["process"].strip().lower()
        command = event["command_line"].lower()

        reasons = []
        mitre = None

        if process == "rundll32.exe":

            if "javascript:" in command and "mshtml" in command:
                reasons.append(
                    "Rundll32 executing JavaScript through MSHTML"
                )
                mitre = "T1218.011 - Rundll32"

        elif process == "regsvr32.exe":

            if "/i:" in command and "scrobj.dll" in command:
                reasons.append(
                    "Regsvr32 scriptlet execution pattern"
                )
                mitre = "T1218.010 - Regsvr32"

        elif process == "mshta.exe":

            if "javascript:" in command or "vbscript:" in command:
                reasons.append(
                    "MSHTA executing a script"
                )
                mitre = "T1218.005 - Mshta"

        elif process == "certutil.exe":

            if "-urlcache" in command:
                reasons.append(
                    "Certutil URL download pattern"
                )
                mitre = "T1105 - Ingress Tool Transfer"

        elif process == "bitsadmin.exe":

            if "/transfer" in command:
                reasons.append(
                    "BITSAdmin file transfer pattern"
                )
                mitre = "T1197 - BITS Jobs"

        if reasons:

            alerts.append({
                "timestamp": event["timestamp"],
                "host": event["host"],
                "user": event["user"],
                "process": event["process"],
                "parent_process": event["parent_process"],
                "command_line": event["command_line"],
                "reasons": reasons,
                "mitre": mitre
            })

    return alerts


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

def display_powershell_alerts(alerts):

    for alert in alerts:

        print("\n[!] SUSPICIOUS POWERSHELL ACTIVITY")
        print(f"Timestamp:      {alert['timestamp']}")
        print(f"Host:           {alert['host']}")
        print(f"User:           {alert['user']}")
        print(f"Process:        {alert['process']}")
        print(f"Parent Process: {alert['parent_process']}")
        print(f"Command Line:   {alert['command_line']}")

        print("\nReasons:")

        for reason in alert["reasons"]:
            print(f"  - {reason}")

        print(f"\nMITRE ATT&CK: {alert['mitre']}")


def display_brute_force_alerts(alerts):

    for alert in alerts:

        print("\n[!] WINDOWS BRUTE-FORCE ACTIVITY")
        print(f"Host:            {alert['host']}")
        print(f"Source IP:       {alert['source_ip']}")
        print(f"Failed Logons:   {alert['failed_attempts']}")
        print(f"First Attempt:   {alert['first_attempt']}")
        print(f"Last Attempt:    {alert['last_attempt']}")

        print(
            "Targeted Users:  "
            + ", ".join(alert["targeted_users"])
        )

        print(f"\nMITRE ATT&CK: {alert['mitre']}")


def display_new_account_alerts(alerts):

    for alert in alerts:

        print("\n[!] NEW USER ACCOUNT CREATED")
        print(f"Timestamp:       {alert['timestamp']}")
        print(f"Host:            {alert['host']}")
        print(f"Created By:      {alert['creator']}")
        print(f"Created Account: {alert['created_account']}")
        print(f"Process:         {alert['process']}")
        print(f"Command Line:    {alert['command_line']}")

        print(f"\nMITRE ATT&CK: {alert['mitre']}")


def display_lolbin_alerts(alerts):

    for alert in alerts:

        print("\n[!] SUSPICIOUS LOLBIN ACTIVITY")
        print(f"Timestamp:      {alert['timestamp']}")
        print(f"Host:           {alert['host']}")
        print(f"User:           {alert['user']}")
        print(f"Process:        {alert['process']}")
        print(f"Parent Process: {alert['parent_process']}")
        print(f"Command Line:   {alert['command_line']}")

        print("\nReasons:")

        for reason in alert["reasons"]:
            print(f"  - {reason}")

        print(f"\nMITRE ATT&CK: {alert['mitre']}")


def main():

    events = load_events(LOG_FILE)

    powershell_alerts = detect_suspicious_powershell(events)
    brute_force_alerts = detect_brute_force(events)
    account_alerts = detect_new_accounts(events)
    lolbin_alerts = detect_suspicious_lolbins(events)

    print("\n========================================")
    print("       WINDOWS THREAT HUNTING")
    print("========================================")

    print("\n--- PowerShell Hunt ---")
    display_powershell_alerts(powershell_alerts)

    print("\n--- Authentication Hunt ---")
    display_brute_force_alerts(brute_force_alerts)

    print("\n--- Account Creation Hunt ---")
    display_new_account_alerts(account_alerts)

    print("\n--- LOLBin Hunt ---")
    display_lolbin_alerts(lolbin_alerts)

    total = (
        len(powershell_alerts)
        + len(brute_force_alerts)
        + len(account_alerts)
        + len(lolbin_alerts)
    )

    print("\n========================================")
    print(f"Total Findings: {total}")
    print("========================================")


if __name__ == "__main__":
    main()