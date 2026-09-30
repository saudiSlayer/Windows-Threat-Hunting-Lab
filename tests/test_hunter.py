import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

from hunter import (
    detect_suspicious_powershell,
    detect_brute_force,
    detect_new_accounts,
    detect_suspicious_lolbins
)


def test_suspicious_powershell():

    events = [
        {
            "event_id": "4688",
            "timestamp": "2026-09-30 09:08:15",
            "host": "WIN-LAB-01",
            "user": "admin",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -enc ABC123",
            "source_ip": "10.0.0.20",
            "message": "Process created"
        }
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 1
    assert alerts[0]["mitre"] == "T1059.001 - PowerShell"


def test_normal_powershell_not_flagged():

    events = [
        {
            "event_id": "4688",
            "timestamp": "2026-09-30 09:08:15",
            "host": "WIN-LAB-01",
            "user": "alice",
            "process": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe Get-Process",
            "source_ip": "10.0.0.20",
            "message": "Process created"
        }
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 0


def test_brute_force_detection():

    events = []

    for i in range(5):

        events.append({
            "event_id": "4625",
            "timestamp": f"2026-09-30 09:05:{22 + i:02d}",
            "host": "WIN-LAB-01",
            "user": "bob",
            "process": "",
            "parent_process": "",
            "command_line": "",
            "source_ip": "10.0.0.55",
            "message": "Failed logon"
        })

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.55"
    assert alerts[0]["failed_attempts"] >= 5


def test_new_account_detection():

    events = [
        {
            "event_id": "4720",
            "timestamp": "2026-09-30 09:10:04",
            "host": "WIN-LAB-01",
            "user": "admin",
            "process": "net.exe",
            "parent_process": "powershell.exe",
            "command_line": "net user backupadmin <REDACTED> /add",
            "source_ip": "10.0.0.20",
            "message": "User account created"
        }
    ]

    alerts = detect_new_accounts(events)

    assert len(alerts) == 1
    assert alerts[0]["created_account"] == "backupadmin"


def test_lolbin_detection():

    events = [
        {
            "event_id": "4688",
            "timestamp": "2026-09-30 09:15:45",
            "host": "WIN-LAB-01",
            "user": "admin",
            "process": "rundll32.exe",
            "parent_process": "explorer.exe",
            "command_line": (
                'rundll32.exe '
                'javascript:"\\..\\mshtml,RunHTMLApplication"'
            ),
            "source_ip": "10.0.0.20",
            "message": "Process created"
        }
    ]

    alerts = detect_suspicious_lolbins(events)

    assert len(alerts) == 1
    assert alerts[0]["mitre"] == "T1218.011 - Rundll32"


def test_normal_rundll32_not_flagged():

    events = [
        {
            "event_id": "4688",
            "timestamp": "2026-09-30 09:15:45",
            "host": "WIN-LAB-01",
            "user": "alice",
            "process": "rundll32.exe",
            "parent_process": "explorer.exe",
            "command_line": "rundll32.exe example.dll,EntryPoint",
            "source_ip": "10.0.0.20",
            "message": "Process created"
        }
    ]

    alerts = detect_suspicious_lolbins(events)

    assert len(alerts) == 0