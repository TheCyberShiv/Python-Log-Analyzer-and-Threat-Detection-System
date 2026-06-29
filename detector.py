def detect_bruteforce(logs):

    ip_count = {}

    for line in logs:

        if "FAILED LOGIN" in line:

            words = line.split()
            ip = words[-1]

            if ip in ip_count:
                ip_count[ip] += 1
            else:
                ip_count[ip] = 1

    return ip_count


def detect_powershell(logs):

    keywords = [
        "powershell.exe",
        "Invoke-WebRequest",
        "EncodedCommand",
        "DownloadString",
        "IEX"
    ]

    alerts = []

    for line in logs:
        for keyword in keywords:
            if keyword in line:
                alerts.append(line.strip())
                break

    return alerts


def detect_user_creation(logs):

    keywords = [
        "User hacker created",
        "net user",
        "useradd"
    ]

    alerts = []

    for line in logs:
        for keyword in keywords:
            if keyword in line:
                alerts.append(line.strip())
                break

    return alerts
def detect_ransomware(logs):

    keywords = [
        "vssadmin delete shadows",
        "cipher.exe",
        "wbadmin",
        "bcdedit"
    ]

    alerts = []

    for line in logs:
        for keyword in keywords:
            if keyword.lower() in line.lower():
                alerts.append(line.strip())
                break

    return alerts
def detect_ioc(logs):

    with open("ioc/malicious_ips.txt", "r") as file:
        malicious_ips = file.read().splitlines()

    alerts = []

    for line in logs:

        for ip in malicious_ips:

            if ip in line:

                alerts.append((ip, line.strip()))

    return alerts
from rules import EVENT_IDS

def detect_event_ids(logs):

    alerts = []

    for line in logs:

        for event_id in EVENT_IDS:

            if event_id in line:

                alerts.append({
                    "event": event_id,
                    "name": EVENT_IDS[event_id]["name"],
                    "severity": EVENT_IDS[event_id]["severity"],
                    "mitre": EVENT_IDS[event_id]["mitre"],
                    "log": line.strip()
                })

    return alerts