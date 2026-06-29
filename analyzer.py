from parser import read_logs
from report import generate_csv, generate_pdf
from report import generate_csv
from detector import (
    detect_bruteforce,
    detect_powershell,
    detect_user_creation,
    detect_ransomware,
    detect_ioc
)
logs = read_logs("logs/windows.log")

ip_count = detect_bruteforce(logs)

print("\n====== SOC ALERT REPORT ======\n")

for ip, count in ip_count.items():

    print("IP:", ip)
    print("Attempts:", count)

    if count >= 3:
        print("🚨 Brute Force Attack")
        print("Severity: HIGH")
        print("MITRE: T1110")

    print("---------------------")
powershell_alerts = detect_powershell(logs)

print("\n====== PowerShell Alerts ======\n")

for alert in powershell_alerts:

    print("🚨 Suspicious PowerShell Activity")
    print("Severity : HIGH")
    print("MITRE ID : T1059")
    print("Command  :", alert)
    print("-----------------------------------")
generate_csv(ip_count)

user_alerts = detect_user_creation(logs)

print("\n====== User Creation Alerts ======\n")

for alert in user_alerts:

    print("🚨 ALERT : User Creation Detected")
    print("Severity : HIGH")
    print("MITRE ID : T1136")
    print("Log      :", alert)

    print("Recommendation:")
    print("- Verify if the account creation is authorized")
    print("- Check administrator activity")
    print("- Disable suspicious accounts")

    print("------------------------------------")
    # -----------------------------
# Ransomware Detection
# -----------------------------

ransomware_alerts = detect_ransomware(logs)

print("\n========== RANSOMWARE ALERTS ==========\n")

for alert in ransomware_alerts:

    print("🚨 ALERT NAME : Possible Ransomware Activity")
    print("Severity      : CRITICAL")
    print("MITRE ID      : T1486")
    print("Command       :", alert)

    print("\nRecommendation:")
    print("- Isolate the affected system")
    print("- Disconnect from the network")
    print("- Preserve forensic evidence")
    print("- Notify Incident Response Team")

    print("----------------------------------------")
    # -----------------------------
# IOC Detection
# -----------------------------

ioc_alerts = detect_ioc(logs)

print("\n========== IOC ALERTS ==========\n")

for ip, log in ioc_alerts:

    print("🚨 ALERT NAME : Known Malicious IP")
    print("Severity      : CRITICAL")
    print("MITRE ID      : T1583")
    print("Malicious IP  :", ip)
    print("Log           :", log)

    print("\nRecommendation:")
    print("- Block this IP")
    print("- Check firewall logs")
    print("- Search for related activity")
    print("- Monitor network traffic")

    print("--------------------------------------")
    generate_csv(ip_count)
    generate_pdf(logs, ip_count)
    