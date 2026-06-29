import streamlit as st
import matplotlib.pyplot as plt

from parser import read_logs

from detector import (
    detect_bruteforce,
    detect_powershell,
    detect_user_creation,
    detect_ransomware,
    detect_ioc,
    detect_event_ids
)

from mitre import get_mitre_mapping

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------

st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------

st.sidebar.title("🛡️ SOC Log Analyzer")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "MITRE ATT&CK",
        "Windows Events",
        "Logs"
    ]
)

# -------------------------------------------------
# LOAD LOGS
# -------------------------------------------------

uploaded_file = st.file_uploader(
    "📂 Upload Log File",
    type=["log", "txt"]
)

if uploaded_file is not None:
    logs = uploaded_file.read().decode("utf-8").splitlines()
else:
    logs = read_logs("logs/windows.log")

# -------------------------------------------------
# RUN DETECTIONS
# -------------------------------------------------

ip_count = detect_bruteforce(logs)

powershell = detect_powershell(logs)

users = detect_user_creation(logs)

ransomware = detect_ransomware(logs)

ioc = detect_ioc(logs)

event_alerts = detect_event_ids(logs)

# -------------------------------------------------
# BRUTE FORCE COUNT
# -------------------------------------------------

bruteforce = 0

for ip, count in ip_count.items():

    if count >= 3:
        bruteforce += 1

# =================================================
# DASHBOARD
# =================================================

if page == "Dashboard":

    st.title("🛡️ Python Log Analyzer & Threat Detection System")

    st.markdown(
        "Professional SOC Level-1 Dashboard"
    )

    st.info("""
✔ Brute Force Detection

✔ PowerShell Detection

✔ User Creation Detection

✔ Ransomware Detection

✔ IOC Detection

✔ Windows Event Detection

✔ MITRE ATT&CK Mapping
""")

    st.divider()

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Brute Force", bruteforce)
    c2.metric("PowerShell", len(powershell))
    c3.metric("User Creation", len(users))
    c4.metric("Ransomware", len(ransomware))
    c5.metric("IOC", len(ioc))

    st.divider()

    st.subheader("📋 Recent Alerts")

    table = []

    for ip, count in ip_count.items():

        if count >= 3:
            table.append(
                ["Brute Force", "HIGH", ip]
            )

    for _ in powershell:
        table.append(
            ["PowerShell", "HIGH", "-"]
        )

    for _ in users:
        table.append(
            ["User Creation", "HIGH", "-"]
        )

    for _ in ransomware:
        table.append(
            ["Ransomware", "CRITICAL", "-"]
        )

    for ip, log in ioc:
        table.append(
            ["IOC", "CRITICAL", ip]
        )

    st.table(
        table
    )

    st.divider()

    st.subheader("📊 Attack Distribution")

    attack_names = [
        "Brute Force",
        "PowerShell",
        "User",
        "Ransomware",
        "IOC"
    ]

    attack_values = [
        bruteforce,
        len(powershell),
        len(users),
        len(ransomware),
        len(ioc)
    ]

    fig, ax = plt.subplots(figsize=(8,5))

    ax.bar(
        attack_names,
        attack_values
    )

    ax.set_title("Detected Attacks")

    ax.set_ylabel("Count")

    st.pyplot(fig)

    st.divider()

    st.subheader("🔥 Severity Distribution")

    severity = [
        "High",
        "Critical"
    ]

    values = [
        bruteforce +
        len(powershell) +
        len(users),

        len(ransomware) +
        len(ioc)
    ]

    fig2, ax2 = plt.subplots(figsize=(5,5))

    ax2.pie(
        values,
        labels=severity,
        autopct="%1.1f%%",
        startangle=90
    )

    ax2.set_title("Alert Severity")

    st.pyplot(fig2)

    st.divider()

    st.subheader("📈 Project Statistics")

    st.write("Total Logs :", len(logs))

    st.write(
        "Windows Events :",
        len(event_alerts)
    )

    st.write(
        "Total Alerts :",
        bruteforce +
        len(powershell) +
        len(users) +
        len(ransomware) +
        len(ioc)
    )

    st.divider()

    st.success("🟢 Low Risk")

    st.warning("🟡 Medium Risk")

    st.error("🔴 Critical Alerts Detected")

    st.divider()

    st.subheader("⬇ Download CSV Report")

    try:

        with open(
            "reports/report.csv",
            "rb"
        ) as file:

            st.download_button(
                "Download CSV",
                file,
                file_name="SOC_Report.csv"
            )

    except:

        st.warning("Generate report first.")

# =================================================
# WINDOWS EVENTS
# =================================================

elif page == "Windows Events":

    st.title("🪟 Windows Event Detection")

    if len(event_alerts) == 0:

        st.success("No Windows Event Alerts")

    else:

        for event in event_alerts:

            st.error(f"""
Event ID : {event['event']}

Name : {event['name']}

Severity : {event['severity']}

MITRE : {event['mitre']}

Log :

{event['log']}
""")

# =================================================
# MITRE
# =================================================

elif page == "MITRE ATT&CK":

    st.title("🛡️ MITRE ATT&CK Mapping")

    mapping = get_mitre_mapping()

    table = []

    for attack, details in mapping.items():

        table.append([
            attack,
            details["id"],
            details["tactic"]
        ])

    st.table(table)

# =================================================
# LOG VIEWER
# =================================================

elif page == "Logs":

    st.title("📄 Log Viewer")

    search = st.text_input("Search")

    for line in logs:

        if search == "" or search.lower() in line.lower():

            st.code(line)

# -------------------------------------------------
# FOOTER
# -------------------------------------------------

st.divider()

st.caption(
    "Developed by Shiv Kumar Maurya | Python SOC Log Analyzer"
)