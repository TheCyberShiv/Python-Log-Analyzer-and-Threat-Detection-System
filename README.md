# 🛡️ Python Log Analyzer & Threat Detection System

## 📌 Overview

A Python-based Security Operations Center (SOC) project that analyzes log files and detects suspicious activities such as brute-force attacks, PowerShell execution, ransomware indicators, user creation, IOC matches, and Windows Event IDs.

---

## 🚀 Features

- Brute Force Detection
- PowerShell Detection
- User Creation Detection
- Ransomware Detection
- IOC Detection
- Windows Event Detection
- MITRE ATT&CK Mapping
- CSV Report Generation
- PDF Incident Report
- Streamlit Dashboard

---

## 🛠️ Technologies Used

- Python
- Streamlit
- Matplotlib
- ReportLab

---

## 📂 Project Structure

```text
Python-Log-Analyzer/
│
├── analyzer.py
├── dashboard.py
├── detector.py
├── parser.py
├── report.py
├── mitre.py
├── rules.py
├── requirements.txt
├── README.md
│
├── logs/
├── reports/
├── ioc/
└── screenshots/
```

---

## ⚙️ Installation

```bash
git clone <repository-url>
cd Python-Log-Analyzer
pip install -r requirements.txt
```

---

## ▶️ Run the Dashboard

```bash
streamlit run dashboard.py
```

---

## 📄 Reports

- CSV Report
- PDF Incident Report

---

## 🛡️ MITRE ATT&CK Techniques

| Attack | Technique |
|---------|-----------|
| Brute Force | T1110 |
| PowerShell | T1059.001 |
| User Creation | T1136 |
| Ransomware | T1486 |

---

<img width="1920" height="1080" alt="DASHBOARD" src="https://github.com/user-attachments/assets/bcf23ef7-cccc-4580-8f29-34f535322324" />

<img width="1920" height="1080" alt="LOGS" src="https://github.com/user-attachments/assets/28c36dae-04f6-441b-b86c-c0cfd377878d" />

<img width="1920" height="1080" alt="MITRE" src="https://github.com/user-attachments/assets/77f375cf-596f-45f3-8e0d-8867e6c3e169" />

<img width="1920" height="1080" alt="WINDOWS EVENTS" src="https://github.com/user-attachments/assets/63c0cb67-ef19-4d22-aca6-f1ec86357479" />





## 👨‍💻 Author

**Shiv Kumar Maurya**

Cybersecurity Enthusiast | SOC Analyst Aspirant
